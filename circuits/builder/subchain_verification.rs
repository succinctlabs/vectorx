use async_trait::async_trait;
use codec::Encode;
use ethers::types::H256;
use itertools::Itertools;
use log::debug;
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::merkle::simple::SimpleMerkleTree;
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, RichField, ValueStream,
    Variable,
};
use serde::{Deserialize, Serialize};

use crate::builder::decoder::DecodingMethods;
use crate::builder::header::HeaderMethods;
use crate::consts::{HEADERS_PER_MAP, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE};
use crate::input::RpcDataFetcher;
use crate::vars::{EncodedHeader, EncodedHeaderVariable, SubchainVerificationVariable};

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub global_start_block: U32Variable,
    pub global_start_header_hash: Bytes32Variable,
    pub global_end_block: U32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    /// Verify a chain of headers and compute the state and data merkle root commitments over the
    /// range [trusted_block + 1, target_block] inclusive, and also return the verified target
    /// header hash.
    fn verify_subchain<C: Circuit, const MAX_HEADER_LENGTH: usize>(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> SubchainVerificationVariable
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct MapReduceSubchainVariable {
    pub num_blocks: Variable,
    pub start_block: U32Variable,
    pub start_header_hash: Bytes32Variable,
    pub start_parent: Bytes32Variable,
    pub end_block: U32Variable,
    pub end_header_hash: Bytes32Variable,
    pub state_merkle_root: Bytes32Variable,
    pub data_merkle_root: Bytes32Variable,
}

impl<L: PlonkParameters<D>, const D: usize> SubChainVerifier<L, D> for CircuitBuilder<L, D> {
    fn verify_subchain<C: Circuit, const MAX_NUM_HEADERS: usize>(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> SubchainVerificationVariable
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            global_start_block: trusted_block,
            global_start_header_hash: trusted_header_hash,
            global_end_block: target_block,
        };

        // The number of map jobs is the smallest power of 2 that is >= to MAX_NUM_HEADERS / HEADERS_PER_MAP.
        let mut num_map_jobs = MAX_NUM_HEADERS / HEADERS_PER_MAP;
        if MAX_NUM_HEADERS % HEADERS_PER_MAP != 0 {
            num_map_jobs += 1;
        }
        let num_jobs_power_of_2 = f32::log2(num_map_jobs as f32).ceil() as u32;
        num_map_jobs = 2usize.pow(num_jobs_power_of_2);
        assert!(num_map_jobs >= 2, "Number of map jobs must be at least 2!");

        let relative_block_nums =
            (1u32..(num_map_jobs as u32 * HEADERS_PER_MAP as u32) + 1).collect_vec();

        let output =
            self.mapreduce::<SubchainVerificationCtx, U32Variable, MapReduceSubchainVariable, C, HEADERS_PER_MAP, _, _>(
                ctx,
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {

                    let batch_start_block =
                        builder.add(map_ctx.global_start_block, map_relative_block_nums.as_vec()[0]);

                    // Get the end block of this leaf.
                    let batch_end_block = builder.add(
                        map_ctx.global_start_block,
                        map_relative_block_nums.as_vec()[HEADERS_PER_MAP - 1],
                    );
                    // Note: These headers are untrusted as they are fetched via a hint, and so need
                    // to be explicitly constrained to the public inputs of the circuit.
                    // Fetches all headers from batch_start_block to max(batch_start_block, min(batch_end_block, global_end_block)). Fills
                    // in the rest of the headers with empty headers.
                    let mut input_stream = VariableStream::new();
                    input_stream.write(&batch_start_block);
                    input_stream.write(&batch_end_block);
                    input_stream.write(&map_ctx.global_end_block);
                    let header_fetcher = HeaderRangeFetcherHint::<MAX_HEADER_SIZE, HEADERS_PER_MAP> {};
                    let headers = builder
                        .async_hint(input_stream, header_fetcher)
                        .read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, HEADERS_PER_MAP>>(
                            builder,
                        );

                    let mut block_nums = Vec::new();
                    let mut block_hashes = Vec::new();
                    let mut block_parent_hashes = Vec::new();
                    let mut block_state_roots = Vec::new();
                    let mut block_data_roots = Vec::new();

                    // "end_block_num" and "end_header_hash" are iterators that will store the
                    // respective values for the header corresponding to target_block.
                    let mut end_block_num: U32Variable = builder.zero();
                    let empty_bytes_32_variable =
                        Bytes32Variable::constant(builder, H256::from_slice(&[0u8; 32]));
                    let mut end_header_hash: Bytes32Variable = empty_bytes_32_variable;

                    let zero = builder.zero::<Variable>();
                    let one = builder.one::<Variable>();
                    let one_u32 = builder.one::<U32Variable>();
                    let true_const = builder._true();

                    let mut num_headers = zero;

                    // Check if the batch is disabled.
                    let is_batch_disabled = builder.lt(
                        map_ctx.global_end_block,
                        batch_start_block,
                    );
                    let mut curr_block_disabled = is_batch_disabled;

                    // The number of enabled leaves in the merkle tree. All leaves after nb_enabled_leaves
                    // are empty leaves.
                    let mut nb_enabled_leaves = builder.zero();

                    for i in 0..HEADERS_PER_MAP {
                        // Compute the block hash.
                        let hash = builder.hash_encoded_header::<MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE>(&headers[i]);
                        block_hashes.push(hash);

                        // Decode the header and save the relevant fields.
                        let header_variable =
                            builder.decode_header::<MAX_HEADER_SIZE>(&headers[i], &hash);
                        block_nums.push(header_variable.block_number);
                        block_parent_hashes.push(header_variable.parent_hash);
                        block_state_roots.push(header_variable.state_root);
                        block_data_roots.push(header_variable.data_root);

                        // Verify that the headers are linked correctly, starting from the start header.
                        // The start header's backwards link is checked in the reduce stage.
                        if i > 0 {
                            // Verify that the parent hash chain and block number chain are correct.
                            let hashes_linked =
                                builder.is_equal(block_parent_hashes[i], block_hashes[i - 1]);
                            let expected_block_num = builder.add(block_nums[i - 1], one_u32);
                            let nums_sequential =
                                builder.is_equal(block_nums[i], expected_block_num);

                            let header_correctly_linked =
                                builder.and(hashes_linked, nums_sequential);

                            // If this block is not disabled, the headers must be correctly linked.
                            let link_check = builder.or(curr_block_disabled, header_correctly_linked);
                            builder.assert_is_equal(link_check, true_const);
                        }

                        // If this is not the final block, update end_block_num, end_header_hash and num_headers.
                        end_block_num = builder.select(
                            curr_block_disabled,
                            end_block_num,
                            header_variable.block_number,
                        );
                        end_header_hash = builder.select(curr_block_disabled, end_header_hash, hash);

                        let num_headers_increment = builder.select(curr_block_disabled, zero, one);
                        num_headers = builder.add(num_headers, num_headers_increment);

                        // Increment the number of enabled leaves if the header is not disabled.
                        let val = builder.select(curr_block_disabled, zero, one);
                        nb_enabled_leaves = builder.add(
                            nb_enabled_leaves,
                            val,
                        );

                        // If this is the target block, set curr_block_disabled to true.
                        let is_final_block = builder.is_equal(header_variable.block_number, map_ctx.global_end_block);
                        curr_block_disabled = builder.or(curr_block_disabled, is_final_block);
                    }

                    // Either the batch is disabled OR the first block's block number is batch_start_block.
                    let first_block_nb_check = builder.is_equal(block_nums[0], batch_start_block);
                    let first_block_nb_check = builder.or(first_block_nb_check, is_batch_disabled);
                    builder.assert_is_equal(first_block_nb_check, true_const);

                    // Either the last block is disabled OR the last block's block number in the batch is batch_end_block.
                    let last_block_nb_check = builder.is_equal(end_block_num, batch_end_block);
                    let last_block_nb_check = builder.or(last_block_nb_check, curr_block_disabled);
                    builder.assert_is_equal(last_block_nb_check, true_const);

                    // Calculate the state and data merkle roots.
                    let state_merkle_root = builder.get_root_from_hashed_leaves::<HEADERS_PER_MAP>(
                        ArrayVariable::<Bytes32Variable, HEADERS_PER_MAP>::new(block_state_roots),
                        nb_enabled_leaves,
                    );
                    let data_merkle_root = builder.get_root_from_hashed_leaves::<HEADERS_PER_MAP>(
                        ArrayVariable::<Bytes32Variable, HEADERS_PER_MAP>::new(block_data_roots),
                        nb_enabled_leaves,
                    );

                    MapReduceSubchainVariable {
                        num_blocks: num_headers,
                        start_block: block_nums[0],
                        start_header_hash: block_hashes[0],
                        start_parent: block_parent_hashes[0],
                        end_block: end_block_num,
                        end_header_hash,
                        state_merkle_root,
                        data_merkle_root,
                    }
                },
                |_, left, right, builder| {
                    let true_v = builder._true();
                    let one = builder.one();
                    // Reduce Stage
                    // 1. Confirm that the left and right subchains are correctly linked if the
                    //  right subchain is enabled. Check that
                    //      a) the last block number of the left subchain is 1 less than the start block number of the right subchain.
                    //      b) the parent of the right subchain is the left subchain's end header hash.
                    // 2. Get the end header hash and end block number for the combined subchain. If
                    //  the right subchain is disabled, use the left subchain's end values.
                    // 3. Compute the state and data merkle roots for the combined subchain.
                    // 4. Compute the total number of blocks in the subchain.

                    // Check to see if the left and right subchains are correctly linked.
                    let are_subchains_linked =
                        builder.is_equal(left.end_header_hash, right.start_parent);
                    let expected_left_end_block_number = builder.sub(right.start_block, one);
                    let are_subchains_sequential = builder.is_equal(left.end_block, expected_left_end_block_number);
                    let are_subchains_linked = builder.and(are_subchains_linked, are_subchains_sequential);

                    // If the right subchain is disabled, then don't need to check the 
                    // are_subchains_linked boolean.
                    let is_right_subchain_inactive = builder.is_zero(right.num_blocks);
                    let is_subchain_link_valid = builder.or(is_right_subchain_inactive, are_subchains_linked);
                    builder.assert_is_equal(is_subchain_link_valid, true_v);

                    // Get the right most block num and hash between the two nodes.
                    // If the right node is not empty, this will be the right node's rightmost entry,
                    // otherwise it will be the left block's rightmost entry.
                    let end_block_nb = builder.select(is_right_subchain_inactive, left.end_block, right.end_block);
                    let end_header_hash =
                        builder.select(is_right_subchain_inactive, left.end_header_hash, right.end_header_hash);

                    // Compute the merkle roots where the left and right nodes are the merkle roots
                    // from the left and right nodes respectively.
                    let mut state_root_bytes = left.state_merkle_root.as_bytes().to_vec();
                    state_root_bytes.extend(&right.state_merkle_root.as_bytes());
                    let state_merkle_root = builder.sha256(&state_root_bytes);

                    let mut data_root_bytes = left.data_merkle_root.as_bytes().to_vec();
                    data_root_bytes.extend(&right.data_merkle_root.as_bytes());
                    let data_merkle_root = builder.sha256(&data_root_bytes);

                    // Compute the total number of blocks in the subchain.
                    let combined_num_blocks = builder.add(left.num_blocks, right.num_blocks);

                    MapReduceSubchainVariable {
                        num_blocks: combined_num_blocks,
                        start_block: left.start_block,
                        start_header_hash: left.start_header_hash,
                        start_parent: left.start_parent,
                        end_block: end_block_nb,
                        end_header_hash,
                        state_merkle_root,
                        data_merkle_root,
                    }
                },
            );

        // Assert the parent of the header chain corresponds to the trusted_header_hash.
        self.assert_is_equal(trusted_header_hash, output.start_parent);

        // Assert the target_block match the end_block.
        self.assert_is_equal(target_block, output.end_block);

        SubchainVerificationVariable {
            target_header_hash: output.end_header_hash,
            state_root_merkle_root: output.state_merkle_root,
            data_root_merkle_root: output.data_merkle_root,
        }
    }
}

// Fetch a range of headers with a hint. Used to generate a data commitment for step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRangeFetcherHint<const HEADER_LENGTH: usize, const NUM_HEADERS: usize> {}

#[async_trait]
impl<
        const HEADER_LENGTH: usize,
        const NUM_HEADERS: usize,
        L: PlonkParameters<D>,
        const D: usize,
    > AsyncHint<L, D> for HeaderRangeFetcherHint<HEADER_LENGTH, NUM_HEADERS>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let start_block = input_stream.read_value::<U32Variable>();
        let mut last_block = input_stream.read_value::<U32Variable>();
        let max_block = input_stream.read_value::<U32Variable>();

        last_block = last_block.min(max_block);

        debug!(
            "HeaderFetcherHint: downloading header range of start_block={}, last_block={}",
            start_block, last_block
        );

        let mut headers = Vec::new();
        if last_block >= start_block {
            headers.extend({
                let mut data_fetcher = RpcDataFetcher::new().await;
                data_fetcher
                    .get_block_headers_range(start_block, last_block)
                    .await
            });
        }

        // Pad `headers` to the correct length for `EncodedHeader` variables.
        let mut header_variables = Vec::new();
        for (i, header) in headers.iter().enumerate() {
            let mut header_bytes = header.encode();
            let header_size = header_bytes.len();
            if header_size > HEADER_LENGTH {
                panic!(
                    "Block {}'s header size is {}, which is greater than the maximum header size of {} bytes.",
                    start_block + i as u32,
                    header_size,
                    HEADER_LENGTH
                );
            }
            header_bytes.resize(HEADER_LENGTH, 0);
            let header_variable = EncodedHeader {
                header_bytes,
                header_size: header_size as u32,
            };
            header_variables.push(header_variable);
        }

        // Pad `header_variables` with empty headers to ensure its length is NUM_HEADERS.
        for _i in headers.len()..NUM_HEADERS {
            let header_variable = EncodedHeader {
                header_bytes: vec![0u8; HEADER_LENGTH],
                header_size: 0u32,
            };
            header_variables.push(header_variable);
        }
        output_stream
            .write_value::<ArrayVariable<EncodedHeaderVariable<HEADER_LENGTH>, NUM_HEADERS>>(
                header_variables,
            );
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
    use plonky2x::prelude::{DefaultBuilder, DefaultParameters, HintRegistry};

    use super::*;
    use crate::consts::BLAKE2B_CHUNK_SIZE_BYTES;

    // MapReduce circuits requires a circuit to be defined in order to invoke the mapreduce method.
    #[derive(Clone, Debug)]
    struct TestSubchainVerificationCircuit<
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    >;

    impl<const MAX_HEADER_SIZE: usize, const MAX_NUM_HEADERS: usize> Circuit
        for TestSubchainVerificationCircuit<MAX_HEADER_SIZE, MAX_NUM_HEADERS>
    {
        fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
        where
            <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
        {
            let trusted_block = builder.evm_read::<U32Variable>();
            let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
            let target_block = builder.evm_read::<U32Variable>();

            // Note: trusted_block and target_block are always in the same authority set.
            let subchain_output = builder.verify_subchain::<Self, MAX_NUM_HEADERS>(
                trusted_block,
                trusted_header_hash,
                target_block,
            );
            builder.watch(&subchain_output.target_header_hash, "target header hash");
        }

        fn register_generators<L: PlonkParameters<D>, const D: usize>(
            registry: &mut HintRegistry<L, D>,
        ) where
            <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
        {
            registry
                .register_async_hint::<HeaderRangeFetcherHint<MAX_HEADER_SIZE, HEADERS_PER_MAP>>();

            let id = MapReduceGenerator::<
                L,
                SubchainVerificationCtx,
                U32Variable,
                MapReduceSubchainVariable,
                Self,
                HEADERS_PER_MAP,
                D,
            >::id();
            registry.register_simple::<MapReduceGenerator<
                L,
                SubchainVerificationCtx,
                U32Variable,
                MapReduceSubchainVariable,
                Self,
                HEADERS_PER_MAP,
                D,
            >>(id);
        }
    }
    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_subchain() {
        env::set_var("RUST_LOG", "debug");
        dotenv::dotenv().ok();
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        const MAX_NUM_HEADERS: usize = 16;
        const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * BLAKE2B_CHUNK_SIZE_BYTES;

        TestSubchainVerificationCircuit::<MAX_HEADER_SIZE, MAX_NUM_HEADERS>::define(&mut builder);
        let circuit = builder.build();

        let mut input = circuit.input();
        let trusted_header = "42933743127422ab194445ad5bf0d27ea7ccd20f98cdc902ee7fc55df00fca68"
            .parse()
            .unwrap();
        let trusted_block = 397855u32;
        let target_block = 397862u32; // mimics test_step_small

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(trusted_header);
        input.evm_write::<U32Variable>(target_block);

        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        TestSubchainVerificationCircuit::<MAX_HEADER_SIZE, MAX_NUM_HEADERS>::test_serialization::<
            L,
            D,
        >();
    }
}
