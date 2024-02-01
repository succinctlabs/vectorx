use ethers::types::H256;
use itertools::Itertools;
use log::{debug, Level};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::merkle::simple::SimpleMerkleTree;
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, RichField, Variable,
};

use crate::builder::decoder::DecodingMethods;
use crate::builder::header::{HeaderMethods, HeaderRangeFetcherHint};
use crate::consts::{HEADERS_PER_MAP, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE};
use crate::vars::EncodedHeaderVariable;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub trusted_block: U32Variable,
    pub trusted_header_hash: Bytes32Variable,
    pub target_block: U32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    fn verify_subchain<C: Circuit, const MAX_HEADER_LENGTH: usize>(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
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
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            trusted_block,
            trusted_header_hash,
            target_block,
        };

        // Calculate the number of map jobs.
        // It should be the smallest power of 2 that is >= to
        // MAX_NUM_HEADERS / HEADERS_PER_MAP.
        let mut num_map_jobs = MAX_NUM_HEADERS / HEADERS_PER_MAP;
        if MAX_NUM_HEADERS % HEADERS_PER_MAP != 0 {
            num_map_jobs += 1;
        }
        let num_jobs_power_of_2 = f32::log2(num_map_jobs as f32).ceil() as u32;
        num_map_jobs = 2usize.pow(num_jobs_power_of_2);
        assert!(num_map_jobs >= 2, "Number of map jobs must be at least 2!");

        debug!("verify_subchain - num_map_jobs: {}", num_map_jobs);

        let relative_block_nums =
            (1u32..(num_map_jobs as u32 * HEADERS_PER_MAP as u32) + 1).collect_vec();

        let output =
            self.mapreduce::<SubchainVerificationCtx, U32Variable, MapReduceSubchainVariable, C, HEADERS_PER_MAP, _, _>(
                ctx,
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {
                    // Get the start block that this map job is responsible for
                    let start_block =
                        builder.add(map_ctx.trusted_block, map_relative_block_nums.as_vec()[0]);

                    // Get the last block that this map job is responsible for
                    let last_block = builder.add(
                        map_ctx.trusted_block,
                        map_relative_block_nums.as_vec()[HEADERS_PER_MAP - 1],
                    );

                    builder.watch_with_level(&start_block, "map job - start block", Level::Debug);
                    builder.watch_with_level(&last_block, "map job - last block", Level::Debug);

                    // Get the max block that the whole MR job is responsible for
                    // Note that the max block may be less than the last_block (or even the start_block).
                    // Right now, there is a hard coded number of map leaves and if the block
                    // range doesn't fill that up, then there could be "no-op" leaves.
                    let max_block = map_ctx.target_block;

                    let mut input_stream = VariableStream::new();
                    input_stream.write(&start_block);
                    input_stream.write(&last_block);
                    input_stream.write(&max_block);
                    let header_fetcher = HeaderRangeFetcherHint::<MAX_HEADER_SIZE, HEADERS_PER_MAP> {};

                    // Retrieve the headers from start_block to min(last_block, max_block) inclusive.
                    // Note that the latter number may be greater than start_block.
                    let output_stream = builder
                        .async_hint(input_stream, header_fetcher);

                    let headers = output_stream.read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, HEADERS_PER_MAP>>(builder);
                    let expected_data_roots = output_stream.read::<ArrayVariable<Bytes32Variable, HEADERS_PER_MAP>>(builder);

                    let mut block_nums = Vec::new();
                    let mut block_hashes = Vec::new();
                    let mut block_parent_hashes = Vec::new();
                    let mut block_state_roots = Vec::new();
                    let mut block_data_roots = Vec::new();

                    // "end_block_num" and "end_header_hash" are iterators that will store the
                    // respective values for the last non-padded header.
                    let mut end_block_num: U32Variable = builder.zero();
                    let empty_bytes_32_variable =
                        Bytes32Variable::constant(builder, H256::from_slice(&[0u8; 32]));
                    let mut end_header_hash: Bytes32Variable = empty_bytes_32_variable;

                    let zero = builder.zero::<Variable>();
                    let one = builder.one::<Variable>();
                    let one_u32 = builder.one::<U32Variable>();
                    let true_const = builder._true();

                    let mut num_headers = zero;

                    // This is a bitmap used for "compute_root_from_leaves".  The size of it will be
                    // equal to BATCH_SIZE.  It specifies which downloaded headers are not pad
                    // headers.
                    let mut nb_enabled_leaves = builder.zero();

                    for (i, header) in headers.as_vec().iter().enumerate() {
                        // Calculate and save the block hash.
                        let hash = builder.hash_encoded_header::<MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE>(header);
                        block_hashes.push(hash);

                        // Seed for extracting the data root from the header.
                        let mut seed = hash.as_bytes().to_vec();
                        seed.extend(&expected_data_roots.as_vec()[i].as_bytes());
                        // Decode the header and save relevant fields.
                        let header_variable =
                            builder.decode_header::<MAX_HEADER_SIZE>(header, &seed);
                        block_nums.push(header_variable.block_number);
                        block_parent_hashes.push(header_variable.parent_hash);
                        block_state_roots.push(header_variable.state_root);
                        block_data_roots.push(header_variable.data_root);

                        // The header is a pad-header if it's size is 0.
                        let is_pad_block = builder.is_zero(header.header_size.variable);

                        // Verify that the headers are linked correctly.
                        if i > 0 {
                            let hashes_linked =
                                builder.is_equal(block_parent_hashes[i], block_hashes[i - 1]);
                            let expected_block_num = builder.add(block_nums[i - 1], one_u32);
                            let nums_sequential =
                                builder.is_equal(block_nums[i], expected_block_num);

                            let header_correctly_linked =
                                builder.and(hashes_linked, nums_sequential);

                            // Either we are at a pad header or the header is correctly linked
                            let link_check = builder.or(is_pad_block, header_correctly_linked);
                            builder.assert_is_equal(link_check, true_const);
                        }

                        // Update the end_block_num value if the header is not a pad header.
                        end_block_num = builder.select(
                            is_pad_block,
                            end_block_num,
                            header_variable.block_number,
                        );
                        // Update the end_header_hash value if the header is not a pad header.
                        end_header_hash = builder.select(is_pad_block, end_header_hash, hash);

                        // Update the num_headers counter
                        let num_headers_increment = builder.select(is_pad_block, zero, one);
                        num_headers = builder.add(num_headers, num_headers_increment);

                        // Increment the number of enabled leaves if the header is not a pad header.
                        let val = builder.select(is_pad_block, zero, one);
                        nb_enabled_leaves = builder.add(
                            nb_enabled_leaves,
                            val,
                        )
                    }

                    builder.watch_with_level(&end_block_num, "end block num", Level::Debug);
                    builder.watch_with_level(&end_header_hash, "end header hash", Level::Debug);

                    // Need to pad block_state_roots and block_data_roots to be of length 16;
                    block_state_roots.resize(HEADERS_PER_MAP, empty_bytes_32_variable);
                    block_data_roots.resize(HEADERS_PER_MAP, empty_bytes_32_variable);


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

                    builder.watch_with_level(&left.num_blocks, "reduce job - left node num blocks", Level::Debug);
                    builder.watch_with_level(&left.end_block, "reduce job - left node end block num", Level::Debug);
                    builder.watch_with_level(&left.end_header_hash, "reduce job - left node end header hash", Level::Debug);
                    builder.watch_with_level(&right.num_blocks, "reduce job - right node num blocks", Level::Debug);
                    builder.watch_with_level(&right.end_block, "reduce job - right node first block num", Level::Debug);
                    builder.watch_with_level(&right.start_parent, "reduce job - right num first block parent hash", Level::Debug);

                    let total_num_blocks = builder.add(left.num_blocks, right.num_blocks);
                    let is_right_empty = builder.is_zero(right.num_blocks);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left.end_header_hash, right.start_parent);
                    let one = builder.one();
                    let expected_block_num = builder.sub(right.start_block, one);
                    let nodes_sequential = builder.is_equal(left.end_block, expected_block_num);
                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    // If the right node is empty, then don't need to check the "node_correctly_linked"
                    // boolean.
                    let link_check = builder.or(is_right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    // Get the right most block num and hash between the two nodes.
                    // If the right node is not empty, this will be the right node's rightmost entry,
                    // otherwise it will be the left block's rightmost entry.
                    let end_block = builder.select(is_right_empty, left.end_block, right.end_block);
                    let end_header_hash =
                        builder.select(is_right_empty, left.end_header_hash, right.end_header_hash);

                    // Compute the merkle roots where the left and right nodes are the merkle roots
                    // from the left and right nodes respectively.
                    let mut state_root_bytes = left.state_merkle_root.as_bytes().to_vec();
                    state_root_bytes.extend(&right.state_merkle_root.as_bytes());
                    let state_merkle_root = builder.sha256(&state_root_bytes);

                    let mut data_root_bytes = left.data_merkle_root.as_bytes().to_vec();
                    data_root_bytes.extend(&right.data_merkle_root.as_bytes());
                    let data_merkle_root = builder.sha256(&data_root_bytes);

                    builder.watch_with_level(&total_num_blocks, "reduce job - total num blocks", Level::Debug);
                    builder.watch_with_level(&left.start_block, "reduce job - first block num", Level::Debug);
                    builder.watch_with_level(&left.start_parent, "reduce job - first block parent hash", Level::Debug);
                    builder.watch_with_level(&end_block, "reduce job - end block num", Level::Debug);
                    builder.watch_with_level(&end_header_hash, "reduce job - end block hash", Level::Debug);

                    MapReduceSubchainVariable {
                        num_blocks: total_num_blocks,
                        start_block: left.start_block,
                        start_header_hash: left.start_header_hash,
                        start_parent: left.start_parent,
                        end_block,
                        end_header_hash,
                        state_merkle_root,
                        data_merkle_root,
                    }
                },
            );

        self.watch_with_level(
            &output.start_parent,
            "verify_subchain - first parent hash",
            Level::Debug,
        );
        self.assert_is_equal(trusted_header_hash, output.start_parent);

        (
            output.end_header_hash,
            output.state_merkle_root,
            output.data_merkle_root,
        )
    }
}

#[cfg(test)]
mod tests {
    use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
    use plonky2x::prelude::{DefaultBuilder, DefaultParameters, HintRegistry};

    use super::*;

    // Test circuit, as MapReduce requires a circuit to be defined.
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

            // Currently assuming that target_block - trusted_block <= MAX_EPOCH_SIZE
            let (target_header_hash, _, _) = builder.verify_subchain::<Self, MAX_NUM_HEADERS>(
                trusted_block,
                trusted_header_hash,
                target_block,
            );
            builder.watch(&target_header_hash, "target header hash");
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
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        const MAX_NUM_HEADERS: usize = 32;
        const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

        TestSubchainVerificationCircuit::<MAX_HEADER_SIZE, MAX_NUM_HEADERS>::define(&mut builder);
        let circuit = builder.build();

        let mut input = circuit.input();
        let trusted_header = "4cfd147756de6e8004a5f2ba9f2ca29e8488bae40acb97474c7086c45b39ff92"
            .parse()
            .unwrap();
        let trusted_block = 272503u32;
        let target_block = 272535u32; // mimics test_step_small

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(trusted_header);
        input.evm_write::<U32Variable>(target_block);

        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        TestSubchainVerificationCircuit::<MAX_HEADER_SIZE, MAX_HEADER_SIZE>::test_serialization::<
            L,
            D,
        >();
    }
}
