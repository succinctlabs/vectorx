use ethers::types::H256;
use itertools::Itertools;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{DefaultSerializer, PlonkParameters};
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, RichField, Variable,
};

use crate::decoder::DecodingMethods;
use crate::header::HeaderFetcherHint;
use crate::vars::EncodedHeaderVariable;

/// The nubmer of map jobs.  This needs to be a power of 2
const NUM_MAP_JOBS: usize = 2;

pub const BATCH_SIZE: usize = 16;

/// Num processed headers per MR job
const HEADERS_PER_JOB: usize = BATCH_SIZE * NUM_MAP_JOBS;

const MAX_HEADER_CHUNK_SIZE: usize = 100;
const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SubchainVerificationCtx {
    pub trusted_block: U32Variable,
    pub trusted_header_hash: Bytes32Variable,
    pub target_block: U32Variable,
}

pub trait SubChainVerifier<L: PlonkParameters<D>, const D: usize> {
    fn verify_subchain(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> SubChainVerifier<L, D> for CircuitBuilder<L, D> {
    fn verify_subchain(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let ctx = SubchainVerificationCtx {
            trusted_block,
            trusted_header_hash,
            target_block,
        };

        let relative_block_nums = (0u32..HEADERS_PER_JOB as u32).collect_vec();

        let (_, _, _, _, _, end_header_hash, state_merkle_root, data_merkle_root) =
            self.mapreduce::<SubchainVerificationCtx, U32Variable, (
                Variable,        // num headers
                U32Variable,     // first block's num
                Bytes32Variable, // first block's hash
                Bytes32Variable, // first block's parent hash
                U32Variable,     // last block's num
                Bytes32Variable, // last block's hash
                Bytes32Variable, // state merkle root
                Bytes32Variable, // data merkle root
            ), DefaultSerializer, BATCH_SIZE, _, _>(
                ctx,
                relative_block_nums,
                |map_ctx, map_relative_block_nums, builder| {
                    let mut input_stream = VariableStream::new();
                    let start_block =
                        builder.add(map_ctx.trusted_block, map_relative_block_nums.as_vec()[0]);
                    let last_block = builder.add(
                        map_ctx.trusted_block,
                        map_relative_block_nums.as_vec()[BATCH_SIZE - 1],
                    );
                    let max_block = map_ctx.target_block;

                    input_stream.write(&start_block);
                    input_stream.write(&last_block);
                    input_stream.write(&max_block);
                    let header_fetcher = HeaderFetcherHint::<MAX_HEADER_SIZE, BATCH_SIZE> {};
                    let headers = builder
                        .hint(input_stream, header_fetcher)
                        .read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, BATCH_SIZE>>(
                            builder,
                        );

                    let mut block_nums = Vec::new();
                    let mut block_hashes = Vec::new();
                    let mut block_parent_hashes = Vec::new();
                    let mut block_state_roots = Vec::new();
                    let mut block_data_roots = Vec::new();

                    let mut end_block_num: U32Variable = builder.zero();
                    let empty_bytes_32_variable =
                        Bytes32Variable::constant(builder, H256::from_slice(&[0u8; 32]));
                    let mut end_header_hash: Bytes32Variable = empty_bytes_32_variable;

                    let zero = builder.zero::<Variable>();
                    let one = builder.one::<Variable>();
                    let one_u32 = builder.one::<U32Variable>();
                    let true_const = builder._true();

                    let mut num_headers = zero;

                    let mut leaves_enabled = Vec::new();

                    for (i, header) in headers.as_vec().iter().enumerate() {
                        let hash = builder.curta_blake2b_variable::<MAX_HEADER_CHUNK_SIZE>(
                            header.header_bytes.as_slice(),
                            header.header_size,
                        );
                        block_hashes.push(hash);

                        let header_variable =
                            builder.decode_header::<MAX_HEADER_SIZE>(header, &hash);
                        block_nums.push(header_variable.block_number);
                        block_parent_hashes.push(header_variable.parent_hash);
                        block_state_roots.push(header_variable.state_root.0);
                        block_data_roots.push(header_variable.data_root.0);

                        let is_pad_block = builder.is_zero(header.header_size);

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

                        end_block_num = builder.select(
                            is_pad_block,
                            end_block_num,
                            header_variable.block_number,
                        );
                        end_header_hash = builder.select(is_pad_block, end_header_hash, hash);

                        let num_headers_increment = builder.select(is_pad_block, zero, one);
                        num_headers = builder.add(num_headers, num_headers_increment);

                        leaves_enabled.push(builder.not(is_pad_block));
                    }

                    // Need to pad block_state_roots and block_data_roots to be of length 16;
                    block_state_roots.resize(16, empty_bytes_32_variable.0);
                    block_data_roots.resize(16, empty_bytes_32_variable.0);

                    let false_const = builder._false();
                    leaves_enabled.resize(16, false_const);

                    let state_merkle_root = builder.compute_root_from_leaves::<16, 32>(
                        block_state_roots,
                        leaves_enabled.clone(),
                    );
                    let data_merkle_root = builder
                        .compute_root_from_leaves::<16, 32>(block_data_roots, leaves_enabled);

                    (
                        num_headers,
                        block_nums[0],
                        block_hashes[0],
                        block_parent_hashes[0],
                        end_block_num,
                        end_header_hash,
                        state_merkle_root,
                        data_merkle_root,
                    )
                },
                |_, left_output, right_output, builder| {
                    let (
                        left_num_blocks,
                        left_first_block,
                        left_first_header_hash,
                        left_first_block_parent,
                        left_end_block,
                        left_end_header_hash,
                        left_state_merkle_root,
                        left_data_merkle_root,
                    ) = left_output;

                    let (
                        right_num_blocks,
                        right_first_block,
                        _,
                        right_first_block_parent,
                        right_end_block,
                        right_end_header_hash,
                        right_state_merkle_root,
                        right_data_merkle_root,
                    ) = right_output;

                    let total_num_blocks = builder.add(left_num_blocks, right_num_blocks);

                    let right_empty = builder.is_zero(right_num_blocks);

                    // Check to see if the left and right nodes are correctly linked.
                    let nodes_linked =
                        builder.is_equal(left_end_header_hash, right_first_block_parent);
                    let one = builder.one();
                    let expected_block_num = builder.sub(right_first_block, one);
                    let nodes_sequential = builder.is_equal(left_end_block, expected_block_num);

                    let nodes_correctly_linked = builder.and(nodes_linked, nodes_sequential);

                    let link_check = builder.or(right_empty, nodes_correctly_linked);
                    let true_const = builder._true();
                    builder.assert_is_equal(link_check, true_const);

                    let end_block = builder.select(right_empty, left_end_block, right_end_block);
                    let end_header_hash =
                        builder.select(right_empty, left_end_header_hash, right_end_header_hash);

                    let mut state_root_bytes = left_state_merkle_root.as_bytes().to_vec();
                    state_root_bytes.extend(&right_state_merkle_root.as_bytes());
                    let state_merkle_root = builder.sha256(&state_root_bytes);

                    let mut data_root_bytes = left_data_merkle_root.as_bytes().to_vec();
                    data_root_bytes.extend(&right_data_merkle_root.as_bytes());
                    let data_merkle_root = builder.sha256(&data_root_bytes);

                    (
                        total_num_blocks,
                        left_first_block,
                        left_first_header_hash,
                        left_first_block_parent,
                        end_block,
                        end_header_hash,
                        state_merkle_root,
                        data_merkle_root,
                    )
                },
            );

        (end_header_hash, state_merkle_root, data_merkle_root)
    }
}
