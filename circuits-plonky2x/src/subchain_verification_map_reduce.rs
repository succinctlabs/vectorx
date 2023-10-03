use itertools::Itertools;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, Field, HintRegistry,
    RichField, Variable, Witness, WitnessWrite,
};
use plonky2x::utils::avail::{HeaderLookupHint, HeaderLookupRet};

use crate::decoder::DecodingMethods;

/// The nubmer of map jobs.  This needs to be a power of 2
const NUM_MAP_JOBS: usize = 16;

/// The batch size for each map job
const BATCH_SIZE: usize = 12;

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

pub struct SubchainVerificationMRCircuit;

impl Circuit for SubchainVerificationMRCircuit {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let trusted_block = builder.read::<U32Variable>();
        let trusted_header_hash = builder.read::<Bytes32Variable>();
        let target_block = builder.read::<U32Variable>();

        // Currently assuming that target_block - trusted_block <= MAX_EPOCH_SIZE

        let ctx = SubchainVerificationCtx {
            trusted_block,
            trusted_header_hash,
            target_block,
        };

        let relative_block_nums = (0..HEADERS_PER_JOB)
            .map(L::Field::from_canonical_usize)
            .collect_vec();

        let _ = builder.mapreduce::<SubchainVerificationCtx, Variable, (
            Variable,
            U32Variable,
            Bytes32Variable,
            Bytes32Variable,
            U32Variable,
            Bytes32Variable,
            Bytes32Variable,
            Bytes32Variable,
        ), _, _, BATCH_SIZE>(
            ctx,
            relative_block_nums,
            |map_ctx, map_relative_block_nums, builder| {
                let mut input_stream = VariableStream::new();
                input_stream.write(&map_ctx);
                input_stream.write(&map_relative_block_nums);
                let hint = HeaderLookupHint {};
                let headers = builder
                    .hint(input_stream, hint)
                    .read::<ArrayVariable<HeaderLookupRet<MAX_HEADER_SIZE>, BATCH_SIZE>>(builder);

                let mut block_nums = Vec::new();
                let mut block_hashes = Vec::new();
                let mut block_parent_hashes = Vec::new();
                let mut block_state_roots = Vec::new();
                let mut block_data_roots = Vec::new();

                let mut end_block: U32Variable;
                let mut end_block_hash: Bytes32Variable;

                let zero = builder.zero();
                let one = builder.one();

                let num_headers = zero;

                for (i, header) in headers.headers.as_vec().iter().enumerate() {
                    let hash = builder.curta_blake2b_variable::<MAX_HEADER_CHUNK_SIZE>(
                        header.header_bytes.as_slice(),
                        header.header_size,
                    );
                    block_hashes.push(hash);

                    let header_variable = builder.decode_header(header, &hash);
                    block_nums.push(header_variable.block_number);
                    block_parent_hashes.push(header_variable.parent_hash);
                    block_state_roots.push(header_variable.state_root.0);
                    block_data_roots.push(header_variable.data_root.0);

                    // Verify that the headers are linked correctly.
                    if i > 0 {
                        let hashes_linked =
                            builder.is_equal(block_parent_hashes[i], block_hashes[i - 1]);
                        let nums_sequential =
                            builder.is_equal(block_nums[i], builder.add(block_nums[i - 1], one));

                        let header_correctly_linked = builder.and(hashes_linked, nums_sequential);

                        // Either we are at a pad header or the header is correctly linked
                        let link_check = builder.or(header.pad_header, header_correctly_linked);
                        builder.assert_is_equal(link_check, one);
                    }

                    end_block =
                        builder.select(header.pad_header, end_block, header_variable.block_number);
                    end_header_hash = builder.select(header.pad_header, end_header_hash, hash);

                    let num_headers_increment = builder.select(header.pad_header, zero, one);
                    num_headers = builder.add(num_headers, num_headers_increment);

                    leaves_enabled.push(builder.not(header.pad_header));
                }

                // Need to pad block_state_roots and block_data_roots to be of length 16;
                block_state_roots.resize(16, Bytes32Variable::default().0);
                block_data_roots.resize(16, Bytes32Variable::default().0);

                let state_merkle_root = builder
                    .compute_root_from_leaves::<16, 32>(block_state_roots, leaves_enabled.clone());
                let data_merkle_root =
                    builder.compute_root_from_leaves::<16, 32>(block_data_roots, leaves_enabled);

                (
                    num_headers,
                    block_nums[0],
                    block_hashes[0],
                    block_parent_hashes[0],
                    end_block,
                    end_header_hash,
                    state_merkle_root,
                    data_merkle_root,
                )
            },
            |_, left_output, right_output, builder| {
                let (
                    left_num_blocks,
                    left_first_block,
                    left_first_block_parent,
                    left_first_header_hash,
                    left_end_block,
                    left_end_header_hash,
                    left_state_merkle_root,
                    left_data_merkle_root,
                ) = left_output;

                let (
                    right_num_blocks,
                    right_first_block,
                    right_first_block_parent,
                    right_first_header_hash,
                    right_end_block,
                    right_end_header_hash,
                    right_state_merkle_root,
                    right_data_merkle_root,
                ) = right_output;

                let total_num_blocks = builder.add(left_num_blocks, right_num_blocks);

                // if right_num_blocks == 0, then rightmost block is from the left_output
                let right_empty = builder.is_zero(right_num_block);
                let right_not_empty = builder.not(right_empty);

                // Check to see if the left and right outputs are correctly linked.
                let nodes_linked = builder.is_equal(left_end_header_hash, right_first_block_parent);
                let nodes_sequential =
                    builder.is_equal(left_end_block, builder.sub(right_first_block, one));

                let nodes_correctly_linked = builder.and(hashes_linked, nums_sequential);

                // Either we are at a pad header or the header is correctly linked
                let link_check = builder.or(right_not_empty, nodes_correctly_linked);
                builder.assert_is_equal(link_check, one);

                let end_block = builder.select(right_not_empty, right_end_block, left_end_block);
                let end_header_hash =
                    builder.select(right_not_empty, right_end_header_hash, left_end_header_hash);

                let mut state_root_bytes = left_state_merkle_roots.as_bytes().to_vec();
                state_root_bytes.extend(&right_state_merkle_roots.as_bytes());
                let state_merkle_root = builder.sha256(&state_root_bytes);

                let mut data_root_bytes = left_data_merkle_roots.as_bytes().to_vec();
                data_root_bytes.extend(&rigth_data_merkle_roots.as_bytes());
                let data_merkle_root = builder.sha256(&data_root_bytes);

                (
                    total_num_blocks,
                    left_first_block,
                    left_first_block_parent,
                    left_first_header_hash,
                    end_block,
                    end_header_hash,
                    state_merkle_root,
                    data_merkle_root,
                )
            },
        );
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let id = MapReduceGenerator::<
            L,
            Variable,
            Variable,
            (
                Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                Bytes32Variable,
            ),
            BATCH_SIZE,
            D,
        >::id();
        registry.register_simple::<MapReduceGenerator<
            L,
            Variable,
            Variable,
            (
                Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                Bytes32Variable,
            ),
            BATCH_SIZE,
            D,
        >>(id);
    }
}

#[cfg(test)]
mod tests {
    use plonky2x::prelude::DefaultParameters;

    use super::*;

    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    fn test_circuit() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();
        MapReduceSubchainVerificationCircuit::define(&mut builder);
        let circuit = builder.build();

        let input = circuit.input();
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        MapReduceSubchainVerificationCircuit::test_serialization::<L, D>();
    }
}
