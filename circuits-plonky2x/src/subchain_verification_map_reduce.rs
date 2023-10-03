use ethers::types::H256;
use itertools::Itertools;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::vars::VariableStream;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, Field, Variable, HintRegistry,
};
use plonky2x::utils::avail::{EncodedHeaderVariable, HeaderLookupHint};

use crate::decoder::DecodingMethods;

/// MAX NUM HEADERS OF EPOCH
//const MAX_EPOCH_SIZE: usize = 200;
const MAX_EPOCH_SIZE: usize = 24;

/// The batch size for each map job
const BATCH_SIZE: usize = 12;

//const BATCH_SIZE: usize = 50;

const MAX_HEADER_CHUNK_SIZE: usize = 100;
const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

pub struct MapReduceSubchainVerificationCircuit;

impl Circuit for MapReduceSubchainVerificationCircuit {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let idxs = (0..MAX_EPOCH_SIZE)
            .map(L::Field::from_canonical_usize)
            .collect_vec();

        let dummy: Variable = builder.zero();

        let _ = builder.mapreduce::<Variable, Variable, (
            Bytes32Variable,
            Bytes32Variable,
            // Bytes32Variable,
            // Bytes32Variable,
        ), _, _, BATCH_SIZE>(
            dummy,
            idxs,
            |_, _, builder| {
                let input_stream = VariableStream::new();
                let hint = HeaderLookupHint {};
                let headers = builder
                    .hint(input_stream, hint)
                    .read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, BATCH_SIZE>>(
                        builder,
                    );

                let mut block_nums = Vec::new();
                // let mut block_hashes = Vec::new();
                let mut block_state_roots = Vec::new();
                let mut block_data_roots = Vec::new();

                let zero_hash = Bytes32Variable::constant(builder, H256([0;32]));

                for header in headers.as_vec().iter() {
                    // let hash = builder.curta_blake2b_variable::<MAX_HEADER_CHUNK_SIZE>(
                    //     header.header_bytes.as_slice(),
                    //     header.header_size,
                    // );
                    // block_hashes.push(hash);

                    let header_variable = builder.decode_header(header, &zero_hash);
                    block_nums.push(header_variable.block_number);
                    block_state_roots.push(header_variable.state_root.0);
                    block_data_roots.push(header_variable.data_root.0);
                }

                // Need to pad block_state_roots and block_data_roots to be of length 16;
                for _i in 0..4 {
                    block_state_roots.push(Bytes32Variable::default().0);
                    block_data_roots.push(Bytes32Variable::default().0);
                }

                let mut leaves_enabled = Vec::new();
                leaves_enabled.extend([builder._true(); 12]);
                leaves_enabled.extend([builder._false(); 4]);

                let state_merkle_root = builder
                    .compute_root_from_leaves::<16, 32>(block_state_roots, leaves_enabled.clone());
                let data_merkle_root =
                    builder.compute_root_from_leaves::<16, 32>(block_data_roots, leaves_enabled);

                (
                    // block_hashes[0],
                    // block_hashes[BATCH_SIZE - 1],
                    state_merkle_root,
                    data_merkle_root,
                )
            },
            |_, left_node, right_node, _| 
            //(left_node.0, right_node.1, left_node.2, left_node.3),
            (left_node.0, right_node.0),
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
            (Bytes32Variable, Bytes32Variable),
            BATCH_SIZE,
            D,
        >::id();
        registry.register_simple::<MapReduceGenerator<
            L,
            Variable,
            Variable,
            (Bytes32Variable, Bytes32Variable),
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
