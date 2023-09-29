use itertools::Itertools;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::vars::{ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, Field, HintRegistry, Variable,
};
use serde::{Deserialize, Serialize};

use crate::vars::EncodedHeaderVariable;

/// MAX NUM HEADERS OF EPOCH
const MAX_EPOCH_SIZE: usize = 200;

/// The batch size for each map job
const BATCH_SIZE: usize = 50;

const MAX_HEADER_CHUNK_SIZE: usize = 100;
const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

struct MapReduceSubchainVerificationCircuit;

impl Circuit for MapReduceSubchainVerificationCircuit {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let headers =
            builder.read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, MAX_EPOCH_SIZE>>();
        let idxs = (0..MAX_EPOCH_SIZE)
            .map(L::Field::from_canonical_usize)
            .collect_vec();

        let _ = builder
            .mapreduce::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, MAX_EPOCH_SIZE>, Variable, (Bytes32Variable, Bytes32Variable), _, _, BATCH_SIZE>(
                headers,
                idxs,
                |map_headers, map_idxs, builder| {
                    let mut input_stream = VariableStream::new();
                    input_stream.write(&map_headers);
                    input_stream.write(&map_idxs[0]);

                    let hint = HeaderLookupHint::<BATCH_SIZE> {};
                    let headers = builder.hint(input_stream, hint).read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, BATCH_SIZE>>(builder);

                    let mut hashes = Vec::new();

                    for header in headers.as_vec().iter() {
                        let hash = builder.curta_blake2b_variable::<MAX_HEADER_CHUNK_SIZE>(
                            header.header_bytes.as_slice(),
                            header.header_size,
                        );

                        hashes.push(hash);
                    }

                    (hashes[0], hashes[BATCH_SIZE - 1])
                },
                |_, left, right, _| {
                    (left.0, right.1)
                }
            );
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let id = MapReduceGenerator::<
            L,
            ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, MAX_EPOCH_SIZE>,
            Variable,
            (Bytes32Variable, Bytes32Variable),
            BATCH_SIZE,
            D,
        >::id();
        registry.register_simple::<MapReduceGenerator<
            L,
            ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, MAX_EPOCH_SIZE>,
            Variable,
            (Bytes32Variable, Bytes32Variable),
            BATCH_SIZE,
            D,
        >>(id);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderLookupHint<const B: usize> {}

impl<L: PlonkParameters<D>, const D: usize, const B: usize> Hint<L, D> for HeaderLookupHint<B> {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let headers = input_stream
            .read_value::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, MAX_EPOCH_SIZE>>();
        let start_idx = input_stream.read_value::<Variable>().to_canonical_u64();

        output_stream.write_value::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, B>>(
            headers[start_idx as usize..start_idx as usize + B].to_vec(),
        );
    }
}

#[cfg(test)]
mod tests {
    use plonky2x::prelude::{bytes, DefaultParameters, GoldilocksField};

    use super::*;
    use crate::testing_utils::tests::{pad_header, ENCODED_HEADERS};
    use crate::vars::EncodedHeaderVariableValue;

    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    fn test_circuit() {
        env_logger::try_init().unwrap_or_default();

        type F = GoldilocksField;

        let mut builder = CircuitBuilder::<L, D>::new();
        MapReduceSubchainVerificationCircuit::define(&mut builder);
        let circuit = builder.build();

        let mut input = circuit.input();

        let mut encoded_headers_values = Vec::new();
        for i in 0..10 {
            for j in 0..20 {
                let encoded_header_value = EncodedHeaderVariableValue {
                    header_bytes: pad_header(bytes!(ENCODED_HEADERS[i * 20 + j]), MAX_HEADER_SIZE),
                    header_size: F::from_canonical_usize(ENCODED_HEADERS[i * 20 + j].len()),
                };
                encoded_headers_values.push(encoded_header_value);
            }
        }

        input.write::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, 180>>(
            encoded_headers_values,
        );

        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        MapReduceSubchainVerificationCircuit::test_serialization::<L, D>();
    }
}
