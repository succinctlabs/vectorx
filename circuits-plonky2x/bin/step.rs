//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

use avail_plonky2x::fetch::RpcDataFetcher;
use avail_plonky2x::justification::HintSimpleJustification;
use avail_plonky2x::vars::{
    EncodedHeader, EncodedHeaderVariable, MAX_LARGE_HEADER_SIZE, MAX_SMALL_HEADER_SIZE,
};
use avail_subxt::primitives::Header;
use codec::Encode;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{U32Variable, ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime; // TODO: re-export this instead of this path

/// This hint takes in a trusted_block and target_block and fetches all the block headers in that range.
/// We return an ArrayVariable of EncodedHeaderVariable of length NUM_HEADERS, padding with empty headers if necessary.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StepOffchainInputs<const HEADER_LENGTH: usize, const NUM_HEADERS: usize> {}

impl<
        const HEADER_LENGTH: usize,
        const NUM_HEADERS: usize,
        L: PlonkParameters<D>,
        const D: usize,
    > Hint<L, D> for StepOffchainInputs<HEADER_LENGTH, NUM_HEADERS>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let trusted_block = input_stream.read_value::<U32Variable>();
        let target_block = input_stream.read_value::<U32Variable>();

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let headers: Vec<Header> = rt.block_on(async {
            let data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .get_block_headers_range(trusted_block, target_block)
                .await
        });

        // We take the returned headers and pad them to the correct length to turn them into an `EncodedHeader` variable.
        let mut header_variables = Vec::new();
        for i in 0..headers.len() {
            let header = &headers[i];
            let header_variable = to_header_variable::<HEADER_LENGTH, L::Field>(header);
            header_variables.push(header_variable);
        }

        // We must pad the rest of `header_variables` with empty headers to ensure its length is NUM_HEADERS.
        for i in headers.len()..NUM_HEADERS {
            let header_variable = EncodedHeader {
                header_bytes: vec![0u8; HEADER_LENGTH],
                header_size: L::Field::from_canonical_usize(0),
            };
            header_variables.push(header_variable);
        }

        output_stream
            .write_value::<ArrayVariable<EncodedHeaderVariable<HEADER_LENGTH>, NUM_HEADERS>>(
                header_variables,
            );
    }
}

struct StepCircuit<
    const VALIDATOR_SET_SIZE: usize,
    const HEADER_LENGTH: usize,
    const NUM_HEADERS: usize,
> {}

impl<const VALIDATOR_SET_SIZE: usize, const HEADER_LENGTH: usize, const NUM_HEADERS: usize> Circuit
    for StepCircuit<VALIDATOR_SET_SIZE, HEADER_LENGTH, NUM_HEADERS>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        // Read the on-chain inputs.
        let trusted_block = builder.evm_read::<U32Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let authority_set_id = builder.evm_read::<U64Variable>();
        let authority_set_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U32Variable>();

        let mut input_stream = VariableStream::new();
        input_stream.write(&trusted_block);
        input_stream.write(&target_block);
        let output_stream = builder.hint(
            input_stream,
            StepOffchainInputs::<HEADER_LENGTH, NUM_HEADERS> {},
        );
        let all_encoded_header_variables = output_stream
            .read::<ArrayVariable<EncodedHeaderVariable<HEADER_LENGTH>, NUM_HEADERS>>(builder);

        // We compute the last header index based on the target_block and trusted_block.
        let last_header_index = builder.sub(target_block, trusted_block);

        // TODO: verify a simple justification for the last header
        // TODO: verify a header chain
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_hint::<StepOffchainInputs<HEADER_LENGTH, NUM_HEADERS>>();
        generator_registry.register_hint::<HintSimpleJustification<VALIDATOR_SET_SIZE>>();
    }
}

fn main() {
    const MAX_VALIDATOR_SET_SIZE: usize = 4;
    const MAX_HEADER_LENGTH: usize = MAX_LARGE_HEADER_SIZE;
    const NUM_HEADERS: usize = 4;
    VerifiableFunction::<StepCircuit<MAX_VALIDATOR_SET_SIZE,MAX_HEADER_LENGTH,NUM_HEADERS>>::entrypoint();
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use ethers::utils::hex;
    use plonky2x::backend::circuit::PublicInput;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_circuit_function_step() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        const MAX_HEADER_LENGTH: usize = MAX_LARGE_HEADER_SIZE;
        const NUM_HEADERS: usize = 4;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, MAX_HEADER_LENGTH, NUM_HEADERS>::register_generators(
            &mut hint_registry,
        );
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, MAX_HEADER_LENGTH, NUM_HEADERS>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_circuit_with_input_bytes() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // This is from block 3000 with requested block 3100
        let input_bytes = hex::decode(
            "a8512f18c34b70e1533cfd5aa04f251fcb0d7be56ec570051fbad9bdb9435e6a0000000000000bb80000000000000c1c",
        )
        .unwrap();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        const MAX_HEADER_LENGTH: usize = 1024;
        const NUM_HEADERS: usize = 4;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let input = PublicInput::Bytes(input_bytes);
        let (_proof, mut output) = circuit.prove(&input);
        let next_header = output.evm_read::<Bytes32Variable>();
        println!("next_header {:?}", next_header);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_circuit_function_step_fixture() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 4;
        const MAX_HEADER_LENGTH: usize = 1024;
        const NUM_HEADERS: usize = 4;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<MAX_VALIDATOR_SET_SIZE, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        // These inputs are taken from: https://kate.avail.tools/#/explorer/query/485710
        let mut input = circuit.input();
        let trusted_header: [u8; 32] =
            hex::decode("5d237ce770cc8d4a0b0fa9f4a5f878076051b3adc359acf6cc68349372599df7")
                .unwrap()
                .try_into()
                .unwrap();
        let trusted_block = 485710u32;
        let target_block = 485712u32; // mimics test_step_small
        let authority_set_id = 0u64; // Placeholder for now
        let authority_set_hash: [u8; 32] = [0u8; 32]; // Placeholder for now

        input.evm_write::<U32Variable>(trusted_block.into());
        input.evm_write::<Bytes32Variable>(H256::from_slice(trusted_header.as_slice()));
        input.evm_write::<U64Variable>(authority_set_id.into());
        input.evm_write::<Bytes32Variable>(H256::from_slice(authority_set_hash.as_slice()));
        input.evm_write::<U32Variable>(target_block.into());

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let target_header = output.evm_read::<Bytes32Variable>();
        println!("target_header {:?}", target_header);
    }
}
