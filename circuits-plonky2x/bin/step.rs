//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

use avail_plonky2x::decoder::FloorDivGenerator;
use avail_plonky2x::header::HeaderFetcherHint;
use avail_plonky2x::justification::{GrandpaJustificationVerifier, HintSimpleJustification};
use avail_plonky2x::subchain_verification::{
    SubChainVerifier, SubchainVerificationCtx, BATCH_SIZE, MAX_HEADER_SIZE,
};
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters, Variable};

#[derive(Clone, Debug)]
struct StepCircuit<
    const VALIDATOR_SET_SIZE: usize,
    const HEADER_LENGTH: usize,
    const NUM_HEADERS: usize,
> {}

impl<const VALIDATOR_SET_SIZE: usize, const HEADER_LENGTH: usize, const NUM_HEADERS: usize> Circuit
    for StepCircuit<VALIDATOR_SET_SIZE, HEADER_LENGTH, NUM_HEADERS>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        // Read the on-chain inputs.
        let trusted_block = builder.evm_read::<U32Variable>();
        builder.watch(&trusted_block, "trusted block");

        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        builder.watch(&trusted_header_hash, "trusted header hash");

        let authority_set_id = builder.evm_read::<U64Variable>();
        builder.watch(&authority_set_id, "authority set id");

        let authority_set_hash = builder.evm_read::<Bytes32Variable>();
        builder.watch(&authority_set_hash, "authority set hash");

        let target_block = builder.evm_read::<U32Variable>();
        builder.watch(&target_block, "target block");

        let (target_header_hash, state_root_merkle_root, data_root_merkle_root) =
            builder.verify_subchain::<StepCircuit<VALIDATOR_SET_SIZE, HEADER_LENGTH, NUM_HEADERS>>(
                trusted_block,
                trusted_header_hash,
                target_block,
            );

        builder.verify_simple_justification::<VALIDATOR_SET_SIZE>(
            target_block,
            target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        builder.evm_write::<Bytes32Variable>(target_header_hash);
        builder.evm_write::<Bytes32Variable>(state_root_merkle_root);
        builder.evm_write::<Bytes32Variable>(data_root_merkle_root);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_hint::<HeaderFetcherHint<HEADER_LENGTH, BATCH_SIZE>>();
        generator_registry.register_hint::<HintSimpleJustification<VALIDATOR_SET_SIZE>>();

        let floor_div_id = FloorDivGenerator::<L::Field, D>::id();
        generator_registry.register_simple::<FloorDivGenerator<L::Field, D>>(floor_div_id);

        let mr_id = MapReduceGenerator::<
            L,
            SubchainVerificationCtx,
            U32Variable,
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
            Self,
            BATCH_SIZE,
            D,
        >::id();
        generator_registry.register_simple::<MapReduceGenerator<
            L,
            SubchainVerificationCtx,
            U32Variable,
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
            Self,
            BATCH_SIZE,
            D,
        >>(mr_id);
    }
}

fn main() {
    const NUM_AUTHORITIES: usize = 76;
    const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
    const NUM_HEADERS: usize = 36;
    VerifiableFunction::<StepCircuit<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>>::entrypoint(
    );
}

#[cfg(test)]
mod tests {
    use std::env;

    use avail_plonky2x::subchain_verification::MAX_HEADER_SIZE;
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

        const NUM_AUTHORITIES: usize = 4;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const NUM_HEADERS: usize = 36;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        StepCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>::register_generators(
            &mut hint_registry,
        );
        StepCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>::register_gates(
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

        const NUM_AUTHORITIES: usize = 4;
        const MAX_HEADER_LENGTH: usize = 1024;
        const NUM_HEADERS: usize = 4;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);

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

        const NUM_AUTHORITIES: usize = 76;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const NUM_HEADERS: usize = 36;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        StepCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        // These inputs are taken from: https://kate.avail.tools/#/explorer/query/485710
        let mut input = circuit.input();
        let trusted_header: [u8; 32] =
            hex::decode("9a69988124baf188d9d6bbbc579977815086a5d9dfa3b91bafa6d315f31047dc")
                .unwrap()
                .try_into()
                .unwrap();
        let trusted_block = 272502u32;
        let target_block = 272534u32; // mimics test_step_small
        let authority_set_id = 256u64;
        let authority_set_hash: [u8; 32] = [0u8; 32]; // Placeholder for now

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(H256::from_slice(trusted_header.as_slice()));
        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(H256::from_slice(authority_set_hash.as_slice()));
        input.evm_write::<U32Variable>(target_block);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let target_header = output.evm_read::<Bytes32Variable>();
        let state_root_merkle_root = output.evm_read::<Bytes32Variable>();
        let data_root_merkle_root = output.evm_read::<Bytes32Variable>();
        println!("target_header {:?}", target_header);
        println!("state root merkle root {:?}", state_root_merkle_root);
        println!("data root merkle root {:?}", data_root_merkle_root);
    }
}
