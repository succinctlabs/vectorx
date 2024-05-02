use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};

use crate::builder::justification::{GrandpaJustificationVerifier, HintSimpleJustification};
use crate::builder::subchain_verification::{
    HeaderRangeFetcherHint, MapReduceSubchainVariable, SubChainVerifier, SubchainVerificationCtx,
};
use crate::consts::HEADERS_PER_MAP;

#[derive(Clone, Debug)]
pub struct HeaderRangeCircuit<
    const MAX_AUTHORITY_SET_SIZE: usize,
    const MAX_HEADER_SIZE: usize,
    const MAX_NUM_HEADERS: usize,
> {}

impl<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    > Circuit for HeaderRangeCircuit<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        // Read the on-chain inputs.
        let trusted_block = builder.evm_read::<U32Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let authority_set_id = builder.evm_read::<U64Variable>();
        let authority_set_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U32Variable>();

        // Get the target_header_hash, state_root, and data_root over the range [trusted_block + 1, target_block].
        let subchain_output = builder.verify_subchain::<HeaderRangeCircuit<
            MAX_AUTHORITY_SET_SIZE,
            MAX_HEADER_SIZE,
            MAX_NUM_HEADERS,
        >, MAX_NUM_HEADERS>(
            trusted_block, trusted_header_hash, target_block
        );

        // Note: target_header_hash and target_block are trusted at this point.
        // Verify that there is a valid justification on target_header_hash by the authority set at authority_set_id.
        builder.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            target_block,
            subchain_output.target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        builder.evm_write::<Bytes32Variable>(subchain_output.target_header_hash);
        builder.evm_write::<Bytes32Variable>(subchain_output.state_root_merkle_root);
        builder.evm_write::<Bytes32Variable>(subchain_output.data_root_merkle_root);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry
            .register_async_hint::<HeaderRangeFetcherHint<MAX_HEADER_SIZE, HEADERS_PER_MAP>>();
        generator_registry.register_async_hint::<HintSimpleJustification<MAX_AUTHORITY_SET_SIZE>>();

        let mr_id = MapReduceGenerator::<
            L,
            SubchainVerificationCtx,
            U32Variable,
            MapReduceSubchainVariable,
            Self,
            HEADERS_PER_MAP,
            D,
        >::id();
        generator_registry.register_simple::<MapReduceGenerator<
            L,
            SubchainVerificationCtx,
            U32Variable,
            MapReduceSubchainVariable,
            Self,
            HEADERS_PER_MAP,
            D,
        >>(mr_id);
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;
    use crate::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_circuit_function_header_range() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 4;
        const NUM_HEADERS: usize = 36;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        HeaderRangeCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, NUM_HEADERS>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        HeaderRangeCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, NUM_HEADERS>::register_generators(
            &mut hint_registry,
        );
        HeaderRangeCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, NUM_HEADERS>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_header_range_small() {
        // Only 10 authorities in the authority set for this authority set id.
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 5;
        const NUM_HEADERS: usize = 32;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        HeaderRangeCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        let trusted_header = "087ee7c739e35c46b2ac422cf683ecf6d4cb4571610efe6a5dff6f5b3d5818c9"
            .parse()
            .unwrap();
        let trusted_block = 4310u32;
        // Step to an epoch end block, so it's not reliant on a stored justification.
        let target_block = 4321u32;
        let authority_set_id = 0u64;
        let authority_set_hash = "54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb"
            .parse()
            .unwrap();

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(trusted_header);
        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
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

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_header_range() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 76;
        const NUM_HEADERS: usize = 100;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        HeaderRangeCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        let trusted_header = "087ee7c739e35c46b2ac422cf683ecf6d4cb4571610efe6a5dff6f5b3d5818c9"
            .parse()
            .unwrap();
        let trusted_block = 4310u32;
        // Step to an epoch end block, so it's not reliant on a stored justification.
        let target_block = 4321u32;
        let authority_set_id = 0u64;
        let authority_set_hash = "54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb"
            .parse()
            .unwrap();

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(trusted_header);
        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
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

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_header_range_large() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_NUM_HEADERS: usize = 256;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        HeaderRangeCircuit::<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        let trusted_header = "86f967bbe95f2314e6e6b81d434997672b3d6fa3a1a32c8de80dade137bc74cf"
            .parse()
            .unwrap();
        let trusted_block = 529000u32;
        // Step to a block that is a stored justification.
        let target_block = 529200u32;
        let authority_set_id = 215u64;
        let authority_set_hash = "a97ebe6c36b2bcde9b8193c0f03b54fe6df67c725ba7b53b915af1735150fc75"
            .parse()
            .unwrap();

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(trusted_header);
        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
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
