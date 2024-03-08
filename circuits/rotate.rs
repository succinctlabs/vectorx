use async_trait::async_trait;
use ethers::types::H256;
use log::{debug, Level};
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    Bytes32Variable, CircuitBuilder, Field, PlonkParameters, ValueStream, VariableStream,
};
use serde::{Deserialize, Serialize};

use crate::builder::justification::HintSimpleJustification;
use crate::builder::rotate::RotateMethods;
use crate::input::RpcDataFetcher;
use crate::vars::{EncodedHeader, RotateStruct, RotateVariable};

// Fetch a single header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateHint<const HEADER_LENGTH: usize, const MAX_AUTHORITY_SET_SIZE: usize> {}

#[async_trait]
impl<
        const HEADER_LENGTH: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        L: PlonkParameters<D>,
        const D: usize,
    > AsyncHint<L, D> for RotateHint<HEADER_LENGTH, MAX_AUTHORITY_SET_SIZE>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let block_number = input_stream.read_value::<U32Variable>();

        debug!(
            "SingleHeaderFetcherHint: downloading header range of block={}",
            block_number
        );

        let mut data_fetcher = RpcDataFetcher::new().await;

        let rotate_data = data_fetcher
            .get_header_rotate::<HEADER_LENGTH, MAX_AUTHORITY_SET_SIZE>(block_number)
            .await;

        let rotate = RotateStruct::<HEADER_LENGTH, MAX_AUTHORITY_SET_SIZE, L::Field> {
            target_header: EncodedHeader {
                header_bytes: rotate_data.header_bytes,
                header_size: rotate_data.header_size as u32,
            },
            target_header_num_authorities: L::Field::from_canonical_usize(
                rotate_data.num_authorities,
            ),
            next_authority_set_start_position: L::Field::from_canonical_usize(
                rotate_data.start_position,
            ),
            expected_new_authority_set_hash: H256::from_slice(
                rotate_data.new_authority_set_hash.as_slice(),
            ),
            new_pubkeys: rotate_data.padded_pubkeys,
        };

        // Rotate data.
        output_stream.write_value::<RotateVariable<HEADER_LENGTH, MAX_AUTHORITY_SET_SIZE>>(rotate);
    }
}

#[derive(Clone, Debug)]
pub struct RotateCircuit<
    const MAX_AUTHORITY_SET_SIZE: usize,
    const MAX_HEADER_SIZE: usize,
    const MAX_HEADER_CHUNK_SIZE: usize,
    // This should be (MAX_AUTHORITY_SET_SIZE + 1) * (VALIDATOR_LENGTH).
    const MAX_SUBARRAY_SIZE: usize,
> {}

impl<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_HEADER_CHUNK_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    > Circuit
    for RotateCircuit<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_SIZE,
        MAX_HEADER_CHUNK_SIZE,
        MAX_SUBARRAY_SIZE,
    >
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        // Read the on-chain inputs. The validators that signed epoch_end_block_number are defined
        // by authority_set_id and authority_set_hash.
        let authority_set_id = builder.evm_read::<U64Variable>();
        builder.watch_with_level(
            &authority_set_id,
            "rotate circuit input - authority set id",
            Level::Debug,
        );
        let authority_set_hash = builder.evm_read::<Bytes32Variable>();
        builder.watch_with_level(
            &authority_set_hash,
            "rotate circuit input - authority set hash",
            Level::Debug,
        );
        // Note: If the user passes in a block number that is not an epoch end block, the circuit
        // will error.
        let epoch_end_block_number = builder.evm_read::<U32Variable>();
        builder.watch_with_level(
            &epoch_end_block_number,
            "rotate circuit input - epoch end block",
            Level::Debug,
        );

        // Fetch the header at epoch_end_block.
        let header_fetcher = RotateHint::<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let rotate_var =
            output_stream.read::<RotateVariable<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>>(builder);

        let expected_new_authority_set_hash = rotate_var.expected_new_authority_set_hash;
        builder.rotate::<MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_AUTHORITY_SET_SIZE, MAX_SUBARRAY_SIZE>(
            epoch_end_block_number,
            authority_set_id,
            authority_set_hash,
            rotate_var
        );

        // Write the hash of the new authority set to the output.
        builder.evm_write::<Bytes32Variable>(expected_new_authority_set_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry
            .register_async_hint::<RotateHint<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>>();
        generator_registry.register_async_hint::<HintSimpleJustification<MAX_AUTHORITY_SET_SIZE>>();
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;
    use crate::consts::{DELAY_LENGTH, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE, VALIDATOR_LENGTH};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 4;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_HEADER_CHUNK_SIZE: usize = 100;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::define(
            &mut builder,
        );
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::register_generators(
            &mut hint_registry,
        );
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_small_authority_set() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 8;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        let authority_set_id = 0u64;
        let authority_set_hash = H256::from_slice(
            &hex::decode("54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb")
                .unwrap(),
        );
        let epoch_end_block_number = 4321u32;

        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
        input.evm_write::<U32Variable>(epoch_end_block_number);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let new_authority_set_hash = output.evm_read::<Bytes32Variable>();
        println!("new_authority_set_hash {:?}", new_authority_set_hash);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_medium_authority_set() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 100;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_HEADER_CHUNK_SIZE: usize = 100;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        let authority_set_id = 0u64;
        let authority_set_hash = H256::from_slice(
            &hex::decode("54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb")
                .unwrap(),
        );
        let epoch_end_block_number = 4321u32;

        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
        input.evm_write::<U32Variable>(epoch_end_block_number);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let new_authority_set_hash = output.evm_read::<Bytes32Variable>();
        println!("new_authority_set_hash {:?}", new_authority_set_hash);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_large_authority_set() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 300;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_SUBARRAY_SIZE>::define(
            &mut builder,
        );

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();
        let authority_set_id = 48u64;
        let authority_set_hash = H256::from_slice(
            &hex::decode("a699e49272d2d23f12e1624fba2ed8d28e1fc777ef25a40a7bcacbb8c0d8d252")
                .unwrap(),
        );
        let epoch_end_block_number = 100005u32;

        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(authority_set_hash);
        input.evm_write::<U32Variable>(epoch_end_block_number);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let new_authority_set_hash = output.evm_read::<Bytes32Variable>();
        println!("new_authority_set_hash {:?}", new_authority_set_hash);
    }
}
