use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};

use super::justification::GrandpaJustificationVerifier;
use crate::step::StepCircuit;
use crate::subchain_verification::SubChainVerifier;

pub trait StepMethods<L: PlonkParameters<D>, const D: usize> {
    // Verify the justification from the current authority set on target block, and compute the
    // state and data merkle root commitments over the range [trusted_block + 1, target_block]
    // inclusive, and also return the verified target header hash.
    fn step<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    >(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> StepMethods<L, D> for CircuitBuilder<L, D> {
    fn step<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    >(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>
    {
        let (target_header_hash, state_root_merkle_root, data_root_merkle_root) = self
            .verify_subchain::<StepCircuit<
            MAX_AUTHORITY_SET_SIZE,
            MAX_HEADER_SIZE,
            MAX_NUM_HEADERS,
        >, MAX_NUM_HEADERS>(
            trusted_block,
            trusted_header_hash,
            target_block,
        );

        self.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            target_block,
            target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        (
            target_header_hash,
            state_root_merkle_root,
            data_root_merkle_root,
        )
    }
}

#[cfg(test)]
pub mod tests {
    use std::env;

    use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
    use plonky2x::prelude::{
        ArrayVariable, ByteVariable, Bytes32Variable, DefaultBuilder, U32Variable, Variable,
        VariableStream,
    };

    use crate::builder::rotate::RotateMethods;
    use crate::consts::{
        DELAY_LENGTH, MAX_HEADER_SIZE, MAX_PREFIX_LENGTH, MAX_SUBARRAY_SIZE, VALIDATOR_LENGTH,
    };
    use crate::rotate::RotateHint;
    use crate::vars::EncodedHeaderVariable;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_prefix_epoch_end_header() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 100;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;

        let mut builder = DefaultBuilder::new();

        let epoch_end_block_number = builder.read::<U32Variable>();

        // Fetch the header at epoch_end_block.
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header =
            output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(&mut builder);

        let num_authorities = output_stream.read::<Variable>(&mut builder);
        let start_position = output_stream.read::<Variable>(&mut builder);
        let _ = output_stream.read::<Bytes32Variable>(&mut builder);
        let _ = output_stream
            .read::<ArrayVariable<CompressedEdwardsYVariable, NUM_AUTHORITIES>>(&mut builder);

        // Convert header to Variables from ByteVariables for get_fixed_subarray.
        let header_variables = target_header
            .header_bytes
            .as_vec()
            .iter()
            .map(|x: &ByteVariable| x.to_variable(&mut builder))
            .collect::<Vec<_>>();
        let header_as_variables =
            ArrayVariable::<Variable, MAX_HEADER_SIZE>::from(header_variables);

        // Get the subarray of the header bytes that we want to verify. In the test
        // we can use the first 32 bytes of the header as the seed to get_fixed_subarray, but this
        // is not correct.
        let target_header_dummy_hash = &target_header.header_bytes.as_vec()[0..32];
        let prefix_subarray = builder
            .get_fixed_subarray_unsafe::<MAX_HEADER_SIZE, MAX_PREFIX_LENGTH>(
                &header_as_variables,
                start_position,
                target_header_dummy_hash,
            );
        let prefix_subarray = ArrayVariable::<ByteVariable, MAX_PREFIX_LENGTH>::from(
            prefix_subarray
                .data
                .iter()
                .map(|x| ByteVariable::from_target(&mut builder, x.0))
                .collect::<Vec<_>>(),
        );

        builder.verify_prefix_epoch_end_header(&prefix_subarray, &num_authorities);

        let circuit = builder.build();
        let mut input = circuit.input();

        let epoch_end_block_number = 4321u32;
        input.write::<U32Variable>(epoch_end_block_number);
        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_epoch_end_header_small_authority_set() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 16;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        let epoch_end_block_number = builder.read::<U32Variable>();

        // Fetch the header at epoch_end_block.
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header =
            output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(&mut builder);

        let num_authorities = output_stream.read::<Variable>(&mut builder);
        let start_position = output_stream.read::<Variable>(&mut builder);
        let expected_new_authority_set_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        let new_pubkeys = output_stream
            .read::<ArrayVariable<CompressedEdwardsYVariable, NUM_AUTHORITIES>>(&mut builder);

        // Note: In verify_epoch_end_header, we just use the header_hash as the seed for randomness,
        // so it's fine to just use the expected_new_authority_set_hash during this test.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            &target_header_hash.as_bytes(),
            &target_header_hash.as_bytes(),
            &num_authorities,
            &start_position,
            &new_pubkeys,
            &expected_new_authority_set_hash,
        );

        let circuit = builder.build();
        let mut input = circuit.input();

        // Authority set size is 5.
        let epoch_end_block_number = 4321u32;
        input.write::<U32Variable>(epoch_end_block_number);
        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_epoch_end_header_large_authority_set() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 100;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_SUBARRAY_SIZE: usize = NUM_AUTHORITIES * VALIDATOR_LENGTH + DELAY_LENGTH;

        let mut builder = DefaultBuilder::new();

        let epoch_end_block_number = builder.read::<U32Variable>();

        // Fetch the header at epoch_end_block.
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header =
            output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(&mut builder);

        let num_authorities = output_stream.read::<Variable>(&mut builder);
        let start_position = output_stream.read::<Variable>(&mut builder);
        let expected_new_authority_set_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        let new_pubkeys = output_stream
            .read::<ArrayVariable<CompressedEdwardsYVariable, NUM_AUTHORITIES>>(&mut builder);

        // Note: In verify_epoch_end_header, we just use the header_hash as the seed for randomness,
        // so it's fine to just use the expected_new_authority_set_hash during this test.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            &target_header_hash.as_bytes(),
            &target_header_hash.as_bytes(),
            &num_authorities,
            &start_position,
            &new_pubkeys,
            &expected_new_authority_set_hash,
        );

        let circuit = builder.build();
        let mut input = circuit.input();

        let epoch_end_block_number = 4321u32;
        input.write::<U32Variable>(epoch_end_block_number);
        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }
}
