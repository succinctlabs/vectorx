use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, Variable,
};

use super::decoder::DecodingMethods;
use crate::builder::justification::GrandpaJustificationVerifier;
use crate::consts::{
    DELAY_LENGTH, MAX_BLOCK_NUMBER_BYTES, MAX_PREFIX_LENGTH, MIN_PREFIX_LENGTH, PUBKEY_LENGTH,
    VALIDATOR_LENGTH, WEIGHT_LENGTH,
};
use crate::vars::*;

pub trait RotateMethods {
    /// Verifies the prefix bytes before the encoded authority set are valid, according to the spec
    /// for the epoch end header. Returns the length of the compact encoding of the new authority set
    /// length.
    ///
    /// TODO: Find the spec for this prefix!
    fn verify_prefix_epoch_end_header<const PREFIX_LENGTH: usize>(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, PREFIX_LENGTH>,
        expected_num_authorities: &Variable,
    ) -> Variable;

    /// Verifies the epoch end header is valid and that the new authority set commitment is correct.
    fn verify_epoch_end_header<
        const MAX_HEADER_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        // This should be (MAX_AUTHORITY_SET_SIZE + 1) * (VALIDATOR_LENGTH)
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> RotateMethods for CircuitBuilder<L, D> {
    /// Verifies the prefix bytes before the encoded authority set are valid, according to the spec
    /// for the epoch end header.
    ///
    /// Returns the length of the compact encoding of the new authority set length.
    /// TODO: Find the spec for this prefix!
    fn verify_prefix_epoch_end_header<const PREFIX_LENGTH: usize>(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, PREFIX_LENGTH>,
        expected_num_authorities: &Variable,
    ) -> Variable {
        // Skip 1 unknown byte.

        // Verify subarray[1] is 0x04 (Consensus Flag = 4u32).
        let consensus_enum_flag = self.constant::<ByteVariable>(4u8);
        let header_consensus_flag = subarray[1];
        self.assert_is_equal(header_consensus_flag, consensus_enum_flag);

        // Verify subarray[2..6] is the Consensus Engine ID: 0x46524e4b [70, 82, 78, 75].
        // TODO: Link to the Consensus Engine ID in subxt for Grandpa.
        let consensus_id_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([70u8, 82u8, 78u8, 75u8].to_vec());
        self.assert_is_equal(
            ArrayVariable::<ByteVariable, 4>::from(subarray[2..6].to_vec()),
            consensus_id_bytes,
        );

        // Skip 2 unknown bytes.

        // Verify subarray[8] is 0x01, denoting a ScheduledChange.
        let scheduled_change_enum_flag = self.constant::<ByteVariable>(1u8);
        let header_schedule_change_flag = subarray[8];
        self.assert_is_equal(header_schedule_change_flag, scheduled_change_enum_flag);

        // Verify the next bytes are the compact encoding of the length of the new authority set.
        let num_authorities_length_bytes =
            ArrayVariable::<ByteVariable, MAX_BLOCK_NUMBER_BYTES>::from(
                subarray[MIN_PREFIX_LENGTH - 1..MIN_PREFIX_LENGTH - 1 + MAX_BLOCK_NUMBER_BYTES]
                    .to_vec(),
            );
        let (num_authorities, compress_mode) =
            self.decode_compact_int(num_authorities_length_bytes);
        self.assert_is_equal(*expected_num_authorities, num_authorities.variable);

        // Number of additional bytes in the compact encoding of the new authority set length.
        // Specifically, the lengths of the compact_encoding - 1.
        let all_possible_lengths = vec![
            self.constant::<Variable>(L::Field::from_canonical_usize(1)),
            self.constant::<Variable>(L::Field::from_canonical_usize(2)),
            self.constant::<Variable>(L::Field::from_canonical_usize(4)),
            self.constant::<Variable>(L::Field::from_canonical_usize(5)),
        ];

        self.select_array_random_gate(&all_possible_lengths, compress_mode)
    }

    /// Verifies the epoch end header is valid and that the new authority set commitment is correct.
    fn verify_epoch_end_header<
        const MAX_HEADER_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    ) {
        let true_v = self._true();
        let one = self.one();

        // Check num_authorities is >= 1.
        let num_authorities_check = self.gte(*num_authorities, one);
        self.assert_is_equal(num_authorities_check, true_v);

        // Convert header to Variables from ByteVariables for get_fixed_subarray.
        let header_variables = header
            .header_bytes
            .as_vec()
            .iter()
            .map(|x: &ByteVariable| x.to_variable(self))
            .collect::<Vec<_>>();
        let header_as_variables =
            ArrayVariable::<Variable, MAX_HEADER_SIZE>::from(header_variables);

        // Initialize the cursor to the start position, which is the start of the consensus log
        // corresponding to an authority set change event in the epoch end header.
        self.watch(start_position, "start_position");
        let mut cursor = *start_position;

        // Get the subarray of the header bytes that we want to verify. The header_hash is used as
        // the seed for randomness.
        let prefix_subarray = self.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_PREFIX_LENGTH>(
            &header_as_variables,
            cursor,
            &header_hash.as_bytes(),
        );
        let prefix_subarray = ArrayVariable::<ByteVariable, MAX_PREFIX_LENGTH>::from(
            prefix_subarray
                .data
                .iter()
                .map(|x| ByteVariable::from_target(self, x.0))
                .collect::<Vec<_>>(),
        );

        // Verify the prefix bytes before the encoded authority set are valid, according to the spec.
        // Returns the byte length of the compact encoding of the new authority set length.
        let encoded_num_authorities_byte_len =
            self.verify_prefix_epoch_end_header(&prefix_subarray, num_authorities);

        // Expected weight for each authority.
        let expected_weight_bytes = self.constant::<ArrayVariable<ByteVariable, WEIGHT_LENGTH>>(
            [1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].to_vec(),
        );
        // Expected delay for the authority set.
        let expected_delay_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([0u8, 0u8, 0u8, 0u8].to_vec());

        let pubkey_len = self.constant::<Variable>(L::Field::from_canonical_usize(PUBKEY_LENGTH));
        let weight_len = self.constant::<Variable>(L::Field::from_canonical_usize(WEIGHT_LENGTH));
        let min_prefix_len =
            self.constant::<Variable>(L::Field::from_canonical_usize(MIN_PREFIX_LENGTH));

        // Get to the start of the encoded authority set. The cursor is the minimum prefix length
        // plus the length of the compact encoding of the new authority set length - 1.
        cursor = self.add(cursor, min_prefix_len);
        cursor = self.add(cursor, encoded_num_authorities_byte_len);
        cursor = self.sub(cursor, one);

        let enc_validator_subarray = self.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_SUBARRAY_SIZE>(
            &header_as_variables,
            cursor,
            &header_hash.as_bytes(),
        );
        let enc_validator_subarray = ArrayVariable::<ByteVariable, MAX_SUBARRAY_SIZE>::from(
            enc_validator_subarray
                .data
                .iter()
                .map(|x| ByteVariable::from_target(self, x.0))
                .collect::<Vec<_>>(),
        );

        let mut validator_disabled = self._false();
        // Verify num_authorities validators are present and valid.
        for i in 0..(MAX_AUTHORITY_SET_SIZE) {
            let idx = i * VALIDATOR_LENGTH;
            let curr_validator = self.constant::<Variable>(L::Field::from_canonical_usize(i + 1));

            // Verify the correctness of the extracted pubkey for each enabled validator and
            // increment the cursor by the pubkey length.
            let extracted_pubkey =
                Bytes32Variable::from(&enc_validator_subarray[idx..idx + PUBKEY_LENGTH]);
            let pubkey_match = self.is_equal(extracted_pubkey, new_pubkeys[i]);
            let pubkey_check = self.or(pubkey_match, validator_disabled);
            self.assert_is_equal(pubkey_check, true_v);
            cursor = self.add(cursor, pubkey_len);

            // Verify the correctness of the extracted weight for each enabled validator and
            // increment the cursor by the weight length.
            let extracted_weight = ArrayVariable::<ByteVariable, WEIGHT_LENGTH>::from(
                enc_validator_subarray[idx + PUBKEY_LENGTH..idx + VALIDATOR_LENGTH].to_vec(),
            );
            let weight_match = self.is_equal(extracted_weight, expected_weight_bytes.clone());
            let weight_check = self.or(weight_match, validator_disabled);
            self.assert_is_equal(weight_check, true_v);
            cursor = self.add(cursor, weight_len);

            // Set validator_disabled to true if the cursor if this is the last validator.
            let at_end = self.is_equal(curr_validator, *num_authorities);
            validator_disabled = self.select(at_end, true_v, validator_disabled);

            let not_at_end = self.not(at_end);

            // If at the end of the authority set, verify the correctness of the delay bytes.
            let extracted_delay = ArrayVariable::<ByteVariable, DELAY_LENGTH>::from(
                enc_validator_subarray
                    [idx + VALIDATOR_LENGTH..idx + VALIDATOR_LENGTH + DELAY_LENGTH]
                    .to_vec(),
            );
            let delay_match = self.is_equal(extracted_delay, expected_delay_bytes.clone());
            let delay_check = self.or(delay_match, not_at_end);
            self.assert_is_equal(delay_check, true_v);
        }

        // Verify the new authority set commitment.
        self.verify_authority_set_commitment(
            *num_authorities,
            *expected_new_authority_set_hash,
            new_pubkeys,
        );
    }
}

#[cfg(test)]
pub mod tests {
    use std::env;

    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, DefaultBuilder, U32Variable, Variable, VariableStream,
    };

    use crate::builder::rotate::RotateMethods;
    use crate::consts::{DELAY_LENGTH, MAX_HEADER_SIZE, VALIDATOR_LENGTH};
    use crate::rotate::RotateHint;
    use crate::vars::{AvailPubkeyVariable, EncodedHeaderVariable};

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
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header =
            output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(&mut builder);

        let num_authorities = output_stream.read::<Variable>(&mut builder);
        let start_position = output_stream.read::<Variable>(&mut builder);
        let expected_new_authority_set_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        let new_pubkeys =
            output_stream.read::<ArrayVariable<AvailPubkeyVariable, NUM_AUTHORITIES>>(&mut builder);

        // Note: In verify_epoch_end_header, we just use the header_hash as the seed for randomness,
        // so it's fine to just use the expected_new_authority_set_hash during this test.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            &target_header_hash,
            &num_authorities,
            &start_position,
            &new_pubkeys,
            &expected_new_authority_set_hash,
        );

        let circuit = builder.build();
        let mut input = circuit.input();

        let epoch_end_block_number = 645610u32;
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
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header =
            output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(&mut builder);

        let num_authorities = output_stream.read::<Variable>(&mut builder);
        let start_position = output_stream.read::<Variable>(&mut builder);
        let expected_new_authority_set_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        let new_pubkeys =
            output_stream.read::<ArrayVariable<AvailPubkeyVariable, NUM_AUTHORITIES>>(&mut builder);

        // Note: In verify_epoch_end_header, we just use the header_hash as the seed for randomness,
        // so it's fine to just use the expected_new_authority_set_hash during this test.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            &target_header_hash,
            &num_authorities,
            &start_position,
            &new_pubkeys,
            &expected_new_authority_set_hash,
        );

        let circuit = builder.build();
        let mut input = circuit.input();

        let epoch_end_block_number = 317857u32;
        input.write::<U32Variable>(epoch_end_block_number);
        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }
}
