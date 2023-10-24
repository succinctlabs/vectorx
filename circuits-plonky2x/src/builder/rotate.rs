use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, Variable,
};

use crate::builder::justification::GrandpaJustificationVerifier;
use crate::consts::{DELAY_LENGTH, PUBKEY_LENGTH, VALIDATOR_LENGTH, WEIGHT_LENGTH};
use crate::vars::*;

pub trait RotateMethods {
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
        end_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> RotateMethods for CircuitBuilder<L, D> {
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
        end_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    ) {
        let header_bytes = &header.header_bytes;
        let one = self.one();

        let mut cursor = *start_position;

        // Skip 1 byte, TODO: Figure out what this byte is.
        cursor = self.add(cursor, one);

        // Verify the next byte is 0x04 (Consensus Flag = 4u32).
        let consensus_enum_flag = self.constant::<ByteVariable>(4u8);
        // TODO: This is inefficient, see if there's a better way to do this.
        let header_consensus_flag = self.select_array(&header_bytes.data, cursor);
        self.assert_is_equal(header_consensus_flag, consensus_enum_flag);
        cursor = self.add(cursor, one);

        // Verify the next 4 bytes are the Consensus Engine ID: 0x46524e4b [70, 82, 78, 75].
        // TODO: Link to the Consensus Engine ID in subxt for Grandpa.
        let consensus_id_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([70u8, 82u8, 78u8, 75u8].to_vec());
        for i in 0..4 {
            // TODO: select_array is inefficient, see if there's a better way to do this.
            let header_consensus_id_byte = self.select_array(&header_bytes.data, cursor);
            self.assert_is_equal(header_consensus_id_byte, consensus_id_bytes[i]);
            cursor = self.add(cursor, one);
        }

        // Skip 2 bytes
        // TODO: Validate what the 2 bytes are. Not sure if this is ncessary.
        for _ in 0..2 {
            cursor = self.add(cursor, one);
        }

        // Verify the next byte is 0x01, denoting a ScheduledChange.
        let scheduled_change_enum_flag = self.constant::<ByteVariable>(1u8);
        // TODO: select_array is inefficient, see if there's a better way to do this.
        let header_schedule_change_flag = self.select_array(&header_bytes.data, cursor);
        self.assert_is_equal(header_schedule_change_flag, scheduled_change_enum_flag);
        cursor = self.add(cursor, one);

        // Skip 2 bytes
        // TODO: Validate what the 2 bytes are. Not sure if this is ncessary.
        for _ in 0..2 {
            cursor = self.add(cursor, one);
        }

        let pubkey_len = self.constant::<Variable>(L::Field::from_canonical_usize(PUBKEY_LENGTH));
        let weight_len = self.constant::<Variable>(L::Field::from_canonical_usize(WEIGHT_LENGTH));
        let delay_len = self.constant::<Variable>(L::Field::from_canonical_usize(DELAY_LENGTH));

        let weight_bytes = self.constant::<ArrayVariable<ByteVariable, WEIGHT_LENGTH>>(
            [1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].to_vec(),
        );

        // Convert header to Variable from ByteVariable for get_fixed_subarray.
        let header_variables = header
            .header_bytes
            .as_vec()
            .iter()
            .map(|x: &ByteVariable| x.to_variable(self))
            .collect::<Vec<_>>();
        let header_as_variables =
            ArrayVariable::<Variable, MAX_HEADER_SIZE>::from(header_variables);

        let true_v = self._true();
        let mut validator_enabled = self._true();

        let delay_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([0u8, 0u8, 0u8, 0u8].to_vec());

        // Note: Use header_hash as seed for randomness.
        // Get the maximum size subarray of the header bytes that we want to verify.
        let subarray = self.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_SUBARRAY_SIZE>(
            &header_as_variables,
            cursor,
            &header_hash.as_bytes(),
        );
        let subarray = ArrayVariable::<ByteVariable, MAX_SUBARRAY_SIZE>::from(
            subarray
                .data
                .iter()
                .map(|x| ByteVariable::from_target(self, x.0))
                .collect::<Vec<_>>(),
        );

        // Verify num_authorities validators are present and valid.
        for i in 0..(MAX_AUTHORITY_SET_SIZE) {
            let idx = i * VALIDATOR_LENGTH;
            let curr_validator = self.constant::<Variable>(L::Field::from_canonical_usize(i));

            let at_delay = self.is_equal(curr_validator, *num_authorities);
            let not_at_delay = self.not(at_delay);

            // Set validator to disabled once we are at the delay.
            validator_enabled = self.and(validator_enabled, not_at_delay);
            let validator_disabled = self.not(validator_enabled);

            // Check if pubkey matches new_pubkey (which forms the new authority set commitment).
            let pubkey = Bytes32Variable::from(&subarray[idx..idx + PUBKEY_LENGTH]);
            let correct_pubkey = self.is_equal(pubkey, new_pubkeys[i]);
            let is_valid_pubkey = self.or(validator_disabled, correct_pubkey);
            self.assert_is_equal(is_valid_pubkey, true_v);
            // Increment the cursor by the pubkey length.
            cursor = self.add(cursor, pubkey_len);

            // Check the weight is [1, 0, 0, 0, 0, 0, 0, 0]
            let weight = ArrayVariable::<ByteVariable, WEIGHT_LENGTH>::from(
                subarray[idx + PUBKEY_LENGTH..idx + VALIDATOR_LENGTH].to_vec(),
            );
            let correct_weight = self.is_equal(weight, weight_bytes.clone());
            let is_valid_weight = self.or(validator_disabled, correct_weight);
            self.assert_is_equal(is_valid_weight, true_v);
            // Increment the cursor by the weight length.
            cursor = self.add(cursor, weight_len);
        }

        // Verifies the delay is at header_bytes[end_position - 4..end_position].
        let mut delay_cursor = self.sub(*end_position, delay_len);
        for j in 0..DELAY_LENGTH {
            // TODO: select_array is inefficient, see if there's a better way to do this.
            let extracted_delay_byte = self.select_array(&header_bytes.data, delay_cursor);
            self.assert_is_equal(extracted_delay_byte, delay_bytes[j]);
            delay_cursor = self.add(delay_cursor, one);
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
    use crate::consts::{MAX_HEADER_SIZE, VALIDATOR_LENGTH};
    use crate::rotate::RotateHint;
    use crate::vars::{AvailPubkeyVariable, EncodedHeaderVariable};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_epoch_end_header() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 100;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_SUBARRAY_SIZE: usize = (NUM_AUTHORITIES + 1) * VALIDATOR_LENGTH;

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
        let end_position = output_stream.read::<Variable>(&mut builder);
        let expected_new_authority_set_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        let new_pubkeys =
            output_stream.read::<ArrayVariable<AvailPubkeyVariable, NUM_AUTHORITIES>>(&mut builder);

        // Note: In verify_epoch_end_header, we use the header_hash as the seed for randomness, so
        // it's fine to just use the expected_new_authority_set_hash during the test.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            &target_header_hash,
            &num_authorities,
            &start_position,
            &end_position,
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
