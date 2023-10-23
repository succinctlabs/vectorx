use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, Variable,
};

use crate::builder::justification::GrandpaJustificationVerifier;
use crate::vars::*;

pub trait RotateMethods {
    fn rotate<const MAX_HEADER_SIZE: usize, const MAX_AUTHORITY_SET_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        end_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    ) -> Bytes32Variable;
}

// Extracts the validators from the epoch end header and computes the validator hash.
impl<L: PlonkParameters<D>, const D: usize> RotateMethods for CircuitBuilder<L, D> {
    fn rotate<const MAX_HEADER_SIZE: usize, const MAX_AUTHORITY_SET_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        end_position: &Variable,
        new_pubkeys: &ArrayVariable<AvailPubkeyVariable, MAX_AUTHORITY_SET_SIZE>,
        expected_new_authority_set_hash: &Bytes32Variable,
    ) -> Bytes32Variable {
        // let header_variable = self.decode_header::<MAX_HEADER_SIZE>(header, header_hash);
        let header_bytes = &header.header_bytes;
        let one = self.one();

        let mut cursor = *start_position;

        // Verify the first byte is 0x04 (enum DigestItemType, Consensus = 4u32).
        let consensus_enum_flag = self.constant::<ByteVariable>(4u8);
        let header_consensus_flag = self.select_array(&header_bytes.data, cursor);
        self.assert_is_equal(header_consensus_flag, consensus_enum_flag);
        cursor = self.add(cursor, one);

        // Verify the next 4 bytes are 0x46524e4b [70, 82, 78, 75], the consensus_id_bytes.
        // TODO: Verify that these 4 bytes are the consensus id bytes? Or what are they
        let consensus_id_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([70u8, 82u8, 78u8, 75u8].to_vec());
        for i in 0..4 {
            let header_consensus_id_byte = self.select_array(&header_bytes.data, cursor);
            self.assert_is_equal(header_consensus_id_byte, consensus_id_bytes[i]);
            cursor = self.add(cursor, one);
        }

        // Skip 5 bytes
        // TODO: Figure out what the 5 bytes are

        for _ in 0..5 {
            cursor = self.add(cursor, one);
        }

        const PUBKEY_LENGTH: usize = 32;
        const WEIGHT_LENGTH: usize = 8;
        const DELAY_LENGTH: usize = 4;
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

        // Verify num_authorities validators are present and valid.
        for i in 0..(MAX_AUTHORITY_SET_SIZE + 1) {
            let curr_validator = self.constant::<Variable>(L::Field::from_canonical_usize(i));

            let at_delay = self.is_equal(curr_validator, *num_authorities);
            let not_at_delay = self.not(at_delay);

            // Set validator to disabled once we are at the delay.
            validator_enabled = self.and(validator_enabled, not_at_delay);
            let validator_disabled = self.not(validator_enabled);

            // Note: Use header_hash as seed for randomness (this works b/c headers are random).
            let pubkey_as_variables = self.get_fixed_subarray::<MAX_HEADER_SIZE, PUBKEY_LENGTH>(
                &header_as_variables,
                cursor,
                &header_hash.0 .0,
            );
            let pubkey = Bytes32Variable::from(
                pubkey_as_variables
                    .data
                    .iter()
                    .map(|x| ByteVariable::from_target(self, x.0))
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            // Check if pubkey matches new_pubkey (which forms the new authority set commitment).
            let correct_pubkey = self.is_equal(pubkey, new_pubkeys[i]);
            let is_valid_pubkey = self.or(validator_disabled, correct_pubkey);
            self.assert_is_equal(is_valid_pubkey, true_v);

            // If we are at the delay, then the first 4 bytes of the "pubkey" should be 0.
            for j in 0..DELAY_LENGTH {
                let correct_delay = self.is_equal(pubkey.0[j], delay_bytes[j]);
                // Either we are not at the delay, or we are at the delay and the byte matches.
                let is_valid_delay = self.or(not_at_delay, correct_delay);
                self.assert_is_equal(is_valid_delay, true_v);
            }
            // If we are at the delay, then cursor + 4 should be equal to end_position.
            let cursor_plus_delay = self.add(cursor, delay_len);
            let is_valid_delay = self.is_equal(cursor_plus_delay, *end_position);
            self.assert_is_equal(is_valid_delay, at_delay);
            // Increment the cursor by the pubkey length.
            cursor = self.add(cursor, pubkey_len);

            let weight_as_variables = self.get_fixed_subarray::<MAX_HEADER_SIZE, WEIGHT_LENGTH>(
                &header_as_variables,
                cursor,
                &header_hash.0 .0,
            );
            let weight = ArrayVariable::<ByteVariable, WEIGHT_LENGTH>::from(
                weight_as_variables
                    .data
                    .iter()
                    .map(|x| ByteVariable::from_target(self, x.0))
                    .collect::<Vec<_>>(),
            );

            // We use validator_disabled to check if the weight should be valid.
            let validator_disabled = self.not(validator_enabled);

            // If this validator is enabled, weight should be equal to weight_bytes.
            for j in 0..WEIGHT_LENGTH {
                let correct_weight = self.is_equal(weight[j], weight_bytes[j]);
                // Either this validator is not enabled or the weight is correct.
                let is_valid_weight = self.or(validator_disabled, correct_weight);
                self.assert_is_equal(is_valid_weight, true_v);
            }
            // Increment the cursor by the weight length.
            cursor = self.add(cursor, weight_len);
        }

        // Verify the new authority set commitment.
        self.verify_authority_set_commitment(
            *num_authorities,
            *expected_new_authority_set_hash,
            new_pubkeys,
        );

        *expected_new_authority_set_hash
    }
}
