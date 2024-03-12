use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, Variable,
};

use super::decoder::DecodingMethods;
use super::header::HeaderMethods;
use crate::builder::justification::GrandpaJustificationVerifier;
use crate::consts::{
    BASE_PREFIX_LENGTH, DELAY_LENGTH, MAX_COMPACT_UINT_BYTES, MAX_PREFIX_LENGTH, PUBKEY_LENGTH,
    VALIDATOR_LENGTH, WEIGHT_LENGTH,
};
use crate::vars::*;

pub trait RotateMethods {
    /// Verifies the prefix bytes before the encoded authority set length are valid, according to the spec
    /// for the epoch end header.
    fn verify_prefix_epoch_end_header<const PREFIX_LENGTH: usize>(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, PREFIX_LENGTH>,
    );

    /// Returns the length of the compact encoding of the new authority set length.
    fn get_new_authority_set_size_encoded_byte_length(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, MAX_PREFIX_LENGTH>,
        expected_num_authorities: &Variable,
    ) -> Variable;

    /// Verifies the epoch end header has a valid encoding, and that the new_pubkeys match the header's
    /// encoded pubkeys.
    fn verify_epoch_end_header<
        const MAX_HEADER_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        new_pubkeys: &ArrayVariable<CompressedEdwardsYVariable, MAX_AUTHORITY_SET_SIZE>,
    );

    // Verify the justification from the current authority set on the epoch end header and extract
    // the new authority set commitment.
    fn rotate<
        const MAX_HEADER_SIZE: usize,
        const MAX_HEADER_CHUNK_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        epoch_end_block_number: U32Variable,
        current_authority_set_id: U64Variable,
        current_authority_set_hash: Bytes32Variable,
        rotate: RotateVariable<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> RotateMethods for CircuitBuilder<L, D> {
    fn verify_prefix_epoch_end_header<const PREFIX_LENGTH: usize>(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, PREFIX_LENGTH>,
    ) {
        // Digest Spec: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/src/api_dev.rs#L30820-L30842
        // Skip 1 unknown byte.

        // Verify subarray[1] is 0x04 (Consensus Flag = 4u32).
        let consensus_enum_flag = self.constant::<ByteVariable>(4u8);
        let header_consensus_flag = subarray[1];
        self.assert_is_equal(header_consensus_flag, consensus_enum_flag);

        // Verify subarray[2..6] is the Consensus Engine ID: 0x46524e4b [70, 82, 78, 75].
        // Consensus Id: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/examples/download_digest_items.rs#L41-L56
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
    }

    /// Returns the length of the compact encoding of the new authority set length.
    fn get_new_authority_set_size_encoded_byte_length(
        &mut self,
        subarray: &ArrayVariable<ByteVariable, MAX_PREFIX_LENGTH>,
        expected_num_authorities: &Variable,
    ) -> Variable {
        // Verify the bytes starting at the base prefix length are the compact encoding of the
        // length of the new authority set.
        let encoded_num_authorities_size_bytes =
            ArrayVariable::<ByteVariable, MAX_COMPACT_UINT_BYTES>::from(
                subarray[BASE_PREFIX_LENGTH..BASE_PREFIX_LENGTH + MAX_COMPACT_UINT_BYTES].to_vec(),
            );
        let (num_authorities, compress_mode) =
            self.decode_compact_int(encoded_num_authorities_size_bytes);
        self.assert_is_equal(*expected_num_authorities, num_authorities.variable);

        // Number of bytes in the compact encoding of the new authority set length.
        let all_possible_lengths = vec![
            self.constant::<Variable>(L::Field::from_canonical_usize(1)),
            self.constant::<Variable>(L::Field::from_canonical_usize(2)),
            self.constant::<Variable>(L::Field::from_canonical_usize(4)),
            self.constant::<Variable>(L::Field::from_canonical_usize(5)),
        ];

        // Select the correct length of the compact encoding of the new authority set length.
        self.select_array_random_gate(&all_possible_lengths, compress_mode)
    }

    fn verify_epoch_end_header<
        const MAX_HEADER_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        new_pubkeys: &ArrayVariable<CompressedEdwardsYVariable, MAX_AUTHORITY_SET_SIZE>,
    ) {
        let false_v = self._false();
        let true_v = self._true();

        // Assert num_authorities is not 0.
        let num_authorities_zero = self.is_zero(*num_authorities);
        self.assert_is_equal(num_authorities_zero, false_v);

        // Initialize the cursor to the start position, which is the start of the consensus log
        // corresponding to an authority set change event in the epoch end header.
        let mut cursor = *start_position;

        // Get the subarray of the header bytes to verify. The header_hash is used as the seed for
        // randomness.
        let prefix_subarray = self.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_PREFIX_LENGTH>(
            &header.header_bytes,
            cursor,
            &header_hash.as_bytes(),
        );

        // Verify the prefix bytes before the encoded authority set are valid, according to the spec.
        self.verify_prefix_epoch_end_header(&prefix_subarray);

        // Returns the byte length of the compact encoding of the new authority set length.
        let encoded_num_authorities_byte_len =
            self.get_new_authority_set_size_encoded_byte_length(&prefix_subarray, num_authorities);

        // Expected weight for each authority.
        let expected_weight_bytes = self.constant::<ArrayVariable<ByteVariable, WEIGHT_LENGTH>>(
            [1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8].to_vec(),
        );
        // Expected delay for the authority set.
        let expected_delay_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([0u8, 0u8, 0u8, 0u8].to_vec());

        let pubkey_len = self.constant::<Variable>(L::Field::from_canonical_usize(PUBKEY_LENGTH));
        let weight_len = self.constant::<Variable>(L::Field::from_canonical_usize(WEIGHT_LENGTH));
        let base_prefix_len =
            self.constant::<Variable>(L::Field::from_canonical_usize(BASE_PREFIX_LENGTH));

        // Get to the start of the encoded authority set. The cursor is the base prefix length
        // plus the length of the compact encoding of the new authority set length.
        cursor = self.add(cursor, base_prefix_len);
        cursor = self.add(cursor, encoded_num_authorities_byte_len);

        let enc_validator_subarray = self.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_SUBARRAY_SIZE>(
            &header.header_bytes,
            cursor,
            &header_hash.as_bytes(),
        );

        let mut validator_disabled = self._false();
        // Verify num_authorities validators are present and valid.
        // Spec: https://github.com/paritytech/subxt/blob/cb67f944558a76f53167be7855c4725cdf80580c/testing/integration-tests/src/full_client/codegen/polkadot.rs#L9484-L9501
        for i in 0..(MAX_AUTHORITY_SET_SIZE) {
            let idx = i * VALIDATOR_LENGTH;
            let curr_validator = self.constant::<Variable>(L::Field::from_canonical_usize(i + 1));

            // Verify the correctness of the extracted pubkey for each enabled validator and
            // increment the cursor by the pubkey length.
            let extracted_pubkey =
                Bytes32Variable::from(&enc_validator_subarray[idx..idx + PUBKEY_LENGTH]);
            let pubkey_match = self.is_equal(extracted_pubkey, new_pubkeys[i].0);
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
    }

    fn rotate<
        const MAX_HEADER_SIZE: usize,
        const MAX_HEADER_CHUNK_SIZE: usize,
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_SUBARRAY_SIZE: usize,
    >(
        &mut self,
        epoch_end_block_number: U32Variable,
        current_authority_set_id: U64Variable,
        current_authority_set_hash: Bytes32Variable,
        rotate: RotateVariable<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>,
    ) -> Bytes32Variable {
        assert_eq!(
            MAX_SUBARRAY_SIZE,
            MAX_AUTHORITY_SET_SIZE * VALIDATOR_LENGTH + DELAY_LENGTH,
            "MAX_SUBARRAY_SIZE must be equal to MAX_AUTHORITY_SET_SIZE * VALIDATOR_LENGTH + DELAY_LENGTH."
        );

        // Hash the header at epoch_end_block.
        let target_header_hash = self
            .hash_encoded_header::<MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE>(&rotate.target_header);

        // Verify the justification from the current authority set on the epoch end header.
        self.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            epoch_end_block_number,
            target_header_hash,
            current_authority_set_id,
            current_authority_set_hash,
        );

        // Verify the epoch end header and the new authority set are valid.
        self.verify_epoch_end_header::<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE, MAX_SUBARRAY_SIZE>(
            &rotate.target_header,
            target_header_hash,
            &rotate.target_header_num_authorities,
            &rotate.next_authority_set_start_position,
            &rotate.new_pubkeys,
        );

        // Sanity check against the witnessed expected_new_authority_set_hash. This doesn't
        // provide any additional safety, but provides sanity for the hint.
        // TODO: Decide whether to remove.
        let computed_new_authority_set_hash = self.compute_authority_set_commitment(
            rotate.target_header_num_authorities,
            &rotate.new_pubkeys,
        );
        self.assert_is_equal(
            computed_new_authority_set_hash,
            rotate.expected_new_authority_set_hash,
        );

        rotate.expected_new_authority_set_hash
    }
}

#[cfg(test)]
pub mod tests {
    use std::env;

    use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, DefaultBuilder, U32Variable, Variable, VariableStream,
    };

    use crate::builder::rotate::RotateMethods;
    use crate::consts::{DELAY_LENGTH, MAX_HEADER_SIZE, MAX_PREFIX_LENGTH, VALIDATOR_LENGTH};
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
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES> {};
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

        // Note: In prod, get_fixed_subarray uses the header_hash as the seed for randomness. The
        // below is unsafe, but it's fine for testing purposes.
        let target_header_dummy_hash = &target_header.header_bytes.as_vec()[0..32];
        let prefix_subarray = builder.get_fixed_subarray::<MAX_HEADER_SIZE, MAX_PREFIX_LENGTH>(
            &target_header.header_bytes,
            start_position,
            target_header_dummy_hash,
        );

        builder.verify_prefix_epoch_end_header(&prefix_subarray);

        let _encoded_num_authorities_byte_len = builder
            .get_new_authority_set_size_encoded_byte_length(&prefix_subarray, &num_authorities);

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
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES> {};
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

        // Note: In prod, get_fixed_subarray uses the header_hash as the seed for randomness. The
        // below is unsafe, but it's fine for testing purposes.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            target_header_hash,
            &num_authorities,
            &start_position,
            &new_pubkeys,
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
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH, NUM_AUTHORITIES> {};
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

        // Note: In prod, get_fixed_subarray uses the header_hash as the seed for randomness. The
        // below is unsafe, but it's fine for testing purposes.
        let target_header_hash = expected_new_authority_set_hash;

        builder.verify_epoch_end_header::<MAX_HEADER_LENGTH, NUM_AUTHORITIES, MAX_SUBARRAY_SIZE>(
            &target_header,
            target_header_hash,
            &num_authorities,
            &start_position,
            &new_pubkeys,
        );

        let circuit = builder.build();
        let mut input = circuit.input();

        let epoch_end_block_number = 4321u32;
        input.write::<U32Variable>(epoch_end_block_number);
        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }
}
