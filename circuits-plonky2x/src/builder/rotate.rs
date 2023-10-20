use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, Field,
    PlonkParameters, Variable,
};

use super::decoder::DecodingMethods;
use crate::vars::*;

pub trait RotateMethods {
    fn rotate<const MAX_HEADER_SIZE: usize, const MAX_AUTHORITY_SET_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
        num_authorities: &Variable,
        start_position: &Variable,
        end_position: &Variable,
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
    ) -> Bytes32Variable {
        // let header_variable = self.decode_header::<MAX_HEADER_SIZE>(header, header_hash);
        let header_bytes = &header.header_bytes;

        // Verify the first byte is 0x04 (enum DigestItemType, Consensus = 4u32).
        let consensus_enum_flag = self.constant::<ByteVariable>(4u8);
        self.assert_is_equal(header_bytes[0], consensus_enum_flag);

        // Verify the next 4 bytes are 0x46524e4b [70, 82, 78, 75], the consensus_id_bytes.
        // TODO: Verify that these 4 bytes are the consensus id bytes? Or what are they
        let consensus_id_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([70u8, 82u8, 78u8, 75u8].to_vec());
        for i in 0..4 {
            self.assert_is_equal(header_bytes[i + 1], consensus_id_bytes[i]);
        }

        // Skip 5 bytes
        // TODO: Figure out what the 5 bytes are

        // 10 = 1 + 4 + 5
        let mut cursor = self.constant::<Variable>(L::Field::from_canonical_usize(10));

        let delay_bytes =
            self.constant::<ArrayVariable<ByteVariable, 4>>([0u8, 0u8, 0u8, 0u8].to_vec());
        // Verify num_authorities validators are present and valid.

        for i in 0..MAX_AUTHORITY_SET_SIZE {
            let curr_idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));

            let at_delay = self.is_equal(curr_idx, *num_authorities);

            // If we are at the delay, verify delay is 0.
            for j in 0..4 {
                self.assert_is_equal(header_bytes[cursor + j], delay_bytes[j]);
            }
        }

        // TODO: Return the hash
        *header_hash
    }
}
