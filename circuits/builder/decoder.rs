use plonky2x::frontend::vars::{EvmVariable, U32Variable};
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, U64Variable, Variable,
};

use crate::consts::{
    DATA_ROOT_OFFSET_FROM_END, ENCODED_PRECOMMIT_LENGTH, HASH_SIZE, MAX_COMPACT_UINT_BYTES,
    MAX_HEADER_SIZE,
};
use crate::vars::*;

pub trait DecodingMethods {
    /// Decode the byte representation of a compact u32 into it's integer representation and SCALE
    /// compress mode. Spec: https://docs.substrate.io/reference/scale-codec/#fn-1
    fn decode_compact_int(
        &mut self,
        compact_bytes: ArrayVariable<ByteVariable, 5>,
    ) -> (U32Variable, Variable);

    /// Get the byte length of a compact int based on the compress mode.
    fn get_compact_int_byte_length(&mut self, compress_mode: Variable) -> Variable;

    /// Decode a header into its components: {block_nb, parent_hash, state_root and data_root}.
    /// header_hash is used for the RLC challenge in get_fixed_subarray.
    fn decode_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
    ) -> HeaderVariable;

    /// Decode a precommit message into its components: {block_hash, block_nb, justification_round, authority_set_id}.
    fn decode_precommit(
        &mut self,
        encoded_precommit: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    ) -> PrecommitVariable;
}

impl<L: PlonkParameters<D>, const D: usize> DecodingMethods for CircuitBuilder<L, D> {
    fn decode_compact_int(
        &mut self,
        compact_bytes: ArrayVariable<ByteVariable, MAX_COMPACT_UINT_BYTES>,
    ) -> (U32Variable, Variable) {
        // Flip the bit order within each byte to LE bits and flatten the array.
        let bool_targets = compact_bytes
            .data
            .iter()
            .flat_map(|x| {
                let mut bool_targets = x.as_bool_targets();
                bool_targets.reverse();
                bool_targets
            })
            .collect::<Vec<_>>();

        // Get the compress mode which is the first two bits. {00, 01, 10, 11} -> Mode {0, 1, 2, 3}.
        let compress_mode = Variable(self.api.le_sum(bool_targets[0..2].iter()));

        // Get all of the possible bytes that could be used to represent the compact int.
        // Spec for compact scale encoding: https://docs.substrate.io/reference/scale-codec/#fn-1.
        // Specifically, extract the LE bits of each potential value as follows:
        //  Mode 0: Upper 6 bits are the value.
        //  Mode 1: Upper 6 bits + next byte are the value.
        //  Mode 2: Upper 6 bits + next 3 bytes are the value.
        //  Mode 3: Upper 6 bits are the length and next 4 bytes are the value.
        let zero_mode_value = Variable(self.api.le_sum(bool_targets[2..8].iter()));
        let one_mode_value = Variable(self.api.le_sum(bool_targets[2..16].iter()));
        let two_mode_value = Variable(self.api.le_sum(bool_targets[2..32].iter()));
        let three_mode_value = Variable(self.api.le_sum(bool_targets[8..40].iter()));

        // Select the correct int value based on compress mode.
        let value = self.select_array_random_gate(
            &[
                zero_mode_value,
                one_mode_value,
                two_mode_value,
                three_mode_value,
            ],
            compress_mode,
        );
        let value = U32Variable::from_variables_unsafe(&[value]);

        // If mode is 3, check the upper 6 bits are 0. These bits represent the number of bytes for
        // the "BigInt" - 4. Since block number is a u32 (4 bytes), this will always be 0.
        let three = self.constant(L::Field::from_canonical_u8(3));
        let is_mode_three = self.is_equal(compress_mode, three);
        let zero = self.constant(L::Field::from_canonical_u8(0));
        let encoded_byte_length = Variable(self.api.le_sum(bool_targets[2..8].iter()));
        let is_encoded_length_zero = self.is_equal(encoded_byte_length, zero);
        let is_valid_encoded_length_check = self.and(is_mode_three, is_encoded_length_zero);
        self.assert_is_equal(is_mode_three, is_valid_encoded_length_check);

        (value, compress_mode)
    }

    fn get_compact_int_byte_length(&mut self, compress_mode: Variable) -> Variable {
        // All possible lengths of a SCALE-encoded compact int.
        let all_possible_lengths = vec![
            self.constant::<Variable>(L::Field::from_canonical_usize(1)),
            self.constant::<Variable>(L::Field::from_canonical_usize(2)),
            self.constant::<Variable>(L::Field::from_canonical_usize(4)),
            self.constant::<Variable>(L::Field::from_canonical_usize(5)),
        ];
        self.select_array_random_gate(&all_possible_lengths, compress_mode)
    }
    fn decode_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
    ) -> HeaderVariable {
        // Spec for Avail header: https://github.com/availproject/avail-core/blob/main/core/src/header/mod.rs#L44-L66

        // The first 32 bytes are the parent hash.
        let parent_hash: Bytes32Variable = header.header_bytes[0..HASH_SIZE].into();

        // Next field is the block number in compact u32 SCALE encoding.
        let block_number_bytes = ArrayVariable::<ByteVariable, MAX_COMPACT_UINT_BYTES>::from(
            header.header_bytes[HASH_SIZE..HASH_SIZE + MAX_COMPACT_UINT_BYTES].to_vec(),
        );
        let (block_number, compress_mode) = self.decode_compact_int(block_number_bytes);

        // The of block_number is 1, 2, 4, or 5 bytes depending on the encoding of the compact int.
        let all_possible_state_roots = vec![
            Bytes32Variable::from(&header.header_bytes[33..33 + HASH_SIZE]),
            Bytes32Variable::from(&header.header_bytes[34..34 + HASH_SIZE]),
            Bytes32Variable::from(&header.header_bytes[36..36 + HASH_SIZE]),
            Bytes32Variable::from(&header.header_bytes[37..37 + HASH_SIZE]),
        ];

        let state_root = self.select_array_random_gate(&all_possible_state_roots, compress_mode);

        // The next field is the data root. The data root is the last 32 bytes of the header.
        // Spec: https://github.com/availproject/avail-core/blob/main/core/src/header/extension/v3.rs#L9-L15
        let data_root_offset = self.constant::<U32Variable>(DATA_ROOT_OFFSET_FROM_END);
        let mut data_root_start = self.sub(header.header_size, data_root_offset);

        // If header_size == 0, then set data_root_start to 0.
        let header_is_zero_size = self.is_zero(header.header_size.variable);
        let zero = self.zero();
        data_root_start = self.select(header_is_zero_size, zero, data_root_start);

        // Extract the data root from the header.
        let data_root_bytes: Vec<ByteVariable> = self
            .get_fixed_subarray::<S, MAX_HEADER_SIZE>(
                &header.header_bytes,
                data_root_start.variable,
                &header.header_bytes.data,
            )
            .as_vec();
        let data_root = Bytes32Variable::from(data_root_bytes.as_slice());

        HeaderVariable {
            block_number,
            parent_hash,
            state_root,
            data_root,
        }
    }

    fn decode_precommit(
        &mut self,
        precommit: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    ) -> PrecommitVariable {
        // Link: https://github.com/paritytech/finality-grandpa/blob/8c45a664c05657f0c71057158d3ba555ba7d20de/src/lib.rs#L224-L239.
        // The first byte is the equivocation type (Precommit) and should be 1.
        let one = self.one();
        let precommit_first_byte = precommit[0].to_variable(self);
        self.assert_is_equal(precommit_first_byte, one);

        // Spec for precommit message encoding: https://github.com/availproject/polkadot-sdk/blob/70e569d5112f879001a987e94402ff70f9683cb5/substrate/primitives/consensus/grandpa/src/lib.rs#L434-L458.
        // Spec for grandpa message: https://github.com/paritytech/finality-grandpa/blob/8c45a664c05657f0c71057158d3ba555ba7d20de/src/lib.rs#L101-L110

        // The next 32 bytes is the block hash.
        let block_hash: Bytes32Variable = precommit[1..33].into();

        // The next 4 bytes is the block number.
        let mut block_number_bytes = precommit[33..37].to_vec();

        // The next 8 bytes is the justification round.
        let mut justification_round_bytes = precommit[37..45].to_vec();

        // The next 8 bytes is the authority set id.
        let mut authority_set_id_bytes = precommit[45..53].to_vec();

        // Reverse the bytes of block_number, justification_round and authority_set_id since they
        // are stored in LE, so CircuitVariable decoding (which expects BE) works correctly.
        block_number_bytes.reverse();
        justification_round_bytes.reverse();
        authority_set_id_bytes.reverse();

        let block_number = U32Variable::decode(self, &block_number_bytes);
        let justification_round = U64Variable::decode(self, &justification_round_bytes);
        let authority_set_id = U64Variable::decode(self, &authority_set_id_bytes);

        PrecommitVariable {
            block_hash,
            block_number,
            justification_round,
            authority_set_id,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::env;

    use avail_subxt::config::Header;
    use codec::{Compact, Encode};
    use plonky2x::frontend::vars::U32Variable;
    use plonky2x::prelude::{
        ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, DefaultBuilder, Field,
        GoldilocksField, U64Variable, Variable,
    };

    use super::DecodingMethods;
    use crate::consts::{ENCODED_PRECOMMIT_LENGTH, MAX_COMPACT_UINT_BYTES, MAX_HEADER_SIZE};
    use crate::input::RpcDataFetcher;
    use crate::vars::{EncodedHeader, EncodedHeaderVariable};

    #[test]
    fn test_decode_compact_int() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        type F = GoldilocksField;

        let mut builder = DefaultBuilder::new();

        let compact_bytes = builder.read::<ArrayVariable<ByteVariable, MAX_COMPACT_UINT_BYTES>>();

        let (value, compress_mode) = builder.decode_compact_int(compact_bytes);
        builder.write(value);
        builder.write(compress_mode);

        let circuit = builder.build();

        // Test cases are (compact int, compress mode).
        let test_cases = [
            (u32::MIN, 0),
            (1u32, 0),
            (63u32, 0),
            (64u32, 1),
            (16383u32, 1),
            (16384u32, 2),
            (1073741823u32, 2),
            (1073741824u32, 3),
            (4294967295u32, 3),
            (u32::MAX, 3),
        ];

        for i in 0..test_cases.len() {
            let mut input = circuit.input();

            // Use compact encoding to encode the block number.
            let encoded_block_num = Compact(test_cases[i].0).encode();

            // Extend encoding to MAX_COMPACT_UINT_BYTES.
            let mut encoded_block_num = encoded_block_num.to_vec();
            encoded_block_num.resize(MAX_COMPACT_UINT_BYTES, 0);

            input.write::<ArrayVariable<ByteVariable, MAX_COMPACT_UINT_BYTES>>(encoded_block_num);

            let (proof, mut output) = circuit.prove(&input);
            circuit.verify(&proof, &input, &output);

            let value = output.read::<U32Variable>();
            let compress_mode = output.read::<Variable>();

            assert_eq!(value, test_cases[i].0);
            assert_eq!(compress_mode, F::from_canonical_usize(test_cases[i].1));
        }
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_decode_headers() {
        const HEAD_BLOCK_NUM: u32 = 272515;
        const NUM_BLOCKS: usize = 1;
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        type F = GoldilocksField;

        let mut builder = DefaultBuilder::new();

        let encoded_headers =
            builder.read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_BLOCKS>>();

        let header_hashes = builder.read::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>();
        let expected_header_nums = builder.read::<ArrayVariable<U32Variable, NUM_BLOCKS>>();
        let expected_parent_hashes = builder.read::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>();
        let expected_state_roots = builder.read::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>();
        let expected_data_roots = builder.read::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>();

        for i in 0..NUM_BLOCKS {
            let decoded_header = builder.decode_header::<MAX_HEADER_SIZE>(&encoded_headers[i]);

            builder.assert_is_equal(decoded_header.block_number, expected_header_nums[i]);
            builder.assert_is_equal(decoded_header.parent_hash, expected_parent_hashes[i]);
            builder.assert_is_equal(decoded_header.state_root, expected_state_roots[i]);
            builder.assert_is_equal(decoded_header.data_root, expected_data_roots[i]);
        }

        let circuit = builder.build();

        let mut input = circuit.input();

        let rt = tokio::runtime::Runtime::new().unwrap();
        // Note: Returns NUM_BLOCKS + 1 headers.
        let headers = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .get_block_headers_range(HEAD_BLOCK_NUM, HEAD_BLOCK_NUM + NUM_BLOCKS as u32)
                .await
        });

        let encoded_headers_values: Vec<EncodedHeader<MAX_HEADER_SIZE, F>> = headers[0..NUM_BLOCKS]
            .iter()
            .map(|x| {
                let mut header: Vec<u8> = x.encode();
                let header_len = header.len();
                header.resize(MAX_HEADER_SIZE, 0);
                EncodedHeader {
                    header_bytes: header.as_slice().into(),
                    header_size: header_len as u32,
                }
            })
            .collect::<_>();

        input.write::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_BLOCKS>>(
            encoded_headers_values,
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            headers[0..NUM_BLOCKS]
                .iter()
                .map(|x| x.hash())
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<U32Variable, NUM_BLOCKS>>(
            (HEAD_BLOCK_NUM..HEAD_BLOCK_NUM + NUM_BLOCKS as u32).collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            headers[0..NUM_BLOCKS]
                .iter()
                .map(|x| x.parent_hash)
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            headers[0..NUM_BLOCKS]
                .iter()
                .map(|x| x.state_root)
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            headers[0..NUM_BLOCKS]
                .iter()
                .map(|x| x.data_root())
                .collect::<Vec<_>>(),
        );

        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }

    #[test]
    fn test_decode_precommit() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        let precommit = builder.read::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>();
        let decoded_precommit = builder.decode_precommit(precommit);
        builder.write::<U32Variable>(decoded_precommit.block_number);
        builder.write::<U64Variable>(decoded_precommit.authority_set_id);

        let circuit = builder.build();

        let mut input = circuit.input();

        let encoded_precommit = [
            1u8, 38, 27, 45, 113, 196, 242, 16, 36, 228, 137, 117, 93, 79, 157, 136, 222, 239, 71,
            241, 37, 152, 13, 194, 159, 190, 169, 38, 234, 124, 89, 223, 233, 161, 217, 4, 0, 75,
            58, 0, 0, 0, 0, 0, 0, 42, 1, 0, 0, 0, 0, 0, 0,
        ];

        let expected_block_number = 317857u32;
        let expected_authority_set_id = 298u64;

        input.write::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(encoded_precommit);

        let (proof, mut output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);

        let block_number = output.read::<U32Variable>();
        let authority_set_id = output.read::<U64Variable>();

        assert_eq!(block_number, expected_block_number);
        assert_eq!(authority_set_id, expected_authority_set_id);
    }
}
