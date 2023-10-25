use std::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::witness::PartitionWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder as BaseCircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2x::frontend::vars::{EvmVariable, U32Variable};
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, RichField, Target, U64Variable, Variable, Witness, WitnessWrite,
};

use crate::consts::{DATA_ROOT_OFFSET_FROM_END, ENCODED_PRECOMMIT_LENGTH, HASH_SIZE};
use crate::vars::*;

#[derive(Debug)]
pub struct FloorDivGenerator<F: RichField + Extendable<D>, const D: usize> {
    divisor: Target,
    dividend: Target,
    quotient: Target,
    remainder: Target,
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> FloorDivGenerator<F, D> {
    pub fn id() -> String {
        "FloorDivGenerator".to_string()
    }
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for FloorDivGenerator<F, D>
{
    fn id(&self) -> String {
        Self::id()
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.divisor)?;
        dst.write_target(self.dividend)?;
        dst.write_target(self.quotient)?;
        dst.write_target(self.remainder)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let divisor = src.read_target()?;
        let dividend = src.read_target()?;
        let quotient = src.read_target()?;
        let remainder = src.read_target()?;
        Ok(Self {
            divisor,
            dividend,
            quotient,
            remainder,
            _marker: PhantomData,
        })
    }

    fn dependencies(&self) -> Vec<Target> {
        Vec::from([self.dividend])
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let divisor = witness.get_target(self.divisor);
        let dividend = witness.get_target(self.dividend);
        let divisor_int = divisor.to_canonical_u64() as u32;
        let dividend_int = dividend.to_canonical_u64() as u32;
        let quotient = dividend_int / divisor_int;
        let remainder = dividend_int % divisor_int;
        out_buffer.set_target(self.quotient, F::from_canonical_u32(quotient));
        out_buffer.set_target(self.remainder, F::from_canonical_u32(remainder));
    }
}

trait CircuitBuilderScaleDecoder {
    fn int_div(&mut self, dividend: Target, divisor: Target) -> Target;

    fn decode_compact_int(&mut self, compact_bytes: &[ByteVariable]) -> (Target, Target, Target);
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderScaleDecoder
    for BaseCircuitBuilder<F, D>
{
    fn int_div(&mut self, dividend: Target, divisor: Target) -> Target {
        let quotient = self.add_virtual_target();
        let remainder = self.add_virtual_target();

        self.add_simple_generator(FloorDivGenerator::<F, D> {
            divisor,
            dividend,
            quotient,
            remainder,
            _marker: PhantomData,
        });
        let base = self.mul(quotient, divisor);
        let rhs = self.add(base, remainder);
        let is_equal = self.is_equal(rhs, dividend);
        self.assert_one(is_equal.target);
        quotient
    }

    /// TODO: Rewrite with CircuitVariable, follow this: https://docs.substrate.io/reference/scale-codec/#fn-1
    fn decode_compact_int(&mut self, compact_bytes: &[ByteVariable]) -> (Target, Target, Target) {
        // For now, assume that compact_bytes is 5 bytes long
        assert!(compact_bytes.len() == 5);

        let mut first_byte_bool_targets = compact_bytes[0].as_bool_targets();
        first_byte_bool_targets.reverse();

        let compress_mode = self.le_sum(first_byte_bool_targets[0..2].iter());

        // Get all of the possible bytes that could be used to represent the compact int

        let zero_mode_value = to_variable_unsafe(self, &compact_bytes[0..1]).0;
        let one_mode_value = to_variable_unsafe(self, &compact_bytes[0..2]).0;
        let two_mode_value = to_variable_unsafe(self, &compact_bytes[0..4]).0;
        let three_mode_value = to_variable_unsafe(self, &compact_bytes[1..5]).0;
        let value = self.random_access(
            compress_mode,
            vec![
                zero_mode_value,
                one_mode_value,
                two_mode_value,
                three_mode_value,
            ],
        );

        // Will need to divide by 4 (remove least 2 significnat bits) for mode 0, 1, 2.  Those bits stores the encoding mode
        let three = self.constant(F::from_canonical_u8(3));
        let is_eq_three = self.is_equal(compress_mode, three);
        let div_by_4 = self.not(is_eq_three);

        let four = self.constant(F::from_canonical_u8(4));
        let value_div_4 = self.int_div(value, four);

        let decoded_int = self.select(div_by_4, value_div_4, value);

        let five = self.constant(F::from_canonical_u8(5));
        let one = self.one();
        let two = self.two();
        let encoded_byte_length = self.random_access(compress_mode, vec![one, two, four, five]);

        (decoded_int, compress_mode, encoded_byte_length)
    }
}

pub trait DecodingMethods {
    fn decode_headers<const S: usize, const N: usize>(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<S>, N>,
        header_hashes: &ArrayVariable<Bytes32Variable, N>,
    ) -> ArrayVariable<HeaderVariable, N>;

    fn decode_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
        header_hash: &Bytes32Variable,
    ) -> HeaderVariable;

    fn decode_precommit(
        &mut self,
        encoded_precommit: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    ) -> PrecommitVariable;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<L: PlonkParameters<D>, const D: usize> DecodingMethods for CircuitBuilder<L, D> {
    // Decode an array of headers into their components. header_hashes are used for the RLC challenge.
    fn decode_headers<const S: usize, const N: usize>(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<S>, N>,
        header_hashes: &ArrayVariable<Bytes32Variable, N>,
    ) -> ArrayVariable<HeaderVariable, N> {
        headers
            .as_vec()
            .iter()
            .zip(header_hashes.as_vec().iter())
            .map(|(header, header_hash)| self.decode_header::<S>(header, header_hash))
            .collect::<Vec<HeaderVariable>>()
            .try_into()
            .unwrap()
    }

    /// Decode a header into its components. header_hash is used for the RLC challenge.
    /// TODO: Use EvmVariable types with decode instead of targets!
    fn decode_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
        header_hash: &Bytes32Variable,
    ) -> HeaderVariable {
        // The first 32 bytes are the parent hash
        let parent_hash: Bytes32Variable = header.header_bytes[0..HASH_SIZE].into();

        // Next field is the block number
        // Can need up to 5 bytes to represent a compact u32
        const MAX_BLOCK_NUMBER_SIZE: usize = 5;
        let (block_number_target, compress_mode, _) = self
            .api
            .decode_compact_int(&header.header_bytes[HASH_SIZE..HASH_SIZE + MAX_BLOCK_NUMBER_SIZE]);

        let all_possible_state_roots = vec![
            Bytes32Variable::from(&header.header_bytes[33..33 + HASH_SIZE]),
            Bytes32Variable::from(&header.header_bytes[34..34 + HASH_SIZE]),
            // TODO: why is 35 missing here
            Bytes32Variable::from(&header.header_bytes[36..36 + HASH_SIZE]),
            Bytes32Variable::from(&header.header_bytes[37..37 + HASH_SIZE]),
        ];

        let state_root =
            self.select_array_random_gate(&all_possible_state_roots, Variable(compress_mode));

        // Need the convert the encoded header header bytes into an array of variables.
        // The byte variable array representation is in bits, and that significantly increases the
        // number of contraints needed for get_fixed_subarray.

        let header_variables = header
            .header_bytes
            .as_vec()
            .iter()
            .map(|x: &ByteVariable| x.to_variable(self))
            .collect::<Vec<_>>();

        let data_root_offset =
            self.constant(L::Field::from_canonical_usize(DATA_ROOT_OFFSET_FROM_END)); // Since we're working with bits

        let mut data_root_start = self.sub(header.header_size, data_root_offset);

        // If header_size == 0, then set data_root_start to 0
        let header_is_zero_size = self.is_zero(header.header_size);
        let zero = self.zero();
        data_root_start = self.select(header_is_zero_size, zero, data_root_start);

        let data_root_variables: Vec<Variable> = self
            .get_fixed_subarray::<S, HASH_SIZE>(
                &ArrayVariable::<Variable, S>::from(header_variables),
                data_root_start,
                &header_hash.as_bytes()[0..15], // Seed the challenger with the first 15 bytes (120 bits) of the header hash
            )
            .as_vec();

        let data_root_byte_vars = data_root_variables
            .iter()
            .map(|x| ByteVariable::from_target(self, x.0))
            .collect::<Vec<_>>();

        let data_root = Bytes32Variable::from(data_root_byte_vars.as_slice());

        HeaderVariable {
            block_number: U32Variable::from_variables_unsafe(&[Variable(block_number_target)]), // TODO: do we need to do a range-check here?
            parent_hash,
            state_root,
            data_root,
        }
    }

    /// Decode a precommit message into its components.
    fn decode_precommit(
        &mut self,
        precommit: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    ) -> PrecommitVariable {
        // The first byte is the varint number and should be 1.
        let one = self.one();
        let precommit_first_byte = precommit[0].to_variable(self);
        self.assert_is_equal(precommit_first_byte, one);

        // The next 32 bytes is the block hash.
        let block_hash: Bytes32Variable = precommit[1..33].into();

        // The next 4 bytes is the block number.
        let mut block_number_bytes = precommit[33..37].to_vec();
        // Need to reverse the bytes since the block number is little endian.
        block_number_bytes.reverse();
        let block_number = U32Variable::decode(self, &block_number_bytes);

        // The next 8 bytes is the justification round.
        let mut justification_round_bytes = precommit[37..45].to_vec();
        // Need to reverse the bytes since the justification round is little endian.
        justification_round_bytes.reverse();
        let justification_round = U64Variable::decode(self, &precommit[37..45]);

        // The next 8 bytes is the authority set id.
        let mut authority_set_id_bytes = precommit[45..53].to_vec();
        // Need to reverse the bytes since the authority set id is little endian.
        authority_set_id_bytes.reverse();
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

    use plonky2x::frontend::vars::U32Variable;
    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, BytesVariable, DefaultBuilder, Field, GoldilocksField,
        U64Variable,
    };
    use plonky2x::utils::{bytes, bytes32};
    use testing_utils::tests::{
        BLOCK_HASHES, ENCODED_HEADERS, HEAD_BLOCK_NUM, NUM_BLOCKS, PARENT_HASHES,
    };

    use super::DecodingMethods;
    use crate::consts::{ENCODED_PRECOMMIT_LENGTH, MAX_HEADER_SIZE};
    use crate::testing_utils;
    use crate::testing_utils::tests::{DATA_ROOTS, STATE_ROOTS};
    use crate::vars::{EncodedHeader, EncodedHeaderVariable};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_decode_headers() {
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
            let decoded_header =
                builder.decode_header::<MAX_HEADER_SIZE>(&encoded_headers[i], &header_hashes[i]);

            builder.assert_is_equal(decoded_header.block_number, expected_header_nums[i]);
            builder.assert_is_equal(decoded_header.parent_hash, expected_parent_hashes[i]);
            builder.assert_is_equal(decoded_header.state_root, expected_state_roots[i]);
            builder.assert_is_equal(decoded_header.data_root, expected_data_roots[i]);
        }

        let circuit = builder.build();

        let mut input = circuit.input();
        let encoded_headers_values: Vec<EncodedHeader<MAX_HEADER_SIZE, F>> = ENCODED_HEADERS
            [0..NUM_BLOCKS]
            .iter()
            .map(|x| {
                let mut header: Vec<u8> = bytes!(x);
                let header_len = header.len();
                header.resize(MAX_HEADER_SIZE, 0);
                EncodedHeader {
                    header_bytes: header.as_slice().try_into().unwrap(),
                    header_size: F::from_canonical_u64(header_len as u64),
                }
            })
            .collect::<_>();

        input.write::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_BLOCKS>>(
            encoded_headers_values,
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            BLOCK_HASHES[0..NUM_BLOCKS]
                .iter()
                .map(|x| bytes32!(x))
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<U32Variable, NUM_BLOCKS>>(
            (HEAD_BLOCK_NUM..HEAD_BLOCK_NUM + NUM_BLOCKS as u32).collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            PARENT_HASHES[0..NUM_BLOCKS]
                .iter()
                .map(|x| bytes32!(x))
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            STATE_ROOTS[0..NUM_BLOCKS]
                .iter()
                .map(|x| bytes32!(x))
                .collect::<Vec<_>>(),
        );

        input.write::<ArrayVariable<Bytes32Variable, NUM_BLOCKS>>(
            DATA_ROOTS[0..NUM_BLOCKS]
                .iter()
                .map(|x| bytes32!(x))
                .collect::<Vec<_>>(),
        );

        let (proof, output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
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

        input.write::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(encoded_precommit);

        let (proof, mut output) = circuit.prove(&input);

        circuit.verify(&proof, &input, &output);

        let block_number = output.read::<U32Variable>();
        let authority_set_id = output.read::<U64Variable>();
        println!("block_number: {:?}", block_number);
        println!("authority_set_id: {:?}", authority_set_id);
    }
}
