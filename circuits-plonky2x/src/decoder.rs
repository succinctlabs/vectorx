use std::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::witness::PartitionWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder as BaseCircuitBuilder;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::plonk_common::reduce_with_powers_circuit;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, GoldilocksField, PlonkParameters, RichField, Target, Variable, Witness, WitnessWrite,
};

use crate::vars::*;

const DATA_ROOT_OFFSET_FROM_END: usize = 132;

#[derive(Debug)]
struct FloorDivGenerator<F: RichField + Extendable<D>, const D: usize> {
    divisor: Target,
    dividend: Target,
    quotient: Target,
    remainder: Target,
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for FloorDivGenerator<F, D>
{
    fn id(&self) -> String {
        "FloorDivGenerator".to_string()
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
    fn decoded_headers<const S: usize, const N: usize>(
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
    // Assumes that header and header_hash are properly linked already
    // header_hash is only used for the RLC challenge
    fn decoded_headers<const S: usize, const N: usize>(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<S>, N>,
        header_hashes: &ArrayVariable<Bytes32Variable, N>,
    ) -> ArrayVariable<HeaderVariable, N> {
        headers
            .as_vec()
            .iter()
            .zip(header_hashes.as_vec().iter())
            .map(|(header, header_hash)| self.decode_header(header, header_hash))
            .collect::<Vec<HeaderVariable>>()
            .try_into()
            .unwrap()
    }

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

        // Parse the data root field.
        // For this, we will use a generator to extract the data root field from the header bytes.
        // To verify that it is correct, we will use a method similar to reduce a row to a value
        // (https://wiki.polygon.technology/docs/miden/design/multiset#computing-a-virtual-tables-trace-column).
        // To retrieve the randomness, we use plonky2's recursive challenger seeding it with 3 elements of 56 bits from the header hash.
        // We do the verification twice to increase the security of it.
        let data_root_offset =
            self.constant(L::Field::from_canonical_usize(DATA_ROOT_OFFSET_FROM_END)); // Since we're working with bits
        let data_root_start = self.sub(header.header_size, data_root_offset);
        let eight = self.constant(L::Field::from_canonical_u8(8));
        let data_root_start_bits = self.mul(data_root_start, eight);
        // TODO: use header_hash to seed the challenger in get_fixed_subarray
        let data_root_variables: Vec<Variable> = self
            .get_fixed_subarray::<HASH_SIZE_BITS>(
                &header.header_bytes.variables(),
                data_root_start_bits,
            )
            .as_vec();
        let data_root = Bytes32Variable::from_variables_unsafe(&data_root_variables);

        HeaderVariable {
            block_number: U32Variable(Variable(block_number_target)), // TODO: do we need to do a range-check here?
            parent_hash,
            state_root,
            data_root,
        }
    }

    fn decode_precommit(
        &mut self,
        precommit: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    ) -> PrecommitVariable {
        // TODO: when we have seamless conversion between BytesVariable and U32/U64 variables, use those instead

        // The first byte is the variant number and should be 1
        let one = self.one::<Variable>();
        let precommit_first_byte = to_variable(&mut self.api, precommit[0]);
        self.assert_is_equal(precommit_first_byte, one);

        // The next 32 bytes is the block hash
        let block_hash: Bytes32Variable = precommit[1..33].into();

        // The next 4 bytes is the block number
        let block_number = to_variable_unsafe(&mut self.api, &precommit[33..37]);

        // The next 8 bytes is the justification round
        let justification_round = to_variable_unsafe(&mut self.api, &precommit[37..45]);

        // The next 8 bytes is the authority set id
        let authority_set_id = to_variable_unsafe(&mut self.api, &precommit[45..53]);

        // It's okay that we're not range checking any of these because the inputs to this function are range-checked
        PrecommitVariable {
            block_hash,
            block_number: U32Variable(block_number),
            justification_round,
            authority_set_id,
        }
    }
}