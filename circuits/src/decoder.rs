use std::marker::PhantomData;

use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::challenger::RecursiveChallenger;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::util::serialization::{Buffer, IoResult};

use crate::utils::{
    AvailHashTarget, CircuitBuilderUtils, EncodedHeaderTarget, HASH_SIZE, MAX_HEADER_SIZE,
};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::{circuit_builder::CircuitBuilder, plonk_common::reduce_with_powers_circuit};

trait CircuitBuilderScaleDecoder {
    fn decode_compact_int(&mut self, compact_bytes: Vec<Target>) -> (Target, Target, Target);

    fn decode_fixed_int(&mut self, bytes: Vec<Target>, num_bytes: usize) -> Target;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderScaleDecoder
    for CircuitBuilder<F, D>
{
    fn decode_compact_int(&mut self, compact_bytes: Vec<Target>) -> (Target, Target, Target) {
        // For now, assume that compact_bytes is 5 bytes long
        assert!(compact_bytes.len() == 5);

        let bits = self.split_le(compact_bytes[0], 8);
        let compress_mode = self.le_sum(bits[0..2].iter());

        // Get all of the possible bytes that could be used to represent the compact int

        let zero_mode_value = compact_bytes[0];
        let alpha = self.constant(F::from_canonical_u16(256));
        let one_mode_value = reduce_with_powers_circuit(self, &compact_bytes[0..2], alpha);
        let two_mode_value = reduce_with_powers_circuit(self, &compact_bytes[0..4], alpha);
        let three_mode_value = reduce_with_powers_circuit(self, &compact_bytes[1..5], alpha);
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

    // WARNING !!!!
    // Note that this only works for fixed ints that are 64 bytes or less, since the goldilocks field is a little under 64 bytes.
    // So technically, it doesn't even work for 64 byte ints, but for now assume that all u64 values we encounter are less than
    // the goldilocks field size.
    fn decode_fixed_int(&mut self, bytes: Vec<Target>, value_byte_length: usize) -> Target {
        assert!(bytes.len() == value_byte_length);
        assert!(value_byte_length <= 64);

        let alpha = self.constant(F::from_canonical_u16(256));
        reduce_with_powers_circuit(self, &bytes, alpha)
    }
}

pub struct HeaderTarget {
    pub block_number: Target,
    pub parent_hash: AvailHashTarget,
    pub state_root: AvailHashTarget,
    pub data_root: AvailHashTarget,
}

pub trait CircuitBuilderHeaderDecoder {
    fn decode_header(
        &mut self,
        header: &EncodedHeaderTarget,
        header_hash: AvailHashTarget,
    ) -> HeaderTarget;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeaderDecoder
    for CircuitBuilder<F, D>
{
    fn decode_header(
        &mut self,
        header: &EncodedHeaderTarget,
        header_hash: AvailHashTarget,
    ) -> HeaderTarget {
        // The first 32 bytes are the parent hash
        let parent_hash_target = header.header_bytes[0..HASH_SIZE].to_vec();

        // Next field is the block number
        // Can need up to 5 bytes to represent a compact u32
        const MAX_BLOCK_NUMBER_SIZE: usize = 5;
        let (block_number_target, compress_mode, _) = self.decode_compact_int(
            header.header_bytes[HASH_SIZE..HASH_SIZE + MAX_BLOCK_NUMBER_SIZE].to_vec(),
        );

        let all_possible_state_roots = vec![
            AvailHashTarget(header.header_bytes[33..33 + HASH_SIZE].try_into().unwrap()),
            AvailHashTarget(header.header_bytes[34..34 + HASH_SIZE].try_into().unwrap()),
            AvailHashTarget(header.header_bytes[36..36 + HASH_SIZE].try_into().unwrap()),
            AvailHashTarget(header.header_bytes[37..37 + HASH_SIZE].try_into().unwrap()),
        ];

        let state_root_target =
            self.random_access_avail_hash(compress_mode, all_possible_state_roots);

        // Parse the data root field.
        // For this, we will use a generator to extract the data root field from the header bytes.
        // To verify that it is correct, we will use a method similar to reduce a row to a value
        // (https://wiki.polygon.technology/docs/miden/design/multiset#computing-a-virtual-tables-trace-column).
        // To retrieve the randomness, we use plonky2's recursive challenger seeding it with 3 elements of 56 bits from the header hash.
        // We do the verification twice to increase the security of it.
        let mut data_root_target = Vec::new();

        for _i in 0..HASH_SIZE {
            data_root_target.push(self.add_virtual_target());
        }

        self.add_simple_generator(DataRootFieldExtractor::<F, D> {
            encoded_header: header.clone(),
            data_root: data_root_target.as_slice().try_into().unwrap(),
            _marker: PhantomData,
        });

        let mut challenger = RecursiveChallenger::<F, PoseidonHash, D>::new(self);
        // Seed the challenger with 3 elements of 56 bits from the header hash.
        let mut seed = Vec::new();
        for i in 0..3 {
            let seed_bytes: [Target; 7] = header_hash.0[i * 7..i * 7 + 7].try_into().unwrap();

            // This code is splitting the bytes into bits and then recombining them into a 56 bit target.
            // TODO:  This can be done by just combining the bytes directly.
            let seed_bits = seed_bytes
                .iter()
                .flat_map(|t| self.split_le(*t, 8))
                .collect::<Vec<_>>();

            seed.push(self.le_sum(seed_bits.iter()));
        }

        challenger.observe_elements(&seed);

        for _i in 0..2 {
            let challenges = challenger.get_n_challenges(self, 32);
            let data_root_size = self.constant(F::from_canonical_usize(32));
            let data_root_start_idx = self.sub(header.header_size, data_root_size);
            let mut within_sub_array = self.zero();
            let one = self.one();

            let mut accumulator1 = self.zero();
            let mut j_target = self.zero();
            for j in 0..MAX_HEADER_SIZE {
                let at_start_idx = self.is_equal(j_target, data_root_start_idx);
                within_sub_array = self.add(within_sub_array, at_start_idx.target);
                let at_end_idx = self.is_equal(j_target, header.header_size);
                within_sub_array = self.sub(within_sub_array, at_end_idx.target);

                let mut subarray_idx = self.sub(j_target, data_root_start_idx);
                subarray_idx = self.mul(subarray_idx, within_sub_array);
                let challenge = self.random_access(subarray_idx, challenges.clone());
                let mut product = self.mul(header.header_bytes[j], challenge);
                product = self.mul(within_sub_array, product);
                accumulator1 = self.add(accumulator1, product);

                j_target = self.add(j_target, one);
            }

            let mut accumulator2 = self.zero();
            for j in 0..HASH_SIZE {
                let product = self.mul(data_root_target[j], challenges[j]);
                accumulator2 = self.add(accumulator2, product);
            }

            self.connect(accumulator1, accumulator2);
        }

        HeaderTarget {
            parent_hash: AvailHashTarget(parent_hash_target.try_into().unwrap()),
            block_number: block_number_target,
            state_root: state_root_target,
            data_root: AvailHashTarget(data_root_target.try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
struct DataRootFieldExtractor<F: RichField + Extendable<D>, const D: usize> {
    encoded_header: EncodedHeaderTarget,
    data_root: [Target; 32],
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for DataRootFieldExtractor<F, D>
{
    fn id(&self) -> String {
        "DataRootFieldExtractor".to_string()
    }

    fn serialize(
        &self,
        _dst: &mut Vec<u8>,
        _common_data: &CommonCircuitData<F, D>,
    ) -> IoResult<()> {
        unimplemented!();
    }

    fn deserialize(_src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        unimplemented!();
    }

    fn dependencies(&self) -> Vec<Target> {
        let mut dependencies = Vec::new();
        dependencies.extend(self.encoded_header.header_bytes.iter());
        dependencies.push(self.encoded_header.header_size);
        dependencies
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let header_length = witness
            .get_target(self.encoded_header.header_size)
            .to_canonical_u64() as usize;
        let data_root_start_idx = header_length - HASH_SIZE;

        for i in data_root_start_idx..data_root_start_idx + HASH_SIZE {
            let byte = witness.get_target(self.encoded_header.header_bytes[i]);
            out_buffer.set_target(self.data_root[i - data_root_start_idx], byte);
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedPrecommitTarget(pub Vec<Target>);

pub struct PrecommitTarget {
    pub block_hash: Vec<Target>, // Vector of 32 bytes
    pub block_number: Target,
    pub justification_round: Target,
    pub authority_set_id: Target,
}

pub trait CircuitBuilderPrecommitDecoder {
    fn decode_precommit(&mut self, precommit: EncodedPrecommitTarget) -> PrecommitTarget;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPrecommitDecoder
    for CircuitBuilder<F, D>
{
    fn decode_precommit(&mut self, precommit: EncodedPrecommitTarget) -> PrecommitTarget {
        // The first byte is the variant number and should be 1
        let one = self.one();
        self.connect(precommit.0[0], one);

        // The next 32 bytes is the block hash
        let block_hash = precommit.0[1..33].to_vec();

        // The next 4 bytes is the block number
        let block_number = self.decode_fixed_int(precommit.0[33..37].to_vec(), 4);

        // The next 8 bytes is the justification round
        let justification_round = self.decode_fixed_int(precommit.0[37..45].to_vec(), 8);

        // The next 8 bytes is the authority set id
        let authority_set_id = self.decode_fixed_int(precommit.0[45..53].to_vec(), 8);

        PrecommitTarget {
            block_hash,
            block_number,
            justification_round,
            authority_set_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::decoder::{
        CircuitBuilderHeaderDecoder, CircuitBuilderScaleDecoder, EncodedHeaderTarget,
    };
    use crate::utils::tests::{
        BLOCK_576728_BLOCK_HASH, BLOCK_576728_HEADER, BLOCK_576728_PARENT_HASH,
        BLOCK_576728_STATE_ROOT, BLOCK_576729_DATA_ROOT,
    };
    use crate::utils::{AvailHashTarget, CircuitBuilderUtils, MAX_HEADER_SIZE};
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    fn test_compact_int(
        encoded_bytes: [u8; 5],
        expected_int: u64,
        expected_compress_mode: u8,
        expected_length: u8,
    ) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut encoded_bytes_target = Vec::new();

        for byte in encoded_bytes.iter() {
            encoded_bytes_target.push(builder.constant(F::from_canonical_u8(*byte)));
        }

        let (decoded_int, compress_mode, length) = builder.decode_compact_int(encoded_bytes_target);

        let expected_int = builder.constant(F::from_canonical_u64(expected_int));
        builder.connect(decoded_int, expected_int);

        let expected_compress_mode = builder.constant(F::from_canonical_u8(expected_compress_mode));
        builder.connect(compress_mode, expected_compress_mode);

        let expected_length = builder.constant(F::from_canonical_u8(expected_length));
        builder.connect(length, expected_length);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_decode_compact_int_0() -> Result<()> {
        let encoded_bytes = [0u8; 5];
        let expected_value = 0;
        test_compact_int(encoded_bytes, expected_value, 0, 1)
    }

    #[test]
    fn test_decode_compact_int_1() -> Result<()> {
        let encoded_bytes = [4, 0, 0, 0, 0];
        let expected_value = 1;
        test_compact_int(encoded_bytes, expected_value, 0, 1)
    }

    #[test]
    fn test_decode_compact_int_64() -> Result<()> {
        let encoded_bytes = [1, 1, 0, 0, 0];
        let expected_value = 64;
        test_compact_int(encoded_bytes, expected_value, 1, 2)
    }

    #[test]
    fn test_decode_compact_int_65() -> Result<()> {
        let encoded_bytes = [5, 1, 0, 0, 0];
        let expected_value = 65;
        test_compact_int(encoded_bytes, expected_value, 1, 2)
    }

    #[test]
    fn test_decode_compact_int_16384() -> Result<()> {
        let encoded_bytes = [2, 0, 1, 0, 0];
        let expected_value = 16384;
        test_compact_int(encoded_bytes, expected_value, 2, 4)
    }

    #[test]
    fn test_decode_compact_int_1073741824() -> Result<()> {
        let encoded_bytes = [3, 0, 0, 0, 64];
        let expected_value = 1073741824;
        test_compact_int(encoded_bytes, expected_value, 3, 5)
    }

    #[test]
    fn test_decode_block() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut header_bytes_target = BLOCK_576728_HEADER
            .iter()
            .map(|b| builder.constant(F::from_canonical_u8(*b)))
            .collect::<Vec<_>>();
        let header_size = builder.constant(F::from_canonical_usize(BLOCK_576728_HEADER.len()));

        // pad the header bytes
        for _ in BLOCK_576728_HEADER.len()..MAX_HEADER_SIZE {
            header_bytes_target.push(builder.zero());
        }

        let block_hash = hex::decode(BLOCK_576728_BLOCK_HASH).unwrap();
        let block_hash_target = AvailHashTarget(
            block_hash
                .iter()
                .map(|b| builder.constant(F::from_canonical_u8(*b)))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let decoded_header = builder.decode_header(
            &EncodedHeaderTarget {
                header_bytes: header_bytes_target.try_into().unwrap(),
                header_size,
            },
            block_hash_target,
        );

        let expected_block_number = builder.constant(F::from_canonical_u64(576728));
        builder.connect(decoded_header.block_number, expected_block_number);

        let expected_parent_hash = hex::decode(BLOCK_576728_PARENT_HASH).unwrap();
        for (i, byte) in expected_parent_hash.iter().enumerate() {
            let expected_parent_hash_byte = builder.constant(F::from_canonical_u8(*byte));
            builder.connect(decoded_header.parent_hash.0[i], expected_parent_hash_byte);
        }

        let expected_state_root = hex::decode(BLOCK_576728_STATE_ROOT).unwrap();
        let expected_state_root_target = AvailHashTarget(
            expected_state_root
                .iter()
                .map(|b| builder.constant(F::from_canonical_u8(*b)))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let expected_data_root = hex::decode(BLOCK_576729_DATA_ROOT).unwrap();
        let expected_data_root_target = AvailHashTarget(
            expected_data_root
                .iter()
                .map(|b| builder.constant(F::from_canonical_u8(*b)))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        builder.connect_avail_hash(decoded_header.data_root, expected_data_root_target);

        builder.connect_avail_hash(decoded_header.state_root, expected_state_root_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }
}
