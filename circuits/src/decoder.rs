use crate::utils::{AvailHashTarget, CircuitBuilderUtils, EncodedHeaderTarget, HASH_SIZE};
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::{hash::hash_types::RichField, plonk::plonk_common::reduce_with_powers_circuit};
use plonky2_field::extension::Extendable;

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
    // pub data_root: HashTarget,
}

pub trait CircuitBuilderHeaderDecoder {
    fn decode_header(&mut self, header: &EncodedHeaderTarget) -> HeaderTarget;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeaderDecoder
    for CircuitBuilder<F, D>
{
    fn decode_header(&mut self, header: &EncodedHeaderTarget) -> HeaderTarget {
        // The first 32 bytes are the parent hash
        let parent_hash_target = header.header_bytes[0..32].to_vec();

        // Next field is the block number
        // Can need up to 5 bytes to represent a compact u32
        const MAX_BLOCK_NUMBER_SIZE: usize = 5;
        let (block_number_target, compress_mode, _) =
            self.decode_compact_int(header.header_bytes[32..32 + MAX_BLOCK_NUMBER_SIZE].to_vec());

        let all_possible_state_roots = vec![
            header.header_bytes[33..33 + HASH_SIZE].to_vec(),
            header.header_bytes[34..34 + HASH_SIZE].to_vec(),
            header.header_bytes[36..36 + HASH_SIZE].to_vec(),
            header.header_bytes[37..37 + HASH_SIZE].to_vec(),
        ];

        let state_root_target = self.random_access_vec(compress_mode, &all_possible_state_roots);

        // Can't get this to work yet.  Getting an error with the random_access gate
        /*
        let mut all_possible_data_roots = Vec::new();

        // 97 bytes is the minimum total size of all the header's fields before the data root
        const DATA_ROOT_MIN_START_IDX: usize = 97;
        for start_idx in DATA_ROOT_MIN_START_IDX..MAX_HEADER_SIZE - HASH_SIZE {
            all_possible_data_roots.push(header.header_bytes[start_idx..start_idx+HASH_SIZE].to_vec());
        }

        // Need to pad all_possible_data_roots to be length of a power of 2
        let min_power_of_2 = ((MAX_HEADER_SIZE - HASH_SIZE) as f32).log2().ceil() as usize;
        let all_possible_data_roots_size = 2usize.pow(min_power_of_2 as u32);
        for _ in all_possible_data_roots.len()..all_possible_data_roots_size {
            all_possible_data_roots.push(vec![self.zero(); HASH_SIZE]);
        }

        let data_root_min_idx = self.constant(F::from_canonical_usize(DATA_ROOT_MIN_START_IDX));
        let data_root_idx = self.sub(header.header_size, data_root_min_idx);

        let data_root_target = self.random_access_vec(data_root_idx, all_possible_data_roots);
        */

        HeaderTarget {
            parent_hash: AvailHashTarget(parent_hash_target.try_into().unwrap()),
            block_number: block_number_target,
            state_root: AvailHashTarget(state_root_target.try_into().unwrap()),
            //data_root: HashTarget(data_root_target.try_into().unwrap()),
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
    use std::fs;

    use crate::decoder::{
        CircuitBuilderHeaderDecoder, CircuitBuilderScaleDecoder, EncodedHeaderTarget,
    };
    use crate::plonky2_config::PoseidonBN128GoldilocksConfig;
    use crate::utils::tests::{
        BLOCK_576728_HEADER, BLOCK_576728_PARENT_HASH, BLOCK_576728_STATE_ROOT,
    };
    use crate::utils::{AvailHashTarget, CircuitBuilderUtils, HASH_SIZE, MAX_HEADER_SIZE};
    use anyhow::Result;
    use log::Level;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::prover::prove;
    use plonky2::util::serialization::DefaultGateSerializer;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::types::Field;
    use plonky2lib_succinct::hash_functions::blake2b::make_blake2b_circuit;

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
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let mut header_bytes_target = BLOCK_576728_HEADER
            .iter()
            .map(|b| builder.constant(F::from_canonical_u8(*b)))
            .collect::<Vec<_>>();
        let header_size = builder.constant(F::from_canonical_usize(BLOCK_576728_HEADER.len()));

        // pad the header bytes
        for _ in BLOCK_576728_HEADER.len()..MAX_HEADER_SIZE {
            header_bytes_target.push(builder.zero());
        }

        let decoded_header = builder.decode_header(&EncodedHeaderTarget {
            header_bytes: header_bytes_target.try_into().unwrap(),
            header_size,
        });

        let expected_block_number = builder.constant(F::from_canonical_u64(576728));
        builder.connect(decoded_header.block_number, expected_block_number);

        let expected_parent_hash = hex::decode(BLOCK_576728_PARENT_HASH).unwrap();
        for i in 0..expected_parent_hash.len() {
            let expected_parent_hash_byte =
                builder.constant(F::from_canonical_u8(expected_parent_hash[i]));
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

        builder.connect_hash(decoded_header.state_root, expected_state_root_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof.clone()).unwrap();

        let mut outer_builder = CircuitBuilder::<F, D>::new(config);
        let inner_proof_target = outer_builder.add_virtual_proof_with_pis(&data.common);
        let inner_verifier_data =
            outer_builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&inner_proof_target, &inner_verifier_data, &data.common);

        let outer_data = outer_builder.build::<C>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&inner_proof_target, &proof);
        outer_pw.set_verifier_data_target(&inner_verifier_data, &data.verifier_only);

        let outer_proof = outer_data.prove(outer_pw).unwrap();

        outer_data.verify(outer_proof.clone()).unwrap();

        let mut final_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let final_proof_target = final_builder.add_virtual_proof_with_pis(&outer_data.common);
        let final_verifier_data =
            final_builder.add_virtual_verifier_data(outer_data.common.config.fri_config.cap_height);
        final_builder.verify_proof::<C>(
            &final_proof_target,
            &final_verifier_data,
            &outer_data.common,
        );

        let final_data = final_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut final_pw = PartialWitness::new();
        final_pw.set_proof_with_pis_target(&final_proof_target, &outer_proof);
        final_pw.set_verifier_data_target(&final_verifier_data, &outer_data.verifier_only);

        let mut timing = TimingTree::new("prove", Level::Debug);
        let final_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(
            &final_data.prover_only,
            &final_data.common,
            final_pw,
            &mut timing,
        )
        .unwrap();
        timing.print();

        final_data.verify(final_proof.clone()).unwrap();

        // Serialize the final proof's artifacts to json (to be used by the gnark plonky2 verifier)
        let final_proof_serialized = serde_json::to_string(&final_proof).unwrap();
        fs::write(
            "final.proof_with_public_inputs.json",
            final_proof_serialized,
        )
        .expect("Unable to write file");

        let final_vd_serialized = serde_json::to_string(&final_data.verifier_only).unwrap();
        fs::write("final.verifier_only_circuit_data.json", final_vd_serialized)
            .expect("Unable to write file");

        let final_cd_serialized = serde_json::to_string(&final_data.common).unwrap();
        fs::write("final.common_circuit_data.json", final_cd_serialized)
            .expect("Unable to write file");

        // Serialize the final proof into byts (to be used by the plonky2 verifier)
        let final_proof_bytes = final_proof.to_bytes();
        fs::write("final.proof_with_public_inputs.bytes", final_proof_bytes)
            .expect("Unable to write file");

        let final_vd_bytes = final_data.verifier_only.to_bytes().unwrap();
        fs::write("final.verifier_only_circuit_data.bytes", final_vd_bytes)
            .expect("Unable to write file");

        let gate_serializer = DefaultGateSerializer;
        let final_cd_bytes = final_data.common.to_bytes(&gate_serializer).unwrap();

        fs::write("final.common_circuit_data.bytes", final_cd_bytes).expect("Unable to write file");

        Ok(())
    }

    #[test]
    fn test_operator_decode_test_case() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let test_header = [
            167, 234, 10, 89, 188, 85, 75, 118, 29, 8, 78, 168, 217, 39, 212, 213, 225, 154, 124,
            81, 31, 192, 42, 102, 206, 139, 77, 0, 115, 152, 129, 225, 66, 35, 6, 0, 178, 77, 240,
            37, 173, 94, 159, 149, 164, 248, 179, 185, 203, 221, 73, 131, 154, 216, 238, 33, 232,
            155, 53, 41, 247, 172, 230, 190, 1, 151, 192, 110, 110, 248, 213, 1, 97, 196, 222, 147,
            6, 140, 47, 232, 216, 80, 110, 88, 243, 135, 187, 16, 147, 229, 47, 36, 139, 47, 80,
            255, 101, 144, 70, 53, 8, 6, 66, 65, 66, 69, 181, 1, 3, 26, 0, 0, 0, 19, 231, 7, 5, 0,
            0, 0, 0, 250, 51, 3, 12, 136, 121, 100, 77, 103, 74, 51, 15, 10, 24, 77, 55, 152, 4,
            59, 227, 246, 155, 107, 186, 50, 79, 72, 134, 47, 14, 199, 66, 103, 12, 255, 225, 138,
            108, 175, 246, 176, 241, 187, 38, 47, 27, 235, 78, 158, 215, 113, 141, 179, 8, 196,
            163, 119, 78, 102, 233, 32, 46, 110, 13, 138, 243, 56, 63, 75, 8, 247, 92, 200, 39,
            113, 34, 155, 1, 106, 143, 153, 18, 95, 241, 162, 65, 200, 6, 27, 31, 102, 94, 66, 172,
            216, 4, 5, 66, 65, 66, 69, 1, 1, 226, 60, 5, 243, 97, 252, 63, 163, 203, 198, 91, 169,
            221, 77, 125, 17, 212, 140, 122, 28, 246, 102, 181, 107, 159, 176, 219, 232, 249, 207,
            120, 114, 59, 73, 121, 218, 199, 121, 67, 74, 215, 54, 31, 203, 86, 20, 10, 157, 158,
            204, 126, 136, 209, 27, 254, 175, 10, 117, 60, 191, 23, 84, 182, 135, 0, 4, 64, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 129, 1, 149, 144, 69, 78, 245, 222, 126, 35, 80, 67, 248, 81, 44, 175, 104, 26, 174,
            5, 242, 143, 213, 95, 10, 118, 7, 124, 234, 215, 137, 167, 208, 101, 212, 73, 15, 159,
            106, 210, 176, 195, 45, 42, 202, 73, 232, 141, 4, 246, 149, 144, 69, 78, 245, 222, 126,
            35, 80, 67, 248, 81, 44, 175, 104, 26, 174, 5, 242, 143, 213, 95, 10, 118, 7, 124, 234,
            215, 137, 167, 208, 101, 212, 73, 15, 159, 106, 210, 176, 195, 45, 42, 202, 73, 232,
            141, 4, 246, 60, 0,
        ]
        .to_vec();

        let mut header_bytes_target = test_header
            .iter()
            .map(|b| builder.constant(F::from_canonical_u8(*b)))
            .collect::<Vec<_>>();
        let header_size = builder.constant(F::from_canonical_usize(test_header.len()));

        // pad the header bytes
        for _ in test_header.len()..MAX_HEADER_SIZE {
            header_bytes_target.push(builder.zero());
        }

        let decoded_header = builder.decode_header(&EncodedHeaderTarget {
            header_bytes: header_bytes_target.try_into().unwrap(),
            header_size,
        });

        let expected_block_number = builder.constant(F::from_canonical_u64(100560));
        builder.connect(decoded_header.block_number, expected_block_number);

        let expected_parent_hash =
            hex::decode("a7ea0a59bc554b761d084ea8d927d4d5e19a7c511fc02a66ce8b4d00739881e1")
                .unwrap();
        for i in 0..expected_parent_hash.len() {
            let expected_parent_hash_byte =
                builder.constant(F::from_canonical_u8(expected_parent_hash[i]));
            builder.connect(decoded_header.parent_hash.0[i], expected_parent_hash_byte);
        }

        let expected_state_root =
            hex::decode("b24df025ad5e9f95a4f8b3b9cbdd49839ad8ee21e89b3529f7ace6be0197c06e")
                .unwrap();
        let expected_state_root_target = AvailHashTarget(
            expected_state_root
                .iter()
                .map(|b| builder.constant(F::from_canonical_u8(*b)))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        builder.connect_hash(decoded_header.state_root, expected_state_root_target);

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof.clone())
    }

    #[test]
    fn test_operator_public_inputs_hash() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let public_inputs_hash_circuit = make_blake2b_circuit(&mut builder, 512 * 8, HASH_SIZE);

        let public_inputs_bytes = [
            54, 115, 158, 107, 120, 233, 121, 250, 121, 187, 210, 98, 170, 57, 7, 75, 254, 120,
            126, 248, 152, 207, 92, 73, 73, 95, 107, 230, 34, 1, 57, 35, 0, 1, 136, 203, 84, 237,
            215, 115, 162, 42, 57, 31, 147, 17, 71, 206, 121, 44, 35, 57, 28, 205, 32, 248, 148,
            145, 75, 53, 164, 121, 116, 249, 232, 103, 203, 75, 0, 0, 0, 0, 0, 0, 0, 94, 126, 114,
            94, 23, 162, 130, 71, 71, 55, 66, 114, 81, 125, 20, 205, 17, 7, 52, 135, 19, 162, 175,
            199, 112, 140, 249, 118, 31, 100, 202, 167, 91, 110, 200, 76, 124, 73, 75, 0, 3, 21,
            170, 7, 121, 42, 201, 131, 173, 74, 209, 53, 202, 155, 147, 36, 135, 194, 245, 139,
            117, 216, 8, 184, 170, 242, 100, 119, 170, 241, 248, 151, 221, 7, 153, 28, 136, 150,
            48, 162, 87, 119, 175, 247, 21, 63, 141, 167, 203, 28, 32, 49, 67, 239, 69, 50, 131,
            64, 195, 182, 92, 199, 22, 38, 83, 132, 193, 225, 54, 249, 233, 118, 114, 20, 57, 227,
            75, 162, 44, 131, 53, 55, 25, 193, 236, 56, 187, 248, 134, 140, 24, 33, 178, 125, 199,
            11, 17, 181, 53, 39, 18, 196, 229, 36, 200, 247, 10, 159, 13, 144, 64, 5, 33, 246, 39,
            87, 196, 81, 182, 193, 87, 112, 124, 39, 106, 46, 165, 89, 190, 159, 103, 121, 212,
            218, 235, 206, 55, 174, 151, 242, 70, 197, 163, 141, 125, 167, 75, 29, 20, 132, 243,
            125, 78, 131, 88, 247, 204, 159, 253, 88, 233, 31, 61, 158, 5, 10, 86, 74, 65, 254,
            126, 82, 133, 127, 9, 235, 49, 117, 120, 171, 34, 102, 142, 67, 32, 167, 234, 10, 89,
            188, 85, 75, 118, 29, 8, 78, 168, 217, 39, 212, 213, 225, 154, 124, 81, 31, 192, 42,
            102, 206, 139, 77, 0, 115, 152, 129, 225, 178, 77, 240, 37, 173, 94, 159, 149, 164,
            248, 179, 185, 203, 221, 73, 131, 154, 216, 238, 33, 232, 155, 53, 41, 247, 172, 230,
            190, 1, 151, 192, 110, 221, 226, 250, 11, 92, 6, 148, 162, 108, 157, 22, 56, 188, 154,
            11, 226, 175, 133, 94, 113, 173, 18, 197, 114, 50, 88, 224, 126, 221, 137, 28, 193,
        ]
        .to_vec();
        let public_inputs_hash_input = public_inputs_bytes
            .iter()
            .flat_map(|byte| {
                let constant_target = builder.constant(F::from_canonical_u8(*byte));
                let mut bits = builder.split_le(constant_target, 8);
                bits.reverse();
                bits
            })
            .collect::<Vec<_>>();

        for (i, bit) in public_inputs_hash_input.iter().enumerate() {
            builder.connect(bit.target, public_inputs_hash_circuit.message[i].target);
        }

        // Add the padding
        let zero = builder.zero();
        for i in public_inputs_hash_input.len()..512 * 8 {
            builder.connect(zero, public_inputs_hash_circuit.message[i].target);
        }

        let public_inputs_input_size =
            builder.constant(F::from_canonical_usize(public_inputs_hash_input.len() / 8));
        builder.connect(
            public_inputs_hash_circuit.message_len,
            public_inputs_input_size,
        );

        let expected_hash =
            hex::decode("955ea4da0455d7128a46513a69231698994b366c8215beb7aed562b166dcc656")
                .unwrap()
                .iter()
                .map(|byte| builder.constant(F::from_canonical_u8(*byte)))
                .collect::<Vec<_>>();

        // Verify that the public input hash matches
        for i in 0..HASH_SIZE {
            let mut bits = builder.split_le(expected_hash[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                builder.connect(
                    public_inputs_hash_circuit.digest[i * 8 + j].target,
                    bit.target,
                );
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof.clone())
    }

    #[test]
    fn test_auth_set_hash() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let input_padding = 512;
        let hash_circuit = make_blake2b_circuit(&mut builder, 10 * 256 + input_padding, HASH_SIZE);

        let auth_set_bytes = [2, 248, 6, 149, 240, 164, 162, 48, 130, 70, 200, 129, 52, 178, 222, 117, 158, 52, 125, 82, 113, 137, 116, 45, 212, 46, 152, 114, 75, 213, 169, 188, 9, 32, 5, 166, 247, 165, 138, 152, 223, 95, 155, 141, 24, 107, 152, 119, 241, 43, 96, 58, 160, 108, 125, 235, 240, 246, 16, 213, 164, 159, 158, 215, 10, 151, 143, 214, 89, 198, 148, 72, 39, 62, 53, 85, 78, 33, 186, 195, 84, 88, 254, 43, 25, 159, 139, 143, 184, 26, 100, 136, 238, 153, 199, 52, 38, 43, 94, 9, 91, 48, 154, 242, 176, 234, 225, 197, 84, 224, 59, 108, 196, 165, 160, 223, 32, 123, 102, 43, 50, 150, 35, 242, 127, 220, 232, 208, 41, 16, 221, 236, 124, 81, 178, 234, 180, 217, 104, 49, 168, 185, 232, 74, 66, 206, 189, 173, 174, 98, 189, 234, 38, 202, 123, 12, 100, 14, 138, 33, 55, 188, 151, 23, 201, 155, 231, 101, 245, 89, 141, 25, 147, 251, 91, 194, 253, 95, 182, 140, 189, 129, 121, 91, 92, 3, 71, 47, 13, 192, 36, 161, 68, 132, 228, 52, 110, 176, 184, 148, 241, 72, 35, 77, 217, 236, 115, 106, 45, 55, 196, 40, 174, 25, 27, 131, 89, 237, 155, 3, 176, 246, 1, 125, 248, 108, 114, 39, 126, 210, 14, 254, 21, 186, 177, 171, 207, 52, 101, 110, 125, 35, 54, 228, 33, 51, 250, 153, 51, 30, 135, 75, 84, 88, 178, 143, 152, 68, 130, 180, 141, 53, 108, 232, 226, 153, 38, 139, 16, 12, 97, 169, 186, 95, 150, 167, 87, 207, 152, 21, 6, 131, 163, 232, 170, 133, 72, 74, 77, 48, 168, 172, 184, 141, 43, 194, 177, 174, 70, 165, 231, 96, 206, 66, 51, 192, 187, 156, 3, 165, 116, 34, 0, 157, 108, 44, 208, 179, 54, 122]
        .to_vec();

        let auth_set_bits = auth_set_bytes
            .iter()
            .flat_map(|byte| {
                let constant_target = builder.constant(F::from_canonical_u8(*byte));
                let mut bits = builder.split_le(constant_target, 8);
                bits.reverse();
                bits
            })
            .collect::<Vec<_>>();

        for (i, bit) in auth_set_bits.iter().enumerate() {
            builder.connect(bit.target, hash_circuit.message[i].target);
        }

        // Add the padding
        let zero = builder.zero();
        for i in auth_set_bits.len()..(10 * 256 + input_padding) {
            builder.connect(zero, hash_circuit.message[i].target);
        }

        let auth_set_size =
            builder.constant(F::from_canonical_usize(auth_set_bits.len() / 8));
        builder.connect(
            hash_circuit.message_len,
            auth_set_size,
        );

        let expected_hash =
            hex::decode("8e6866fa26ff254cdb0c2d7adf78b551a108770400317886aeb22f90556edeb9")
                .unwrap()
                .iter()
                .map(|byte| builder.constant(F::from_canonical_u8(*byte)))
                .collect::<Vec<_>>();

        // Verify that the public input hash matches
        for i in 0..HASH_SIZE {
            let mut bits = builder.split_le(expected_hash[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                builder.connect(
                    hash_circuit.digest[i * 8 + j].target,
                    bit.target,
                );
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof.clone())
    }
}
