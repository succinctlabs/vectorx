use plonky2::{hash::hash_types::RichField, plonk::plonk_common::reduce_with_powers_circuit};
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use crate::utils::{ CircuitBuilderUtils, HASH_SIZE, MAX_HEADER_SIZE };

trait CircuitBuilderScaleDecoder {
    fn decode_compact_int(
        &mut self,
        compact_bytes: Vec<Target>,
    ) -> (Target, Target, Target);

    fn decode_fixed_int(
        &mut self,
        bytes: Vec<Target>,
        num_bytes: usize,
    ) -> Target;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderScaleDecoder for CircuitBuilder<F, D> {
    fn decode_compact_int(
        &mut self,
        compact_bytes: Vec<Target>
    ) -> (Target, Target, Target) {
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
        let value = self.random_access(compress_mode, vec![zero_mode_value, one_mode_value, two_mode_value, three_mode_value]);

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
    fn decode_fixed_int(
        &mut self,
        bytes: Vec<Target>,
        value_byte_length: usize,
    ) -> Target {
        assert!(bytes.len() == value_byte_length);
        assert!(value_byte_length <= 64);

        let alpha = self.constant(F::from_canonical_u16(256));
        let value = reduce_with_powers_circuit(self, &bytes, alpha);

        value
    }


}


pub struct EncodedHeaderTarget {
    pub header_bytes: Vec<Target>,
    pub header_size: Target,
}

pub struct HeaderTarget {
    pub block_number: Target,
    pub parent_hash: Vec<Target>,    // Vector of 32 bytes
    pub state_root: Vec<Target>,     // Vector of 32 bytes
    // pub data_root: Vec<Target>,      // Vector of 32 bytes
}


pub trait CircuitBuilderHeaderDecoder {
    fn decode_header(
        &mut self,
        header: EncodedHeaderTarget,
    ) -> HeaderTarget;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeaderDecoder for CircuitBuilder<F, D> {
    fn decode_header(
        &mut self,
        header: EncodedHeaderTarget,
    ) -> HeaderTarget {

        // The first 32 bytes are the parent hash
        let parent_hash_target = header.header_bytes[0..32].to_vec();

        // Next field is the block number
        // Can need up to 5 bytes to represent a compact u32
        const MAX_BLOCK_NUMBER_SIZE: usize = 5;
        let (block_number_target, compress_mode, _) = self.decode_compact_int(header.header_bytes[32..32+MAX_BLOCK_NUMBER_SIZE].to_vec());

        let mut all_possible_state_roots = Vec::new();
        all_possible_state_roots.push(header.header_bytes[33..33+HASH_SIZE].to_vec());
        all_possible_state_roots.push(header.header_bytes[34..34+HASH_SIZE].to_vec());
        all_possible_state_roots.push(header.header_bytes[36..36+HASH_SIZE].to_vec());
        all_possible_state_roots.push(header.header_bytes[37..37+HASH_SIZE].to_vec());

        let state_root_target = self.random_access_vec::<Target>(
            compress_mode,
            &all_possible_state_roots,
            |x| *x,
            |x| *x,
        );

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
            parent_hash: parent_hash_target,
            block_number: block_number_target,
            state_root: state_root_target,
            //data_root: data_root_target,
        }
    }
}


#[derive(Clone, Debug)]
pub struct EncodedPrecommitTarget(pub Vec<Target>);

pub struct PrecommitTarget {
    pub block_hash: Vec<Target>,   // Vector of 32 bytes
    pub block_number: Target,
    pub justification_round: Target,
    pub authority_set_id: Target,
}


pub trait CircuitBuilderPrecommitDecoder {
    fn decode_precommit(
        &mut self,
        precommit: EncodedPrecommitTarget,
    ) -> PrecommitTarget;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderPrecommitDecoder for CircuitBuilder<F, D> {
    fn decode_precommit(
        &mut self,
        precommit: EncodedPrecommitTarget,
    ) -> PrecommitTarget {
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
            block_hash: block_hash,
            block_number: block_number,
            justification_round: justification_round,
            authority_set_id: authority_set_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use log::Level;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::types::Field;
    use crate::config::PoseidonBN128GoldilocksConfig;
    use crate::utils::MAX_HEADER_SIZE;
    use crate::utils::tests::{BLOCK_576728_HEADER, BLOCK_576728_PARENT_HASH, BLOCK_576728_STATE_ROOT};
    use crate::decoder::{ CircuitBuilderScaleDecoder, CircuitBuilderHeaderDecoder, EncodedHeaderTarget };

    fn test_compact_int(
        encoded_bytes: [u8; 5],
        expected_int: u64,
        expected_compress_mode: u8,
        expected_length: u8
    ) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut encoded_bytes_target = Vec::new();

        for i in 0..encoded_bytes.len() {
            encoded_bytes_target.push(builder.constant(F::from_canonical_u8(encoded_bytes[i])));
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
    fn test_decode_compact_int_16384() -> Result<()>  {
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

        let mut header_bytes_target = BLOCK_576728_HEADER.iter().map(|b| {
            builder.constant(F::from_canonical_u8(*b))
        }).collect::<Vec<_>>();
        let header_size = builder.constant(F::from_canonical_usize(BLOCK_576728_HEADER.len()));

        // pad the header bytes
        for _ in BLOCK_576728_HEADER.len()..MAX_HEADER_SIZE {
            header_bytes_target.push(builder.zero());
        }

        let decoded_header = builder.decode_header(EncodedHeaderTarget{header_bytes: header_bytes_target, header_size});

        let expected_block_number = builder.constant(F::from_canonical_u64(576728));
        builder.connect(decoded_header.block_number, expected_block_number);

        let expected_parent_hash = hex::decode(BLOCK_576728_PARENT_HASH).unwrap();
        for i in 0..expected_parent_hash.len() {
            let expected_parent_hash_byte = builder.constant(F::from_canonical_u8(expected_parent_hash[i]));
            builder.connect(decoded_header.parent_hash[i], expected_parent_hash_byte);
        }

        let expected_state_root = hex::decode(BLOCK_576728_STATE_ROOT).unwrap();
        for i in 0..expected_state_root.len() {
            let expected_state_root_byte = builder.constant(F::from_canonical_u8(expected_state_root[i]));
            builder.connect(decoded_header.state_root[i], expected_state_root_byte);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof.clone()).unwrap();

        let mut outer_builder = CircuitBuilder::<F, D>::new(config);
        let inner_proof_target = outer_builder.add_virtual_proof_with_pis(&data.common);
        let inner_verifier_data = outer_builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&inner_proof_target, &inner_verifier_data, &data.common);

        let outer_data = outer_builder.build::<C>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&inner_proof_target, &proof);
        outer_pw.set_verifier_data_target(&inner_verifier_data, &data.verifier_only);

        let outer_proof = outer_data.prove(outer_pw).unwrap();

        outer_data.verify(outer_proof.clone()).unwrap();

        let mut final_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let final_proof_target = final_builder.add_virtual_proof_with_pis(&outer_data.common);
        let final_verifier_data = final_builder.add_virtual_verifier_data(outer_data.common.config.fri_config.cap_height);
        final_builder.verify_proof::<C>(&final_proof_target, &final_verifier_data, &outer_data.common);

        let final_data = final_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut final_pw = PartialWitness::new();
        final_pw.set_proof_with_pis_target(&final_proof_target, &outer_proof);
        final_pw.set_verifier_data_target(&final_verifier_data, &outer_data.verifier_only);

        let mut timing = TimingTree::new("prove", Level::Debug);
        let final_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(&final_data.prover_only, &final_data.common, final_pw, &mut timing).unwrap();
        timing.print();

        let final_proof_serialized = serde_json::to_string(&final_proof).unwrap();
        fs::write(
            "final.proof_with_public_inputs.json",
            final_proof_serialized,
        )
        .expect("Unable to write file");
    
        let final_vd_serialized = serde_json::to_string(&final_data.verifier_only).unwrap();
        fs::write(
            "final.verifier_only_circuit_data.json",
            final_vd_serialized,
        )
        .expect("Unable to write file");

        let final_cd_serialized = serde_json::to_string(&final_data.common).unwrap();
        fs::write(
            "final.common_circuit_data.json",
            final_cd_serialized,
        )
        .expect("Unable to write file");

        Ok(())


    }
}
