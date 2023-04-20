use ed25519::sha512::blake2b::{ make_blake2b_circuit, CHUNK_128_BYTES };
use plonky2::{iop::target::{Target, BoolTarget}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;
use crate::encoding::make_scale_header_circuit;

const MAX_HEADER_SIZE:usize = CHUNK_128_BYTES * 10; // 1280 bytes
const HASH_SIZE:usize = 32; // in bytes

#[derive(Clone)]
pub struct VerifySubchainTarget {
    pub head_block_hash: Vec<BoolTarget>,   // The input is a vector of bits (in BE bit order)
    pub encoded_headers: Vec<Vec<Target>>,
    pub encoded_header_sizes: Vec<Target>,
}

// This function will accept an array of encoded header targets (and their sizes), and verify that 
// they are sequential within the chain.
// Specifically, it wll verify that each header's parent hash is equal to the block hash of the previous header.
pub fn verify_headers<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    num_headers: usize
) -> VerifySubchainTarget {
    let mut encoded_headers = Vec::new();
    let mut encoded_header_sizes = Vec::new();

    // Create the input targets
    for _i in 0 .. num_headers {
        // Create the input targets
        let mut encoded_header = Vec::new();
        for _j in 0 .. MAX_HEADER_SIZE {
            encoded_header.push(builder.add_virtual_target());
        }
        encoded_headers.push(encoded_header);
        encoded_header_sizes.push(builder.add_virtual_target());
    }

    let mut head_block_hash = Vec::new();
    for _i in 0 .. HASH_SIZE * 8 {
        head_block_hash.push(builder.add_virtual_bool_target_safe());
    }

    // The i'th hash in calculated_hashes is the calculated blake2b hash for header i
    let mut calculated_hashes: Vec<Vec<BoolTarget>> = Vec::new();
    for i in 0 .. num_headers {
        let encoder = make_scale_header_circuit(
            builder,
            MAX_HEADER_SIZE
        );

        let scale_header_decoder_input = encoder.get_encoded_header_target();

        for j in 0..MAX_HEADER_SIZE {
            builder.connect(encoded_headers[i][j], scale_header_decoder_input[j]);
        }
    
        let header_parent_hash = encoder.get_parent_hash();

        // Verify that the previous block hash is equal to the parent hash of the current header
        for j in 0 .. HASH_SIZE {
            let mut bits = builder.split_le(header_parent_hash[j], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for k in 0..8 {
                if i == 0 {
                    builder.connect(head_block_hash[j*8+k].target, bits[k].target);
                } else {
                    builder.connect(calculated_hashes[i-1][j*8+k].target, bits[k].target);
                }
            }    
        }

        // Calculate the hash for the current header
        let hash_circuit = make_blake2b_circuit(
            builder,
            MAX_HEADER_SIZE * 8,
            HASH_SIZE
        );

        // Input the encoded header into the hasher
        for j in 0 .. MAX_HEADER_SIZE {
            let mut bits = builder.split_le(encoded_headers[i][j], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for k in 0..8 {
                builder.connect(hash_circuit.message[j*8+k].target, bits[k].target);
            }
        }

        builder.connect(hash_circuit.message_len, encoded_header_sizes[i]);

        calculated_hashes.push(hash_circuit.digest);
    }

    VerifySubchainTarget {
        head_block_hash,
        encoded_headers,
        encoded_header_sizes,
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use crate::avail::{MAX_HEADER_SIZE, verify_headers, HASH_SIZE};

    fn to_bits(msg: Vec<u8>) -> Vec<bool> {
        let mut res = Vec::new();
        for i in 0..msg.len() {
            let char = msg[i];
            for j in 0..8 {
                if (char & (1 << 7 - j)) != 0 {
                    res.push(true);
                } else {
                    res.push(false);
                }
            }
        }
        res
    }

    #[test]
    fn test_verify_headers_one() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let mut headers = Vec::new();
        headers.push([108, 242, 111, 76, 73, 236, 173, 181, 185, 120, 209, 64, 87, 52, 103, 183, 225, 15, 124, 163, 29, 100, 34, 212, 175, 20, 95, 76, 212, 94, 233, 54, 110, 169, 33, 0, 198, 144, 168, 106, 112, 152, 176, 136, 22, 60, 32, 139, 156, 71, 78, 2, 27, 60, 159, 122, 252, 143, 177, 230, 134, 215, 255, 26, 29, 233, 145, 31, 125, 83, 230, 96, 94, 106, 209, 25, 78, 147, 152, 45, 39, 30, 240, 0, 130, 192, 177, 8, 248, 198, 25, 208, 1, 130, 101, 63, 244, 72, 11, 162, 8, 6, 66, 65, 66, 69, 52, 2, 2, 0, 0, 0, 84, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 144, 173, 119, 113, 168, 134, 67, 97, 48, 60, 25, 147, 134, 147, 217, 106, 149, 0, 171, 62, 184, 71, 147, 202, 134, 74, 115, 173, 58, 0, 198, 40, 92, 168, 114, 172, 4, 71, 221, 206, 183, 165, 84, 174, 63, 123, 208, 123, 128, 63, 224, 160, 134, 148, 53, 248, 78, 217, 33, 178, 68, 41, 35, 143, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 4, 0].to_vec());
        let head_block_hash = hex::decode("6cf26f4c49ecadb5b978d140573467b7e10f7ca31d6422d4af145f4cd45ee936").unwrap();
        let head_block_hash_bits = to_bits(head_block_hash);

        let targets = verify_headers(&mut builder, headers.len());

        // Set the head_block_hash_target
        for i in 0..HASH_SIZE * 8 {
            pw.set_bool_target(targets.head_block_hash[i], head_block_hash_bits[i]);
        }

        // Set the header targets
        for i in 0..headers.len() {
            for j in 0..headers[i].len() {
                pw.set_target(targets.encoded_headers[i][j], F::from_canonical_u32(headers[i][j]));
            }

            for j in headers[i].len()..MAX_HEADER_SIZE {
                pw.set_target(targets.encoded_headers[i][j], F::from_canonical_u32(0));
            }

            pw.set_target(targets.encoded_header_sizes[i], F::from_canonical_usize(headers[i].len()));
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_verify_headers_two() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let head_block_hash = hex::decode("f9525f8ef08fd795aeac5dbdf53c51dcceb90c2782f440288c4e496b5c9d75da").unwrap();
        let head_block_hash_bits = to_bits(head_block_hash);
        let mut headers = Vec::new();
        headers.push([249, 82, 95, 142, 240, 143, 215, 149, 174, 172, 93, 189, 245, 60, 81, 220, 206, 185, 12, 39, 130, 244, 64, 40, 140, 78, 73, 107, 92, 157, 117, 218, 106, 169, 33, 0, 7, 206, 182, 42, 235, 67, 224, 80, 17, 57, 117, 1, 54, 21, 125, 64, 37, 193, 250, 48, 199, 89, 112, 194, 150, 19, 161, 210, 139, 251, 195, 234, 123, 82, 140, 71, 248, 192, 191, 194, 121, 176, 7, 199, 176, 169, 223, 141, 135, 18, 22, 35, 221, 254, 142, 165, 46, 5, 125, 182, 248, 27, 118, 85, 8, 6, 66, 65, 66, 69, 52, 2, 6, 0, 0, 0, 83, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 52, 149, 214, 150, 25, 59, 150, 170, 183, 1, 125, 204, 25, 111, 162, 14, 76, 69, 46, 205, 61, 181, 0, 99, 169, 177, 18, 160, 220, 217, 102, 96, 36, 128, 98, 54, 170, 127, 187, 142, 179, 123, 195, 162, 53, 68, 215, 46, 98, 142, 174, 172, 252, 135, 53, 108, 79, 45, 215, 15, 143, 103, 213, 132, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 128, 17, 83, 36, 221, 46, 89, 166, 46, 64, 63, 63, 149, 246, 58, 14, 178, 4, 90, 52, 156, 138, 93, 145, 142, 138, 167, 241, 69, 147, 248, 23, 154, 10, 103, 110, 108, 143, 41, 34, 66, 171, 18, 51, 123, 184, 119, 113, 128, 17, 83, 36, 221, 46, 89, 166, 46, 64, 63, 63, 149, 246, 58, 14, 178, 4, 90, 52, 156, 138, 93, 145, 142, 138, 167, 241, 69, 147, 248, 23, 154, 10, 103, 110, 108, 143, 41, 34, 66, 171, 18, 51, 123, 184, 119, 113, 4, 0].to_vec());
        headers.push([108, 242, 111, 76, 73, 236, 173, 181, 185, 120, 209, 64, 87, 52, 103, 183, 225, 15, 124, 163, 29, 100, 34, 212, 175, 20, 95, 76, 212, 94, 233, 54, 110, 169, 33, 0, 198, 144, 168, 106, 112, 152, 176, 136, 22, 60, 32, 139, 156, 71, 78, 2, 27, 60, 159, 122, 252, 143, 177, 230, 134, 215, 255, 26, 29, 233, 145, 31, 125, 83, 230, 96, 94, 106, 209, 25, 78, 147, 152, 45, 39, 30, 240, 0, 130, 192, 177, 8, 248, 198, 25, 208, 1, 130, 101, 63, 244, 72, 11, 162, 8, 6, 66, 65, 66, 69, 52, 2, 2, 0, 0, 0, 84, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 144, 173, 119, 113, 168, 134, 67, 97, 48, 60, 25, 147, 134, 147, 217, 106, 149, 0, 171, 62, 184, 71, 147, 202, 134, 74, 115, 173, 58, 0, 198, 40, 92, 168, 114, 172, 4, 71, 221, 206, 183, 165, 84, 174, 63, 123, 208, 123, 128, 63, 224, 160, 134, 148, 53, 248, 78, 217, 33, 178, 68, 41, 35, 143, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 4, 0].to_vec());

        let targets = verify_headers(&mut builder, headers.len());

        // Set the head_block_hash_target
        for i in 0..HASH_SIZE * 8 {
            pw.set_bool_target(targets.head_block_hash[i], head_block_hash_bits[i]);
        }

        // Set the header targets
        for i in 0..headers.len() {
            for j in 0..headers[i].len() {
                pw.set_target(targets.encoded_headers[i][j], F::from_canonical_u32(headers[i][j]));
            }

            for j in headers[i].len()..MAX_HEADER_SIZE {
                pw.set_target(targets.encoded_headers[i][j], F::from_canonical_u32(0));
            }

            pw.set_target(targets.encoded_header_sizes[i], F::from_canonical_usize(headers[i].len()));
        }

        let data = builder.build::<C>();
        
        let proof_gen_start_time = SystemTime::now();
        let proof = data.prove(pw).unwrap();
        let proof_gen_end_time = SystemTime::now();
        let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();

        let proof_verification_start_time = SystemTime::now();
        let verification_result = data.verify(proof);
        let proof_verification_end_time = SystemTime::now();
        let proof_verification_time = proof_verification_end_time.duration_since(proof_verification_start_time).unwrap();

        println!("proof gen time is {:?}", proof_gen_duration);
        println!("proof verification time is {:?}", proof_verification_time);

        verification_result
    }    
}