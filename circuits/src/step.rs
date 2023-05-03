use ed25519::curve::curve_types::Curve;
use ed25519::sha512::blake2b::make_blake2b_circuit;
use plonky2::{iop::target::{Target, BoolTarget}, hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;
use crate::decoder::{CircuitBuilderHeaderDecoder, EncodedHeaderTarget};
use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget};
use crate::utils::{MAX_HEADER_SIZE, HASH_SIZE, MAX_NUM_HEADERS_PER_STEP};

#[derive(Clone)]
pub struct VerifySubchainTarget {
    pub head_block_hash: Vec<BoolTarget>,   // The input is a vector of bits (in BE bit order)
    pub head_block_num: Target,
    pub encoded_headers: Vec<Vec<Target>>,
    pub encoded_header_sizes: Vec<Target>,
}

pub trait CircuitBuilderStep<C: Curve> {
    fn step(
        &mut self,
        subchain: VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_id: Target,
    );
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderStep<C> for CircuitBuilder<F, D> {

    // This function will accept an array of encoded header targets (and their sizes), and verify that 
    // they are sequential within the chain.
    // Specifically, it wll verify that each header's parent hash is equal to the block hash of the previous header.
    fn step(
        &mut self,
        subchain: VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_id: Target,
    ) {
        assert!(subchain.encoded_headers.len() <= MAX_NUM_HEADERS_PER_STEP);
        assert!(subchain.encoded_headers.len() == subchain.encoded_header_sizes.len());

        for i in 0 .. subchain.encoded_headers.len() {
            assert_eq!(subchain.encoded_headers[i].len(), MAX_HEADER_SIZE);

            for j in 0..MAX_HEADER_SIZE {
                self.range_check(subchain.encoded_headers[i][j], 8);
            }

            self.range_check(subchain.encoded_header_sizes[i], (MAX_HEADER_SIZE as f32).log2().ceil() as usize);
        }

        // The i'th hash in calculated_hashes is the calculated blake2b hash for header i
        let mut calculated_hashes: Vec<Vec<BoolTarget>> = Vec::new();
        let mut decoded_block_nums = Vec::new();
        for i in 0 .. subchain.encoded_headers.len() {
            let decoded_header = self.decode_header(
                EncodedHeaderTarget {
                    header_bytes: subchain.encoded_headers[i].clone(),
                    header_size: subchain.encoded_header_sizes[i],
                },
            );

            // Verify that the previous block hash is equal to the parent hash of the current header
            for j in 0 .. HASH_SIZE {
                let mut bits = self.split_le(decoded_header.parent_hash[j], 8);

                // Needs to be in bit big endian order for the EDDSA verification circuit
                bits.reverse();
                for k in 0..8 {
                    if i == 0 {
                        // Connect it to the passed in head block hash (which should of already been verified from the last step txn).
                        self.connect(subchain.head_block_hash[j*8+k].target, bits[k].target);
                    } else {
                        // Connect it to the previous calculated hash in the subchain array
                        self.connect(calculated_hashes[i-1][j*8+k].target, bits[k].target);
                    }
                }
            }

            // Calculate the hash for the current header
            let hash_circuit = make_blake2b_circuit(
                self,
                MAX_HEADER_SIZE * 8,
                HASH_SIZE
            );

            // Input the encoded header into the hasher
            for j in 0 .. MAX_HEADER_SIZE {
                let mut bits = self.split_le(subchain.encoded_headers[i][j], 8);

                // Needs to be in bit big endian order for the EDDSA verification circuit
                bits.reverse();
                for k in 0..8 {
                    self.connect(hash_circuit.message[j*8+k].target, bits[k].target);
                }
            }

            self.connect(hash_circuit.message_len, subchain.encoded_header_sizes[i]);

            calculated_hashes.push(hash_circuit.digest);


            // Verify that the block numbers are sequential
            if i == 0 {
                self.connect(subchain.head_block_num, decoded_header.block_number);
            } else {
                self.connect(decoded_block_nums[i-1], decoded_header.block_number);
            }

            decoded_block_nums.push(decoded_header.block_number);
        }

        let last_calculated_hash = calculated_hashes.last().unwrap();
        let mut last_calcualted_hash_bytes = Vec::new();
        // Convert the last calculated hash into bytes
        // The bits in the calculated hash are in bit big endian format
        for i in 0 .. HASH_SIZE {
            last_calcualted_hash_bytes.push(self.le_sum(last_calculated_hash[i*8..i*8+8].to_vec().iter()));
        }

        // Now verify the grandpa justification
        self.verify_justification(
            signed_precommits,
            last_calcualted_hash_bytes,
            *decoded_block_nums.last().unwrap(),
            authority_set_id,
        );
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::iop::witness::{PartialWitness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Field;

    use crate::step::{MAX_HEADER_SIZE, HASH_SIZE, CircuitBuilderStep, VerifySubchainTarget};
    use crate::utils::{
        to_bits,
        BLOCK_530527_HEADER,
        BLOCK_530527_AUTHORITY_SET_ID,
        BLOCK_530527_PARENT_HASH,
        BLOCK_530527_PRECOMMIT_MESSAGE,
        BLOCK_530527_AUTHORITY_SIGS,
        BLOCK_530527_AUTHORITY_PUB_KEYS,
        QUORUM_SIZE};
    use crate::justification::tests::generate_precommits;

    fn test_step(
        headers: Vec<Vec<u8>>,
        head_block_hash: Vec<u8>,
        head_block_num: u64,

        authority_set_id: u64,
        precommit_message: Vec<u8>,
        signatures: Vec<Vec<u8>>,
        pub_keys: Vec<Vec<u8>>,
    ) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let pw: PartialWitness<GoldilocksField> = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let head_block_hash_bits = to_bits(head_block_hash);

        let mut head_block_hash_target = Vec::new();
        for i in 0..HASH_SIZE * 8 {
            head_block_hash_target.push(builder.constant_bool(head_block_hash_bits[i]));
        }

        // Set the header targets
        let mut header_targets = Vec::new();
        let mut header_size_targets = Vec::new();
        for i in 0..headers.len() {
            header_targets.push(Vec::new());
            for j in 0..headers[i].len() {
                header_targets[i].push(builder.constant(F::from_canonical_u8(headers[i][j])));
            }

            // Pad the headers
            for _ in headers[i].len()..MAX_HEADER_SIZE {
                header_targets[i].push(builder.constant(F::from_canonical_u32(0)));
            }

            header_size_targets.push(builder.constant(F::from_canonical_usize(headers[i].len())));
        }

        let precommit_targets = generate_precommits(
            &mut builder,
            (0..QUORUM_SIZE).map(|_| precommit_message.clone().to_vec()).collect::<Vec<_>>(),
            signatures.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            pub_keys.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        );

        let head_block_num_target = builder.constant(F::from_canonical_u64(head_block_num));
        let authority_set_id_target = builder.constant(F::from_canonical_u64(authority_set_id));
        builder.step(
            VerifySubchainTarget {
                head_block_hash: head_block_hash_target,
                head_block_num: head_block_num_target,
                encoded_headers: header_targets,
                encoded_header_sizes: header_size_targets,
            },
            precommit_targets,
            authority_set_id_target,
        );

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)

    }

    #[test]
    fn test_verify_headers_one() -> Result<()> {
        let mut headers = Vec::new();
        headers.push(BLOCK_530527_HEADER.to_vec());
        let head_block_hash = hex::decode(BLOCK_530527_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530526,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_PUB_KEYS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        )
    }

    /*
    #[test]
    fn test_verify_headers_one() -> Result<()> {
        let mut headers = Vec::new();
        headers.push([108, 242, 111, 76, 73, 236, 173, 181, 185, 120, 209, 64, 87, 52, 103, 183, 225, 15, 124, 163, 29, 100, 34, 212, 175, 20, 95, 76, 212, 94, 233, 54, 110, 169, 33, 0, 198, 144, 168, 106, 112, 152, 176, 136, 22, 60, 32, 139, 156, 71, 78, 2, 27, 60, 159, 122, 252, 143, 177, 230, 134, 215, 255, 26, 29, 233, 145, 31, 125, 83, 230, 96, 94, 106, 209, 25, 78, 147, 152, 45, 39, 30, 240, 0, 130, 192, 177, 8, 248, 198, 25, 208, 1, 130, 101, 63, 244, 72, 11, 162, 8, 6, 66, 65, 66, 69, 52, 2, 2, 0, 0, 0, 84, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 144, 173, 119, 113, 168, 134, 67, 97, 48, 60, 25, 147, 134, 147, 217, 106, 149, 0, 171, 62, 184, 71, 147, 202, 134, 74, 115, 173, 58, 0, 198, 40, 92, 168, 114, 172, 4, 71, 221, 206, 183, 165, 84, 174, 63, 123, 208, 123, 128, 63, 224, 160, 134, 148, 53, 248, 78, 217, 33, 178, 68, 41, 35, 143, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 4, 0].to_vec());
        let head_block_hash = hex::decode("6cf26f4c49ecadb5b978d140573467b7e10f7ca31d6422d4af145f4cd45ee936").unwrap();
        test_step(headers, head_block_hash)
    }

    #[test]
    fn test_verify_headers_two() -> Result<()> {
        let head_block_hash = hex::decode("f9525f8ef08fd795aeac5dbdf53c51dcceb90c2782f440288c4e496b5c9d75da").unwrap();
        let mut headers = Vec::new();
        headers.push([249, 82, 95, 142, 240, 143, 215, 149, 174, 172, 93, 189, 245, 60, 81, 220, 206, 185, 12, 39, 130, 244, 64, 40, 140, 78, 73, 107, 92, 157, 117, 218, 106, 169, 33, 0, 7, 206, 182, 42, 235, 67, 224, 80, 17, 57, 117, 1, 54, 21, 125, 64, 37, 193, 250, 48, 199, 89, 112, 194, 150, 19, 161, 210, 139, 251, 195, 234, 123, 82, 140, 71, 248, 192, 191, 194, 121, 176, 7, 199, 176, 169, 223, 141, 135, 18, 22, 35, 221, 254, 142, 165, 46, 5, 125, 182, 248, 27, 118, 85, 8, 6, 66, 65, 66, 69, 52, 2, 6, 0, 0, 0, 83, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 52, 149, 214, 150, 25, 59, 150, 170, 183, 1, 125, 204, 25, 111, 162, 14, 76, 69, 46, 205, 61, 181, 0, 99, 169, 177, 18, 160, 220, 217, 102, 96, 36, 128, 98, 54, 170, 127, 187, 142, 179, 123, 195, 162, 53, 68, 215, 46, 98, 142, 174, 172, 252, 135, 53, 108, 79, 45, 215, 15, 143, 103, 213, 132, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 128, 17, 83, 36, 221, 46, 89, 166, 46, 64, 63, 63, 149, 246, 58, 14, 178, 4, 90, 52, 156, 138, 93, 145, 142, 138, 167, 241, 69, 147, 248, 23, 154, 10, 103, 110, 108, 143, 41, 34, 66, 171, 18, 51, 123, 184, 119, 113, 128, 17, 83, 36, 221, 46, 89, 166, 46, 64, 63, 63, 149, 246, 58, 14, 178, 4, 90, 52, 156, 138, 93, 145, 142, 138, 167, 241, 69, 147, 248, 23, 154, 10, 103, 110, 108, 143, 41, 34, 66, 171, 18, 51, 123, 184, 119, 113, 4, 0].to_vec());
        headers.push([108, 242, 111, 76, 73, 236, 173, 181, 185, 120, 209, 64, 87, 52, 103, 183, 225, 15, 124, 163, 29, 100, 34, 212, 175, 20, 95, 76, 212, 94, 233, 54, 110, 169, 33, 0, 198, 144, 168, 106, 112, 152, 176, 136, 22, 60, 32, 139, 156, 71, 78, 2, 27, 60, 159, 122, 252, 143, 177, 230, 134, 215, 255, 26, 29, 233, 145, 31, 125, 83, 230, 96, 94, 106, 209, 25, 78, 147, 152, 45, 39, 30, 240, 0, 130, 192, 177, 8, 248, 198, 25, 208, 1, 130, 101, 63, 244, 72, 11, 162, 8, 6, 66, 65, 66, 69, 52, 2, 2, 0, 0, 0, 84, 72, 2, 5, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 144, 173, 119, 113, 168, 134, 67, 97, 48, 60, 25, 147, 134, 147, 217, 106, 149, 0, 171, 62, 184, 71, 147, 202, 134, 74, 115, 173, 58, 0, 198, 40, 92, 168, 114, 172, 4, 71, 221, 206, 183, 165, 84, 174, 63, 123, 208, 123, 128, 63, 224, 160, 134, 148, 53, 248, 78, 217, 33, 178, 68, 41, 35, 143, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 168, 108, 140, 152, 202, 190, 158, 8, 97, 36, 53, 185, 230, 251, 24, 49, 114, 47, 209, 91, 195, 20, 219, 20, 55, 237, 10, 120, 29, 37, 219, 215, 189, 118, 219, 225, 110, 251, 53, 142, 173, 208, 234, 14, 166, 42, 188, 170, 4, 0].to_vec());
        test_step(headers, head_block_hash)
    }
    */
}