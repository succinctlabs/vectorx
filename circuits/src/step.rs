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
            let one = self.one();
            if i == 0 {
                let expected_block_num = self.add(subchain.head_block_num, one);
                self.connect(expected_block_num, decoded_header.block_number);
            } else {
                let expected_block_num = self.add(decoded_block_nums[i-1], one);
                self.connect(expected_block_num, decoded_header.block_number);
            }

            decoded_block_nums.push(decoded_header.block_number);
        }

        let last_calculated_hash = calculated_hashes.last().unwrap();
        let mut last_calculated_hash_bytes = Vec::new();
        // Convert the last calculated hash into bytes
        // The bits in the calculated hash are in bit big endian format
        for i in 0 .. HASH_SIZE {
            last_calculated_hash_bytes.push(self.le_sum(last_calculated_hash[i*8..i*8+8].to_vec().iter().rev()));
        }

        // Now verify the grandpa justification
        self.verify_justification(
            signed_precommits,
            last_calculated_hash_bytes,
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
    use crate::utils::{to_bits,QUORUM_SIZE};
    use crate::utils::tests::{
        BLOCK_530508_PARENT_HASH,
        BLOCK_530508_HEADER,
        BLOCK_530509_HEADER,
        BLOCK_530510_HEADER,
        BLOCK_530511_HEADER,
        BLOCK_530512_HEADER,
        BLOCK_530513_HEADER,
        BLOCK_530514_HEADER,
        BLOCK_530515_HEADER,
        BLOCK_530516_HEADER,
        BLOCK_530517_HEADER,
        BLOCK_530518_PARENT_HASH,
        BLOCK_530518_HEADER,
        BLOCK_530519_HEADER,
        BLOCK_530520_HEADER,
        BLOCK_530521_HEADER,
        BLOCK_530522_HEADER,
        BLOCK_530523_PARENT_HASH,
        BLOCK_530523_HEADER,
        BLOCK_530524_HEADER,
        BLOCK_530525_HEADER,
        BLOCK_530526_PARENT_HASH,
        BLOCK_530526_HEADER,
        BLOCK_530527_HEADER,
        BLOCK_530527_AUTHORITY_SET_ID,
        BLOCK_530527_PARENT_HASH,
        BLOCK_530527_PRECOMMIT_MESSAGE,
        BLOCK_530527_AUTHORITY_SIGS,
        BLOCK_530527_AUTHORITY_PUB_KEYS,
    };
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
            signatures,
            pub_keys,
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

    #[test]
    fn test_verify_headers_two() -> Result<()> {
        let mut headers = Vec::new();
        headers.push(BLOCK_530526_HEADER.to_vec());
        headers.push(BLOCK_530527_HEADER.to_vec());
        let head_block_hash = hex::decode(BLOCK_530526_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530525,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_PUB_KEYS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn test_verify_headers_five() -> Result<()> {
        let mut headers = Vec::new();
        headers.push(BLOCK_530523_HEADER.to_vec());
        headers.push(BLOCK_530524_HEADER.to_vec());
        headers.push(BLOCK_530525_HEADER.to_vec());
        headers.push(BLOCK_530526_HEADER.to_vec());
        headers.push(BLOCK_530527_HEADER.to_vec());
        let head_block_hash = hex::decode(BLOCK_530523_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530522,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_PUB_KEYS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn test_verify_headers_ten() -> Result<()> {
        let mut headers = Vec::new();
        headers.push(BLOCK_530518_HEADER.to_vec());
        headers.push(BLOCK_530519_HEADER.to_vec());
        headers.push(BLOCK_530520_HEADER.to_vec());
        headers.push(BLOCK_530521_HEADER.to_vec());
        headers.push(BLOCK_530522_HEADER.to_vec());
        headers.push(BLOCK_530523_HEADER.to_vec());
        headers.push(BLOCK_530524_HEADER.to_vec());
        headers.push(BLOCK_530525_HEADER.to_vec());
        headers.push(BLOCK_530526_HEADER.to_vec());
        headers.push(BLOCK_530527_HEADER.to_vec());
        let head_block_hash = hex::decode(BLOCK_530518_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530517,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_PUB_KEYS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn test_verify_headers_twenty() -> Result<()> {
        let mut headers = Vec::new();
        headers.push(BLOCK_530508_HEADER.to_vec());
        headers.push(BLOCK_530509_HEADER.to_vec());
        headers.push(BLOCK_530510_HEADER.to_vec());
        headers.push(BLOCK_530511_HEADER.to_vec());
        headers.push(BLOCK_530512_HEADER.to_vec());
        headers.push(BLOCK_530513_HEADER.to_vec());
        headers.push(BLOCK_530514_HEADER.to_vec());
        headers.push(BLOCK_530515_HEADER.to_vec());
        headers.push(BLOCK_530516_HEADER.to_vec());
        headers.push(BLOCK_530517_HEADER.to_vec());
        headers.push(BLOCK_530518_HEADER.to_vec());
        headers.push(BLOCK_530519_HEADER.to_vec());
        headers.push(BLOCK_530520_HEADER.to_vec());
        headers.push(BLOCK_530521_HEADER.to_vec());
        headers.push(BLOCK_530522_HEADER.to_vec());
        headers.push(BLOCK_530523_HEADER.to_vec());
        headers.push(BLOCK_530524_HEADER.to_vec());
        headers.push(BLOCK_530525_HEADER.to_vec());
        headers.push(BLOCK_530526_HEADER.to_vec());
        headers.push(BLOCK_530527_HEADER.to_vec());
        let head_block_hash = hex::decode(BLOCK_530508_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530507,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_PUB_KEYS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        )
    }
}