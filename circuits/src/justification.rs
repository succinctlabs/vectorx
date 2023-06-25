use plonky2_ecdsa::gadgets::biguint::CircuitBuilderBiguint;
use plonky2lib_succinct::ed25519::curve::curve_types::Curve;
use plonky2lib_succinct::ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2lib_succinct::ed25519::gadgets::eddsa::verify_message_circuit;
use plonky2lib_succinct::ed25519::gadgets::eddsa::{EDDSASignatureTarget};
use plonky2lib_succinct::hash_functions::blake2b::{make_blake2b_circuit, CHUNK_128_BYTES};
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::nonnative::CircuitBuilderNonNative;
use plonky2_field::extension::Extendable;
use plonky2_field::types::Field;
use plonky2::iop::target::Target;
use crate::utils::{ CircuitBuilderUtils, AvailHashTarget, QUORUM_SIZE, HASH_SIZE, ENCODED_PRECOMMIT_LENGTH, NUM_AUTHORITIES, NUM_AUTHORITIES_PADDED, PUB_KEY_SIZE };
use crate::decoder::{ CircuitBuilderPrecommitDecoder, EncodedPrecommitTarget };

#[derive(Clone, Debug)]
pub struct PrecommitTarget<C: Curve> {
    pub precommit_message: [Target; ENCODED_PRECOMMIT_LENGTH],
    pub signature: EDDSASignatureTarget<C>,
    pub pub_key_idx: Target,   // The ith index in the AuthoritySetSignersTarget.pub_keys vector.  Must have value between 0 and NUM_AUTHORITIES-1
}

#[derive(Clone, Debug)]
pub struct PubKeyTarget(pub [Target; PUB_KEY_SIZE]); // The pub key in compressed form (i.e. 32 bytes)

#[derive(Clone)]
pub struct AuthoritySetSignersTarget {
    pub pub_keys: [PubKeyTarget; NUM_AUTHORITIES_PADDED],           // Array of pub keys (in compressed form)
    pub commitment: AvailHashTarget,
    pub set_id: Target,
}

pub struct FinalizedBlockTarget {
    pub hash: AvailHashTarget,
    pub num: Target,
}

pub trait CircuitBuilderGrandpaJustificationVerifier<C: Curve> {
    fn add_virtual_precommit_target_safe(&mut self) -> PrecommitTarget<C>;

    fn add_virtual_authority_set_signers_target_safe(&mut self) -> AuthoritySetSignersTarget;

    fn verify_justification(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        finalized_block: &FinalizedBlockTarget);
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderGrandpaJustificationVerifier<C> for CircuitBuilder<F, D> {
    fn add_virtual_precommit_target_safe(&mut self) -> PrecommitTarget<C> {
        let precommit_message = self.add_virtual_targets(ENCODED_PRECOMMIT_LENGTH);
        for i in 0..ENCODED_PRECOMMIT_LENGTH {
            self.range_check(precommit_message[i], 8);
        }

        let sig_r = self.add_virtual_affine_point_target();
        // Range check sig_r coordinates
        let one = self.one();
        let base_field_order = self.constant_biguint(&C::BaseField::order());
        let x_biguint = self.nonnative_to_canonical_biguint(&sig_r.x);
        let x_cmp = self.cmp_biguint(&x_biguint, &base_field_order);
        self.connect(x_cmp.target, one);

        let y_biguint = self.nonnative_to_canonical_biguint(&sig_r.y);
        let y_cmp = self.cmp_biguint(&y_biguint, &base_field_order);
        self.connect(y_cmp.target, one);

        let sig_s = self.add_virtual_nonnative_target::<C::ScalarField>();

        // Range check sig_s value
        let scalar_field_order = self.constant_biguint(&C::ScalarField::order());
        let s_biguint = self.nonnative_to_canonical_biguint(&sig_s);
        let s_cmp = self.cmp_biguint(&s_biguint, &scalar_field_order);
        self.connect(s_cmp.target, one);

        let signature = EDDSASignatureTarget {
            r: sig_r,
            s: sig_s,
        };

        let pub_key_idx = self.add_virtual_target();

        // Range check the indices.  They should be between 0 - (NUM_AUTHORITIES-1).
        // Doing a range check for a value that is not less than a power of 2 is a bit tricky.
        // For NUM_AUTHORITIES==10, we need to check two constraints:
        // 1) The value is less than 16.
        // 2) If the 4th significant bit is set, then the 3rd and 2nd significant bits must be zero. (Allow for the values 8 and 9)
        let zero = self.zero();

        // split_le does a range check
        let bits = self.split_le(pub_key_idx, 4);
        let third_second_bits = self.or(bits[2], bits[1]);
        let check_third_second_bits = self.select(bits[3], third_second_bits.target, zero);
        self.connect(check_third_second_bits, zero);

        PrecommitTarget {
            precommit_message: precommit_message.try_into().unwrap(),
            signature,
            pub_key_idx,
        }
    }

    fn add_virtual_authority_set_signers_target_safe(&mut self) -> AuthoritySetSignersTarget {

        let mut pub_keys = Vec::new();
        for _i in 0..NUM_AUTHORITIES_PADDED {
            // Create the virtual target for the pub keys
            let mut pub_key = Vec::new();
            for _j in 0..PUB_KEY_SIZE {
                let pub_key_byte = self.add_virtual_target();

                // TODO:  Can also decompose the bytes into bits here, since the range check basically does that.
                self.range_check(pub_key_byte, 8);
                pub_key.push(pub_key_byte);
            }

            pub_keys.push(PubKeyTarget(pub_key.try_into().unwrap()));
        }

        let commitment = self.add_virtual_avail_hash_target_safe(false);
        let set_id = self.add_virtual_target();
        // The set_id should be a u64
        self.range_check(set_id, 64);

        AuthoritySetSignersTarget {
            pub_keys: pub_keys.try_into().unwrap(),
            commitment,
            set_id,
        }
    }

    // This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
    fn verify_justification(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        finalized_block: &FinalizedBlockTarget
    ) {

        // First check to see that we have the right authority set
        // Calculate the hash for the authority set
        // Note that the input to this circuit must be of chunks of 128 bytes, so it may need to be padded.
        let input_padding = (CHUNK_128_BYTES * 8) - ((NUM_AUTHORITIES * 256) % (CHUNK_128_BYTES * 8));
        assert!(input_padding == 512);
        let hash_circuit = make_blake2b_circuit(
            self,
            NUM_AUTHORITIES * 256 + input_padding,   // each EDDSA pub key in compressed for is 256 bits and padding to make it fit 128 byte chunks
            HASH_SIZE,
        );

        // Input the pub keys into the hasher
        for i in 0 .. NUM_AUTHORITIES {
            for j in 0..PUB_KEY_SIZE {
                // covert bytes to BE bits for the BLAKE2B circuit
                let mut bits = self.split_le(authority_set_signers.pub_keys[i].0[j], 8);
                bits.reverse();
                for k in 0..8 {
                    self.connect(hash_circuit.message[i*256 + j*8 + k].target, bits[k].target);
                }
            }
        }

        // Add the padding
        let zero = self.zero();
        for i in (NUM_AUTHORITIES * 256)..(NUM_AUTHORITIES * 256 + input_padding) {
            self.connect(hash_circuit.message[i].target, zero);
        }

        // Length of the input in bytes
        let authority_set_hash_input_length = self.constant(F::from_canonical_usize(NUM_AUTHORITIES * 32));
        self.connect(hash_circuit.message_len, authority_set_hash_input_length);

        // Verify that the hash matches
        for i in 0 .. HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for j in 0..8 {
                self.connect(hash_circuit.digest[i*8+j].target, bits[j].target);
            }
        }

        // TODO:  Need to check for dupes of the pub_key_idx field

        // Now verify all of the signatures
        for i in 0..QUORUM_SIZE {
            // Get the pub key
            // Random access arrays must be a power of 2, so we pad the array to 16
            let mut pub_key = self.random_access_vec(
                signed_precommits[i].pub_key_idx,
                &authority_set_signers.pub_keys.iter().map(|x| x.0.to_vec()).collect::<Vec<_>>(),
            );

            // Need to reverse the byte endianess of the pub key
            pub_key.reverse();
            let mut pub_key_bits = Vec::new();

            for i in 0..PUB_KEY_SIZE {
                let mut bits = self.split_le(pub_key[i], 8);
                bits.reverse();
                pub_key_bits.extend(bits);
            }
            let pub_key_uncompressed = self.decompress_point(&pub_key_bits);

            // Verify that the precommit's fields match the claimed finalized block's
            // Note that we are currently assuming that all of the authorities sign on the finalized block,
            // as opposed to a decendent of that block.
            let decoded_precommit_msg = self.decode_precommit(EncodedPrecommitTarget(signed_precommits[i].precommit_message.to_vec()));
            self.connect(finalized_block.num, decoded_precommit_msg.block_number);
            for j in 0..HASH_SIZE {
                self.connect(finalized_block.hash.0[j], decoded_precommit_msg.block_hash[j]);
            }
            self.connect(authority_set_signers.set_id, decoded_precommit_msg.authority_set_id);

            // Need to convert the encoded message to a bit array.  For now, assume that all validators are signing the same message
            let mut encoded_msg_bits = Vec::with_capacity(ENCODED_PRECOMMIT_LENGTH * 8);
            for j in 0..ENCODED_PRECOMMIT_LENGTH {
                let mut bits = self.split_le(signed_precommits[i].precommit_message[j], 8);

                // Needs to be in bit big endian order for the EDDSA verification circuit
                bits.reverse();
                for k in 0..8 {
                    encoded_msg_bits.push(bits[k]);
                }
            }

            let eddsa_verify_circuit = verify_message_circuit(self, ENCODED_PRECOMMIT_LENGTH as u128);

            for j in 0..ENCODED_PRECOMMIT_LENGTH * 8 {
                self.connect(encoded_msg_bits[j].target, eddsa_verify_circuit.msg[j].target);
            }

            self.connect_affine_point(&eddsa_verify_circuit.sig.r,&signed_precommits[i].signature.r);
            self.connect_nonnative(&eddsa_verify_circuit.sig.s,&signed_precommits[i].signature.s);
            self.connect_affine_point(&eddsa_verify_circuit.pub_key.0, &pub_key_uncompressed);
        }
    }

}


#[cfg(test)]
pub (crate) mod tests {
    use std::time::SystemTime;

    use anyhow::Result;
    use log::Level;
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2_ecdsa::gadgets::biguint::WitnessBigUint;
    use plonky2lib_succinct::ed25519::curve::curve_types::Curve;
    use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;
    use plonky2lib_succinct::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use plonky2lib_succinct::ed25519::field::ed25519_scalar::Ed25519Scalar;
    use plonky2lib_succinct::ed25519::gadgets::curve::decompress_point;
    use plonky2lib_succinct::ed25519::gadgets::eddsa::{EDDSATargets, verify_message_circuit};
    use plonky2lib_succinct::hash_functions::blake2b::make_blake2b_circuit;
    use ed25519_dalek::{PublicKey, Signature};
    use hex::decode;
    use num::BigUint;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::extension::Extendable;
    use plonky2_field::types::{Field, PrimeField};

    use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget, FinalizedBlockTarget, AuthoritySetSignersTarget};
    use crate::utils::tests::{BLOCK_530527_PRECOMMIT_MESSAGE, BLOCK_530527_AUTHORITY_SIGS, BLOCK_530527_PUB_KEY_INDICES, BLOCK_530527_AUTHORITY_SET, BLOCK_530527_AUTHORITY_SET_ID, BLOCK_530527_BLOCK_HASH, BLOCK_530527_AUTHORITY_SET_COMMITMENT, convert_hash_to_chunks};
    use crate::utils::{to_bits, CircuitBuilderUtils, WitnessAvailHash, ENCODED_PRECOMMIT_LENGTH, MAX_HEADER_SIZE, QUORUM_SIZE, HASH_SIZE, NUM_AUTHORITIES_PADDED, NUM_AUTHORITIES, PUB_KEY_SIZE};

    pub struct JustificationTarget<C: Curve> {
        precommit_targets: Vec<PrecommitTarget<C>>,
        authority_set_signers: AuthoritySetSignersTarget,
        finalized_block: FinalizedBlockTarget,
    }

    pub fn make_justification_circuit<F: RichField + Extendable<D>, const D: usize, C: Curve>(builder: &mut CircuitBuilder::<F, D>) -> JustificationTarget<C> {
        let mut precommit_targets = Vec::new();
        for _i in 0..QUORUM_SIZE {
            precommit_targets.push(builder.add_virtual_precommit_target_safe());
        }

        let authority_set = <CircuitBuilder<F, D> as CircuitBuilderGrandpaJustificationVerifier<C>>::add_virtual_authority_set_signers_target_safe(builder);

        let finalized_block_hash = builder.add_virtual_avail_hash_target_safe(false);
        let finalized_block_num = builder.add_virtual_target();

        builder.verify_justification(
            precommit_targets.clone(),
            &authority_set,
            &FinalizedBlockTarget {
                hash: finalized_block_hash.clone(),
                num: finalized_block_num,
            }
        );

        JustificationTarget {
            precommit_targets,
            authority_set_signers: authority_set,
            finalized_block: FinalizedBlockTarget {
                hash: finalized_block_hash,
                num: finalized_block_num,
            }
        }
    }

    pub fn set_precommits_pw<F: RichField + Extendable<D>, const D: usize, C: Curve>(
        pw: &mut PartialWitness<F>,
        precommit_targets: Vec<PrecommitTarget<C>>,
        precommit_messages: Vec<Vec<u8>>,
        signatures: Vec<Vec<u8>>,
        pub_key_indices: Vec<usize>,
        pub_keys: Vec<Vec<u8>>,
    ) {
        assert!(precommit_targets.len() == QUORUM_SIZE);
        assert!(precommit_messages.len() == QUORUM_SIZE);
        assert!(signatures.len() == QUORUM_SIZE);
        assert!(pub_key_indices.len() == QUORUM_SIZE);
        assert!(pub_keys.len() == NUM_AUTHORITIES_PADDED);

        // Set the precommit partial witness values
        for i in 0..precommit_messages.len() {
            let sig_r = decompress_point(&signatures[i][0..32]);
            assert!(sig_r.is_valid());

            let pub_key = &pub_keys[pub_key_indices[i]];

            let sig_s_biguint = BigUint::from_bytes_le(&signatures[i][32..64]);
            let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
            let sig = EDDSASignature { r: sig_r, s: sig_s };

            let pub_key_point = decompress_point(&pub_key[..]);
            assert!(pub_key_point.is_valid());

            let precommit_message_bits = to_bits(precommit_messages[i].clone());

            assert!(verify_message(
                &precommit_message_bits,
                &sig,
                &EDDSAPublicKey(pub_key_point)
            ));

            let precommit_target = &precommit_targets[i];
            pw.set_biguint_target(&precommit_target.signature.r.x.value, &sig.r.x.to_canonical_biguint());
            pw.set_biguint_target(&precommit_target.signature.r.y.value, &sig.r.y.to_canonical_biguint());
            pw.set_biguint_target(&precommit_target.signature.s.value, &sig_s.to_canonical_biguint());

            pw.set_target(precommit_target.pub_key_idx, F::from_canonical_usize(pub_key_indices[i]));

            assert!(precommit_messages[i].len() == ENCODED_PRECOMMIT_LENGTH);
            assert!(precommit_messages[i].len() == precommit_target.precommit_message.len());

            precommit_messages[i].iter()
            .zip(precommit_target.precommit_message.iter())
            .for_each(|(msg_byte, msg_byte_target)| pw.set_target(*msg_byte_target, F::from_canonical_u8(*msg_byte)));
        }
    }

    pub fn set_authority_set_pw<F: RichField + Extendable<D>, const D: usize, C: Curve>(
        pw: &mut PartialWitness<F>,
        authority_set_target: &AuthoritySetSignersTarget,
        pub_keys: Vec<Vec<u8>>,
        authority_set_id: u64,
        authority_set_commitment: Vec<u8>,
    ) {
        assert!(pub_keys.len() == NUM_AUTHORITIES_PADDED);
        assert!(authority_set_target.pub_keys.len() == NUM_AUTHORITIES_PADDED);

        // Set the authority set partial witness values
        for i in 0..pub_keys.len() {
            let authority_set_signers_target = &authority_set_target.pub_keys[i];
            let pub_key = &pub_keys[i];

            assert!(pub_key.len() == PUB_KEY_SIZE);
            assert!(pub_key.len() == authority_set_signers_target.0.len());

            pub_key.iter()
            .zip(authority_set_signers_target.0.iter())
            .for_each(|(pub_key_byte, pub_key_byte_target)| pw.set_target(*pub_key_byte_target, F::from_canonical_u8(*pub_key_byte)));
        }

        pw.set_target(authority_set_target.set_id, F::from_canonical_u64(authority_set_id));

        for i in 0..HASH_SIZE {
            pw.set_target(authority_set_target.commitment.0[i], F::from_canonical_u8(authority_set_commitment[i]));
        }
    }



    #[test]
    fn test_avail_eddsa_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        // grabbed from avail round 7642
        // let sig_msg = hex::decode("019f87ee2f28b0debfbe661c573beaa899db45211fd2b3b41f44bdbc685599e2be106a040082300000000000000f01000000000000").unwrap();
        let sig_msg = hex::decode("0162f1aaf6297b86b3749448d66cc43deada49940c3912a4ec4916344058e8f0655f180800680b000000000000f001000000000000").unwrap();
        let sig_msg_bits = to_bits(sig_msg.to_vec());

        // let signature= hex::decode("cc1286a1716d00a8c310cfae32e8fb83f5f9c8bc1a6da1fb0de33361aaf7871d2e33e6c72606295e5b175ec4033b7e63392d76e2e4271561d6d2db149191e609").unwrap();
        let signature= hex::decode("3ebc508daaf5edd7a4b4779743ce9241519aa8940264c2be4f39dfd0f7a4f2c4c587752fbc35d6d34b8ecd494dfe101e49e6c1ccb0e41ff2aa52bc481fcd3e0c").unwrap();
        let sig_r = decompress_point(&signature[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint =
            BigUint::from_bytes_le(&signature[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        let pubkey_bytes =
            hex::decode("0e0945b2628f5c3b4e2a6b53df997fc693344af985b11e3054f36a384cc4114b")
                .unwrap();
        let pub_key = decompress_point(&pubkey_bytes[..]);
        assert!(pub_key.is_valid());

        assert!(verify_message(
            &sig_msg_bits,
            &sig,
            &EDDSAPublicKey(pub_key)
        ));

        let targets: EDDSATargets<Curve> = verify_message_circuit(&mut builder, sig_msg.len().try_into().unwrap());

        let mut msg = Vec::with_capacity(sig_msg.len());
        for i in 0..sig_msg.len() {
            msg.push(CircuitBuilder::constant(&mut builder, F::from_canonical_u8(sig_msg[i])));
        }

        let mut msg_bits = Vec::with_capacity(sig_msg.len() * 8);
        for i in 0..sig_msg.len() {
            let mut bits = builder.split_le(msg[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for j in 0..8 {
                msg_bits.push(bits[j]);
            }
        }

        for i in 0..msg_bits.len() {
            builder.connect(msg_bits[i].target, targets.msg[i].target)
        }

        pw.set_biguint_target(&targets.pub_key.0.x.value, &pub_key.x.to_canonical_biguint());
        pw.set_biguint_target(&targets.pub_key.0.y.value, &pub_key.y.to_canonical_biguint());

        pw.set_biguint_target(&targets.sig.r.x.value, &sig_r.x.to_canonical_biguint());
        pw.set_biguint_target(&targets.sig.r.y.value, &sig_r.y.to_canonical_biguint());

        pw.set_biguint_target(&targets.sig.s.value, &sig_s.to_canonical_biguint());

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_avail_eddsa() -> Result<()> {
        let sig_msg = hex::decode("0162f1aaf6297b86b3749448d66cc43deada49940c3912a4ec4916344058e8f0655f180800680b000000000000f001000000000000").unwrap();

        let signature_bytes= hex::decode("3ebc508daaf5edd7a4b4779743ce9241519aa8940264c2be4f39dfd0f7a4f2c4c587752fbc35d6d34b8ecd494dfe101e49e6c1ccb0e41ff2aa52bc481fcd3e0c").unwrap();
        let signature = Signature::from_bytes(&signature_bytes)?;

        let pubkey_bytes =
            hex::decode("0e0945b2628f5c3b4e2a6b53df997fc693344af985b11e3054f36a384cc4114b")
                .unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes)?;

        let is_ok = PublicKey::verify_strict(&pubkey, &sig_msg[..], &signature);

        if is_ok.is_err() {
            panic!("it dont work");
        }
        Ok(())
    }

    #[test]
    fn test_blake2() -> Result<()> {
        // let hash_msg = [144, 117, 45, 72, 111, 237, 228, 218, 116, 101, 43, 1, 223, 40, 157, 214, 121, 105, 103, 193, 192, 190, 76, 74, 170, 58, 227, 134, 92, 62, 213, 14, 122, 66, 19, 0, 193, 241, 98, 251, 119, 243, 126, 139, 222, 180, 26, 156, 8, 112, 238, 97, 139, 84, 14, 237, 239, 199, 22, 202, 25, 78, 9, 79, 47, 79, 93, 183, 76, 136, 103, 4, 210, 247, 12, 241, 84, 31, 81, 154, 95, 173, 53, 213, 1, 66, 97, 126, 17, 163, 170, 125, 57, 151, 215, 23, 43, 22, 65, 199, 8, 6, 66, 65, 66, 69, 181, 1, 1, 2, 0, 0, 0, 147, 174, 254, 4, 0, 0, 0, 0, 50, 26, 21, 229, 88, 9, 151, 22, 46, 53, 8, 34, 225, 248, 32, 112, 71, 251, 168, 47, 18, 216, 70, 137, 123, 19, 123, 22, 186, 45, 246, 39, 230, 1, 21, 94, 11, 77, 192, 130, 12, 119, 209, 134, 62, 196, 151, 102, 220, 219, 16, 134, 212, 68, 110, 223, 212, 25, 194, 204, 49, 221, 102, 0, 129, 249, 20, 6, 179, 67, 166, 223, 157, 127, 37, 184, 248, 77, 109, 234, 32, 249, 82, 210, 26, 246, 98, 254, 14, 198, 20, 149, 72, 164, 18, 3, 5, 66, 65, 66, 69, 1, 1, 12, 98, 1, 92, 64, 109, 0, 15, 225, 90, 161, 6, 20, 185, 110, 4, 128, 114, 49, 74, 151, 255, 76, 51, 7, 242, 243, 244, 106, 96, 115, 12, 31, 144, 167, 82, 234, 157, 223, 169, 32, 31, 174, 135, 250, 158, 181, 247, 236, 69, 172, 154, 45, 87, 248, 253, 7, 21, 112, 210, 5, 59, 69, 131, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 171, 123, 251, 117, 13, 76, 175, 100, 53, 44, 84, 214, 215, 237, 138, 212, 129, 32, 136, 13, 248, 88, 237, 131, 73, 6, 10, 6, 98, 221, 120, 24, 230, 125, 12, 215, 241, 155, 79, 26, 112, 220, 246, 161, 103, 151, 163, 92, 171, 123, 251, 117, 13, 76, 175, 100, 53, 44, 84, 214, 215, 237, 138, 212, 129, 32, 136, 13, 248, 88, 237, 131, 73, 6, 10, 6, 98, 221, 120, 24, 230, 125, 12, 215, 241, 155, 79, 26, 112, 220, 246, 161, 103, 151, 163, 92, 4, 0];
        let hash_msg = [199, 211, 173, 1, 148, 4, 184, 168, 129, 158, 147, 33, 229, 118, 216, 13, 115, 19, 16, 247, 138, 29, 38, 58, 16, 201, 126, 227, 246, 65, 8, 20, 18, 67, 19, 0, 206, 224, 13, 243, 214, 81, 145, 197, 22, 192, 185, 107, 124, 228, 0, 177, 84, 165, 36, 60, 189, 240, 167, 84, 127, 36, 127, 208, 159, 18, 50, 187, 77, 220, 223, 56, 66, 161, 202, 34, 41, 145, 22, 163, 106, 65, 153, 178, 42, 201, 52, 212, 10, 217, 219, 194, 46, 53, 158, 23, 20, 222, 6, 120, 8, 6, 66, 65, 66, 69, 52, 2, 8, 0, 0, 0, 185, 174, 254, 4, 0, 0, 0, 0, 5, 66, 65, 66, 69, 1, 1, 58, 46, 57, 142, 51, 163, 68, 38, 85, 183, 197, 114, 35, 78, 186, 34, 26, 1, 156, 8, 97, 93, 205, 194, 183, 135, 236, 239, 49, 238, 230, 126, 17, 234, 170, 147, 165, 234, 103, 133, 13, 142, 94, 84, 170, 115, 252, 85, 122, 118, 38, 180, 165, 130, 28, 14, 36, 93, 69, 137, 130, 219, 194, 132, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 129, 115, 27, 207, 203, 27, 3, 117, 164, 108, 3, 254, 15, 21, 180, 159, 109, 175, 75, 141, 62, 222, 193, 34, 49, 5, 197, 217, 170, 223, 45, 117, 151, 0, 144, 196, 186, 13, 34, 201, 45, 235, 114, 248, 182, 157, 126, 55, 129, 115, 27, 207, 203, 27, 3, 117, 164, 108, 3, 254, 15, 21, 180, 159, 109, 175, 75, 141, 62, 222, 193, 34, 49, 5, 197, 217, 170, 223, 45, 117, 151, 0, 144, 196, 186, 13, 34, 201, 45, 235, 114, 248, 182, 157, 126, 55, 4, 0];
        let hash_msg_bits = to_bits(hash_msg.to_vec());
        // let expected_hash_digest = b"65616ede4572088aae86f4fe72c91284e48d56b6da61b4e0a2f599a750e531b1";
        let expected_hash_digest = b"4741d5048f282c0459e35d951d81d1adc20ef564e341cd84ee834a683aa40571";
        let hash_digest_bits = to_bits(decode(expected_hash_digest).unwrap());
        let hash_len: usize = 32;

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_blake2b_circuit(
            &mut builder,
            MAX_HEADER_SIZE * 8,
            hash_len
        );

        let mut pw = PartialWitness::new();

        for i in 0..hash_msg_bits.len() {
            pw.set_bool_target(targets.message[i], hash_msg_bits[i]);
        }

        for i in hash_msg_bits.len() .. MAX_HEADER_SIZE*8 {
            pw.set_bool_target(targets.message[i], false);
        }

        pw.set_target(targets.message_len, F::from_canonical_usize(hash_msg.len()));

        for i in 0..hash_digest_bits.len() {
            if hash_digest_bits[i] {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_grandpa_verification_simple() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw = PartialWitness::new();

        let justification_target = make_justification_circuit::<F, D, Curve>(&mut builder);

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            justification_target.precommit_targets,
            (0..QUORUM_SIZE).map(|_| BLOCK_530527_PRECOMMIT_MESSAGE.clone().to_vec()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &justification_target.authority_set_signers,
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SET_ID,
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        let block_hash_bytes = convert_hash_to_chunks(BLOCK_530527_BLOCK_HASH);
        pw.set_avail_hash_target(&justification_target.finalized_block.hash, &block_hash_bytes);
        pw.set_target(justification_target.finalized_block.num, F::from_canonical_u32(530527u32));

        let data = builder.build::<C>();
        let proof_gen_start_time = SystemTime::now();
        let proof = data.prove(pw).unwrap();
        let proof_gen_end_time = SystemTime::now();
        let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();

        let proof_verification_start_time = SystemTime::now();
        let verification_res = data.verify(proof);
        let proof_verification_end_time = SystemTime::now();
        let proof_verification_time = proof_verification_end_time.duration_since(proof_verification_start_time).unwrap();

        println!("proof gen time is {:?}", proof_gen_duration);
        println!("proof verification time is {:?}", proof_verification_time);

        verification_res
    }

    #[test]
    fn test_blake2b_authority_set_commitment() -> Result<()> {
        let mut msg = Vec::new();

        for i in 0..NUM_AUTHORITIES {
            let mut pub_key_bytes = hex::decode(BLOCK_530527_AUTHORITY_SET[i]).unwrap();
            msg.append(pub_key_bytes.as_mut());
        }

        let msg_bits = to_bits(msg.to_vec());
        let expected_digest = BLOCK_530527_AUTHORITY_SET_COMMITMENT;
        let digest_bits = to_bits(hex::decode(expected_digest).unwrap());

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_blake2b_circuit(
            &mut builder,
            NUM_AUTHORITIES * 256 + 512,
            32,
        );
        let mut pw = PartialWitness::new();

        for i in 0..msg_bits.len() {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        for i in msg_bits.len()..msg_bits.len() + 512 {
            pw.set_bool_target(targets.message[i], false);
        }

        pw.set_target(targets.message_len, F::from_canonical_usize(msg.len()));

        for i in 0..digest_bits.len() {
            if digest_bits[i] {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();

        let mut timing = TimingTree::new("proof gen", Level::Info);
        let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing).unwrap();

        data.verify(proof)
    }    
}
