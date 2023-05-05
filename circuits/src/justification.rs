use ed25519::curve::curve_types::Curve;
use ed25519::gadgets::curve::CircuitBuilderCurve;
use ed25519::gadgets::eddsa::verify_message_circuit;
use ed25519::gadgets::eddsa::{EDDSASignatureTarget};
use ed25519::gadgets::nonnative::CircuitBuilderNonNative;
use ed25519::sha512::blake2b::make_blake2b_circuit;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::{Target, BoolTarget};
use crate::utils::{ QUORUM_SIZE, HASH_SIZE, ENCODED_PRECOMMIT_LENGTH, NUM_AUTHORITIES, CircuitBuilderUtils, NUM_AUTHORITIES_PADDED };
use crate::decoder::{ CircuitBuilderPrecommitDecoder, EncodedPrecommitTarget };

#[derive(Clone, Debug)]
pub struct PrecommitTarget<C: Curve> {
    pub precommit_message: Vec<Target>,
    pub signature: EDDSASignatureTarget<C>,
    pub pub_key_idx: Target,   // The ith index in the AuthoritySetSignersTarget.pub_keys vector
}

pub struct AuthoritySetSignersTarget {
    pub pub_keys: Vec<Vec<BoolTarget>>,           // Array of pub keys (in compressed form)
    pub commitment: Vec<Target>,
    pub set_id: Target,
}

pub struct FinalizedBlockTarget {
    hash: Vec<Target>,
    num: Target,
}

pub trait CircuitBuilderGrandpaJustificationVerifier<C: Curve> {
    fn verify_justification(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: AuthoritySetSignersTarget,
        finalized_block: FinalizedBlockTarget);
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderGrandpaJustificationVerifier<C> for CircuitBuilder<F, D> {
    fn verify_justification(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: AuthoritySetSignersTarget,
        finalized_block: FinalizedBlockTarget
    ) {
        assert!(signed_precommits.len() == QUORUM_SIZE, "Number of signed precommits is not correct");
        assert!(authority_set_signers.pub_keys.len() == NUM_AUTHORITIES_PADDED, "Number of pub keys is not correct");

        // Range check the set_id.  It's a 64 bit number
        self.range_check(authority_set_signers.set_id, 64);

        // Range check the authority set commitment
        for i in 0..HASH_SIZE {
            self.range_check(authority_set_signers.commitment[i], 8);
        }

        // Range check the compressed pub keys
        // TODO: Do we really need this?
        for i in 0..NUM_AUTHORITIES {
            for j in 0..256 {
                self.range_check(authority_set_signers.pub_keys[i][j].target, 1);
            }
        }

        // Range check the indices.  They should be between 0 - (NUM_AUTHORITIES-1).
        // Doing a range check for a value that is not less than a power of 2 is a bit tricky.
        // For NUM_AUTHORITIES==10, we need to check two constraints:
        // 1) The value is less than 16.
        // 2) If the 4th significant bit is set, then the 3rd and 2nd significant bits must be zero. (Allow for the values 8 and 9)
        let zero = self.zero();
        for i in 0..QUORUM_SIZE {
            self.range_check(signed_precommits[i].pub_key_idx, 4);
            let bits = self.split_le(signed_precommits[i].pub_key_idx, 4);
            let third_second_bits = self.or(bits[2], bits[1]);
            let check_third_second_bits = self.select(bits[3], third_second_bits.target, zero);
            self.connect(check_third_second_bits, zero);
        }

        // First check to see that we have the right authority set
        // Calculate the hash for the authority set
        let hash_circuit = make_blake2b_circuit(
            self,
            NUM_AUTHORITIES * 256 + 512,   // each EDDSA pub key in compressed for is 256 bits and padding to make it fit 128 byte chunks
            HASH_SIZE,
        );

        // Input the pub keys into the hasher
        for i in 0 .. NUM_AUTHORITIES {
            assert!(authority_set_signers.pub_keys[i].len() == 256);

            for j in 0..256 {
                self.connect(hash_circuit.message[i*256+j].target, authority_set_signers.pub_keys[i][j].target);
            }
        }

        let authority_set_hash_input_length  = self.constant(F::from_canonical_usize(NUM_AUTHORITIES * 256));
        self.connect(hash_circuit.message_len, authority_set_hash_input_length);

        // Verify that the hash matches
        for i in 0 .. HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for j in 0..8 {
                self.connect(hash_circuit.digest[i*8+j].target, bits[j].target);
            }
        }

        // Now verify all of the signatures
        for i in 0..QUORUM_SIZE {
            assert!(signed_precommits[i].precommit_message.len() == ENCODED_PRECOMMIT_LENGTH, "Precommit message is not the correct length");

            // Range check the encoded msg
            for j in 0..ENCODED_PRECOMMIT_LENGTH {
                self.range_check(signed_precommits[i].precommit_message[j], 8);
            }

            // TODO:  Need to double check that the signature and pub key are range checked

            // Get the pub key
            // Random access arrays must be a power of 2, so we pad the array to 16
            let pub_key = self.random_access_bool_vec(
                signed_precommits[i].pub_key_idx,
                &authority_set_signers.pub_keys
            );
            let pub_key_uncompressed = self.decompress_point(&pub_key);

            // Verify that the precommit's fields match the claimed finalized block's
            // Note that we are currently assuming that all of the authorities sign on the finalized block,
            // as opposed to a decendent of that block.
            let decoded_precommit_msg = self.decode_precommit(EncodedPrecommitTarget(signed_precommits[i].precommit_message.clone()));
            self.connect(finalized_block.num, decoded_precommit_msg.block_number);
            for j in 0..HASH_SIZE {
                self.connect(finalized_block.hash[j], decoded_precommit_msg.block_hash[j]);
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
    use ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use ed25519::curve::ed25519::Ed25519;
    use ed25519::field::ed25519_scalar::Ed25519Scalar;
    use ed25519::gadgets::curve::{decompress_point, CircuitBuilderCurve, WitnessAffinePoint};
    use ed25519::gadgets::eddsa::{verify_message_circuit, EDDSASignatureTarget};
    use ed25519::gadgets::nonnative::{CircuitBuilderNonNative, WitnessNonNative};
    use ed25519::sha512::blake2b::{ make_blake2b_circuit };
    use ed25519_dalek::{PublicKey, Signature};
    use hex::decode;
    use num::BigUint;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    use plonky2_field::extension::Extendable;
    use plonky2_field::types::Field;

    use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget, FinalizedBlockTarget, AuthoritySetSignersTarget};
    use crate::utils::tests::{BLOCK_530527_PRECOMMIT_MESSAGE, BLOCK_530527_AUTHORITY_SIGS, BLOCK_530527_PUB_KEY_INDICES, BLOCK_530527_AUTHORITY_SET, BLOCK_530527_AUTHORITY_SET_ID, BLOCK_530527_BLOCK_HASH, BLOCK_530527_AUTHORITY_SET_COMMITMENT};
    use crate::utils::{to_bits, MAX_HEADER_SIZE, QUORUM_SIZE, HASH_SIZE, NUM_AUTHORITIES_PADDED};

    pub fn generate_precommits<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        precommit_message: Vec<Vec<u8>>,
        signatures: Vec<Vec<u8>>,
        pub_key_indices: Vec<usize>,
        pub_keys: Vec<Vec<u8>>,
    ) -> Vec<PrecommitTarget<Ed25519>> {
        let mut precommits = Vec::new();
        for i in 0..precommit_message.len() {
            let sig_r = decompress_point(&signatures[i][0..32]);
            assert!(sig_r.is_valid());

            let pub_key = &pub_keys[pub_key_indices[i]];

            let sig_s_biguint = BigUint::from_bytes_le(&signatures[i][32..64]);
            let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
            let sig = EDDSASignature { r: sig_r, s: sig_s };

            let pub_key_point = decompress_point(&pub_key[..]);
            assert!(pub_key_point.is_valid());

            let precommit_message_bits = to_bits(precommit_message[i].clone());

            assert!(verify_message(
                &precommit_message_bits,
                &sig,
                &EDDSAPublicKey(pub_key_point)
            ));

            let precommit_message_target = precommit_message[i].iter().map(|x| builder.constant(F::from_canonical_u8(*x))).collect::<Vec<_>>();

            precommits.push(
                PrecommitTarget{
                    precommit_message: precommit_message_target,
                    signature: EDDSASignatureTarget{
                        r: builder.constant_affine_point(sig_r),
                        s: builder.constant_nonnative(sig_s),
                    },
                    pub_key_idx: builder.constant(F::from_canonical_usize(pub_key_indices[i])),
                }
            );
        }
        precommits
    }

    #[test]
    fn test_avail_eddsa_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

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

        let targets = verify_message_circuit(&mut builder, sig_msg.len().try_into().unwrap());

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

        pw.set_affine_point_target(&targets.pub_key.0, &pub_key);
        pw.set_affine_point_target(&targets.sig.r, &sig_r);
        pw.set_nonnative_target(&targets.sig.s, &sig_s);

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
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let precommit_targets = generate_precommits(
            &mut builder,
            (0..QUORUM_SIZE).map(|_| BLOCK_530527_PRECOMMIT_MESSAGE.clone().to_vec()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),

        );

        let mut pub_key_targets = Vec::new();
        for i in 0..NUM_AUTHORITIES_PADDED {
            let mut pub_key_bits = Vec::new();
            let bits = to_bits(hex::decode(BLOCK_530527_AUTHORITY_SET[i]).unwrap());
            for j in 0..bits.len() {
                pub_key_bits.push(builder.constant_bool(bits[j]));
            }
            pub_key_targets.push(pub_key_bits);
        }

        let mut authority_set_commitment_target = Vec::new();
        let authority_set_bytes = hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap();
        for i in 0..HASH_SIZE {
            authority_set_commitment_target.push(builder.constant(F::from_canonical_u8(authority_set_bytes[i])));
        }

        let authority_set_id_target = builder.constant(F::from_canonical_u64(BLOCK_530527_AUTHORITY_SET_ID));

        let mut block_hash_target = Vec::new();
        let block_hash_bytes = hex::decode(BLOCK_530527_BLOCK_HASH).unwrap();
        for i in 0..block_hash_bytes.len() {
            block_hash_target.push(builder.constant(F::from_canonical_u8(block_hash_bytes[i])));
        }

        let block_number_target = builder.constant(F::from_canonical_u32(530527u32));

        builder.verify_justification(
            precommit_targets,
            AuthoritySetSignersTarget {
                pub_keys: pub_key_targets,
                commitment: authority_set_commitment_target,
                set_id: authority_set_id_target,
            },
            FinalizedBlockTarget{
                hash: block_hash_target,
                num: block_number_target,
            },
        );

        let pw = PartialWitness::new();
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
}
