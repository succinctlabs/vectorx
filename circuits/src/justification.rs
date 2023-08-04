use curta::plonky2::field::CubicParameters;
use num::BigUint;

use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericConfig, AlgebraicHasher};
use plonky2_gadgets::ecc::ed25519::curve::curve_types::Curve;
use plonky2_gadgets::ecc::ed25519::curve::eddsa::{EDDSASignature, EDDSAPublicKey, verify_message};
use plonky2_gadgets::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2_gadgets::ecc::ed25519::gadgets::curve::{CircuitBuilderCurve, decompress_point};
use plonky2_gadgets::ecc::ed25519::gadgets::eddsa::verify_signatures_circuit;
use plonky2_gadgets::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2_gadgets::hash::blake2::blake2b::blake2b;
use plonky2_gadgets::num::biguint::{CircuitBuilderBiguint, WitnessBigUint};
use plonky2_gadgets::num::nonnative::nonnative::CircuitBuilderNonNative;

use crate::utils::{
    CircuitBuilderUtils,
    AvailHashTarget,
    QUORUM_SIZE,
    HASH_SIZE,
    ENCODED_PRECOMMIT_LENGTH,
    NUM_AUTHORITIES,
    NUM_AUTHORITIES_PADDED,
    PUB_KEY_SIZE,
    to_bits, CHUNK_128_BYTES
};
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

pub trait CircuitBuilderGrandpaJustificationVerifier<
        F: RichField + Extendable<D>,
        C: Curve,
        const D: usize>
{
    fn add_virtual_precommit_target_safe(&mut self) -> PrecommitTarget<C>;

    fn add_virtual_authority_set_signers_target_safe(&mut self) -> AuthoritySetSignersTarget;

    fn verify_justification<
        Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        E: CubicParameters<F>>
    (
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        finalized_block: &FinalizedBlockTarget
    )
    where
        Config::Hasher: AlgebraicHasher<F>
    ;    
}

impl<F: RichField + Extendable<D>, C: Curve, const D: usize> CircuitBuilderGrandpaJustificationVerifier<F, C, D> for CircuitBuilder<F, D> {
    fn add_virtual_precommit_target_safe(&mut self) -> PrecommitTarget<C> {
        let precommit_message = self.add_virtual_targets(ENCODED_PRECOMMIT_LENGTH);
        for byte in precommit_message.iter().take(ENCODED_PRECOMMIT_LENGTH) {
            self.range_check(*byte, 8);
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
    fn verify_justification<
            Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
            E: CubicParameters<F>>
    (    
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        finalized_block: &FinalizedBlockTarget
    )
    where
        Config::Hasher: AlgebraicHasher<F>,
    {	
        // First check to see that we have the right authority set
        // Calculate the hash for the authority set
        // Note that the input to this circuit must be of chunks of 128 bytes, so it may need to be padded.
        const AUTHORITIES_INPUT_LENGTH: usize = NUM_AUTHORITIES * PUB_KEY_SIZE;
        const AUTHORITIES_INPUT_PADDING: usize = (CHUNK_128_BYTES - (AUTHORITIES_INPUT_LENGTH % CHUNK_128_BYTES)) % CHUNK_128_BYTES;
        const AUTHORITIES_INPUT_PADDED_LENGTH: usize = AUTHORITIES_INPUT_LENGTH + AUTHORITIES_INPUT_PADDING;
        let hash_circuit = blake2b::<F, D, AUTHORITIES_INPUT_PADDED_LENGTH, HASH_SIZE>(
            self,
        );

        // Input the pub keys into the hasher
        for i in 0 .. NUM_AUTHORITIES {
            for j in 0..PUB_KEY_SIZE {
                // covert bytes to BE bits for the BLAKE2B circuit
                let mut bits = self.split_le(authority_set_signers.pub_keys[i].0[j], 8);
                bits.reverse();
                for (k, bit) in bits.iter().enumerate().take(8) {
                    self.connect(hash_circuit.message[i*256 + j*8 + k].target, bit.target);
                }
            }
        }

        // Add the padding
        let zero = self.zero();
	for i in AUTHORITIES_INPUT_LENGTH..AUTHORITIES_INPUT_PADDED_LENGTH {
            self.connect(hash_circuit.message[i].target, zero);
        }

        // Length of the input in bytes
	let authority_set_hash_input_length = self.constant(F::from_canonical_usize(NUM_AUTHORITIES * PUB_KEY_SIZE));
        self.connect(hash_circuit.message_len, authority_set_hash_input_length);

        // Verify that the hash matches
        for i in 0 .. HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(hash_circuit.digest[i*8+j].target, bit.target);
            }
        }

        // TODO:  Need to check for dupes of the pub_key_idx field

	let verify_sigs_targets = verify_signatures_circuit::<F, C, E, Config, D>(self, QUORUM_SIZE, ENCODED_PRECOMMIT_LENGTH as u128);

        // Now verify all of the signatures
        for (i, signed_precommit) in signed_precommits.iter().enumerate().take(QUORUM_SIZE) {
            // Get the pub key
            // Random access arrays must be a power of 2, so we pad the array to 16
            let mut pub_key = self.random_access_vec(
                signed_precommit.pub_key_idx,
                &authority_set_signers.pub_keys.iter().map(|x| x.0.to_vec()).collect::<Vec<_>>(),
            );

            // Need to reverse the byte endianess of the pub key
            pub_key.reverse();
            let mut pub_key_bits = Vec::new();

            for byte in pub_key.iter().take(PUB_KEY_SIZE) {
                let mut bits = self.split_le(*byte, 8);
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
                for bit in bits.iter().take(8) {
                    encoded_msg_bits.push(*bit);
                }
            }

            for (j, bit) in encoded_msg_bits.iter().enumerate().take(ENCODED_PRECOMMIT_LENGTH * 8) {
	            self.connect(verify_sigs_targets.msgs[i][j].target, bit.target);
            }

            self.connect_affine_point(&verify_sigs_targets.sigs[i].r,&signed_precommits[i].signature.r);
            self.connect_nonnative(&verify_sigs_targets.sigs[i].s,&signed_precommits[i].signature.s);
            self.connect_affine_point(&verify_sigs_targets.pub_keys[i].0, &pub_key_uncompressed);
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
    for (i, pub_key) in pub_keys.iter().enumerate() {
        let authority_set_signers_target = &authority_set_target.pub_keys[i];

        assert!(pub_key.len() == PUB_KEY_SIZE);
        assert!(pub_key.len() == authority_set_signers_target.0.len());

        pub_key.iter()
        .zip(authority_set_signers_target.0.iter())
        .for_each(|(pub_key_byte, pub_key_byte_target)| pw.set_target(*pub_key_byte_target, F::from_canonical_u8(*pub_key_byte)));
    }

    pw.set_target(authority_set_target.set_id, F::from_canonical_u64(authority_set_id));

    for (i, byte) in authority_set_commitment.iter().enumerate().take(HASH_SIZE) {
        pw.set_target(authority_set_target.commitment.0[i], F::from_canonical_u8(*byte));
    }
}

#[cfg(test)]
pub (crate) mod tests {
    use std::time::SystemTime;

    use anyhow::Result;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use curta::plonky2::field::CubicParameters;
    use ed25519_dalek::{PublicKey, Signature};
    use num::BigUint;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::{Field, PrimeField};
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig, AlgebraicHasher};
    use plonky2_gadgets::num::biguint::WitnessBigUint;
    use plonky2_gadgets::ecc::ed25519::curve::curve_types::Curve;
    use plonky2_gadgets::ecc::ed25519::curve::ed25519::Ed25519;
    use plonky2_gadgets::ecc::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use plonky2_gadgets::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
    use plonky2_gadgets::ecc::ed25519::gadgets::curve::decompress_point;
    use plonky2_gadgets::ecc::ed25519::gadgets::eddsa::{EDDSATargets, verify_signatures_circuit};

    use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget, FinalizedBlockTarget, AuthoritySetSignersTarget, set_precommits_pw, set_authority_set_pw};
    use crate::utils::tests::{BLOCK_530527_PRECOMMIT_MESSAGE, BLOCK_530527_AUTHORITY_SIGS, BLOCK_530527_PUB_KEY_INDICES, BLOCK_530527_AUTHORITY_SET, BLOCK_530527_AUTHORITY_SET_ID, BLOCK_530527_BLOCK_HASH, BLOCK_530527_AUTHORITY_SET_COMMITMENT};
    use crate::utils::{to_bits, CircuitBuilderUtils, WitnessAvailHash, QUORUM_SIZE};

    pub struct JustificationTarget<C: Curve> {
        precommit_targets: Vec<PrecommitTarget<C>>,
        authority_set_signers: AuthoritySetSignersTarget,
        finalized_block: FinalizedBlockTarget,
    }

    pub fn make_justification_circuit<
        F: RichField + Extendable<D>,
        const D: usize,
        C: Curve,
        Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        E: CubicParameters<F>>
    (
        builder: &mut CircuitBuilder::<F, D>
    ) -> JustificationTarget<C>
    where
        Config::Hasher: AlgebraicHasher<F>,
    {
        let mut precommit_targets = Vec::new();
        for _i in 0..QUORUM_SIZE {
            precommit_targets.push(builder.add_virtual_precommit_target_safe());
        }

        let authority_set = <CircuitBuilder<F, D> as CircuitBuilderGrandpaJustificationVerifier<F, C, D>>::add_virtual_authority_set_signers_target_safe(builder);

        let finalized_block_hash = builder.add_virtual_avail_hash_target_safe(false);
        let finalized_block_num = builder.add_virtual_target();

        builder.verify_justification::<Config, E>(
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

    #[test]
    fn test_avail_eddsa_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type E = GoldilocksCubicParameters;
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

        let targets: EDDSATargets<Curve> = verify_signatures_circuit::<F, Curve, E, C, D>(&mut builder, 1, sig_msg.len().try_into().unwrap());

        let mut msg = Vec::with_capacity(sig_msg.len());
        for byte in sig_msg.iter() {
            msg.push(CircuitBuilder::constant(&mut builder, F::from_canonical_u8(*byte)));
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
            builder.connect(msg_bits[i].target, targets.msgs[0][i].target)
        }

        pw.set_biguint_target(&targets.pub_keys[0].0.x.value, &pub_key.x.to_canonical_biguint());
        pw.set_biguint_target(&targets.pub_keys[0].0.y.value, &pub_key.y.to_canonical_biguint());

        pw.set_biguint_target(&targets.sigs[0].r.x.value, &sig_r.x.to_canonical_biguint());
        pw.set_biguint_target(&targets.sigs[0].r.y.value, &sig_r.y.to_canonical_biguint());

        pw.set_biguint_target(&targets.sigs[0].s.value, &sig_s.to_canonical_biguint());

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
    fn test_grandpa_verification_simple() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type E = GoldilocksCubicParameters;
        type Curve = Ed25519;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw = PartialWitness::new();

        let justification_target = make_justification_circuit::<F, D, Curve, C, E>(&mut builder);

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

        let block_hash_bytes = hex::decode(BLOCK_530527_BLOCK_HASH).unwrap();
        pw.set_avail_hash_target(&justification_target.finalized_block.hash, &(block_hash_bytes.try_into().unwrap()));
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
}
