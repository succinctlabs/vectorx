use curta::plonky2::field::CubicParameters;
use num::BigUint;

use plonky2::field::extension::Extendable;
use plonky2::field::types::{Field, PrimeField};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{Target, BoolTarget};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
use plonky2x::ecc::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
use plonky2x::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::ecc::ed25519::gadgets::eddsa::verify_signatures_circuit;
use plonky2x::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::hash::blake2::blake2b::blake2b;
use plonky2x::num::biguint::{CircuitBuilderBiguint, WitnessBigUint};
use plonky2x::num::nonnative::nonnative::CircuitBuilderNonNative;

use crate::decoder::{CircuitBuilderPrecommitDecoder, EncodedPrecommitTarget};
use crate::utils::{
    to_bits, AvailHashTarget, CircuitBuilderUtils, CHUNK_128_BYTES, ENCODED_PRECOMMIT_LENGTH,
    HASH_SIZE, NUM_AUTHORITIES, PUB_KEY_SIZE, QUORUM_SIZE,
};

#[derive(Clone, Debug)]
pub struct PrecommitTarget<C: Curve> {
    pub precommit_message: [Target; ENCODED_PRECOMMIT_LENGTH],
    pub signature: EDDSASignatureTarget<C>,
    pub pub_key: AffinePointTarget<C>,
}

#[derive(Clone)]
pub struct AuthoritySetSignersTarget<C: Curve> {
    pub pub_keys: [AffinePointTarget<C>; NUM_AUTHORITIES], // Array of pub keys (in compressed form)
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
    const D: usize,
>
{
    fn add_virtual_precommit_target_safe(&mut self) -> PrecommitTarget<C>;

    fn add_virtual_authority_set_signers_target_safe(&mut self) -> AuthoritySetSignersTarget<C>;

    fn verify_justification<
        Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        E: CubicParameters<F>,
    >(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        finalized_block: &FinalizedBlockTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, C: Curve, const D: usize>
    CircuitBuilderGrandpaJustificationVerifier<F, C, D> for CircuitBuilder<F, D>
{
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

        let signature = EDDSASignatureTarget { r: sig_r, s: sig_s };

        let pub_key = self.add_virtual_affine_point_target();

        PrecommitTarget {
            precommit_message: precommit_message.try_into().unwrap(),
            signature,
            pub_key,
        }
    }

    fn add_virtual_authority_set_signers_target_safe(&mut self) -> AuthoritySetSignersTarget<C> {
        let mut pub_keys = Vec::new();
        for _i in 0..NUM_AUTHORITIES {
            pub_keys.push(self.add_virtual_affine_point_target());
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
        E: CubicParameters<F>,
    >(
        &mut self,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        finalized_block: &FinalizedBlockTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>,
    {
        // First check to see that we have the right authority set
        // Calculate the hash for the authority set
        // Note that the input to this circuit must be of chunks of 128 bytes, so it may need to be padded.
        const AUTHORITIES_INPUT_LENGTH: usize = NUM_AUTHORITIES * PUB_KEY_SIZE;
        const AUTHORITIES_INPUT_PADDING: usize =
            (CHUNK_128_BYTES - (AUTHORITIES_INPUT_LENGTH % CHUNK_128_BYTES)) % CHUNK_128_BYTES;
        const AUTHORITIES_INPUT_PADDED_LENGTH: usize =
            AUTHORITIES_INPUT_LENGTH + AUTHORITIES_INPUT_PADDING;
        let hash_circuit = blake2b::<F, D, AUTHORITIES_INPUT_PADDED_LENGTH, HASH_SIZE>(self);

        /*
        // Input the pub keys into the hasher
        for i in 0..NUM_AUTHORITIES {
            let mut compressed_pub_key = self.compress_point(&authority_set_signers.pub_keys[i]);

            // Reverse the byte endian order
            for (byte_num, bits) in compressed_pub_key
                .bit_targets
                .chunks_mut(8)
                .rev()
                .enumerate()
            {
                for (bit_num, bit) in bits.iter().enumerate() {
                    self.connect(
                        hash_circuit.message[i * 256 + byte_num * 8 + bit_num].target,
                        bit.target,
                    );
                }
            }
        }

        // Add the padding
        let zero = self.zero();
        for i in AUTHORITIES_INPUT_LENGTH * 8..AUTHORITIES_INPUT_PADDED_LENGTH * 8 {
            self.connect(hash_circuit.message[i].target, zero);
        }

        // Length of the input in bytes
        let authority_set_hash_input_length =
            self.constant(F::from_canonical_usize(NUM_AUTHORITIES * PUB_KEY_SIZE));
        self.connect(hash_circuit.message_len, authority_set_hash_input_length);

        // Verify that the hash matches
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(hash_circuit.digest[i * 8 + j].target, bit.target);
            }
        }
        */

        /*
        // First verify that each signed precommit is using a pub key from the authority set
        for signed_precommit in signed_precommits.iter() {
            let mut is_valid_pub_key = self._false();
            let true_t = self._true();
            for auth_key in authority_set_signers.pub_keys.iter() {
                let is_equal = self.is_equal_affine_point(auth_key, &signed_precommit.pub_key);
                is_valid_pub_key = BoolTarget::new_unsafe(self.select(is_equal, true_t.target, is_valid_pub_key.target));
            }

            self.assert_one(is_valid_pub_key.target);
        }

        // Verify there are no duplicate pub key within the signed_precommits
        for i in 0..QUORUM_SIZE {
            for j in i + 1..QUORUM_SIZE {
                let is_equal = self.is_equal_affine_point(
                    &signed_precommits[i].pub_key,
                    &signed_precommits[j].pub_key,
                );
                self.assert_zero(is_equal.target);
            }
        }
        */

        let verify_sigs_targets = verify_signatures_circuit::<F, C, E, Config, D>(
            self,
            QUORUM_SIZE,
            ENCODED_PRECOMMIT_LENGTH as u128,
        );

        // Now verify all of the signatures
        for (i, signed_precommit) in signed_precommits.iter().enumerate().take(QUORUM_SIZE) {
            // Verify that the precommit's fields match the claimed finalized block's
            // Note that we are currently assuming that all of the authorities sign on the finalized block,
            // as opposed to a decendent of that block.
            let decoded_precommit_msg = self.decode_precommit(EncodedPrecommitTarget(
                signed_precommits[i].precommit_message.to_vec(),
            ));
            self.connect(finalized_block.num, decoded_precommit_msg.block_number);
            for j in 0..HASH_SIZE {
                self.connect(
                    finalized_block.hash.0[j],
                    decoded_precommit_msg.block_hash[j],
                );
            }
            self.connect(
                authority_set_signers.set_id,
                decoded_precommit_msg.authority_set_id,
            );

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

            for (j, bit) in encoded_msg_bits
                .iter()
                .enumerate()
                .take(ENCODED_PRECOMMIT_LENGTH * 8)
            {
                self.connect(verify_sigs_targets.msgs[i][j].target, bit.target);
            }

            self.connect_affine_point(
                &verify_sigs_targets.sigs[i].r,
                &signed_precommits[i].signature.r,
            );
            self.connect_nonnative(
                &verify_sigs_targets.sigs[i].s,
                &signed_precommits[i].signature.s,
            );
            self.connect_affine_point(&verify_sigs_targets.pub_keys[i].0, &signed_precommit.pub_key);
        }
    }
}

pub fn set_precommits_pw<F: RichField + Extendable<D>, const D: usize, C: Curve>(
    pw: &mut PartialWitness<F>,
    precommit_targets: Vec<PrecommitTarget<C>>,
    precommit_messages: Vec<Vec<u8>>,
    signatures: Vec<Vec<u8>>,
    signer_pub_keys: Vec<Vec<u8>>,
    pub_keys: Vec<Vec<u8>>,
) {
    assert!(precommit_targets.len() == QUORUM_SIZE);
    assert!(precommit_messages.len() == QUORUM_SIZE);
    assert!(signatures.len() == QUORUM_SIZE);
    assert!(signer_pub_keys.len() == QUORUM_SIZE);
    assert!(pub_keys.len() == NUM_AUTHORITIES);

    // Set the precommit partial witness values
    for i in 0..precommit_messages.len() {
        let sig_r = AffinePoint::new_from_compressed_point(&signatures[i][0..32]);
        assert!(sig_r.is_valid());

        let pub_key = &signer_pub_keys[i];

        let sig_s_biguint = BigUint::from_bytes_le(&signatures[i][32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        let pub_key_point = AffinePoint::new_from_compressed_point(&pub_key[..]);
        assert!(pub_key_point.is_valid());

        let precommit_message_bits = to_bits(precommit_messages[i].clone());

        assert!(verify_message(
            &precommit_message_bits,
            &sig,
            &EDDSAPublicKey(pub_key_point)
        ));

        let precommit_target = &precommit_targets[i];
        pw.set_biguint_target(
            &precommit_target.signature.r.x.value,
            &sig.r.x.to_canonical_biguint(),
        );
        pw.set_biguint_target(
            &precommit_target.signature.r.y.value,
            &sig.r.y.to_canonical_biguint(),
        );
        pw.set_biguint_target(
            &precommit_target.signature.s.value,
            &sig_s.to_canonical_biguint(),
        );

        pw.set_biguint_target(
            &precommit_target.pub_key.x.value,
            &pub_key_point.x.to_canonical_biguint(),
        );
        pw.set_biguint_target(
            &precommit_target.pub_key.y.value,
            &pub_key_point.y.to_canonical_biguint(),
        );

        assert!(precommit_messages[i].len() == ENCODED_PRECOMMIT_LENGTH);
        assert!(precommit_messages[i].len() == precommit_target.precommit_message.len());

        precommit_messages[i]
            .iter()
            .zip(precommit_target.precommit_message.iter())
            .for_each(|(msg_byte, msg_byte_target)| {
                pw.set_target(*msg_byte_target, F::from_canonical_u8(*msg_byte))
            });
    }
}

pub fn set_authority_set_pw<F: RichField + Extendable<D>, const D: usize, C: Curve>(
    pw: &mut PartialWitness<F>,
    authority_set_target: &AuthoritySetSignersTarget<C>,
    pub_keys: Vec<Vec<u8>>,
    authority_set_id: u64,
    authority_set_commitment: Vec<u8>,
) {
    assert!(pub_keys.len() == NUM_AUTHORITIES);
    assert!(authority_set_target.pub_keys.len() == NUM_AUTHORITIES);

    // Set the authority set partial witness values
    for (i, pub_key) in pub_keys.iter().enumerate() {
        let authority_set_signers_target = &authority_set_target.pub_keys[i];
        let pub_key_affine_point = AffinePoint::<C>::new_from_compressed_point(&pub_key[..]);

        pw.set_biguint_target(
            &authority_set_signers_target.x.value,
            &pub_key_affine_point.x.to_canonical_biguint(),
        );
        pw.set_biguint_target(
            &authority_set_signers_target.y.value,
            &pub_key_affine_point.y.to_canonical_biguint(),
        );
    }

    pw.set_target(
        authority_set_target.set_id,
        F::from_canonical_u64(authority_set_id),
    );

    for (i, byte) in authority_set_commitment.iter().enumerate().take(HASH_SIZE) {
        pw.set_target(
            authority_set_target.commitment.0[i],
            F::from_canonical_u8(*byte),
        );
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;

    use anyhow::Result;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use curta::plonky2::field::CubicParameters;
    use log::Level;
    use num::BigUint;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::{Field, PrimeField};
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2x::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
    use plonky2x::ecc::ed25519::curve::ed25519::Ed25519;
    use plonky2x::ecc::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use plonky2x::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
    use plonky2x::ecc::ed25519::gadgets::eddsa::{verify_signatures_circuit, EDDSATargets};
    use plonky2x::num::biguint::WitnessBigUint;

    use crate::justification::{
        set_authority_set_pw, set_precommits_pw, AuthoritySetSignersTarget,
        CircuitBuilderGrandpaJustificationVerifier, FinalizedBlockTarget, PrecommitTarget,
    };
    use crate::testing_utils::tests::{BLOCK_272515_PRECOMMIT_MESSAGE, BLOCK_272515_SIGS, BLOCK_272515_AUTHORITY_SET, BLOCK_272515_AUTHORITY_SET_ID, BLOCK_272515_AUTHORITY_SET_COMMITMENT, BLOCK_HASHES, BLOCK_272515_SIGNERS, HEAD_BLOCK_NUM, NUM_BLOCKS};
    use crate::utils::{to_bits, CircuitBuilderUtils, WitnessAvailHash, QUORUM_SIZE};

    pub struct JustificationTarget<C: Curve> {
        precommit_targets: Vec<PrecommitTarget<C>>,
        authority_set_signers: AuthoritySetSignersTarget<C>,
        finalized_block: FinalizedBlockTarget,
    }

    pub fn make_justification_circuit<
        F: RichField + Extendable<D>,
        const D: usize,
        C: Curve,
        Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        E: CubicParameters<F>,
    >(
        builder: &mut CircuitBuilder<F, D>,
    ) -> JustificationTarget<C>
    where
        Config::Hasher: AlgebraicHasher<F>,
    {
        let mut precommit_targets = Vec::new();
        for _i in 0..QUORUM_SIZE {
            precommit_targets.push(builder.add_virtual_precommit_target_safe());
        }

        let authority_set = <CircuitBuilder<F, D> as CircuitBuilderGrandpaJustificationVerifier<
            F,
            C,
            D,
        >>::add_virtual_authority_set_signers_target_safe(builder);

        let finalized_block_hash = builder.add_virtual_avail_hash_target_safe(false);
        let finalized_block_num = builder.add_virtual_target();

        builder.verify_justification::<Config, E>(
            precommit_targets.clone(),
            &authority_set,
            &FinalizedBlockTarget {
                hash: finalized_block_hash.clone(),
                num: finalized_block_num,
            },
        );

        JustificationTarget {
            precommit_targets,
            authority_set_signers: authority_set,
            finalized_block: FinalizedBlockTarget {
                hash: finalized_block_hash,
                num: finalized_block_num,
            },
        }
    }

    #[test]
    fn test_verify_signatures_circuit() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type E = GoldilocksCubicParameters;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let sig_msg = hex::decode("0162f1aaf6297b86b3749448d66cc43deada49940c3912a4ec4916344058e8f0655f180800680b000000000000f001000000000000").unwrap();
        let sig_msg_bits = to_bits(sig_msg.to_vec());

        let signature= hex::decode("3ebc508daaf5edd7a4b4779743ce9241519aa8940264c2be4f39dfd0f7a4f2c4c587752fbc35d6d34b8ecd494dfe101e49e6c1ccb0e41ff2aa52bc481fcd3e0c").unwrap();
        let sig_r = AffinePoint::new_from_compressed_point(&signature[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&signature[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        let pubkey_bytes =
            hex::decode("0e0945b2628f5c3b4e2a6b53df997fc693344af985b11e3054f36a384cc4114b")
                .unwrap();
        let pub_key = AffinePoint::new_from_compressed_point(&pubkey_bytes[..]);
        assert!(pub_key.is_valid());

        assert!(verify_message(
            &sig_msg_bits,
            &sig,
            &EDDSAPublicKey(pub_key)
        ));

        let targets: EDDSATargets<Curve> = verify_signatures_circuit::<F, Curve, E, C, D>(
            &mut builder,
            1,
            sig_msg.len().try_into().unwrap(),
        );

        let mut msg = Vec::with_capacity(sig_msg.len());
        for byte in sig_msg.iter() {
            msg.push(CircuitBuilder::constant(
                &mut builder,
                F::from_canonical_u8(*byte),
            ));
        }

        let mut msg_bits = Vec::with_capacity(sig_msg.len() * 8);
        for i in 0..sig_msg.len() {
            let mut bits = builder.split_le(msg[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for bit in bits.iter().take(8) {
                msg_bits.push(*bit);
            }
        }

        for (i, bit) in msg_bits.iter().enumerate() {
            builder.connect(bit.target, targets.msgs[0][i].target)
        }

        pw.set_biguint_target(
            &targets.pub_keys[0].0.x.value,
            &pub_key.x.to_canonical_biguint(),
        );
        pw.set_biguint_target(
            &targets.pub_keys[0].0.y.value,
            &pub_key.y.to_canonical_biguint(),
        );

        pw.set_biguint_target(&targets.sigs[0].r.x.value, &sig_r.x.to_canonical_biguint());
        pw.set_biguint_target(&targets.sigs[0].r.y.value, &sig_r.y.to_canonical_biguint());

        pw.set_biguint_target(&targets.sigs[0].s.value, &sig_s.to_canonical_biguint());

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
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

        let mut reverse_index: HashMap<&str, usize> = HashMap::new();

        // Populate the HashMap with the reverse index
        for (index, &value) in BLOCK_272515_AUTHORITY_SET.iter().enumerate() {
            reverse_index.insert(value, index);
        }

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            justification_target.precommit_targets,
            (0..QUORUM_SIZE)
                .map(|_| hex::decode(BLOCK_272515_PRECOMMIT_MESSAGE).unwrap())
                .collect::<Vec<_>>(),
                BLOCK_272515_SIGS
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_SIGNERS.iter().map(|x| hex::decode(x).unwrap()).collect::<Vec<_>>(),
            BLOCK_272515_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &justification_target.authority_set_signers,
            BLOCK_272515_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
                BLOCK_272515_AUTHORITY_SET_ID,
            hex::decode(BLOCK_272515_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        let block_hash_bytes = hex::decode(BLOCK_HASHES[BLOCK_HASHES.len() - 1]).unwrap();
        pw.set_avail_hash_target(
            &justification_target.finalized_block.hash,
            &(block_hash_bytes.try_into().unwrap()),
        );
        pw.set_target(
            justification_target.finalized_block.num,
            F::from_canonical_u32(HEAD_BLOCK_NUM + (NUM_BLOCKS as u32) - 1),
        );

        let data = builder.build::<C>();
        let mut timing = TimingTree::new("grandpa proof gen", Level::Info);
        let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing).unwrap();
        timing.print();
        data.verify(proof)
    }
}
