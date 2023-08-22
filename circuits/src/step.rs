use crate::header_verification::CircuitBuilderHeaderVerification;
use crate::justification::{
    AuthoritySetSignersTarget, CircuitBuilderGrandpaJustificationVerifier, FinalizedBlockTarget,
    PrecommitTarget,
};
use crate::utils::HASH_SIZE;
use crate::utils::{AvailHashTarget, CircuitBuilderUtils, QUORUM_SIZE};
use curta::plonky2::field::CubicParameters;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2x::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::hash::blake2::blake2b::blake2b;

pub trait CircuitBuilderStep<F: RichField + Extendable<D>, const D: usize, C: Curve> {
    fn step<Config: GenericConfig<D, F = F, FE = F::Extension> + 'static, E: CubicParameters<F>>(
        &mut self,
        header_verification_proof: &ProofWithPublicInputsTarget<D>,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderStep<F, D, C>
    for CircuitBuilder<F, D>
{
    fn step<Config: GenericConfig<D, F = F, FE = F::Extension> + 'static, E: CubicParameters<F>>(
        &mut self,
        header_verification_proof: &ProofWithPublicInputsTarget<D>,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>,
    {
        // The public inputs are 240 bytes long;
        // Need to store each byte as BE bits
        let mut public_inputs_hash_input = Vec::new();

        let header_verification_proof_pis =
            self.parse_public_inputs(&header_verification_proof.public_inputs);

        // Input the initial head head hash into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(header_verification_proof_pis.initial_block_hash.0[i], 8);

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the updated head hash into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(header_verification_proof_pis.latest_block_hash.0[i], 8);

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the initial data root commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(
                header_verification_proof_pis
                    .initial_data_root_accumulator
                    .0[i],
                8,
            );

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the updated data root commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(
                header_verification_proof_pis.latest_data_root_accumulator.0[i],
                8,
            );

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the validator commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the validator set id into the public inputs hasher
        let mut set_id_bits = self.split_le(authority_set_signers.set_id, 64);
        set_id_bits.reverse();
        public_inputs_hash_input.append(&mut set_id_bits);

        // Input the initial block number into the public inputs hasher
        let mut initial_block_num_bits =
            self.split_le(header_verification_proof_pis.initial_block_num, 32);
        initial_block_num_bits.reverse();
        public_inputs_hash_input.append(&mut initial_block_num_bits);

        // Input the updated block number into the public inputs hasher
        let mut latest_block_num_bits =
            self.split_le(header_verification_proof_pis.latest_block_num, 32);
        latest_block_num_bits.reverse();
        public_inputs_hash_input.append(&mut latest_block_num_bits);

        // The input digest is 240 bytes.  So padded input length would be 256.
        const PUBLIC_INPUTS_MAX_SIZE: usize = 256;
        let public_inputs_hash_circuit = blake2b::<F, D, PUBLIC_INPUTS_MAX_SIZE, HASH_SIZE>(self);

        for (i, bit) in public_inputs_hash_input.iter().enumerate() {
            self.connect(bit.target, public_inputs_hash_circuit.message[i].target);
        }

        // Add the padding
        let zero = self.zero();
        for i in public_inputs_hash_input.len()..PUBLIC_INPUTS_MAX_SIZE * 8 {
            self.connect(zero, public_inputs_hash_circuit.message[i].target);
        }

        let public_inputs_input_size =
            self.constant(F::from_canonical_usize(public_inputs_hash_input.len() / 8));
        self.connect(
            public_inputs_hash_circuit.message_len,
            public_inputs_input_size,
        );

        // Verify that the public input hash matches
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(public_inputs_hash.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(
                    public_inputs_hash_circuit.digest[i * 8 + j].target,
                    bit.target,
                );
            }
        }

        let inner_cd = self.header_verification_ivc_common_data();
        let inner_vd = self.header_verification_ivc_verifier_data::<Config>();
        let inner_vd_t = self.constant_verifier_data(&inner_vd);

        self.verify_proof::<Config>(header_verification_proof, &inner_vd_t, &inner_cd);

        // Now verify the grandpa justification
        self.verify_justification::<Config, E>(
            signed_precommits,
            authority_set_signers,
            &FinalizedBlockTarget {
                num: header_verification_proof_pis.latest_block_num,
                hash: header_verification_proof_pis.latest_block_hash,
            },
        );
    }
}

#[derive(Clone)]
pub struct StepTarget<const D: usize, C: Curve> {
    pub subchain_target: ProofWithPublicInputsTarget<D>,
    pub precommits: [PrecommitTarget<C>; QUORUM_SIZE],
    pub authority_set: AuthoritySetSignersTarget<C>,
    pub public_inputs_hash: AvailHashTarget,
}

pub fn make_step_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    E: CubicParameters<F>,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> StepTarget<D, C>
where
    Config::Hasher: AlgebraicHasher<F>,
{
    let cd = builder.header_verification_ivc_common_data();
    let header_verification_proof = builder.add_virtual_proof_with_pis(&cd);

    let mut precommit_targets = Vec::new();
    for _i in 0..QUORUM_SIZE {
        precommit_targets.push(builder.add_virtual_precommit_target_safe());
    }

    let authority_set = <CircuitBuilder<F, D> as CircuitBuilderGrandpaJustificationVerifier<
        F,
        C,
        D,
    >>::add_virtual_authority_set_signers_target_safe(builder);

    let public_inputs_hash = builder.add_virtual_avail_hash_target_safe(true);

    builder.step::<Config, E>(
        &header_verification_proof,
        precommit_targets.clone(),
        &authority_set,
        &public_inputs_hash,
    );

    StepTarget {
        subchain_target: header_verification_proof,
        precommits: precommit_targets.try_into().unwrap(),
        authority_set,
        public_inputs_hash,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use log::Level;
    use plonky2::field::extension::Extendable;
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2x::ecc::ed25519::curve::ed25519::Ed25519;

    use crate::justification::{set_authority_set_pw, set_precommits_pw};
    use crate::plonky2_config::PoseidonBN128GoldilocksConfig;
    use crate::step::make_step_circuit;
    use crate::utils::tests::{
        BLOCK_530508_HEADER, BLOCK_530508_PARENT_HASH, BLOCK_530509_HEADER, BLOCK_530510_HEADER,
        BLOCK_530511_HEADER, BLOCK_530512_HEADER, BLOCK_530513_HEADER, BLOCK_530514_HEADER,
        BLOCK_530515_HEADER, BLOCK_530516_HEADER, BLOCK_530517_HEADER, BLOCK_530518_HEADER,
        BLOCK_530519_HEADER, BLOCK_530520_HEADER, BLOCK_530521_HEADER, BLOCK_530522_HEADER,
        BLOCK_530523_HEADER, BLOCK_530524_HEADER, BLOCK_530525_HEADER, BLOCK_530526_HEADER,
        BLOCK_530527_AUTHORITY_SET, BLOCK_530527_AUTHORITY_SET_COMMITMENT,
        BLOCK_530527_AUTHORITY_SET_ID, BLOCK_530527_AUTHORITY_SIGS, BLOCK_530527_HEADER,
        BLOCK_530527_PRECOMMIT_MESSAGE, BLOCK_530527_PUBLIC_INPUTS_HASH,
        BLOCK_530527_PUB_KEY_INDICES,
    };
    use crate::utils::{WitnessAvailHash, WitnessEncodedHeader, QUORUM_SIZE};

    fn gen_step_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        cd: &CircuitData<F, C, D>,
        pw: &PartialWitness<F>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut timing = TimingTree::new("step proof gen", Level::Info);
        let proof = prove::<F, C, D>(&cd.prover_only, &cd.common, pw.clone(), &mut timing);
        timing.print();

        proof.unwrap()
    }

    #[test]
    fn test_recursive_verify_step() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type E = GoldilocksCubicParameters;
        type Curve = Ed25519;

        let headers = vec![
            BLOCK_530508_HEADER.to_vec(),
            BLOCK_530509_HEADER.to_vec(),
            BLOCK_530510_HEADER.to_vec(),
            BLOCK_530511_HEADER.to_vec(),
            BLOCK_530512_HEADER.to_vec(),
            BLOCK_530513_HEADER.to_vec(),
            BLOCK_530514_HEADER.to_vec(),
            BLOCK_530515_HEADER.to_vec(),
            BLOCK_530516_HEADER.to_vec(),
            BLOCK_530517_HEADER.to_vec(),
            BLOCK_530518_HEADER.to_vec(),
            BLOCK_530519_HEADER.to_vec(),
            BLOCK_530520_HEADER.to_vec(),
            BLOCK_530521_HEADER.to_vec(),
            BLOCK_530522_HEADER.to_vec(),
            BLOCK_530523_HEADER.to_vec(),
            BLOCK_530524_HEADER.to_vec(),
            BLOCK_530525_HEADER.to_vec(),
            BLOCK_530526_HEADER.to_vec(),
            BLOCK_530527_HEADER.to_vec(),
        ];
        let head_block_hash = hex::decode(BLOCK_530508_PARENT_HASH).unwrap();
        let head_block_num = 530507;

        let public_inputs_hash = hex::decode(BLOCK_530527_PUBLIC_INPUTS_HASH).unwrap();

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let step_target = make_step_circuit::<F, D, Curve, C, E>(&mut builder);

        pw.set_avail_hash_target(
            &step_target.subchain_target.head_block_hash,
            &(head_block_hash.try_into().unwrap()),
        );
        pw.set_target(
            step_target.subchain_target.head_block_num,
            F::from_canonical_u64(head_block_num),
        );
        for (i, header) in headers.iter().enumerate() {
            pw.set_encoded_header_target(
                &step_target.subchain_target.encoded_headers[i],
                header.clone(),
            );
        }

        pw.set_avail_hash_target(
            &step_target.public_inputs_hash,
            &(public_inputs_hash.try_into().unwrap()),
        );

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            step_target.precommits.to_vec(),
            (0..QUORUM_SIZE)
                .map(|_| BLOCK_530527_PRECOMMIT_MESSAGE.clone().to_vec())
                .collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SIGS
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &step_target.authority_set,
            BLOCK_530527_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SET_ID,
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        let inner_data = builder.build();
        let inner_proof = gen_step_proof::<F, C, D>(&inner_data, &pw);
        inner_data.verify(inner_proof.clone()).unwrap();

        println!(
            "inner circuit digest is {:?}",
            inner_data.verifier_only.circuit_digest
        );

        let mut outer_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let outer_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let outer_verifier_data =
            outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(
            &outer_proof_target,
            &outer_verifier_data,
            &inner_data.common,
        );
        outer_builder.register_public_inputs(&outer_proof_target.public_inputs);
        outer_builder.register_public_inputs(&outer_verifier_data.circuit_digest.elements);

        let outer_data = outer_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&outer_proof_target, &inner_proof);
        outer_pw.set_verifier_data_target(&outer_verifier_data, &inner_data.verifier_only);

        let mut timing = TimingTree::new("step proof gen", Level::Info);
        let outer_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(
            &outer_data.prover_only,
            &outer_data.common,
            outer_pw.clone(),
            &mut timing,
        )
        .unwrap();
        timing.print();

        let ret = outer_data.verify(outer_proof.clone());

        // Verify the public inputs:

        assert_eq!(outer_proof.public_inputs.len(), 36);

        // Blake2b hash of the public inputs
        assert_eq!(
            outer_proof.public_inputs[0..32]
                .iter()
                .map(|element| u8::try_from(element.to_canonical_u64()).unwrap())
                .collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_PUBLIC_INPUTS_HASH).unwrap(),
        );

        /*  TODO:  It appears that the circuit digest changes after every different run, even if none of the code changes.  Need to find out why.
        // Step circuit's digest
        assert_eq!(
            outer_proof.public_inputs[32..36].iter()
            .map(|element| element.to_canonical_u64()).collect::<Vec<_>>(),
            [17122441374070351185, 18368451173317844989, 5752543660850962321, 1428786498560175815],
        );
        */

        for gate in outer_data.common.gates.iter() {
            println!("outer circuit: gate is {:?}", gate);
        }

        println!(
            "Recursive circuit digest is {:?}",
            outer_data.verifier_only.circuit_digest
        );

        let outer_common_circuit_data_serialized =
            serde_json::to_string(&outer_data.common).unwrap();
        fs::write(
            "step_recursive.common_circuit_data.json",
            outer_common_circuit_data_serialized,
        )
        .expect("Unable to write file");

        let outer_verifier_only_circuit_data_serialized =
            serde_json::to_string(&outer_data.verifier_only).unwrap();
        fs::write(
            "step_recursive.verifier_only_circuit_data.json",
            outer_verifier_only_circuit_data_serialized,
        )
        .expect("Unable to write file");

        let outer_proof_serialized = serde_json::to_string(&outer_proof).unwrap();
        fs::write(
            "step_recursive.proof_with_public_inputs.json",
            outer_proof_serialized,
        )
        .expect("Unable to write file");

        ret
    }
}
