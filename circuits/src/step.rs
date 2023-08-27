use crate::justification::{
    AuthoritySetSignersTarget, CircuitBuilderGrandpaJustificationVerifier, FinalizedBlockTarget,
    PrecommitTarget,
};
use crate::subchain_verification::{
    verify_header_ivc_cd, verify_header_ivc_vd, CircuitBuilderHeaderVerification,
};
use crate::utils::HASH_SIZE;
use crate::utils::{AvailHashTarget, CircuitBuilderUtils, QUORUM_SIZE};
use curta::math::prelude::CubicParameters;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::hash::sha::sha256::sha256;

pub trait CircuitBuilderStep<F: RichField + Extendable<D>, const D: usize, C: Curve> {
    fn verify_public_inputs_hash(
        &mut self,
        subchain_verification_proof: &ProofWithPublicInputsTarget<D>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    );

    fn step<Config: GenericConfig<D, F = F, FE = F::Extension> + 'static, E: CubicParameters<F>>(
        &mut self,
        subchain_verification_proof: &ProofWithPublicInputsTarget<D>,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderStep<F, D, C>
    for CircuitBuilder<F, D>
{
    fn verify_public_inputs_hash(
        &mut self,
        subchain_verification_proof: &ProofWithPublicInputsTarget<D>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    ) {
        let subchain_verification_proof_pis =
            self.parse_public_inputs(&subchain_verification_proof.public_inputs);

        let mut public_inputs_hash_input = Vec::new();

        // Input the initial head head hash into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits =
                self.split_le(subchain_verification_proof_pis.initial_block_hash.0[i], 8);

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.extend(bits);
        }

        // Input the updated head hash into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(subchain_verification_proof_pis.latest_block_hash.0[i], 8);

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.extend(bits);
        }

        // Input the initial data root commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(
                subchain_verification_proof_pis
                    .initial_data_root_accumulator
                    .0[i],
                8,
            );

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.extend(bits);
        }

        // Input the updated data root commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(
                subchain_verification_proof_pis
                    .latest_data_root_accumulator
                    .0[i],
                8,
            );

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.extend(bits);
        }

        // Input the validator commitment into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);
            bits.reverse();
            public_inputs_hash_input.extend(bits);
        }

        // Input the validator set id into the public inputs hasher
        let mut set_id_bits = self.split_le(authority_set_signers.set_id, 64);
        set_id_bits.reverse();
        public_inputs_hash_input.extend(set_id_bits);

        // Input the initial block number into the public inputs hasher
        let mut initial_block_num_bits =
            self.split_le(subchain_verification_proof_pis.initial_block_num, 32);
        initial_block_num_bits.reverse();
        public_inputs_hash_input.extend(initial_block_num_bits);

        // Input the updated block number into the public inputs hasher
        let mut latest_block_num_bits =
            self.split_le(subchain_verification_proof_pis.latest_block_num, 32);
        latest_block_num_bits.reverse();
        public_inputs_hash_input.extend(latest_block_num_bits);

        let calculated_public_inputs_hash = sha256(self, &public_inputs_hash_input);

        // Verify that the public input hash matches
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(public_inputs_hash.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(calculated_public_inputs_hash[i * 8 + j].target, bit.target);
            }
        }
    }

    fn step<Config: GenericConfig<D, F = F, FE = F::Extension> + 'static, E: CubicParameters<F>>(
        &mut self,
        subchain_verification_proof: &ProofWithPublicInputsTarget<D>,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget<C>,
        public_inputs_hash: &AvailHashTarget,
    ) where
        Config::Hasher: AlgebraicHasher<F>,
    {
        // First verify public inputs hash
        self.verify_public_inputs_hash(
            subchain_verification_proof,
            authority_set_signers,
            public_inputs_hash,
        );

        let inner_cd = verify_header_ivc_cd();
        let inner_vd = verify_header_ivc_vd::<Config, F, D>();
        let inner_vd_t = self.constant_verifier_data(&inner_vd);

        self.verify_proof::<Config>(subchain_verification_proof, &inner_vd_t, &inner_cd);

        let subchain_verification_proof_pis =
            self.parse_public_inputs(&subchain_verification_proof.public_inputs);

        // Now verify the grandpa justification
        self.verify_justification::<Config, E>(
            signed_precommits,
            authority_set_signers,
            &FinalizedBlockTarget {
                num: subchain_verification_proof_pis.latest_block_num,
                hash: subchain_verification_proof_pis.latest_block_hash,
            },
        );
    }
}

#[derive(Clone)]
pub struct StepTarget<const D: usize, C: Curve> {
    pub subchain_verification_proof: ProofWithPublicInputsTarget<D>,
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
    let cd = verify_header_ivc_cd();
    let subchain_verification_proof = builder.add_virtual_proof_with_pis(&cd);

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
        &subchain_verification_proof,
        precommit_targets.clone(),
        &authority_set,
        &public_inputs_hash,
    );

    StepTarget {
        subchain_verification_proof,
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
    use plonky2::field::types::PrimeField64;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;

    use crate::justification::{
        set_authority_set_pw, set_precommits_pw, CircuitBuilderGrandpaJustificationVerifier,
    };
    use crate::plonky2_config::PoseidonBN128GoldilocksConfig;
    use crate::step::{make_step_circuit, CircuitBuilderStep};
    use crate::subchain_verification::tests::retrieve_subchain_verification_proof;
    use crate::subchain_verification::verify_header_ivc_cd;
    use crate::testing_utils::tests::{
        BLOCK_272515_AUTHORITY_SET, BLOCK_272515_AUTHORITY_SET_COMMITMENT,
        BLOCK_272515_AUTHORITY_SET_ID, BLOCK_272515_AUTHORITY_WEIGHTS,
        BLOCK_272515_PRECOMMIT_MESSAGE, BLOCK_272515_PUBLIC_INPUTS_HASH, BLOCK_272515_SIGNERS,
        BLOCK_272515_SIGS,
    };
    use crate::utils::{CircuitBuilderUtils, WitnessAvailHash, QUORUM_SIZE};

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
    fn test_verify_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let subchain_verification_proof =
            retrieve_subchain_verification_proof().expect("subchain proof generation failed");

        let subchain_verification_proof_pis =
            builder.add_virtual_proof_with_pis(&verify_header_ivc_cd::<F, D>());
        let authority_set_signers = builder.add_virtual_authority_set_signers_target_safe();
        let public_inputs_hash = builder.add_virtual_avail_hash_target_safe(false);

        builder.verify_public_inputs_hash(
            &subchain_verification_proof_pis,
            &authority_set_signers,
            &public_inputs_hash,
        );

        pw.set_proof_with_pis_target(
            &subchain_verification_proof_pis,
            &subchain_verification_proof,
        );

        pw.set_avail_hash_target(
            &public_inputs_hash,
            hex::decode(BLOCK_272515_PUBLIC_INPUTS_HASH)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &authority_set_signers,
            BLOCK_272515_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_AUTHORITY_WEIGHTS.to_vec(),
            BLOCK_272515_AUTHORITY_SET_ID,
            hex::decode(BLOCK_272515_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        let data = builder.build();
        let proof = gen_step_proof::<F, C, D>(&data, &pw);
        data.verify(proof)
    }

    #[test]
    fn test_recursive_verify_step() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type E = GoldilocksCubicParameters;
        type Curve = Ed25519;

        let public_inputs_hash = hex::decode(BLOCK_272515_PUBLIC_INPUTS_HASH).unwrap();

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let step_target = make_step_circuit::<F, D, Curve, C, E>(&mut builder);

        let subchain_verification_proof =
            retrieve_subchain_verification_proof().expect("subchain proof generation failed");

        pw.set_proof_with_pis_target(
            &step_target.subchain_verification_proof,
            &subchain_verification_proof,
        );

        pw.set_avail_hash_target(
            &step_target.public_inputs_hash,
            &(public_inputs_hash.try_into().unwrap()),
        );

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            step_target.precommits.to_vec(),
            (0..QUORUM_SIZE)
                .map(|_| hex::decode(BLOCK_272515_PRECOMMIT_MESSAGE).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_SIGS
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_SIGNERS
                .iter()
                .map(|x| hex::decode(x).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &step_target.authority_set,
            BLOCK_272515_AUTHORITY_SET
                .iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<_>>(),
            BLOCK_272515_AUTHORITY_WEIGHTS.to_vec(),
            BLOCK_272515_AUTHORITY_SET_ID,
            hex::decode(BLOCK_272515_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        println!("building the step circuit");
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
            hex::decode(BLOCK_272515_PUBLIC_INPUTS_HASH).unwrap(),
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
