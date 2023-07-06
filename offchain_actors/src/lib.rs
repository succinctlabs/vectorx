use log::Level;
use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;
use plonky2::{plonk::{circuit_data::{CircuitData, CircuitConfig}, config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_builder::CircuitBuilder, prover::prove}, iop::witness::WitnessWrite, util::timing::TimingTree};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::PartialWitness;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use succinct_avail_proof_generators::{
    step::{make_step_circuit, StepTarget},
    justification::{set_precommits_pw, set_authority_set_pw},
    utils::{WitnessAvailHash, WitnessEncodedHeader, QUORUM_SIZE},
    plonky2_config::PoseidonBN128GoldilocksConfig
};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type Curve = Ed25519;

pub type RecC = PoseidonBN128GoldilocksConfig;


pub fn to_bits(msg: Vec<u8>) -> Vec<bool> {
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






pub fn create_step_circuit() -> (CircuitData<GoldilocksField, C, D>, StepTarget<Curve>) {
    // Compile the step circuit
    println!("Compiling the step circuit...");

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let grandpa_justif_targets = make_step_circuit::<GoldilocksField, D, Curve>(&mut builder);
    let grandpa_justif_circuit = builder.build::<C>();

    println!("inner step circuit digest is {:?}", grandpa_justif_circuit.verifier_only.circuit_digest);

    (grandpa_justif_circuit, grandpa_justif_targets)
}


pub fn generate_step_proof(
    step_circuit: &Option<CircuitData<F, C, D>>,
    step_target: StepTarget<Curve>,

    headers: Vec<Vec<u8>>,
    head_block_hash: Vec<u8>,
    head_block_num: u32,

    authority_set_id: u64,
    precommit_message: Vec<u8>,
    signatures: Vec<Vec<u8>>,

    pub_key_indices: Vec<usize>,
    authority_set: Vec<Vec<u8>>,
    authority_set_commitment: Vec<u8>,

    public_inputs_hash: Vec<u8>,
) -> Option<ProofWithPublicInputs<F, RecC, D>> {
    let mut pw: PartialWitness<F> = PartialWitness::new();

    pw.set_avail_hash_target(&step_target.subchain_target.head_block_hash, &(head_block_hash.try_into().unwrap()));
    pw.set_target(step_target.subchain_target.head_block_num, F::from_canonical_u32(head_block_num));
    for (i, header) in headers.iter().enumerate() {
        pw.set_encoded_header_target(&step_target.subchain_target.encoded_headers[i], header.clone());
    }

    set_precommits_pw::<F, D, Curve>(
        &mut pw,
        step_target.precommits.to_vec(),
        (0..QUORUM_SIZE).map(|_| precommit_message.clone().to_vec()).collect::<Vec<_>>(),
        signatures,
        pub_key_indices,
        authority_set.clone(),
    );

    set_authority_set_pw::<F, D, Curve>(
        &mut pw,
        &step_target.authority_set,
        authority_set,
        authority_set_id,
        authority_set_commitment,
    );

    pw.set_avail_hash_target(&step_target.public_inputs_hash, &(public_inputs_hash.try_into().unwrap()));

    let unwrapped_circuit = step_circuit.as_ref().unwrap();

    let mut timing = TimingTree::new("step proof gen", Level::Info);
    let step_proof = prove::<F, C, D>(
        &unwrapped_circuit.prover_only,
        &unwrapped_circuit.common,
        pw,
        &mut timing).unwrap();
    timing.print();

    // TODO:  Should build the recursive circuit on startup
    let mut outer_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let outer_proof_target = outer_builder.add_virtual_proof_with_pis(&unwrapped_circuit.common);
    let outer_verifier_data = outer_builder.add_virtual_verifier_data(unwrapped_circuit.common.config.fri_config.cap_height);
    outer_builder.verify_proof::<C>(&outer_proof_target, &outer_verifier_data, &unwrapped_circuit.common);
    outer_builder.register_public_inputs(&outer_proof_target.public_inputs);
    //outer_builder.register_public_inputs(&outer_verifier_data.circuit_digest.elements);

    let outer_data = outer_builder.build::<PoseidonBN128GoldilocksConfig>();

    let mut outer_pw = PartialWitness::new();
    outer_pw.set_proof_with_pis_target(&outer_proof_target, &step_proof);
    outer_pw.set_verifier_data_target(&outer_verifier_data, &unwrapped_circuit.verifier_only);


    let mut timing = TimingTree::new("recursive proof gen", Level::Info);
    let outer_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(&outer_data.prover_only, &outer_data.common, outer_pw.clone(), &mut timing).unwrap();
    timing.print();

    outer_data.verify(outer_proof.clone()).unwrap();
    Some(outer_proof)
}




#[tarpc::service]
pub trait ProofGenerator {
    async fn generate_step_proof_rpc(
        headers: Vec<Vec<u8>>,
        head_block_hash: Vec<u8>,
        head_block_num: u32,

        authority_set_id: u64,
        precommit_message: Vec<u8>,
        signatures: Vec<Vec<u8>>,

        pub_key_indices: Vec<usize>,
        authority_set: Vec<Vec<u8>>,
        authority_set_commitment: Vec<u8>,

        public_inputs_hash: Vec<u8>,
    ) -> ProofWithPublicInputs<F, RecC, D>;
}