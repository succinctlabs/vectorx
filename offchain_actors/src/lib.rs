use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;
use plonky2::{plonk::{circuit_data::{CircuitData, CircuitConfig}, config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_builder::CircuitBuilder}, iop::witness::WitnessWrite};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::PartialWitness;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use succinct_avail_proof_generators::{step::{make_step_circuit, StepTarget}, justification::{set_precommits_pw, set_authority_set_pw}, utils::{WitnessAvailHash, WitnessEncodedHeader, QUORUM_SIZE}};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type Curve = Ed25519;


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

) -> Option<ProofWithPublicInputs<F, C, D>> {
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

    let proof = step_circuit.as_ref().unwrap().prove(pw);

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    None
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
    ) -> ProofWithPublicInputs<F, C, D>;
}