use plonky2lib_succinct::ed25519::{curve::{ed25519::Ed25519, eddsa::{EDDSASignature, verify_message, EDDSAPublicKey}}, gadgets::{curve::{decompress_point, WitnessAffinePoint}, nonnative::WitnessNonNative}, field::ed25519_scalar::Ed25519Scalar};
use num::BigUint;
use plonky2::{plonk::{circuit_data::{CircuitData, CircuitConfig}, config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_builder::CircuitBuilder}, iop::witness::WitnessWrite};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::PartialWitness;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use subxt::ext::sp_core::H256;
use succinct_avail_proof_generators::{step::{verify_headers, VerifySubchainTarget}, justification::{build_grandpa_justification_verifier, GrandpaJustificationVerifierTargets}};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type Curve = Ed25519;


const HASH_SIZE:usize = 32; // in bytes
pub const CHUNK_128_BYTES: usize = 128;
const MAX_HEADER_SIZE:usize = CHUNK_128_BYTES * 10; // 1280 bytes

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



pub fn create_header_validation_circuit() -> (CircuitData<GoldilocksField, C, D>, VerifySubchainTarget) {
    // Compile the header validation circuit
    println!("Compiling the header validation circuit...");

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let targets = verify_headers(&mut builder, 1);

    let header_validation_circuit = builder.build::<C>();
    (header_validation_circuit, targets)
}

pub fn generate_header_validation_proof(header_validation_circuit: &Option<CircuitData<F, C, D>>, previous_block_hash: H256, header: Vec<u8>, targets: VerifySubchainTarget) -> Option<ProofWithPublicInputs<F, C, D>> {
    let mut pw: PartialWitness<GoldilocksField> = PartialWitness::new();

    let previous_hash_digest_bits = to_bits(previous_block_hash.as_fixed_bytes().to_vec());

    // Set the head_block_hash_target
    for i in 0..HASH_SIZE * 8 {
        pw.set_bool_target(targets.head_block_hash[i], previous_hash_digest_bits[i]);
    }

    // Set the header targets
    for i in 0..header.len() {
        pw.set_target(targets.encoded_headers[0][i], F::from_canonical_u8(header[i]));
    }

    for j in header.len()..MAX_HEADER_SIZE {
        pw.set_target(targets.encoded_headers[0][j], F::from_canonical_u32(0));
    }

    pw.set_target(targets.encoded_header_sizes[0], F::from_canonical_usize(header.len()));

    let proof = header_validation_circuit.as_ref().unwrap().prove(pw);

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    return None
}









pub fn create_grandpa_justification_verifier_circuit() -> (CircuitData<GoldilocksField, C, D>, GrandpaJustificationVerifierTargets<Curve>) {
    // Compile the header validation circuit
    println!("Compiling the grandpa justification verifier circuit...");

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let grandpa_justif_targets = build_grandpa_justification_verifier::<GoldilocksField, Curve, D>(&mut builder, CHUNK_128_BYTES * 10, 7);
    let grandpa_justif_circuit = builder.build::<C>();

    (grandpa_justif_circuit, grandpa_justif_targets)
}


pub fn generate_grandpa_justification_verifier_proof(
    granda_justif_circuit: &Option<CircuitData<F, C, D>>,
    encoded_header: Vec<u8>,
    encoded_message: Vec<u8>,
    signatures: Vec<[u8; 64]>,
    pub_keys: Vec<[u8; 32]>,
    targets: GrandpaJustificationVerifierTargets<Curve>
) -> Option<ProofWithPublicInputs<F, C, D>> {
    let mut pw: PartialWitness<F> = PartialWitness::new();

    for i in 0..encoded_header.len() {
        pw.set_target(targets.encoded_header[i], GoldilocksField(encoded_header[i] as u64));
    }
    for i in encoded_header.len() .. CHUNK_128_BYTES * 10 {
        pw.set_target(targets.encoded_header[i], GoldilocksField(0));
    }

    pw.set_target(targets.encoded_header_length, GoldilocksField(encoded_header.len() as u64));

    for i in 0..encoded_message.len() {
        pw.set_target(targets.encoded_message[i], GoldilocksField(encoded_message[i] as u64));
    }

    let encoded_messsage_bits = to_bits(encoded_message.to_vec());

    // We are hardcoding verifition of 7 signatures for now.
    // Avail testnet has 10 validators, so a quorum [ceil(2/3*n)] is 7.
    for i in 0..7 {
        let sig_r = decompress_point(&signatures[i][0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&signatures[i][32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        let pub_key = decompress_point(&pub_keys[i][..]);
        assert!(pub_key.is_valid());

        assert!(verify_message(
            &encoded_messsage_bits,
            &sig,
            &EDDSAPublicKey(pub_key)
        ));

        // eddsa verification witness stuff
        pw.set_affine_point_target(&targets.pub_keys[i].0, &pub_key);
        pw.set_affine_point_target(&targets.signatures[i].r, &sig_r);
        pw.set_nonnative_target(&targets.signatures[i].s, &sig_s);
    }

    let proof = granda_justif_circuit.as_ref().unwrap().prove(pw);

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    return None
}






#[tarpc::service]
pub trait ProofGenerator {
    async fn generate_header_proof(previous_block_hash: H256, block_hash: H256, header: Vec<u8>) -> ProofWithPublicInputs<F, C, D>;
    async fn generate_grandpa_justif_proof(block_hash: H256, header: Vec<u8>, message: Vec<u8>, signature: Vec<Vec<u8>>, sig_owners: Vec<[u8; 32]>) -> ProofWithPublicInputs<F, C, D>;
}