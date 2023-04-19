use plonky2::plonk::{circuit_data::{CircuitData, CircuitConfig}, config::{PoseidonGoldilocksConfig, GenericConfig}, circuit_builder::CircuitBuilder};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use subxt::ext::sp_core::H256;
use succinct_avail_proof_generators::avail::{verify_headers, VerifySubchainTarget};

pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;

const HASH_SIZE:usize = 32; // in bytes
pub const CHUNK_128_BYTES: usize = 128;
const MAX_HEADER_SIZE:usize = CHUNK_128_BYTES * 10; // 1280 bytes

fn to_bits(msg: Vec<u8>) -> Vec<bool> {
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

    println!("set the target");

    let proof = header_validation_circuit.as_ref().unwrap().prove(pw);

    println!("set the target");

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    return None
}

#[tarpc::service]
pub trait ProofGenerator {
    async fn generate_header_proof(previous_block_hash: H256, block_hash: H256, header: Vec<u8>) -> String;
}