use std::time::SystemTime;

use avail_subxt::primitives::Header;
use avail_subxt::build_client;
use codec::Encode;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::types::Field;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use sp_core::{H256, blake2_256};
use avail_proof_generators::gadgets::avail::{verify_headers, VerifySubchainTarget};
use subxt::rpc::RpcParams;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

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


fn generate_proof(header_validation_circuit: &CircuitData<F, C, D>, previous_block_hash: H256, header: Vec<u8>, targets: VerifySubchainTarget) -> Option<ProofWithPublicInputs<F, C, D>> {
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

    let proof = header_validation_circuit.prove(pw);

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    return None
}


#[tokio::main]
pub async fn main() {
    // Compile the header validation circuit
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let targets = verify_headers(&mut builder, 1);

    let header_validation_circuit = builder.build::<C>();

    let url: &str = "wss://testnet.avail.tools:443/ws";
    let c = build_client(url).await.unwrap();
    let t = c.rpc();
    let sub: Result<subxt::rpc::Subscription<Header>, subxt::Error> = t
        .subscribe(
            "chain_subscribeFinalizedHeads",
            RpcParams::new(),
            "chain_unsubscribeFinalizedHeads",
        )
        .await;

    let mut sub = sub.unwrap();
    let mut previous_block_hash = None;

    // Wait for headers
    while let Some(Ok(header)) = sub.next().await {
        let block_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
        println!("got a header with number {:?} and hash {:?}", header.number, block_hash);

        if !previous_block_hash.is_none() {
            let encoded_header = header.encode();
            println!("generating proof!");
            let proof_gen_start_time = SystemTime::now();
            let proof = generate_proof(&header_validation_circuit, previous_block_hash.unwrap(), encoded_header, targets.clone());
            let proof_gen_end_time = SystemTime::now();
            let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();    
            if proof.is_some() {
                println!("proof generated - time: {:?}", proof_gen_duration);

                let verification_res = header_validation_circuit.verify(proof.unwrap());
                if !verification_res.is_err() {
                    println!("proof verification succeeded");
                } else {
                    println!("proof verification failed");
                }
            } else {
                println!("failed to generate proof");
            }
        }

        println!("\n\n\n");

        previous_block_hash = Some(block_hash);
    }
}
