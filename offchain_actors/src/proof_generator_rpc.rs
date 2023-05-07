use std::{net::{IpAddr, Ipv6Addr, SocketAddr}, time::SystemTime};
use clap::Parser;

use futures::{future, prelude::*};
use plonky2::plonk::{circuit_data::CircuitData, proof::ProofWithPublicInputs};
use tarpc::{
    context,
    server::{self, incoming::Incoming, Channel},
    tokio_serde::formats::Json,
};
use subxt::ext::sp_core::H256;
use service::{Curve, C, F, D, ProofGenerator, create_header_validation_circuit, generate_header_validation_proof, create_grandpa_justification_verifier_circuit, generate_grandpa_justification_verifier_proof};
use succinct_avail_proof_generators::{step::VerifySubchainTarget};

static mut HEADER_VALIDATION_CIRCUIT: Option<CircuitData<F, C, D>> = None;
static mut HEADER_VALIDATION_TARGETS: Option<VerifySubchainTarget> = None;
static mut GRANDPA_JUSTIF_VERIFICATION_CIRCUIT: Option<CircuitData<F, C, D>> = None;
static mut GRANDPA_JUSTIF_VERIFICATION_TARGETS: Option<GrandpaJustificationVerifierTargets<Curve>> = None;

#[derive(Clone)]
struct ProofGeneratorServer(SocketAddr) {
    header_validation_circuit: Option<CircuitData<F, C, D>>,
    header_validation_targets: Option<VerifySubchainTarget>,
    grandpa_justif_verification_circuit: Option<CircuitData<F, C, D>>,
    grandpa_justif_verification_targets: Option<GrandpaJustificationVerifierTargets<Curve>>,
};

#[tarpc::server]
impl ProofGenerator for ProofGeneratorServer {
    async fn generate_header_proof(self, _: context::Context, previous_block_hash: H256, block_hash: H256, header: Vec<u8>) -> ProofWithPublicInputs<F, C, D> {
        println!("Got a generate_header_proof request with previous_block_hash: {:?} and block_hash: {:?}", previous_block_hash, block_hash);

        unsafe {
            let proof_gen_start_time = SystemTime::now();
            let header_validation_target = HEADER_VALIDATION_TARGETS.clone().unwrap();
            let proof = generate_header_validation_proof(&HEADER_VALIDATION_CIRCUIT, previous_block_hash, header, header_validation_target);
            let proof_gen_end_time = SystemTime::now();
            let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();    
            if proof.is_some() {
                println!("proof generated - time: {:?}", proof_gen_duration);
                let verification_res = HEADER_VALIDATION_CIRCUIT.as_ref().unwrap().verify(proof.clone().unwrap());
                if !verification_res.is_err() {
                    println!("proof verification succeeded");
                } else {
                    println!("proof verification failed");
                }
            } else {
                println!("failed to generate proof");
            }

            println!("\n\n\n");

            proof.unwrap()
        }
    }


    async fn generate_grandpa_justif_proof(self, _: context::Context, block_hash: H256, header: Vec<u8>, message: Vec<u8>, signature: Vec<Vec<u8>>, sig_owners: Vec<[u8; 32]>) -> ProofWithPublicInputs<F, C, D> {
        println!("Got a generate_grandpa_justif_proof request with block_hash: {:?}",  block_hash);

        // convert signature to Vec<[u8; 64]>
        let mut sigs = Vec::new();
        for sig in signature {
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&sig);
            sigs.push(sig_arr);
        }

        unsafe {
            let proof_gen_start_time = SystemTime::now();
            let grandpa_justif_verification_target = GRANDPA_JUSTIF_VERIFICATION_TARGETS.clone().unwrap();
            let proof = generate_grandpa_justification_verifier_proof(
                &GRANDPA_JUSTIF_VERIFICATION_CIRCUIT, 
                header, 
                message, 
                sigs, 
                sig_owners, 
                grandpa_justif_verification_target);
            let proof_gen_end_time = SystemTime::now();
            let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();    
            if proof.is_some() {
                println!("proof generated - time: {:?}", proof_gen_duration);
                let verification_res = GRANDPA_JUSTIF_VERIFICATION_CIRCUIT.as_ref().unwrap().verify(proof.clone().unwrap());
                if !verification_res.is_err() {
                    println!("proof verification succeeded");
                } else {
                    println!("proof verification failed");
                }
            } else {
                println!("failed to generate proof");
            }

            println!("\n\n\n");

            proof.unwrap()
        }

    }

    async fn generate_step_proof(
        self, _: context::Context,
        current_head_block_hash: H256,
        current_head_block_num: uint32,
        new_headers: Vec<Vec<u8>>,
        justification: GrandpaJustification,
    ) -> ProofWithPublicInputs<F, C, D> {
        println!("Got a generate_step_proof request with current head ({:?}, {:?}) and {:?} new headers", current_head_block_num, current_head_block_hash, new_headers.len());

        let proof_gen_start_time = SystemTime::now();
        let header_validation_target = HEADER_VALIDATION_TARGETS.clone().unwrap();
        let proof = generate_header_validation_proof(&HEADER_VALIDATION_CIRCUIT, previous_block_hash, header, header_validation_target);
        let proof_gen_end_time = SystemTime::now();
        let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();    
        if proof.is_some() {
            println!("proof generated - time: {:?}", proof_gen_duration);
            let verification_res = HEADER_VALIDATION_CIRCUIT.as_ref().unwrap().verify(proof.clone().unwrap());
            if !verification_res.is_err() {
                println!("proof verification succeeded");
            } else {
                println!("proof verification failed");
            }
        } else {
            println!("failed to generate proof");
        }

        println!("\n\n\n");

        proof.unwrap()
    }

}

#[derive(Parser)]
struct Flags {
    /// Sets the port number to listen on.
    #[clap(long)]
    port: u16,
}

pub fn create_step_circuit() -> (CircuitData<GoldilocksField, C, D>, GrandpaJustificationVerifierTargets<Curve>) {
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

#[tokio::main]
async fn main() -> anyhow::Result<()>  {
    let (header_validation_circuit, header_validation_targets) = create_header_validation_circuit();
    let (grandpa_justif_verification_circuit, grandpa_justif_verification_targets) = create_grandpa_justification_verifier_circuit();
    unsafe {
        HEADER_VALIDATION_CIRCUIT = Some(header_validation_circuit);
        HEADER_VALIDATION_TARGETS = Some(header_validation_targets);
        GRANDPA_JUSTIF_VERIFICATION_CIRCUIT = Some(grandpa_justif_verification_circuit);
        GRANDPA_JUSTIF_VERIFICATION_TARGETS = Some(grandpa_justif_verification_targets);
    }

    let flags = Flags::parse();
    let server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), flags.port);
    let mut listener = tarpc::serde_transport::tcp::listen(&server_addr, Json::default).await?;
    println!("Listening on port {}", listener.local_addr().port());
    listener.config_mut().max_frame_length(usize::MAX);
    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        // Limit channels to 1 per IP.
        .max_channels_per_key(1, |t| t.transport().peer_addr().unwrap().ip())
        // serve is generated by the service attribute. It takes as input any type implementing
        // the generated World trait.
        .map(|channel| {
            let server = ProofGeneratorServer(channel.transport().peer_addr().unwrap());
            channel.execute(server.serve())
        })
        // Max 10 channels.
        .buffer_unordered(10)
        .for_each(|_| async {})
        .await;

    Ok(())
}