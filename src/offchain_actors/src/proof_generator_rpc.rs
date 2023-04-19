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
use succinct_avail_proof_generators::{avail::VerifySubchainTarget, consensus::GrandpaJustificationVerifierTargets};

static mut HEADER_VALIDATION_CIRCUIT: Option<CircuitData<F, C, D>> = None;
static mut HEADER_VALIDATION_TARGETS: Option<VerifySubchainTarget> = None;
static mut GRANDPA_JUSTIF_VERIFICATION_CIRCUIT: Option<CircuitData<F, C, D>> = None;
static mut GRANDPA_JUSTIF_VERIFICATION_TARGETS: Option<GrandpaJustificationVerifierTargets<Curve>> = None;

#[derive(Clone)]
struct ProofGeneratorServer(SocketAddr);

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

}

#[derive(Parser)]
struct Flags {
    /// Sets the port number to listen on.
    #[clap(long)]
    port: u16,
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