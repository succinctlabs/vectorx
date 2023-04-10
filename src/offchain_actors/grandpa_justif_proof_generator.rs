use std::sync::Arc;
use std::time::SystemTime;

use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use ed25519::gadgets::nonnative::WitnessNonNative;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use avail_proof_generators::gadgets::consensus::{build_grandpa_justification_verifier, GrandpaJustificationVerifierTargets};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use serde::{Deserialize, Serialize};
use sp_core::blake2_256;
use sp_core::{
    ed25519::{Public as EdPublic, Signature},
    H256,
};
use subxt::rpc::RpcParams;
use jsonrpsee::ws_client::WsClientBuilder;
use ::ed25519::curve::ed25519::Ed25519;
use ed25519::gadgets::curve::{decompress_point, WitnessAffinePoint};
use ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
use ed25519::field::ed25519_scalar::Ed25519Scalar;
use num::BigUint;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type Curve = Ed25519;

#[derive(Clone, Serialize, Deserialize)]
pub struct JustificationNotification(pub sp_core::Bytes);

// Perform a highly unsafe type-casting between two types hidden behind an Arc.
pub unsafe fn unsafe_arc_cast<T, U>(arc: Arc<T>) -> Arc<U> {
	let ptr = Arc::into_raw(arc).cast::<U>();
	Arc::from_raw(ptr)
}

// We redefine these here because we want the header to be bounded by subxt::config::Header in the
// prover
/// Commit
pub type Commit = finality_grandpa::Commit<H256, u32, Signature, EdPublic>;

/// Justification
#[cfg_attr(any(feature = "std", test), derive(Debug))]
#[derive(Clone, Encode, Decode)]
pub struct GrandpaJustification {
	/// Current voting round number, monotonically increasing
	pub round: u64,
	/// Contains block hash & number that's being finalized and the signatures.
	pub commit: Commit,
	/// Contains the path from a [`PreCommit`]'s target hash to the GHOST finalized block.
	pub votes_ancestries: Vec<Header>,
}

/// Finality for block B is proved by providing:
/// 1) the justification for the descendant block F;
/// 2) headers sub-chain (B; F] if B != F;
#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct FinalityProof<H: codec::Codec> {
	/// The hash of block F for which justification is provided.
	pub block: H256,
	/// Justification of the block F.
	pub justification: Vec<u8>,
	/// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
	pub unknown_headers: Vec<H>,
}

#[derive(Clone, Debug, Decode, Encode, Deserialize)]
pub struct Precommit {
    pub target_hash: H256,
    /// The target block's number
    pub target_number: u32,
}

pub const CHUNK_128_BYTES: usize = 128;

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

fn generate_proof(
    granda_justif_circuit: &CircuitData<F, C, D>,
    encoded_header: Vec<u8>,
    encoded_message: Vec<u8>,
    signatures: Vec<&Signature>,
    pub_keys: Vec<EdPublic>,
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

    for i in 0..signatures.len() {
        let signature = signatures[i].0.to_vec();
        let sig_r = decompress_point(&signature[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&signature[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        let pubkey_bytes = pub_keys[i].0.to_vec();
        let pub_key = decompress_point(&pubkey_bytes[..]);
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

    let proof = granda_justif_circuit.prove(pw);

    match proof {
        Ok(v) => return Some(v),
        Err(e) => println!("error parsing header: {e:?}"),
    };

    return None
}

#[tokio::main]
pub async fn main() {
    // Compile the header validation circuit
    const CHUNK_128_BYTES:usize = 128;

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let targets = build_grandpa_justification_verifier::<GoldilocksField, Curve, D>(&mut builder, CHUNK_128_BYTES * 10, 7);
    let grandpa_justif_circuit = builder.build::<C>();

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

    // How often we want to generate a proof of grandpa justification
    const FINALIZATION_PERIOD: usize = 5;

    // Wait for headers
    while let Some(Ok(header)) = sub.next().await {
        println!("Got header: {:?}", header.number);
        if header.number % (FINALIZATION_PERIOD as u32) == 0 {
            println!("Going to retrieve the justification for header: {:?}", header.number);
            let encoded_header = header.encode();

            let relay_ws_client = Arc::new(WsClientBuilder::default().build(url).await);
            let encoded_justification = finality_grandpa_rpc::GrandpaApiClient::<JustificationNotification, H256, u32>::prove_finality(
                &*unsafe {
					unsafe_arc_cast::<_, jsonrpsee_ws_client::WsClient>(
						relay_ws_client
					)
				},
                header.number
            ).await.unwrap().unwrap().0;

            let mut finality_proof = FinalityProof::<H256>::decode(&mut &encoded_justification[..]).unwrap();

            let justification: GrandpaJustification =
                GrandpaJustification::decode(&mut &finality_proof.justification[..]).unwrap();

            let set_id_key = api::storage().grandpa().current_set_id();
            let set_id = c.storage().fetch(&set_id_key, None).await.unwrap().unwrap();

            // Form a message which is signed in the justification
            let encoded_message = Encode::encode(&(
                &Precommit{ target_hash: Encode::using_encoded(&header, blake2_256).into(), target_number: header.number }, 
                &justification.round,
                &set_id,
            ));

            // retrieve the signatures
            let mut signatures: Vec<&Signature> = Vec::new();
            let mut pub_keys: Vec<EdPublic> = Vec::new();
            for i in 0..justification.commit.precommits.len() {
                signatures.push(&justification.commit.precommits[i].signature);
                pub_keys.push(justification.commit.precommits[i].id);
            }

            /*
            println!("encoded_header is {:?}", encoded_header);
            println!("encoded messages is {:?}", encoded_message);
            let signatures_vec = signatures.iter().map(|x| x.0.to_vec()).collect::<Vec<Vec<u8>>>();
            println!("signatures are {:?}", signatures_vec);

            let pub_keys_vec = pub_keys.iter().map(|x| x.0.to_vec()).collect::<Vec<Vec<u8>>>();
            println!("pub_keys are {:?}", pub_keys_vec);
            */

            println!("generating proof for justification.  block hash: {:?}, block number: {:?}", header.encode(), header.number);
            let proof_gen_start_time = SystemTime::now();
            let proof = generate_proof(
                &grandpa_justif_circuit,
                encoded_header,
                encoded_message,
                signatures,
                pub_keys,
                targets.clone()
            );
            let proof_gen_end_time = SystemTime::now();
            let proof_gen_duration = proof_gen_end_time.duration_since(proof_gen_start_time).unwrap();
        }
    }
}
