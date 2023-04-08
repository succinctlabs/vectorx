use std::sync::Arc;

use avail_subxt::api::runtime_types::sp_core::crypto::KeyTypeId;
use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use futures_util::future::join_all;
use futures_util::StreamExt;
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use avail_proof_generators::gadgets::consensus::{build_grandpa_justification_verifier, GrandpaJustificationVerifierTargets};
use serde::de::Error;
use serde::{Deserialize, Serialize};
use sp_core::{
    blake2_256, bytes,
    crypto::Pair,
    ed25519::{self, Public as EdPublic, Signature},
    H256,
};
use subxt::rpc::RpcParams;
use jsonrpsee::ws_client::WsClientBuilder;

#[derive(Deserialize, Debug)]
pub struct SubscriptionMessageResult {
    pub result: String,
    pub subscription: String,
}

#[derive(Deserialize, Debug)]
pub struct SubscriptionMessage {
    pub jsonrpc: String,
    pub params: SubscriptionMessageResult,
    pub method: String,
}

#[derive(Clone, Debug, Decode, Encode, Deserialize)]
pub struct Precommit {
    pub target_hash: H256,
    /// The target block's number
    pub target_number: u32,
}

#[derive(Clone, Debug, Decode, Deserialize)]
pub struct SignedPrecommit {
    pub precommit: Precommit,
    /// The signature on the message.
    pub signature: Signature,
    /// The Id of the signer.
    pub id: EdPublic,
}
#[derive(Clone, Debug, Decode, Deserialize)]
pub struct Commit {
    pub target_hash: H256,
    /// The target block's number.
    pub target_number: u32,
    /// Precommits for target block or any block after it that justify this commit.
    pub precommits: Vec<SignedPrecommit>,
}

#[derive(Clone, Debug, Decode)]
pub struct GrandpaJustification {
    pub round: u64,
    pub commit: Commit,
    pub votes_ancestries: Vec<Header>,
}

impl<'de> Deserialize<'de> for GrandpaJustification {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = bytes::deserialize(deserializer)?;
        Self::decode(&mut &encoded[..])
            .map_err(|codec_err| D::Error::custom(format!("Invalid decoding: {:?}", codec_err)))
    }
}

#[derive(Debug, Decode)]
pub struct Authority(EdPublic, u64);

#[derive(Debug, Encode)]
pub enum SignerMessage {
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

#[derive(Clone, Serialize, Deserialize)]
pub struct JustificationNotification(pub sp_core::Bytes);

// Perform a highly unsafe type-casting between two types hidden behind an Arc.
pub unsafe fn unsafe_arc_cast<T, U>(arc: Arc<T>) -> Arc<U> {
	let ptr = Arc::into_raw(arc).cast::<U>();
	Arc::from_raw(ptr)
}

/// Represents a Hash in this library
pub type Hash = H256;

/// Finality for block B is proved by providing:
/// 1) the justification for the descendant block F;
/// 2) headers sub-chain (B; F] if B != F;
#[derive(Debug, PartialEq, Encode, Decode, Clone)]
pub struct FinalityProof<H: codec::Codec> {
	/// The hash of block F for which justification is provided.
	pub block: Hash,
	/// Justification of the block F.
	pub justification: Vec<u8>,
	/// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
	pub unknown_headers: Vec<H>,
}

#[tokio::main]
pub async fn main() {
    // Compile the header validation circuit
    //let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    //let targets = build_grandpa_justification_verifier(&mut builder, 1);

    //let header_validation_circuit = builder.build::<C>();

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
                header.number)
                .await.unwrap().unwrap().0;
    
                let finality_proof = FinalityProof::<H256>::decode(&mut &encoded_justification[..]).unwrap();
    
                let justification =
                    GrandpaJustification::decode(&mut &finality_proof.justification[..]).unwrap();
    
                println!("justification is {:?}", justification);
        }
    }
}