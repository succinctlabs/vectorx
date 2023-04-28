use std::ops::Deref;

use avail_subxt::{build_client, primitives::Header};
use codec::{Decode, Encode};
use serde::de::Error;
use serde::Deserialize;
use serde::Serialize;

use subxt::{
	ext::{
		sp_core::{bytes, Bytes, ed25519::{Public as EdPublic, Signature}, H256},
	},
    rpc::RpcParams,
};

// use anyhow::Result;

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

#[derive(Debug, PartialEq, Encode, Decode, Clone, Deserialize)]
pub struct FinalityProof {
	/// The hash of block F for which justification is provided.
	pub block: H256,
	/// Justification of the block F.
	pub justification: Vec<u8>,
	/// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
	pub unknown_headers: Vec<Header>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedFinalityProof(pub Bytes);

#[derive(Debug, thiserror::Error, Deserialize)]
pub enum FinalityProofError {
	/// The requested block has not yet been finalized.
	#[error("Block not yet finalized")]
	BlockNotYetFinalized,
	/// The requested block is not covered by authority set changes. Likely this means the block is
	/// in the latest authority set, and the subscription API is more appropriate.
	#[error("Block not covered by authority set changes")]
	BlockNotInAuthoritySetChanges,
}

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://testnet.avail.tools:443/ws";

    let c = build_client(url).await.unwrap();
    let t = c.rpc().deref();
    
    let mut params = RpcParams::new();
    let _ = params.push(577729);

    //Result<Option<EncodedFinalityProof>, sc_consensus_grandpa::FinalityProofError>

    let encoded_finality_proof = t.request::<EncodedFinalityProof>("grandpa_proveFinality", params).await.unwrap();
    let finality_proof: FinalityProof = Decode::decode(&mut encoded_finality_proof.0.0.as_slice()).unwrap();
    let justfication: GrandpaJustification = Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

    println!("{:?}", justfication);
    println!("finality_proof:block {:?}", finality_proof.block);
    println!("finality_proof:unknown_headers {:?}", finality_proof.unknown_headers.len());
}