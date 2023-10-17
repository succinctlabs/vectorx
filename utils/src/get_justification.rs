use std::ops::Deref;

use avail_subxt::primitives::Header;
use avail_subxt::{api, build_client};
use codec::{Decode, Encode};
use primitive_types::H256;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use sp_core::ed25519::{Public as EdPublic, Signature};
use sp_core::{bytes, ed25519, Bytes, Pair};
use subxt::rpc::RpcParams;

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
    let header_num = 272534;
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, false).await.unwrap();
    let t = c.rpc().deref();

    let mut params = RpcParams::new();
    let _ = params.push(header_num);
    let encoded_finality_proof = t
        .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
        .await
        .unwrap();
    let finality_proof: FinalityProof =
        Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
    let justification: GrandpaJustification =
        Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

    println!("{:?}", justification);
    println!("finality_proof:block {:?}", finality_proof.block);
    println!(
        "finality_proof:unknown_headers length {:?}",
        finality_proof.unknown_headers.len()
    );
    for header in finality_proof.unknown_headers.iter() {
        println!("finality_proof:unknown_header number {:?}", header.number);
    }

    let set_id_key = api::storage().grandpa().current_set_id();
    let set_id = c
        .storage()
        .at(Some(finality_proof.block))
        .await
        .unwrap()
        .fetch(&set_id_key)
        .await
        .unwrap()
        .unwrap()
        - 1;
    println!("set_id {:?}", set_id);

    // Form a message which is signed in the justification
    let signed_message = Encode::encode(&(
        &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
        &justification.round,
        &set_id,
    ));

    println!(
        "signed message is {:?}",
        hex::encode(signed_message.clone())
    );

    let mut signatures = Vec::new();
    let mut pub_keys = Vec::new();

    // Verify all the signatures of the justification
    justification
        .commit
        .precommits
        .iter()
        .for_each(|precommit| {
            let is_ok = <ed25519::Pair as Pair>::verify_weak(
                &precommit.clone().signature.0[..],
                signed_message.as_slice(),
                precommit.clone().id,
            );
            signatures.push(precommit.clone().signature.0);
            pub_keys.push(precommit.clone().id);
            assert!(is_ok);
        });

    println!("signatures:");
    let signatures_str = signatures
        .iter()
        .map(|x| hex::encode(x.as_slice()))
        .collect::<Vec<String>>();
    println!("{:?}", signatures_str);

    println!("pub_keys:");
    let pub_keys_str = pub_keys
        .iter()
        .map(|x| hex::encode(x.0))
        .collect::<Vec<String>>();
    println!("{:?}", pub_keys_str);
}
