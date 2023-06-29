use std::ops::Deref;

use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use serde::de::Error;
use serde::Deserialize;
use sp_core::{
	blake2_256, bytes,
	ed25519::{self, Public as EdPublic, Signature},
	Pair, H256,
};
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

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, true).await.unwrap();
    let t = c.rpc().deref();
    let sub: Result<avail_subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;

    let mut sub = sub.unwrap();

    // Wait for new justification
    while let Some(Ok(justification)) = sub.next().await {
        // Get the header corresponding to the new justification
        let header = c
            .rpc()
            .header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();
        // A bit redundant, but just to make sure the hash is correct
        let calculated_hash: H256 = Encode::using_encoded(&header, blake2_256).into();

        if justification.commit.target_hash != calculated_hash {
            continue;
        }

        // Get current authority set ID
        let set_id_key = api::storage().grandpa().current_set_id();
        let set_id = c.storage().at(None).await.unwrap().fetch(&set_id_key).await.unwrap().unwrap();

        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &set_id,
        ));

        // Verify all the signatures of the justification and extract the public keys
        let mut sig_owners = justification
            .commit
            .precommits
            .iter()
            .map(|precommit| {
                let is_ok = <ed25519::Pair as Pair>::verify_weak(
                    &precommit.clone().signature.0[..],
                    signed_message.as_slice(),
                    &precommit.clone().id,
                );
                if is_ok {
                    Some(precommit.clone().id.0)
                } else {
                    None
                }
            })
            .filter(|signer| {signer.is_some()})
            .map(|some_signer| {hex::encode(some_signer.unwrap())})
            .collect::<Vec<_>>();

        sig_owners.sort();

        if sig_owners.len() < 7 {
            continue;
        }

        println!("justification block number: {}", justification.commit.target_number);
        println!("justification set id: {}", set_id);
        println!("justification signers: {:?}", sig_owners);
        println!("\n\n\n");
    }
}
