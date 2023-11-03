//! To build the binary:
//!
//!     `cargo build --release --bin rotate`
//!
//!
//!
//!
//!
use std::collections::HashMap;
use std::ops::Deref;

use avail_subxt::avail::Client;
use avail_subxt::config::Header as HeaderTrait;
use avail_subxt::primitives::Header;
use avail_subxt::{api, build_client};
use codec::{Decode, Encode};
use plonky2x::frontend::ecc::ed25519::gadgets::verify::DUMMY_SIGNATURE;
use serde::de::Error;
use serde::Deserialize;
use sp_core::ed25519::{self, Public as EdPublic, Signature};
use sp_core::{blake2_256, bytes, Pair, H256};
use subxt::rpc::RpcParams;
use vectorx::input::types::StoredJustificationData;
use vectorx::input::{RedisClient, RpcDataFetcher};
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
    println!("Starting indexer");

    let fetcher = RpcDataFetcher::new().await;

    let url: &str = "wss://kate.avail.tools:443/ws";

    let c: Client = build_client(url, false).await.unwrap();
    let t = c.rpc().deref();
    let sub: Result<avail_subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;

    let mut r: RedisClient = RedisClient::new().await;

    let mut sub = sub.unwrap();

    // Wait for new justification
    while let Some(Ok(justification)) = sub.next().await {
        println!("New justification");

        // Note: justification.commit.target_hash is probably block_hash, but it is not header_hash!
        // Noticed this because it retrieves the correct header but doesn't match header.hash()

        // Get the header corresponding to the new justification
        let header = c
            .rpc()
            .header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();
        // A bit redundant, but just to make sure the hash is correct
        let block_hash = justification.commit.target_hash;
        println!("block hash: {}", hex::encode(block_hash.0));
        let header_hash = header.hash();
        let calculated_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
        if header_hash != calculated_hash {
            continue;
        }

        // Get current authority set ID
        let set_id_key = api::storage().grandpa().current_set_id();
        let set_id = c
            .storage()
            .at(block_hash)
            .fetch(&set_id_key)
            .await
            .unwrap()
            .unwrap();

        println!("set id: {}", set_id);

        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &set_id,
        ));

        // Verify all the signatures of the justification and extract the public keys
        // Note: Are the authorities always going to be in the same order?

        let validators = justification
            .commit
            .precommits
            .iter()
            .filter_map(|precommit| {
                let is_ok = <ed25519::Pair as Pair>::verify(
                    &precommit.clone().signature,
                    signed_message.as_slice(),
                    &precommit.clone().id,
                );
                if is_ok {
                    Some((
                        precommit.clone().id.0.to_vec(),
                        precommit.clone().signature.0.to_vec(),
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let pubkeys = validators.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
        let signatures = validators.iter().map(|v| v.1.clone()).collect::<Vec<_>>();

        // Create map from pubkey to signature.
        let pubkey_to_signature = HashMap::new();
        for (pubkey, signature) in pubkeys.iter().zip(signatures.iter()) {
            pubkey_to_signature.insert(pubkey, signature);
        }

        // Check that at least 2/3 of the validators signed the justification.
        // Note: Assumes the validator set have equal voting power.
        let authorities = fetcher.get_authorities(header.number - 1).await;
        let num_authorities = authorities.len();
        if 3 * pubkeys.len() < num_authorities * 2 {
            continue;
        }

        let justification_pubkeys = Vec::new();
        let justification_signatures = Vec::new();
        let validator_signed = Vec::new();
        for authority_pubkey in authorities.iter() {
            if let Some(signature) = pubkey_to_signature.get(authority_pubkey) {
                justification_pubkeys.push(authority_pubkey);
                justification_signatures.push(signature);
                validator_signed.push(true);
            } else {
                justification_pubkeys.push(authority_pubkey);
                justification_signatures.push(DUMMY_SIGNATURE);
                validator_signed.push(false);
            }
        }

        // Add justification to Redis.
        let store_justification_data = StoredJustificationData {
            block_number: header.number,
            signed_message: signed_message.clone(),
            pubkeys: justification_pubkeys,
            signatures: justification_signatures,
            num_authorities: authorities.len(),
            validator_signed,
        };
        r.add_justification(store_justification_data).await;
    }
}
