use std::ops::Deref;

use avail_subxt::api::runtime_types::sp_core::crypto::KeyTypeId;
use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use futures_util::future::join_all;
use futures_util::StreamExt;
use serde::de::Error;
use serde::Deserialize;
use sp_core::{
    blake2_256, bytes,
    crypto::Pair,
    ed25519::{self, Public as EdPublic, Signature},
    H256,
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
    //let url = "wss://devnet06.dataavailability.link:28546";
    let url: &str = "wss://testnet.avail.tools:443/ws";

    let c = build_client(url).await.unwrap();
    let mut e = c.events().subscribe().await.unwrap().filter_events::<(
        api::grandpa::events::NewAuthorities,
        api::grandpa::events::Paused,
        api::grandpa::events::Resumed,
    )>();

    tokio::spawn(async move {
        while let Some(ev) = e.next().await {
            let event_details = ev.unwrap();
            match event_details.event {
                (Some(new_auths), None, None) => println!("New auths: {new_auths:?}"),
                (None, Some(paused), None) => println!("Auth set paused: {paused:?}"),
                (None, None, Some(resumed)) => println!("Auth set resumed: {resumed:?}"),
                _ => unreachable!(),
            }
        }
    });

    let t = c.rpc().deref();
    let sub: Result<subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;

    let mut sub = sub.unwrap();

    // Wait for new justification
    while let Some(Ok(justification)) = sub.next().await {
        println!("Justification: {justification:?}");

        // Get the header corresponding to the new justification
        let header = c
            .rpc()
            .header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();
        // A bit redundant, but just to make sure the hash is correct
        let calculated_hash: H256 = Encode::using_encoded(&header, blake2_256).into();

        // println!("Header is {header:?}");
        let header_number = header.number;
        println!("header number is {header_number:?}");

        // let encoded_header = header.encode();
	    // println!("Header encoding is {encoded_header:?}");

        assert_eq!(justification.commit.target_hash, calculated_hash);
        // Get current authority set ID
        let set_id_key = api::storage().grandpa().current_set_id();
        let set_id = c.storage().fetch(&set_id_key, None).await.unwrap().unwrap();
        // println!("Current set id: {set_id:?}");

        let unencoded_message = (
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &set_id,
        );

        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &set_id,
        ));

        // Verify all the signatures of the justification and extract the public keys
        let sig_owners_fut = justification
            .commit
            .precommits
            .iter()
            .map(|precommit| async {
                let is_ok = <ed25519::Pair as Pair>::verify_weak(
                    &precommit.clone().signature.0[..],
                    signed_message.as_slice(),
                    &precommit.clone().id,
                );
                assert!(is_ok, "Not signed by this signature!");
                // println!("Justification AccountId: {p:?}");
                let session_key_key_owner = api::storage().session().key_owner(
                    KeyTypeId(sp_core::crypto::key_types::GRANDPA.0),
                    precommit.clone().id.0,
                );
                c.storage().fetch(&session_key_key_owner, None).await
            })
            .collect::<Vec<_>>();
        let sig_owners = join_all(sig_owners_fut)
            .await
            .into_iter()
            .map(|e| e.unwrap().unwrap())
            .collect::<Vec<_>>();

        // Get the current authority set and extract all owner accounts and weights
        let authority_set_key = api::storage().babe().authorities();
        let authority_set = c
            .storage()
            .fetch(&authority_set_key, None)
            .await
            .unwrap()
            .unwrap();
        let auth_set_fut = authority_set.0.iter().map(|e| async {
            let (public_key, weight) = e.clone();
            let pk = public_key.0 .0;
            let session_key_key_owner = api::storage()
                .session()
                .key_owner(KeyTypeId(sp_core::crypto::key_types::BABE.0), pk);
            let f = c.storage().fetch(&session_key_key_owner, None).await;
            (f.unwrap().unwrap(), weight)
        });

        let auth_owners = join_all(auth_set_fut).await;

        // Calculate the total weight of the authority set
        let total_weight: u64 = auth_owners.iter().map(|e| e.1).sum();

        // Crosscheck all the weight and calculate how much was in the concensus
        let weight: u64 = sig_owners
            .iter()
            .map(|e| {
                auth_owners
                    .iter()
                    .find(|e1| e1.0.eq(e))
                    .map(|e| e.1)
                    .unwrap_or(0)
            })
            .sum();
        println!("Total auth weight: {total_weight}");
        println!("Total weight signed: {weight}");
        assert!(weight as f64 >= ((total_weight as f64) * 2. / 3.));
    }
}
