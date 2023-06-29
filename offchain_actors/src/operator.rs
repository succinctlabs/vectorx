
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, Duration};

use service::{ProofGeneratorClient, to_bits};
use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use plonky2lib_succinct::ed25519::curve::eddsa::{EDDSASignature, verify_message, EDDSAPublicKey};
use plonky2lib_succinct::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2lib_succinct::ed25519::gadgets::curve::decompress_point;
use num::BigUint;
use plonky2_field::types::Field;
use serde::de::Error;
use serde::Deserialize;

use sp_core::{
	blake2_256, bytes,
	ed25519::{self, Public as EdPublic, Signature},
	Pair, H256,
};
use subxt::rpc::RpcParams;

use tarpc::{client, context};
use tarpc::tokio_serde::formats::Json;

use futures::{select, StreamExt, pin_mut};


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

pub const CHUNK_128_BYTES: usize = 128;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    /*
    let server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 52357);

    let mut transport = tarpc::serde_transport::tcp::connect(server_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let client = ProofGeneratorClient::new(client::Config::default(), transport.await?).spawn();
    */

    let url: &str = "wss://kate.avail.tools:443/ws";
    
    let c = build_client(url, true).await.unwrap();

    let t = c.rpc();

    
    let justification_sub: subxt::rpc::Subscription<GrandpaJustification> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await
        .unwrap();


    let header_sub: subxt::rpc::Subscription<Header> = t
        .subscribe(
            "chain_subscribeFinalizedHeads",
            RpcParams::new(),
            "chain_unsubscribeFinalizedHeads",
        )
        .await
        .unwrap();

    let t1 = header_sub.fuse();
    let t2 = justification_sub.fuse();

    pin_mut!(t1, t2);

    let mut last_processed_block_num: Option<u32> = None;
    let mut headers = HashMap::new();
    let mut justification_to_process = None;

    'main_loop: loop {
        select! {
            // Currently assuming that all the headers received will be sequential
            header = t1.next() => {
                let unwrapped_header = header.unwrap().unwrap();

                if last_processed_block_num.is_none() {
                    last_processed_block_num = Some(unwrapped_header.number);
                }

                println!("Downloaded a header for block number: {:?}", unwrapped_header.number);
                headers.insert(unwrapped_header.number, unwrapped_header);
            }

            justification = t2.next() => {
                // Wait until we get at least one header
                if last_processed_block_num.is_none() {
                    continue;
                }

                let unwrapped_just = justification.unwrap().unwrap();

                println!("Downloaded a justification for block number: {:?}", unwrapped_just.commit.target_number);
                if unwrapped_just.commit.target_number >= last_processed_block_num.unwrap() + 5 {
                    justification_to_process = Some(unwrapped_just);
                }
            }
        }

        if justification_to_process.is_some() {
            let unwrapped_just = justification_to_process.clone().unwrap();

            let just_block_num = unwrapped_just.commit.target_number;

            // Check to see if we downloaded the header yet
            if !headers.contains_key(&just_block_num) {
                println!("Don't have header for block number: {:?}", just_block_num);
                continue 'main_loop;
            }

            // Check that all the precommit's target number is the same as the precommits' target number
            for precommit in unwrapped_just.commit.precommits.iter() {
                if just_block_num != precommit.precommit.target_number {
                    println!(
                        "Justification has precommits that are not the same number as the commit. Commit's number: {:?}, Precommit's number: {:?}",
                        just_block_num,
                        precommit.precommit.target_number
                    );
                    justification_to_process = None;
                    continue 'main_loop;
                }
            }

            let set_id_key = api::storage().grandpa().current_set_id();

            // Need to get the set id at the previous block
            let previous_hash: H256 = headers.get(&(just_block_num)).unwrap().parent_hash;
            let set_id = c.storage().at(Some(previous_hash)).await.unwrap().fetch(&set_id_key).await.unwrap().unwrap();    

            // Form a message which is signed in the justification
            let signed_message = Encode::encode(&(
                &SignerMessage::PrecommitMessage(unwrapped_just.commit.precommits[0].clone().precommit),
                &unwrapped_just.round,
                &set_id,
            ));

            // Verify all the signatures of the justification and extract the public keys
            for precommit in unwrapped_just.commit.precommits.iter() {
                let is_ok = <ed25519::Pair as Pair>::verify_weak(
                    &precommit.clone().signature.0[..],
                    signed_message.as_slice(),
                    precommit.clone().id,
                );
                if !is_ok {
                    println!("Invalid signature in justification");
                    justification_to_process = None;
                    continue 'main_loop;
                }
            }

            let mut header_batch = Vec::new();
            if headers.contains_key(&unwrapped_just.commit.target_number) {
                for i in last_processed_block_num.unwrap()..unwrapped_just.commit.target_number {
                    header_batch.push(headers.get(&i).unwrap().clone());
                    headers.remove(&i);
                }
            }

            println!(
                "Going to process a batch of headers of size: {:?}, block numbers: {:?} and justification with number {:?}",
                header_batch.len(),
                header_batch.iter().map(|h| h.number).collect::<Vec<u32>>(),
                unwrapped_just.commit.target_number,
            );
            // process(header_batch, justification_to_process.unwrap().clone());
            justification_to_process = None;
        }
    }

    /*
    // Wait for headers
    while let Some(Ok(justification)) = justification_sub.next().await {
        // Get the header corresponding to the new justification
        let header = c
            .rpc()
            .header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();

        println!("Got justification for header with number: {:?}", header.number);

        if header.number % (FINALIZATION_PERIOD as u32) == 0 {
            let block_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
            println!("Generate justification for header with number: {:?} and hash: {:?}", header.number, block_hash);

            // Get current authority set ID
            let set_id_key = api::storage().grandpa().current_set_id();
            let set_id = c.storage().fetch(&set_id_key, None).await.unwrap().unwrap();

            // Form a message which is signed in the justification
            let encoded_message = Encode::encode(&(
                &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
                &justification.round,
                &set_id,
            ));

            let signatures = justification.
            commit.
            precommits.
            iter().
            map(|x| x.clone().signature.0).collect::<Vec<_>>();

            let sig_owners = justification
            .commit
            .precommits
            .iter()
            .map(|precommit| {
                let is_ok = <ed25519::Pair as Pair>::verify_weak(
                    &precommit.clone().signature.0[..],
                    encoded_message.as_slice(),
                    &precommit.clone().id,
                );
                assert!(is_ok, "Not signed by this signature!");
                assert!(precommit.signature.0.len() == 64);
                assert!(precommit.id.0.len() == 32);
                precommit.clone().id.0
            })
            .collect::<Vec<_>>();

            // retrieve the signatures
            let encoded_messsage_bits = to_bits(encoded_message.clone());

            for i in 0..signatures.len() {
                let sig_r = decompress_point(&signatures[i][0..32]);
                assert!(sig_r.is_valid());
        
                let sig_s_biguint = BigUint::from_bytes_le(&signatures[i][32..64]);
                let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
                let sig = EDDSASignature { r: sig_r, s: sig_s };
        
                let pub_key = decompress_point(&sig_owners[i][0..32]);
                assert!(pub_key.is_valid());
        
                assert!(verify_message(
                    &encoded_messsage_bits,
                    &sig,
                    &EDDSAPublicKey(pub_key)
                ));
            }

            let encoded_header = header.encode();


            let mut context = context::current();
            context.deadline = SystemTime::now() + Duration::from_secs(600);

            // Convert signatures to Vec<Vec<u8>>
            let sigs = signatures.iter().map(|x| x.to_vec()).collect::<Vec<_>>();

            let res = client.generate_grandpa_justif_proof(
                context, 
                block_hash, 
                encoded_header.clone(),
                encoded_message.clone(),
                sigs.clone(),
                sig_owners.clone(),
            ).await;
        
            match res {
                Ok(_) => println!("Retrieved grandpa justification verification proof for block: number - {:?}; hash - {:?}", header.number, block_hash),
                Err(e) => println!("{:?}", anyhow::Error::from(e)),
            }

            println!("\n\n\n");
        }
        */
}
