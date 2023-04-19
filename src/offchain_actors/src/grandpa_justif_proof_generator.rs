
use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, Duration};

use service::{ProofGeneratorClient, to_bits};
use avail_subxt::{api, build_client, primitives::Header};
use codec::{Decode, Encode};
use ::ed25519::curve::eddsa::{EDDSASignature, verify_message, EDDSAPublicKey};
use ::ed25519::field::ed25519_scalar::Ed25519Scalar;
use ::ed25519::gadgets::curve::decompress_point;
use num::BigUint;
use plonky2_field::types::Field;
use serde::de::Error;
use serde::Deserialize;

use subxt::{
	ext::{
		sp_core::{blake2_256, bytes, crypto::Pair, ed25519::{self, Public as EdPublic, Signature}, H256},
	},
    rpc::RpcParams,
};
use tarpc::{client, context};
use tarpc::tokio_serde::formats::Json;


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
    let server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 52357);

    let mut transport = tarpc::serde_transport::tcp::connect(server_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);
    let client = ProofGeneratorClient::new(client::Config::default(), transport.await?).spawn();

    let url: &str = "wss://testnet.avail.tools:443/ws";
    
    let c = build_client(url).await.unwrap();
    let t = c.rpc();
    let sub: Result<subxt::rpc::Subscription<GrandpaJustification>, subxt::Error> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;

    let mut sub = sub.unwrap();

    // How often we want to generate a proof of grandpa justification
    const FINALIZATION_PERIOD: usize = 20;

    // Wait for headers
    while let Some(Ok(justification)) = sub.next().await {
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
                Ok(proof) => println!("Retrieve grandpa justification verification proof: {:?}", proof),
                Err(e) => println!("{:?}", anyhow::Error::from(e)),
            }

            println!("\n\n\n");
        }
    }

    Ok(())
}
