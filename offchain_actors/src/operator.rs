
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::time::{SystemTime, Duration};

use avail_subxt::{
    api,
    AvailConfig,
    build_client,
    primitives::Header
};
use base58::FromBase58;
use codec::{Decode, Encode};
use futures::{select, StreamExt, pin_mut};
use pallet_grandpa::{VersionedAuthorityList, AuthorityList};
use serde::{
    de::Error,
    Deserialize
};
use service::ProofGeneratorClient;
use sp_core::{
	bytes,
	ed25519::{self, Public as EdPublic, Signature},
    H256,
	Pair,
};
use subxt::{
    config::{Hasher, Header as SPHeader},
    OnlineClient,
    rpc::{RpcParams, Subscription},
};
use tarpc::{
    client, context,
    tokio_serde::formats::Json
};

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

async fn get_authority_set(c: &OnlineClient<AvailConfig>, block_hash: H256) -> (Vec<Vec<u8>>, Vec<u8>) {
    let grandpa_authorities_bytes = c.storage().at(Some(block_hash)).await.unwrap().fetch_raw(b":grandpa_authorities").await.unwrap().unwrap();
    let grandpa_authorities = VersionedAuthorityList::decode(&mut grandpa_authorities_bytes.as_slice()).unwrap();
    let authority_list:AuthorityList = grandpa_authorities.into();

    let decoded_authority_set = authority_list.iter()
        .map(|authority|
            {
                let auth_bytes = authority.0.to_string().from_base58().unwrap();
                auth_bytes.as_slice()[1..33].to_vec()
            }
        )
        .collect::<Vec<_>>();
    let hash_input = decoded_authority_set.clone().into_iter().flatten().collect::<Vec<_>>();
    let authority_set_commitment = avail_subxt::config::substrate::BlakeTwo256::hash(&hash_input);

    (decoded_authority_set, authority_set_commitment.as_bytes().to_vec())
}

async fn submit_proof_gen_request(
    plonky2_pg_client: &ProofGeneratorClient,
    head_block_num: u32,
    head_block_hash: H256,
    headers: Vec<Header>,
    justification: GrandpaJustification,
    authority_set_id: u64,
    authority_set: Vec<Vec<u8>>,
    authority_set_commitment: Vec<u8>,
) {
    println!("Generate justification for block number: {:?}", justification.commit.target_number);

    // First scale encode the headers
    let encoded_headers = headers.iter().map(|x| x.encode()).collect::<Vec<_>>();

    // Form a message which is signed in the justification
    let precommit_message = Encode::encode(&(
        &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
        &justification.round,
        &authority_set_id,
    ));

    // Get the first 7 signatures and pub_keys.
    // This is to test against the step circuit that is only compatible with 10 authorities.
    let signatures = justification.
        commit.precommits.
        iter().
        map(|x| x.clone().signature.0.to_vec()).
        take(7).
        collect::<Vec<_>>();

    let mut public_keys = justification.
        commit.precommits.
        into_iter().
        map(|x| x.id.0.to_vec()).
        take(7).
        collect::<Vec<_>>();

    // Add 3 additional pub keys to make it 10
    // START HACK
    let authority_hashset = HashSet::from_iter(authority_set.into_iter());
    let public_keys_set: HashSet<Vec<u8>> = HashSet::from_iter(public_keys.iter().map(|x| x.to_vec()));
    let diff = authority_hashset.difference(&public_keys_set).collect::<Vec<_>>();
    let mut add_three = diff.iter().take(3).cloned().cloned().collect::<Vec<_>>();
    public_keys.append(&mut add_three);

    let authority_set_hash_input = public_keys.clone().into_iter().flatten().collect::<Vec<_>>();
    let authority_set_commitment = avail_subxt::config::substrate::BlakeTwo256::hash(&authority_set_hash_input);

    // Add 6 additions pub keys for padding
    let mut add_six = diff.into_iter().take(6).cloned().collect::<Vec<_>>();
    public_keys.append(&mut add_six);
    let authority_set = public_keys;

    let pub_key_indices = vec![0, 1, 2, 3, 4, 5, 6];
    // END HACK

    // Calculate public_inputs_hash
    let mut public_inputs_hash = Vec::new();
    public_inputs_hash.extend(&head_block_hash.0);
    public_inputs_hash.extend(head_block_num.to_be_bytes());
    public_inputs_hash.extend(authority_set_commitment.0);
    public_inputs_hash.extend(authority_set_id.to_be_bytes());
    for header in headers.iter() {
        public_inputs_hash.extend(header.state_root.0);
        public_inputs_hash.extend(header.hash().0);
    }
    assert!(public_inputs_hash.len() == 396);

    let public_inputs_hash = avail_subxt::config::substrate::BlakeTwo256::hash(&public_inputs_hash);

    /*
    // Find the pub_key_indices
    let pub_key_indices = public_keys.iter()
        .map(|x| authority_set.iter().position(|y| y == x)
        .unwrap()).collect::<Vec<_>>();
    */

    println!("headers: {:?}", encoded_headers);
    println!("head_block_hash: {:?}", head_block_hash);
    println!("head_block_num: {:?}", head_block_num);
    println!("authority_set_id: {:?}", authority_set_id);
    println!("precommit_message: {:?}", precommit_message);
    println!("signatures: {:?}", signatures);
    println!("pub_key_indices: {:?}", pub_key_indices);
    println!("authority_set: {:?}", authority_set);
    println!("authority_set_commitment: {:?}", authority_set_commitment);
    println!("public_inputs_hash: {:?}", public_inputs_hash);

    let mut context = context::current();
    context.deadline = SystemTime::now() + Duration::from_secs(600);

    let res = plonky2_pg_client.generate_step_proof_rpc(
        context,
        encoded_headers,
        head_block_hash.0.to_vec(),
        head_block_num,
        authority_set_id,
        precommit_message,
        signatures,
        pub_key_indices,
        authority_set,
        authority_set_commitment.0.to_vec(),
        public_inputs_hash.0.to_vec(),
    ).await;
        
    match res {
        Ok(_) => println!("Retrieved step verification proof for block: number - {:?}; hash - {:?}", justification.commit.target_number, justification.commit.target_hash),
        Err(e) => println!("{:?}", anyhow::Error::from(e)),
    }

    println!("\n\n\n");
}


async fn main_loop(
    header_sub : Subscription<Header>,
    justification_sub : Subscription<GrandpaJustification>,
    c: OnlineClient<AvailConfig>,
    plonky2_pg_client: ProofGeneratorClient,
) {
    let fused_header_sub = header_sub.fuse();
    let fused_justification_sub = justification_sub.fuse();

    pin_mut!(fused_header_sub, fused_justification_sub);

    let mut last_processed_block_num: Option<u32> = None;
    let mut last_processed_block_hash: Option<H256> = None;
    let mut headers = HashMap::new();

    // If this is not none, then the main loop will submit a proof generation request
    let mut justification_to_process = None;

    'main_loop: loop {
        select! {
            // Currently assuming that all the headers received will be sequential
            header = fused_header_sub.next() => {
                let unwrapped_header = header.unwrap().unwrap();

                if last_processed_block_num.is_none() {
                    last_processed_block_num = Some(unwrapped_header.number);
                    last_processed_block_hash = Some(unwrapped_header.hash());
                }

                println!("Downloaded a header for block number: {:?}", unwrapped_header.number);
                headers.insert(unwrapped_header.number, unwrapped_header);

                // TODO: Handle rotations if there is a new grandpa authority set event in the downloaded header
            }

            justification = fused_justification_sub.next() => {
                // Wait until we get at least one header
                if last_processed_block_num.is_none() {
                    continue;
                }

                let unwrapped_just = justification.unwrap().unwrap();

                if justification_to_process.is_none() && unwrapped_just.commit.target_number >= last_processed_block_num.unwrap() + 5 {
                    println!("Saving justification for block number: {:?}", unwrapped_just.commit.target_number);
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
            let (authority_set, authority_set_commitment) = get_authority_set(&c, previous_hash).await;

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
                for i in last_processed_block_num.unwrap()+1..unwrapped_just.commit.target_number+1 {
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

            submit_proof_gen_request(
                &plonky2_pg_client,
                last_processed_block_num.unwrap(),
                last_processed_block_hash.unwrap(),
                header_batch,
                justification_to_process.unwrap(),
                set_id,
                authority_set,
                authority_set_commitment,
            ).await;

            last_processed_block_num = Some(unwrapped_just.commit.target_number);
            last_processed_block_hash = Some(unwrapped_just.commit.target_hash);
            justification_to_process = None;
        }
    }
}

#[tokio::main]
pub async fn main() {
    let plonky2_pg_server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 52357);

    let mut transport = tarpc::serde_transport::tcp::connect(plonky2_pg_server_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let plonky2_pg_client = ProofGeneratorClient::new(client::Config::default(), transport.await.unwrap()).spawn();

    let url: &str = "wss://kate.avail.tools:443/ws";
    
    let c = build_client(url, false).await.unwrap();
    let t = c.rpc();

    // TODO:  Will need to sync the chain first

    let header_sub: subxt::rpc::Subscription<Header> = t
    .subscribe(
        "chain_subscribeFinalizedHeads",
        RpcParams::new(),
        "chain_unsubscribeFinalizedHeads",
    )
    .await
    .unwrap();

    let justification_sub: subxt::rpc::Subscription<GrandpaJustification> = t
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await
        .unwrap();

    main_loop(header_sub, justification_sub, c, plonky2_pg_client).await;
}

#[cfg(test)]
mod tests {
    use subxt::config::Hasher;

    #[test]
    fn calculate_public_inputs_hash() {
        let head_block_hash = hex::decode("36739e6b78e979fa79bbd262aa39074bfe787ef898cf5c49495f6be622013923").unwrap();
        let head_block_num:u32 = 100555;
        let authority_set_commitment = hex::decode("8e6866fa26ff254cdb0c2d7adf78b551a108770400317886aeb22f90556edeb9").unwrap();
        let authority_set_id:u64 = 94;
        let header_state_roots = [
            hex::decode("7e725e17a2824747374272517d14cd1107348713a2afc7708cf9761f64caa75b").unwrap(),
            hex::decode("f26477aaf1f897dd07991c889630a25777aff7153f8da7cb1c203143ef453283").unwrap(),
            hex::decode("8c1821b27dc70b11b5352712c4e524c8f70a9f0d90400521f62757c451b6c157").unwrap(),
            hex::decode("8358f7cc9ffd58e91f3d9e050a564a41fe7e52857f09eb317578ab22668e4320").unwrap(),
            hex::decode("b24df025ad5e9f95a4f8b3b9cbdd49839ad8ee21e89b3529f7ace6be0197c06e").unwrap(),
        ].to_vec();
        let header_hashes = [
            hex::decode("6ec84c7c494b000315aa07792ac983ad4ad135ca9b932487c2f58b75d808b8aa").unwrap(),
            hex::decode("40c3b65cc716265384c1e136f9e976721439e34ba22c83353719c1ec38bbf886").unwrap(),
            hex::decode("707c276a2ea559be9f6779d4daebce37ae97f246c5a38d7da74b1d1484f37d4e").unwrap(),
            hex::decode("a7ea0a59bc554b761d084ea8d927d4d5e19a7c511fc02a66ce8b4d00739881e1").unwrap(),
            hex::decode("dde2fa0b5c0694a26c9d1638bc9a0be2af855e71ad12c5723258e07edd891cc1").unwrap(),
        ].to_vec();

        let mut public_inputs_hash = Vec::new();
        public_inputs_hash.extend(head_block_hash);
        public_inputs_hash.extend(head_block_num.to_be_bytes());
        public_inputs_hash.extend(authority_set_commitment);
        public_inputs_hash.extend(authority_set_id.to_be_bytes());
        for i in 0..header_state_roots.len() {
            public_inputs_hash.extend(header_state_roots[i].clone());
            public_inputs_hash.extend(header_hashes[i].clone());
        }

        let hash = avail_subxt::config::substrate::BlakeTwo256::hash(&public_inputs_hash);

        println!("public_inputs_hash: {:?}", public_inputs_hash);
        println!("hash: {:?}", hash);
    }

}
