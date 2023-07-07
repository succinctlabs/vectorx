use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{SystemTime, Duration};

use avail_subxt::{
    api,
    AvailConfig,
    build_client,
    primitives::Header as AvailHeader,
};
use base58::FromBase58;
use codec::{Decode, Encode, Output};
use ethers::prelude::{abigen, SignerMiddleware};
use ethers::providers::Provider;
use ethers::signers::{LocalWallet};
use ethers::types::Address;
use ethers_core::types::Bytes;
use futures::{select, StreamExt, pin_mut};
use num::BigInt;
use num::bigint::Sign;
use pallet_grandpa::{VersionedAuthorityList, AuthorityList};
use serde::{
    de::Error,
    Deserialize
};
use service::ProofGeneratorClient;
use sp_core::twox_128;
use sp_core::{
	bytes,
	ed25519::{self, Public as EdPublic, Signature},
    H256,
	Pair,
};
use structopt::StructOpt;
use subxt::storage::StorageKey;
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
    pub votes_ancestries: Vec<AvailHeader>,
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

async fn get_authority_set(c: &OnlineClient<AvailConfig>, block_hash: H256) -> (u64, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<u8>) {
    // Construct the storage key for the current set id
    let mut epoch_index_storage_key = twox_128(b"Grandpa").to_vec();
    epoch_index_storage_key.extend(twox_128(b"CurrentSetId").to_vec());
    let sk = StorageKey(epoch_index_storage_key);
    let keys = [sk.0.as_slice()];
    let data = c.rpc().storage(keys[0], Some(block_hash)).await.unwrap().unwrap();
    let auth_set_id = u64::from_le_bytes(data.0.as_slice().try_into().unwrap());

    // Get the MP for that current set id
    let auth_set_id_proof = c.rpc().read_proof(keys, Some(block_hash)).await.unwrap();
    let mut proof_bytes = Vec::new();
    for i in 0..auth_set_id_proof.proof.len() {
        proof_bytes.push(auth_set_id_proof.proof[i].0.clone());
    }

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

    (auth_set_id, proof_bytes, decoded_authority_set, authority_set_commitment.as_bytes().to_vec())
}

abigen!(
    LightClient,
    "../contracts/out/LightClient.sol/LightClient.json",
);

async fn submit_step_txn(
    lc_address: Address,
    headers: Vec<Header>,
    authority_set_id: AuthoritySetIDProof,
    proof: Groth16Proof,
) {
    const RPC_URL: &str = "http://127.0.0.1:8546";

    let wallet: LocalWallet = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
        .parse::<LocalWallet>().unwrap();

    let provider = Provider::try_from(RPC_URL).unwrap();
    let client = SignerMiddleware::new(provider.clone(), wallet.clone());

    let contract = LightClient::new(lc_address, client.into());

    let mut header_data = Vec::new();
    for header in headers.iter() {
        let header_hash_hex = hex::encode(header.header_hash.as_slice());
        let state_root_hex = hex::encode(header.state_root.as_slice());
        let data_root_hex = hex::encode(header.data_root.as_slice());
        header_data.push(format!("{:?},{:?},{:?},{:?}", header.block_number, header_hash_hex, state_root_hex, data_root_hex));
    }

    let all_headers_str = header_data.join(",");
    let authority_set_str = format!(
        "({:?},[{:?}])",
        authority_set_id.authority_set_id,
        authority_set_id.merkle_proof.iter().map(|x| hex::encode(x.0.to_vec().as_slice())).collect::<Vec<_>>().join(","));
    let proof_str = format!(
        "([{:?},{:?}],[[{:?},{:?}],[{:?},{:?}]],[{:?},{:?}])",
        proof.a[0].to_string(),
        proof.a[1].to_string(),
        proof.b[0][0].to_string(),
        proof.b[0][1].to_string(),
        proof.b[1][0].to_string(),
        proof.b[1][1].to_string(),
        proof.c[0].to_string(),
        proof.c[1].to_string(),
    );

    println!("cast send {:?} \"step(((uint32, bytes32, bytes32, bytes32)[],(uint64, bytes[]),(uint256[2],uint256[2][2],uint256[2])))\" ([{:?}],{:?},{:?})", lc_address, all_headers_str, authority_set_str, proof_str);

    let a = contract.step(
        Step {
            headers,
            authority_set_id_proof: authority_set_id,
            proof
        }
    ).send().await.unwrap().await.unwrap();

    println!("Called step() at tx hash: {:?}", a);
}

fn to_u64_limbs(x: &BigInt) -> [u64; 4] {
    let (sign, digits) = x.to_u64_digits();
    assert!(sign == Sign::Plus);
    assert!(digits.len() <= 4);

    let mut limbs = [0u64; 4];
    for (i, d) in digits.iter().enumerate() {
        limbs[i] = *d;
    }

    limbs
}

async fn submit_proof_gen_request(
    plonky2_pg_client: &ProofGeneratorClient,
    head_block_num: u32,
    head_block_hash: H256,
    headers: &Vec<AvailHeader>,
    justification: GrandpaJustification,
    authority_set_id: u64,
    authority_set: Vec<Vec<u8>>,
    authority_set_commitment: Vec<u8>,
) -> Option<Groth16Proof> {        
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
        take(1).
        collect::<Vec<_>>();

    let mut public_keys = justification.
        commit.precommits.
        into_iter().
        map(|x| x.id.0.to_vec()).
        take(1).
        collect::<Vec<_>>();

    // Add 3 additional pub keys to make it 10
    // START HACK
    let authority_hashset = HashSet::from_iter(authority_set.into_iter());
    let public_keys_set: HashSet<Vec<u8>> = HashSet::from_iter(public_keys.iter().map(|x| x.to_vec()));
    let diff = authority_hashset.difference(&public_keys_set).collect::<Vec<_>>();
    let mut add_nine = diff.iter().take(9).cloned().cloned().collect::<Vec<_>>();
    public_keys.append(&mut add_nine);

    let authority_set_hash_input = public_keys.clone().into_iter().flatten().collect::<Vec<_>>();
    let authority_set_commitment = avail_subxt::config::substrate::BlakeTwo256::hash(&authority_set_hash_input);

    // Add 6 additions pub keys for padding
    let mut add_six = diff.into_iter().take(6).cloned().collect::<Vec<_>>();
    public_keys.append(&mut add_six);
    let authority_set = public_keys;

    let pub_key_indices = vec![0];
    // END HACK

    // Calculate public_inputs_hash
    let mut public_inputs_hash = Vec::new();
    /*
    public_inputs_hash.extend(&head_block_hash.0);
    public_inputs_hash.extend(head_block_num.to_be_bytes());
    public_inputs_hash.extend(authority_set_commitment.0);
    public_inputs_hash.extend(authority_set_id.to_be_bytes());
    */
    for header in headers.iter() {
        public_inputs_hash.extend(header.state_root.0);
        public_inputs_hash.extend(header.hash().0);
    }
    assert!(public_inputs_hash.len() == 320);

    let public_inputs_hash = avail_subxt::config::substrate::BlakeTwo256::hash(&public_inputs_hash);

    /*
    // Find the pub_key_indices
    let pub_key_indices = public_keys.iter()
        .map(|x| authority_set.iter().position(|y| y == x)
        .unwrap()).collect::<Vec<_>>();
    */

    println!("head_block_hash: {:?}", head_block_hash);
    println!("head_block_num: {:?}", head_block_num);
    println!("authority_set_id: {:?}", authority_set_id);
    println!("signatures: {:?}", signatures);
    println!("pub_key_indices: {:?}", pub_key_indices);
    println!("authority_set_commitment: {:?}", authority_set_commitment);
    println!("public_inputs_hash: {:?}", public_inputs_hash);

    let mut context = context::current();
    context.deadline = SystemTime::now() + Duration::from_secs(1200);

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
        Ok(proof) => {
            println!("Retrieved step verification proof for block: number - {:?}; hash - {:?}", justification.commit.target_number, justification.commit.target_hash);
            let proof_serialized = serde_json::to_string(&proof).unwrap();

            static SOCKET_PATH: &str = "/tmp/echo.sock";

            let socket = Path::new(SOCKET_PATH);

            let mut stream = UnixStream::connect(socket).unwrap();

            stream.write(proof_serialized.as_bytes());
            stream.write(hex::decode("1e").unwrap().as_slice());
            println!("Sent proof to gnark prover");
            // Write the character "Record Separater" to indicate the end of the proof


            let mut proof_bytes = Vec::new();
            let bytes_read = stream.read_to_end(&mut proof_bytes).unwrap();
            assert!(bytes_read == 256);

            // Read the returned generated groth16 proof.  Should be 256 bytes long.  There should also be a EOF charater.
            let fp_size = 32;
            let a_0 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[0 .. fp_size]);
            let a_1 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size .. fp_size*2]);
            let b_0_0 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*2 .. fp_size*3]);
            let b_0_1 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*3 .. fp_size*4]);
            let b_1_0 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*4 .. fp_size*5]);
            let b_1_1 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*5 .. fp_size*6]);
            let c_0 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*6 .. fp_size*7]);
            let c_1 = BigInt::from_bytes_be(Sign::Plus, &proof_bytes[fp_size*7 .. fp_size*8]);

            println!("a[0] is {:?}", a_0.to_string());
            println!("a[1] is {:?}", a_1.to_string());

            println!("b[0][0] is {:?}", b_0_0.to_string());
            println!("b[0][1] is {:?}", b_0_1.to_string());
            println!("b[1][0] is {:?}", b_1_0.to_string());
            println!("b[1][1] is {:?}", b_1_1.to_string());

            println!("c[0] is {:?}", c_0.to_string());
            println!("c[1] is {:?}", c_1.to_string());

            // Note that the b coordinates are switched
            Some(Groth16Proof {
                a: [
                    ethers_core::types::U256(to_u64_limbs(&a_0)),
                    ethers_core::types::U256(to_u64_limbs(&a_1)),
                ],
                b: [
                    [
                        ethers_core::types::U256(to_u64_limbs(&b_0_1)),
                        ethers_core::types::U256(to_u64_limbs(&b_0_0))
                    ],
                    [
                        ethers_core::types::U256(to_u64_limbs(&b_1_1)),
                        ethers_core::types::U256(to_u64_limbs(&b_1_0)),
                    ],
                   ],
                c: [
                    ethers_core::types::U256(to_u64_limbs(&c_0)),
                    ethers_core::types::U256(to_u64_limbs(&c_1)),
                   ],
            })
        },
        Err(e) => {
            println!("{:?}", anyhow::Error::from(e));
            None
        }
    }

}

async fn main_loop(
    header_sub : Subscription<AvailHeader>,
    justification_sub : Subscription<GrandpaJustification>,
    c: OnlineClient<AvailConfig>,
    plonky2_pg_client: ProofGeneratorClient,
    lc_address: Address,
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
            let (auth_set_id, auth_set_id_proof, authority_set, authority_set_commitment) = get_authority_set(&c, previous_hash).await;

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

            let proof = submit_proof_gen_request(
                &plonky2_pg_client,
                last_processed_block_num.unwrap(),
                last_processed_block_hash.unwrap(),
                &header_batch,
                justification_to_process.unwrap(),
                set_id,
                authority_set,
                authority_set_commitment,
            ).await;

            let headers_md = header_batch.iter()
                .map(|h|
                    Header {
                        block_number: h.number,
                        header_hash: h.hash().0,
                        state_root: h.state_root.0,
                        data_root: h.data_root().0,
                    })
                .collect::<Vec<_>>();

            submit_step_txn(
                lc_address,
                headers_md,
                AuthoritySetIDProof {
                    authority_set_id: auth_set_id,
                    merkle_proof: auth_set_id_proof.into_iter().map(Bytes::from).collect::<Vec<_>>(),
                },
                proof.unwrap(),
            ).await;

            last_processed_block_num = Some(unwrapped_just.commit.target_number);
            last_processed_block_hash = Some(unwrapped_just.commit.target_hash);
            justification_to_process = None;
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "Operator", about = "Operator for Succinct Lab's Avail Light Client")]
struct Opt {
    // The address of the Light Client
    #[structopt(long = "light-client-address")]
    lc_address: Address,
}

#[tokio::main]
pub async fn main() {
    let opt = Opt::from_args();

    let plonky2_pg_server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 52357);

    let mut transport = tarpc::serde_transport::tcp::connect(plonky2_pg_server_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let plonky2_pg_client = ProofGeneratorClient::new(client::Config::default(), transport.await.unwrap()).spawn();

    let url: &str = "wss://kate.avail.tools:443/ws";
    
    let c = build_client(url, false).await.unwrap();
    let t = c.rpc();

    // TODO:  Will need to sync the chain first

    let header_sub: subxt::rpc::Subscription<AvailHeader> = t
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

    main_loop(header_sub, justification_sub, c, plonky2_pg_client, opt.lc_address).await;
}