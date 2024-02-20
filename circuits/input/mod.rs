pub mod types;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

use alloy_sol_types::{sol, SolType};
use avail_subxt::avail::Client;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use avail_subxt::subxt_rpc::RpcParams;
use avail_subxt::{api, build_client};
use codec::{Compact, Decode, Encode};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use ethers::types::H256;
use futures::future::join_all;
use log::{debug, info};
use plonky2x::frontend::curta::ec::point::CompressedEdwardsY;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::{DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE};
use redis::aio::Connection;
use redis::{AsyncCommands, JsonAsyncCommands};
use sha2::{Digest, Sha256};
use tokio::time::sleep;

use self::types::{
    CircuitJustification, EncodedFinalityProof, FinalityProof, GrandpaJustification,
    HeaderRotateData, SignerMessage, SimpleJustificationData, StoredJustificationData,
};
use crate::consts::{
    BASE_PREFIX_LENGTH, DELAY_LENGTH, HASH_SIZE, MAX_NUM_HEADERS, PUBKEY_LENGTH, VALIDATOR_LENGTH,
    WEIGHT_LENGTH,
};

#[derive(Clone)]
pub struct RedisClient {
    pub redis: redis::Client,
}

pub struct DataCommitmentRange {
    pub start: u32,
    pub end: u32,
    pub data_commitment: Vec<u8>,
}

type DataCommitmentRangeTuple = sol! { tuple(uint32, uint32, bytes32) };

impl RedisClient {
    const MAX_RECONNECT_ATTEMPTS: usize = 3;
    const RECONNECT_DELAY: Duration = Duration::from_secs(5);

    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let redis = redis::Client::open(redis_url).expect("Redis client not created");
        RedisClient { redis }
    }

    pub async fn get_connection(&mut self) -> Result<Connection, String> {
        for i in 0..Self::MAX_RECONNECT_ATTEMPTS {
            match self.redis.get_async_connection().await {
                Ok(con) => return Ok(con),
                Err(e) => {
                    // Log the retry attempt and error.
                    debug!(
                        "Attempt {} failed with error: {}. Retrying in {:?}...",
                        i,
                        e,
                        Self::RECONNECT_DELAY
                    );
                    // Wait for the delay before the next retry.
                    sleep(Self::RECONNECT_DELAY).await;
                }
            };
        }
        Err("Failed to connect to Redis after multiple attempts!".to_string())
    }

    /// Stores justification data in Redis. Errors if setting the key fails.
    pub async fn add_justification(&mut self, justification: StoredJustificationData) {
        let mut con = match self.get_connection().await {
            Ok(con) => con,
            Err(e) => panic!("{}", e),
        };

        // Justification is stored as a JSON object.
        let _: () = con
            .json_set(justification.block_number, "$", &justification)
            .await
            .expect("Failed to set key");

        // Add the block number to a sorted set, for easy querying of justifications in a range.
        let _: () = con
            .zadd(
                "blocks",
                justification.block_number,
                justification.block_number,
            )
            .await
            .expect("Failed to add key to sorted set");

        debug!(
            "Added justification for block {:?}",
            justification.block_number
        )
    }

    /// Gets justification data from Redis. Errors if getting the key fails.
    pub async fn get_justification(
        &mut self,
        block_number: u32,
    ) -> Result<StoredJustificationData, ()> {
        let mut con = match self.get_connection().await {
            Ok(con) => con,
            Err(e) => panic!("{}", e),
        };

        // Result is always stored as serialized bytes: https://github.com/redis-rs/redis-rs#json-support.
        let serialized_justification: Vec<u8> = con
            .json_get(block_number, "$")
            .await
            .expect("Failed to get key");

        match serde_json::from_slice::<Vec<StoredJustificationData>>(&serialized_justification) {
            Ok(justification) => Ok(justification[0].clone()),
            Err(e) => {
                eprintln!("Failed to deserialize justification: {}", e);
                Err(())
            }
        }
    }

    /// Gets all blocks in range [start, end] (inclusive) that have justifications in Redis.
    pub async fn get_blocks_in_range(&mut self, start: u32, end: u32) -> Vec<u32> {
        let mut con = match self.get_connection().await {
            Ok(con) => con,
            Err(e) => panic!("{}", e),
        };

        con.zrangebyscore("blocks", start, end)
            .await
            .expect("Failed to get keys")
    }

    /// Stores data commitment range data in Redis. Errors if setting the key fails.
    pub async fn add_data_commitment_range(
        &mut self,
        chain_id: u64,
        address: Vec<u8>,
        range: DataCommitmentRange,
    ) {
        let mut con = match self.get_connection().await {
            Ok(con) => con,
            Err(e) => panic!("{}", e),
        };

        // Add 0x prefix to address.
        let address = format!("0x{}", hex::encode(address));

        let key = format!("{}:{}:ranges", chain_id, address);

        let data_commitment: [u8; 32] = range.data_commitment.try_into().unwrap();

        let range_data: Vec<u8> =
            DataCommitmentRangeTuple::abi_encode_packed(&(range.start, range.end, data_commitment));
        // Branch is stored as an ABI encode packed tuple.
        let _: () = con
            .zadd(key.clone(), hex::encode(range_data), range.end)
            .await
            .expect("Failed to set key");

        info!(
            "Added range: {:?}-{:?} with data commitment: {:?}",
            range.start,
            range.end,
            hex::encode(data_commitment)
        );
    }
}

/// This function is useful for verifying that a Ed25519 signature is valid, it will panic if the signature is not valid
pub fn verify_signature(pubkey_bytes: &[u8], signed_message: &[u8], signature: &[u8; 64]) {
    let pubkey_dalek = PublicKey::from_bytes(pubkey_bytes).unwrap();
    let verified = pubkey_dalek.verify(signed_message, &Signature::from_bytes(signature).unwrap());
    if verified.is_err() {
        panic!("Signature is not valid");
    }
}

// Compute the chained hash of the authority set.
pub fn compute_authority_set_hash(authorities: &[CompressedEdwardsY]) -> Vec<u8> {
    let mut hash_so_far = Vec::new();
    for i in 0..authorities.len() {
        let authority = authorities[i];
        let mut hasher = sha2::Sha256::new();
        hasher.update(hash_so_far);
        hasher.update(authority.as_bytes());
        hash_so_far = hasher.finalize().to_vec();
    }
    hash_so_far
}

pub fn decode_precommit(precommit: Vec<u8>) -> (H256, u32, u64, u64) {
    // The first byte should be a 1.
    assert_eq!(precommit[0], 1);

    // The next 32 bytes are the block hash.
    let block_hash = &precommit[1..33];

    // The next 4 bytes are the block number.
    let block_number = &precommit[33..37];
    // Convert the block number to a u32.
    let block_number = u32::from_le_bytes(block_number.try_into().unwrap());

    // The next 8 bytes are the justification round.
    let round = &precommit[37..45];
    // Convert the round to a u64.
    let round = u64::from_le_bytes(round.try_into().unwrap());

    // The next 8 bytes are the authority set id.
    let authority_set_id = &precommit[45..53];
    // Convert the authority set id to a u64.
    let authority_set_id = u64::from_le_bytes(authority_set_id.try_into().unwrap());

    (
        H256::from_slice(block_hash),
        block_number,
        round,
        authority_set_id,
    )
}

#[derive(Clone)]
pub struct RpcDataFetcher {
    pub client: Client,
    pub avail_url: String,
    pub redis_client: RedisClient,
    pub save: Option<String>,
}

impl RpcDataFetcher {
    const MAX_RECONNECT_ATTEMPTS: usize = 3;
    const RECONNECT_DELAY: Duration = Duration::from_secs(5);

    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let url = env::var("AVAIL_URL").expect("AVAIL_URL must be set");
        let client = build_client(url.as_str(), false).await.unwrap();
        let redis_client = RedisClient::new().await;
        RpcDataFetcher {
            client: client.0,
            avail_url: url,
            redis_client,
            save: None,
        }
    }

    async fn check_client_connection(&mut self) -> Result<(), String> {
        for _ in 0..Self::MAX_RECONNECT_ATTEMPTS {
            match self.client.rpc().system_health().await {
                Ok(_) => return Ok(()),
                Err(_) => match build_client(self.avail_url.as_str(), false).await {
                    Ok(new_client) => {
                        self.client = new_client.0;
                        return Ok(());
                    }
                    Err(_) => {
                        debug!("Failed to connect to client, retrying...");
                        tokio::time::sleep(Self::RECONNECT_DELAY).await;
                    }
                },
            }
        }
        Err("Failed to connect to Avail client after multiple attempts!".to_string())
    }

    pub async fn check_data_commitment(&mut self, block: u32) {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        let header = self.get_header(block).await;
        let data_root = header.data_root().0.to_vec();
        println!("data_root {:?}", data_root);

        let encoded_header_bytes = header.encode();
        println!("encoded_header_bytes {:?}", encoded_header_bytes);

        // Find the data_root in the header.
        let mut data_root_index = -1;
        for i in 0..(encoded_header_bytes.len() - HASH_SIZE) + 1 {
            if encoded_header_bytes[i..i + HASH_SIZE] == data_root[..] {
                data_root_index = i as i32;
                break;
            }
        }

        println!("data_root_index {:?}", data_root_index);
    }

    /// Finds all blocks with valid justifications. This includes justifications in Redis and epoch
    /// end blocks within the given range of block numbers. Includes start and end blocks.
    pub async fn find_justifications_in_range(
        &mut self,
        start_block: u32,
        end_block: u32,
    ) -> Vec<u32> {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");
        info!(
            "Finding justifications in range [{}, {}].",
            start_block, end_block
        );
        // Query Redis for all keys in the range [start_block, end_block].
        let redis_blocks: Vec<u32> = self
            .redis_client
            .get_blocks_in_range(start_block, end_block)
            .await;

        info!("Found {} blocks in Redis.", redis_blocks.len());

        // Query the chain for all era end blocks in the range [start_block, end_block].
        let start_era = self.get_authority_set_id(start_block - 1).await;

        let mut curr_block = start_block;
        let mut curr_era = start_era;
        let mut epoch_end_blocks = Vec::new();
        while curr_block < end_block {
            let epoch_end_block = self.last_justified_block(curr_era).await;
            if epoch_end_block == 0 {
                // This era is currently active, so there are no epoch end blocks.
                break;
            }

            if epoch_end_block <= end_block {
                epoch_end_blocks.push(epoch_end_block);
                curr_block = epoch_end_block;
                curr_era += 1;
            } else {
                break;
            }
        }

        // Combine the Redis blocks and epoch end blocks.
        let mut all_blocks = redis_blocks;
        all_blocks.extend(epoch_end_blocks);
        all_blocks.sort();

        all_blocks
    }

    // This function returns the last block justified by target_authority_set_id. This block
    // also specifies the new authority set, which starts justifying after this block.
    // Returns 0 if curr_authority_set_id <= target_authority_set_id.
    pub async fn last_justified_block(&mut self, target_authority_set_id: u64) -> u32 {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        let mut low = 0;
        let head_block = self.get_head().await;
        let mut high = head_block.number;
        let mut epoch_end_block_number = 0;

        while low <= high {
            let mid = (low + high) / 2;
            let mid_authority_set_id = self.get_authority_set_id(mid).await;

            match mid_authority_set_id.cmp(&(target_authority_set_id + 1)) {
                Ordering::Equal => {
                    if mid == 0 {
                        // Special case: there is no block "mid - 1", just return the found block.
                        epoch_end_block_number = mid;
                        break;
                    }
                    let prev_authority_set_id = self.get_authority_set_id(mid - 1).await;
                    if prev_authority_set_id == target_authority_set_id {
                        epoch_end_block_number = mid;
                        break;
                    } else {
                        high = mid - 1;
                    }
                }
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid - 1,
            }
        }
        epoch_end_block_number
    }

    pub async fn get_block_hash(&self, block_number: u32) -> H256 {
        let block_hash = self
            .client
            .rpc()
            .block_hash(Some(block_number.into()))
            .await;
        block_hash.unwrap().unwrap()
    }

    // Computes the simple Merkle root of the leaves.
    // If the number of leaves is not a power of 2, the leaves are extended with 0s to the next power of 2.
    pub fn get_merkle_root(leaves: Vec<Vec<u8>>) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![];
        }

        // Extend leaves to a power of 2.
        let mut leaves = leaves;
        while leaves.len().count_ones() != 1 {
            leaves.push([0u8; 32].to_vec());
        }

        // In VectorX, the leaves are not hashed.
        let mut nodes = leaves.clone();
        while nodes.len() > 1 {
            nodes = (0..nodes.len() / 2)
                .map(|i| {
                    let mut hasher = Sha256::new();
                    hasher.update(&nodes[2 * i]);
                    hasher.update(&nodes[2 * i + 1]);
                    hasher.finalize().to_vec()
                })
                .collect();
        }

        nodes[0].clone()
    }

    pub async fn get_merkle_root_commitments(
        &mut self,
        start_block: u32,
        end_block: u32,
    ) -> (Vec<u8>, Vec<u8>) {
        if (end_block - start_block) as usize > MAX_NUM_HEADERS {
            panic!("Range too large!");
        }

        // Uses the simple merkle tree implementation, which defaults to 256 leaves in Avail.
        let headers = self.get_block_headers_range(start_block, end_block).await;

        let mut data_root_leaves = Vec::new();
        let mut state_root_leaves = Vec::new();
        for i in 1..headers.len() {
            let header = &headers[i];
            data_root_leaves.push(header.data_root().0.to_vec());
            state_root_leaves.push(header.state_root.0.to_vec());
        }

        for _ in headers.len() - 1..MAX_NUM_HEADERS {
            data_root_leaves.push([0u8; 32].to_vec());
            state_root_leaves.push([0u8; 32].to_vec());
        }

        (
            Self::get_merkle_root(state_root_leaves),
            Self::get_merkle_root(data_root_leaves),
        )
    }

    // This function returns a vector of headers for a given range of block numbers, inclusive of the start and end block numbers.
    pub async fn get_block_headers_range(
        &mut self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        // Fetch the headers in batches of MAX_CONCURRENT_WS_REQUESTS. The WS connection will error if there
        // are too many concurrent requests.
        // TODO: Find the configuration for the maximum number of concurrent requests.
        const MAX_CONCURRENT_WS_REQUESTS: usize = 200;
        let mut headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let end_block = std::cmp::min(
                curr_block + MAX_CONCURRENT_WS_REQUESTS as u32 - 1,
                end_block_number,
            );
            let header_futures: Vec<_> = (curr_block..end_block)
                .map(|block_number| self.get_header(block_number))
                .collect();

            // Await all futures concurrently
            let headers_batch: Vec<Header> = join_all(header_futures)
                .await
                .into_iter()
                .collect::<Vec<_>>();

            headers.extend_from_slice(&headers_batch);
            curr_block += MAX_CONCURRENT_WS_REQUESTS as u32;
        }
        headers
    }

    pub async fn get_header(&self, block_number: u32) -> Header {
        let block_hash = self.get_block_hash(block_number).await;
        println!("Getting header for block number: {:?}", block_number);
        let header_result = self.client.rpc().header(Some(block_hash)).await;
        header_result.unwrap().unwrap()
    }

    pub async fn get_head(&mut self) -> Header {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");
        let head_block_hash = self.client.rpc().finalized_head().await.unwrap();
        let header = self.client.rpc().header(Some(head_block_hash)).await;
        header.unwrap().unwrap()
    }

    pub async fn get_authority_set_id(&mut self, block_number: u32) -> u64 {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");
        let block_hash = self.get_block_hash(block_number).await;

        let set_id_key = api::storage().grandpa().current_set_id();
        self.client
            .storage()
            .at(block_hash)
            .fetch(&set_id_key)
            .await
            .unwrap()
            .unwrap()
    }

    // This function returns the authorities (as AffinePoint and public key bytes) for a given block number
    // by fetching the "authorities_bytes" from storage and decoding the bytes to a VersionedAuthorityList.
    pub async fn get_authorities(&mut self, block_number: u32) -> Vec<CompressedEdwardsY> {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        let block_hash = self.get_block_hash(block_number).await;

        let grandpa_authorities_bytes = self
            .client
            .storage()
            .at(block_hash)
            .fetch_raw(b":grandpa_authorities")
            .await
            .unwrap()
            .unwrap();

        // The grandpa_authorities_bytes is the following:
        // V || X || <pub_key_compressed> || W || <pub_key_compressed> || W || ...
        // V is a "Version" number (1u8), which in compact encoding will be 1 byte.
        // X is the compact scale encoding of the number of authorities (1-2 bytes).
        // <pub_key_compressed> is the compressed EdDDSA public key (32 bytes).
        // W is the compact scale encoding of the weight (8 bytes long).
        // Compact scale encoding reference: https://docs.substrate.io/reference/scale-codec/#fn-1

        // If the number of authorities is <=63, the compact encoding of the number of authorities is 1 byte.
        // If the number of authorities is >63 & < 2^14, the compact encoding of the number of authorities is 2 bytes.
        // So, the offset is 2 if the number of authorities is <=63, and 3 if the number of authorities is >63.
        let offset = if grandpa_authorities_bytes.len() <= ((32 + 8) * 63) + 2 {
            2
        } else {
            3
        };

        // Each encoded authority is 32 bytes for the public key, and 8 bytes for the weight, so
        // the rest of the bytes should be a multiple of 40.
        assert!((grandpa_authorities_bytes.len() - offset) % (32 + 8) == 0);

        let pubkey_and_weight_bytes = &grandpa_authorities_bytes[offset..];

        let mut authorities: Vec<CompressedEdwardsY> = Vec::new();
        for authority_pubkey_weight in pubkey_and_weight_bytes.chunks(VALIDATOR_LENGTH) {
            let pub_key = CompressedEdwardsY::from_slice(&authority_pubkey_weight[..32]).unwrap();
            authorities.push(pub_key);

            let expected_weight = [1, 0, 0, 0, 0, 0, 0, 0];

            // Assert the LE representation of the weight of each validator is 1.
            assert_eq!(
                authority_pubkey_weight[32..40],
                expected_weight,
                "The weight of the authority is not 1!"
            );
        }

        authorities
    }

    // Computes the authority_set_hash for a given block number. Note: This is the authority set hash
    // that validates the next block after the given block number.
    pub async fn compute_authority_set_hash(&mut self, block_number: u32) -> H256 {
        let authorities = self.get_authorities(block_number).await;

        let mut hash_so_far = Vec::new();
        for i in 0..authorities.len() {
            let authority = authorities[i];
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash_so_far);
            hasher.update(authority.as_bytes());
            hash_so_far = hasher.finalize().to_vec();
        }
        H256::from_slice(&hash_so_far)
    }

    async fn get_justification_data<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        block_number: u32,
    ) -> SimpleJustificationData {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        // Note: grandpa_proveFinality will serve the proof for the last justified block in an epoch.
        // get_simple_justification should fail for any block that is not the last justified block
        // in an epoch.
        let curr_authority_set_id = self.get_authority_set_id(block_number).await;
        let prev_authority_set_id = self.get_authority_set_id(block_number - 1).await;

        // If epoch end block, use grandpa_proveFinality to get the justification.
        if curr_authority_set_id == prev_authority_set_id + 1 {
            let mut params = RpcParams::new();
            let _ = params.push(block_number);

            let encoded_finality_proof = self
                .client
                .rpc()
                .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
                .await
                .unwrap();

            let finality_proof: FinalityProof =
                Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
            let justification: GrandpaJustification =
                Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

            // The authority set id for the current block is defined in the previous block.
            let authority_set_id = self.get_authority_set_id(block_number - 1).await;

            // The authorities for the current block are defined in the previous block.
            let authorities_pubkey_bytes = self.get_authorities(block_number - 1).await;

            if authorities_pubkey_bytes.len() > VALIDATOR_SET_SIZE_MAX {
                panic!("Too many authorities");
            }

            // Form a message which is signed in the justification.
            let signed_message = Encode::encode(&(
                &SignerMessage::PrecommitMessage(
                    justification.commit.precommits[0].clone().precommit,
                ),
                &justification.round,
                &authority_set_id,
            ));

            let mut pubkey_bytes_to_signature = HashMap::new();

            // Verify all the signatures of the justification.
            justification
                .commit
                .precommits
                .iter()
                .for_each(|precommit| {
                    let pubkey = precommit.clone().id;
                    let signature = precommit.clone().signature.0;
                    let pubkey_bytes = pubkey.0.to_vec();

                    // Verify the signature by this validator over the signed_message which is shared.
                    verify_signature(&pubkey_bytes, &signed_message, &signature);
                    pubkey_bytes_to_signature.insert(pubkey_bytes, signature);
                });

            let mut validator_signed = Vec::new();
            let mut signatures = Vec::new();
            let mut pubkeys = Vec::new();
            let mut voting_weight = 0;
            for pubkey_bytes in authorities_pubkey_bytes.iter() {
                let signature = pubkey_bytes_to_signature.get(&pubkey_bytes.as_bytes().to_vec());

                if let Some(valid_signature) = signature {
                    validator_signed.push(true);
                    pubkeys.push(
                        CompressedEdwardsY::from_slice(pubkey_bytes.as_bytes().as_ref()).unwrap(),
                    );
                    signatures.push((*valid_signature).to_vec());
                    voting_weight += 1;
                } else {
                    validator_signed.push(false);
                    pubkeys.push(
                        CompressedEdwardsY::from_slice(pubkey_bytes.as_bytes().as_ref()).unwrap(),
                    );
                    // Push a dummy signature, since this validator did not sign.
                    signatures.push(DUMMY_SIGNATURE.to_vec());
                }
            }
            SimpleJustificationData {
                pubkeys,
                signatures,
                validator_signed,
                signed_message,
                voting_weight,
                num_authorities: authorities_pubkey_bytes.len() as u64,
            }
        } else {
            // If this is not an epoch end block, load the justification data from Redis.
            let stored_justification_data: StoredJustificationData = self
                .redis_client
                .get_justification(block_number)
                .await
                .expect("Failed to get justification from Redis");

            let mut voting_weight = 0;
            for validator_signed in stored_justification_data.validator_signed.iter() {
                if *validator_signed {
                    voting_weight += 1;
                }
            }

            let pubkeys = stored_justification_data
                .pubkeys
                .iter()
                .map(|pubkey| CompressedEdwardsY::from_slice(pubkey).unwrap())
                .collect::<Vec<CompressedEdwardsY>>();
            SimpleJustificationData {
                pubkeys,
                signatures: stored_justification_data.signatures,
                validator_signed: stored_justification_data.validator_signed,
                signed_message: stored_justification_data.signed_message,
                voting_weight,
                num_authorities: stored_justification_data.num_authorities as u64,
            }
        }
    }

    // Fetch the authority set and justification proof for block_number. If the finality proof is a
    // simple justification, return a CircuitJustification with the encoded precommit that all
    // authorities sign, the validator signatures, and the authority set's pubkeys.
    pub async fn get_justification_from_block<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        block_number: u32,
    ) -> CircuitJustification {
        let data = self
            .get_justification_data::<VALIDATOR_SET_SIZE_MAX>(block_number)
            .await;

        let current_authority_set_id = self.get_authority_set_id(block_number - 1).await;
        let current_authority_set_hash = compute_authority_set_hash(&data.pubkeys);

        if data.voting_weight * 3 < data.num_authorities * 2 {
            panic!("Not enough voting power");
        }

        let mut padded_pubkeys = Vec::new();
        let mut padded_signatures = Vec::new();
        let mut padded_validator_signed = Vec::new();
        for i in 0..data.num_authorities as usize {
            padded_pubkeys.push(data.pubkeys[i]);
            padded_signatures.push(data.signatures[i].as_slice().try_into().unwrap());
            padded_validator_signed.push(data.validator_signed[i]);
        }

        for _ in data.num_authorities as usize..VALIDATOR_SET_SIZE_MAX {
            padded_validator_signed.push(false);
            // Push a dummy pubkey and signature, to pad the array to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap());
            padded_signatures.push(DUMMY_SIGNATURE);
        }

        CircuitJustification {
            authority_set_id: current_authority_set_id,
            signed_message: data.signed_message,
            validator_signed: padded_validator_signed,
            pubkeys: padded_pubkeys,
            signatures: padded_signatures,
            num_authorities: data.num_authorities as usize,
            current_authority_set_hash,
        }
    }

    /// This function takes in a block_number as input, and fetches the new authority set specified
    /// in the epoch end block. It returns the data necessary to prove the new authority set, which
    /// specifies the new authority set hash, the number of authorities, and the start and end
    /// position of the encoded new authority set in the header.
    pub async fn get_header_rotate<
        const HEADER_LENGTH: usize,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        epoch_end_block: u32,
    ) -> HeaderRotateData {
        // Assert epoch_end_block is a valid epoch end block.
        let epoch_end_block_authority_set_id = self.get_authority_set_id(epoch_end_block).await;
        let prev_authority_set_id = self.get_authority_set_id(epoch_end_block - 1).await;
        assert_eq!(epoch_end_block_authority_set_id - 1, prev_authority_set_id);

        let header = self.get_header(epoch_end_block).await;

        let mut header_bytes = header.encode();
        let header_size = header_bytes.len();
        if header_size > HEADER_LENGTH {
            panic!(
                "header size {} is greater than HEADER_LENGTH {}",
                header_size, HEADER_LENGTH
            );
        }
        header_bytes.resize(HEADER_LENGTH, 0);

        // Fetch the new authority set specified in the epoch end block.
        let new_authorities = self.get_authorities(epoch_end_block).await;

        let num_authorities = new_authorities.len();
        let encoded_num_authorities_len = Compact(num_authorities as u32).encode().len();

        let mut position = 0;
        let number_encoded = Compact(epoch_end_block).encode();
        // Skip past parent_hash, number, state_root, extrinsics_root.
        position += HASH_SIZE + number_encoded.len() + HASH_SIZE + HASH_SIZE;

        let mut found_correct_log = false;
        for log in header.digest.logs {
            let encoded_log = log.clone().encode();
            // Note: Two bytes are skipped between the consensus id and value.
            if let DigestItem::Consensus(consensus_id, value) = log {
                if consensus_id == [70, 82, 78, 75] {
                    found_correct_log = true;

                    // Denotes that this is a `ScheduledChange` log.
                    assert_eq!(value[0], 1);

                    // The bytes after the prefix are the compact encoded number of authorities.
                    // Follows the encoding format: https://docs.substrate.io/reference/scale-codec/#fn-1
                    // If the number of authorities is <=63, the compact encoding is 1 byte.
                    // If the number of authorities is >63 & < 2^14, the compact encoding is 2 bytes.
                    let mut cursor = 1 + encoded_num_authorities_len;
                    let authorities_bytes = &value[cursor..];

                    for (i, authority_chunk) in
                        authorities_bytes.chunks_exact(VALIDATOR_LENGTH).enumerate()
                    {
                        let pubkey = &authority_chunk[..PUBKEY_LENGTH];
                        let weight = &authority_chunk[PUBKEY_LENGTH..];

                        // Assert the pubkey in the encoded log is correct.
                        assert_eq!(*pubkey, new_authorities[i].0);

                        // Assert weight's LE representation == 1
                        for j in 0..WEIGHT_LENGTH {
                            if j == 0 {
                                assert_eq!(weight[j], 1);
                            } else {
                                assert_eq!(weight[j], 0);
                            }
                        }

                        cursor += VALIDATOR_LENGTH;
                    }

                    // Assert delay is [0, 0, 0, 0]
                    let delay = &value[cursor..];
                    for i in 0..DELAY_LENGTH {
                        assert_eq!(delay[i], 0);
                    }

                    break;
                }
            }
            // If this is not the correct log, increment position by the length of the encoded log.
            if !found_correct_log {
                position += encoded_log.len();
            }
        }

        // Panic if there is not a consensus log.
        if !found_correct_log {
            panic!(
                "Block: {:?} should be an epoch end block, but did not find corresponding consensus log!",
                epoch_end_block
            );
        }

        let new_authority_set_hash = compute_authority_set_hash(&new_authorities);
        let mut padded_pubkeys = Vec::new();
        for i in 0..new_authorities.len() {
            padded_pubkeys.push(CompressedEdwardsY::from_slice(&new_authorities[i].0).unwrap());
        }
        for _ in new_authorities.len()..VALIDATOR_SET_SIZE_MAX {
            // Pad the array with dummy pubkeys to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(CompressedEdwardsY::from_slice(&DUMMY_PUBLIC_KEY).unwrap());
        }

        // TODO: Find out what the unknown bytes are (probably an enum).
        // 1 unknown, 1 consensus id, 4 consensus engine id, 2 unknown,
        // 1 scheduled change, variable length compact encoding of the number of authorities.
        let prefix_length = BASE_PREFIX_LENGTH + encoded_num_authorities_len;
        // The end position is the position + prefix_length + encoded pubkeys len + 4 delay bytes.
        let end_position = position + prefix_length + ((32 + 8) * new_authorities.len()) + 4;

        HeaderRotateData {
            header_bytes,
            header_size,
            num_authorities: new_authorities.len(),
            start_position: position,
            end_position,
            new_authority_set_hash,
            padded_pubkeys,
        }
    }
}

#[cfg(test)]
mod tests {
    use avail_subxt::config::Header;

    use super::*;
    use crate::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE};

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_block_headers_range() {
        let mut fetcher = RpcDataFetcher::new().await;
        let _ = fetcher.get_block_headers_range(100000, 100256).await;
        // assert_eq!(headers.len(), 181);
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_header_hash() {
        let mut fetcher = RpcDataFetcher::new().await;

        let target_block = 645570;
        let header = fetcher.get_header(target_block).await;
        let _ = fetcher.get_block_hash(target_block).await;

        println!("header hash {:?}", hex::encode(header.hash().0));

        let id_1 = fetcher.get_authority_set_id(target_block - 1).await;
        let authority_set_hash = fetcher.compute_authority_set_hash(target_block - 1).await;
        println!("authority set id {:?}", id_1);
        println!("authority set hash {:?}", hex::encode(authority_set_hash.0));
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_authority_set_id() {
        let mut fetcher = RpcDataFetcher::new().await;
        let mut block: u32 = 215000;

        loop {
            let authority_set_id = fetcher.get_authority_set_id(block).await;
            println!("authority_set_id {:?}", authority_set_id);

            let prev_epoch_end_block = fetcher.last_justified_block(authority_set_id - 1).await;
            println!("prev end block {:?}", prev_epoch_end_block);
            // The current authorities are defined in the last block of the previous epoch.
            let curr_authorities = fetcher.get_authorities(prev_epoch_end_block).await;

            let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;
            println!("curr end block {:?}", epoch_end_block);
            // The next authority set is defined by the last block of the current epoch.
            let next_authorities = fetcher.get_authorities(epoch_end_block).await;

            if curr_authorities.len() != next_authorities.len() {
                println!("genesis id {:?}", authority_set_id);
                println!(
                    "genesis authority set hash {:?}",
                    hex::encode(compute_authority_set_hash(&curr_authorities))
                );
                println!(
                    "genesis block (last block justified by genesis id) {:?}",
                    epoch_end_block
                );
                let genesis_header = fetcher.get_header(epoch_end_block).await;
                println!("genesis header {:?}", hex::encode(genesis_header.hash().0));

                break;
            }
            block += 1000;
        }
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_simple_justification_change_authority_set() {
        let mut fetcher = RpcDataFetcher::new().await;

        // This is an block in the middle of an era.
        let block = 645570;

        let authority_set_id = fetcher.get_authority_set_id(block - 1).await;
        let authority_set_hash = fetcher.compute_authority_set_hash(block - 1).await;
        let header = fetcher.get_header(block).await;
        let header_hash = header.hash();

        println!("authority_set_id {:?}", authority_set_id);
        println!("authority_set_hash {:?}", hex::encode(authority_set_hash.0));
        println!("header_hash {:?}", hex::encode(header_hash.0));

        const VALIDATOR_SET_SIZE_MAX: usize = 100;
        let _ = fetcher
            .get_justification_from_block::<VALIDATOR_SET_SIZE_MAX>(block)
            .await;
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_new_authority_set() {
        let mut fetcher = RpcDataFetcher::new().await;

        // A binary search given a target_authority_set_id, returns the last block justified by
        // target_authority_set_id. This block also specifies the new authority set,
        // target_authority_set_id + 1.
        let target_authority_set_id = 513;
        let epoch_end_block_number = fetcher.last_justified_block(target_authority_set_id).await;

        // Verify that this is an epoch end block.
        assert_ne!(epoch_end_block_number, 0);
        println!("epoch_end_block_number {:?}", epoch_end_block_number);

        let previous_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number - 1)
            .await;
        let authority_set_id = fetcher.get_authority_set_id(epoch_end_block_number).await;

        // Verify this is an epoch end block.
        assert_eq!(previous_authority_set_id + 1, authority_set_id);
        assert_eq!(authority_set_id, target_authority_set_id);

        let rotate_data = fetcher
            .get_header_rotate::<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>(epoch_end_block_number)
            .await;
        println!(
            "new authority set hash {:?}",
            rotate_data.new_authority_set_hash
        );
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_grandpa_prove_finality() {
        let mut fetcher = RpcDataFetcher::new().await;

        let block_number = 642000;
        let authority_set_id = fetcher.get_authority_set_id(block_number - 1).await;

        let last_justified_block = fetcher.last_justified_block(authority_set_id).await;

        let header = fetcher.get_header(last_justified_block).await;
        println!("header hash {:?}", hex::encode(header.hash().0));
        let authority_set_hash = fetcher.compute_authority_set_hash(block_number - 1).await;
        println!("authority set hash {:?}", hex::encode(authority_set_hash.0));

        let new_authority_set_id = fetcher.get_authority_set_id(last_justified_block).await;

        println!(
            "last justified block from authority set {:?} is: {:?}",
            authority_set_id, last_justified_block
        );

        println!("new authority set id is: {:?}", new_authority_set_id);

        let mut params = RpcParams::new();
        let _ = params.push(last_justified_block + 1);

        let encoded_finality_proof = fetcher
            .client
            .rpc()
            .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
            .await
            .unwrap();

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        let authority_set_id = fetcher.get_authority_set_id(block_number - 1).await;

        // Form a message which is signed in the justification.
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id,
        ));

        let (_, block_number, _, _) = decode_precommit(signed_message.clone());

        println!("block number {:?}", block_number);
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_query_redis_block_range() {
        let mut data_fetcher = RpcDataFetcher::new().await;

        let prev_last_justified_block = data_fetcher.last_justified_block(615).await;
        println!("prev_last_justified_block {:?}", prev_last_justified_block);
        let last_justified_block = data_fetcher.last_justified_block(616).await;
        println!("last_justified_block {:?}", last_justified_block);
        let blocks = data_fetcher
            .find_justifications_in_range(prev_last_justified_block, last_justified_block)
            .await;
        println!("keys {:?}", blocks);
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_header_rotate() {
        env::set_var("RUST_LOG", "debug");
        dotenv::dotenv().ok();
        env_logger::init();

        let mut data_fetcher = RpcDataFetcher::new().await;

        // let head = data_fetcher.get_head().await.number;
        let mut start_epoch = 179;
        loop {
            let epoch_end_block = data_fetcher.last_justified_block(start_epoch).await;
            if epoch_end_block == 0 {
                break;
            }
            log::debug!("epoch_end_block {:?}", epoch_end_block);

            let _ = data_fetcher
                .get_header_rotate::<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>(epoch_end_block)
                .await;

            let num_authorities = data_fetcher.get_authorities(epoch_end_block).await.len();
            println!("num authorities {:?}", num_authorities);

            start_epoch += 1;
        }
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_data_commitment() {
        let mut data_fetcher = RpcDataFetcher::new().await;

        let trusted_block = 338901;
        let target_block = 339157;

        let (state_merkle_root, data_merkle_root) = data_fetcher
            .get_merkle_root_commitments(trusted_block, target_block)
            .await;
        println!(
            "state_merkle_root {:?}",
            hex::encode(state_merkle_root.as_slice())
        );
        println!(
            "data_merkle_root {:?}",
            hex::encode(data_merkle_root.as_slice())
        );
    }
}
