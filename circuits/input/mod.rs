pub mod types;

use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use std::time::Duration;

use avail_subxt::avail::Client;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use avail_subxt::rpc::RpcParams;
use avail_subxt::{api, build_client};
use codec::{Compact, Decode, Encode};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use ethers::types::H256;
use log::debug;
use plonky2x::frontend::ecc::ed25519::gadgets::verify::{DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE};
use redis::aio::Connection;
use redis::{AsyncCommands, JsonAsyncCommands};
use sha2::Digest;
use tokio::time::sleep;

use self::types::{
    EncodedFinalityProof, FinalityProof, GrandpaJustification, HeaderRotateData, SignerMessage,
    StoredJustificationData,
};
use crate::consts::{
    BASE_PREFIX_LENGTH, DELAY_LENGTH, HASH_SIZE, PUBKEY_LENGTH, VALIDATOR_LENGTH, WEIGHT_LENGTH,
};
use crate::input::types::SimpleJustificationData;
use crate::vars::{AffinePoint, Curve};

pub struct RedisClient {
    pub redis: redis::Client,
}

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

        // Add the block number to a sorted set, so we can query for all blocks with justifications.
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
                // Handle the error appropriately, maybe return an Err if your function can return a Result
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
pub fn compute_authority_set_hash(authorities: &[Vec<u8>]) -> Vec<u8> {
    let mut hash_so_far = Vec::new();
    for i in 0..authorities.len() {
        let authority = authorities[i].clone();
        let mut hasher = sha2::Sha256::new();
        hasher.update(hash_so_far);
        hasher.update(authority);
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

pub struct RpcDataFetcher {
    pub client: Client,
    pub redis_client: RedisClient,
    pub save: Option<String>,
}

impl RpcDataFetcher {
    const MAX_RECONNECT_ATTEMPTS: usize = 3;
    const RECONNECT_DELAY: Duration = Duration::from_secs(5);

    pub async fn new() -> Self {
        // let mut url = env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env");
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        let redis_client = RedisClient::new().await;
        RpcDataFetcher {
            client,
            redis_client,
            save: None,
        }
    }

    async fn check_client_connection(&mut self) -> Result<(), String> {
        for _ in 0..Self::MAX_RECONNECT_ATTEMPTS {
            match self.client.rpc().system_health().await {
                Ok(_) => return Ok(()),
                Err(_) => {
                    let url = "wss://kate.avail.tools:443/ws".to_string();
                    match build_client(url.as_str(), false).await {
                        Ok(new_client) => {
                            self.client = new_client;
                            return Ok(());
                        }
                        Err(_) => {
                            debug!("Failed to connect to client, retrying...");
                            tokio::time::sleep(Self::RECONNECT_DELAY).await;
                        }
                    }
                }
            }
        }
        Err("Failed to connect to Avail client after multiple attempts!".to_string())
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
        // Query Redis for all keys in the range [start_block, end_block].
        let redis_blocks: Vec<u32> = self
            .redis_client
            .get_blocks_in_range(start_block, end_block)
            .await;

        // Query the chain for all era end blocks in the range [start_block, end_block].
        let start_era = self.get_authority_set_id(start_block - 1).await;

        let mut curr_block = start_block;
        let mut curr_era = start_era;
        let mut epoch_end_blocks = Vec::new();
        while curr_block < end_block {
            let epoch_end_block = self.last_justified_block(curr_era).await;
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

    pub async fn get_block_hash(&mut self, block_number: u32) -> H256 {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");

        let block_hash = self
            .client
            .rpc()
            .block_hash(Some(block_number.into()))
            .await;
        block_hash.unwrap().unwrap()
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

        let mut headers = Vec::new();
        for block_number in start_block_number..end_block_number + 1 {
            let block_hash = self.get_block_hash(block_number).await;
            let header_result = self.client.rpc().header(Some(block_hash)).await;
            let header: Header = header_result.unwrap().unwrap();
            headers.push(header);
        }
        headers
    }

    pub async fn get_header(&mut self, block_number: u32) -> Header {
        self.check_client_connection()
            .await
            .expect("Failed to establish connection to Avail WS.");
        let block_hash = self.get_block_hash(block_number).await;
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
    pub async fn get_authorities(&mut self, block_number: u32) -> Vec<Vec<u8>> {
        let block_hash = self.get_block_hash(block_number).await;

        let grandpa_authorities_bytes = self
            .client
            .storage()
            .at(block_hash)
            .fetch_raw(b":grandpa_authorities")
            .await
            .unwrap()
            .unwrap();

        // TODO: Reference the following comment for verifying the compact scale encoding inside of the circuit.
        // The grandpa_authorities_bytes has one of the two following formats:
        // [V, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]
        // [V, X, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]
        // Where V is a "Version" number (right now it's 1u8)
        // Where X or XX is the compact scale encoding of the number of authorities
        // This is a reference on how compact scale encoding works: https://docs.substrate.io/reference/scale-codec/#fn-1

        // The prefix length is 2 if the number of authorities is <=63, otherwise it is 3 (including)
        // the version number. This is because the compact scale encoding will be only 1 byte if the
        // number of authorities is <=63.
        let offset = if grandpa_authorities_bytes.len() < ((32 + 8) * 63) + 3 {
            2
        } else {
            3
        };

        // Each encoded authority is 32 bytes for the public key, and 8 bytes for the weight, so
        // the rest of the bytes should be a multiple of 40.
        assert!((grandpa_authorities_bytes.len() - offset) % (32 + 8) == 0);

        let pubkey_and_weight_bytes = &grandpa_authorities_bytes[offset..];

        let mut authorities: Vec<AffinePoint<Curve>> = Vec::new();
        let mut authories_pubkey_bytes: Vec<Vec<u8>> = Vec::new();
        for authority_pubkey_weight in pubkey_and_weight_bytes.chunks(VALIDATOR_LENGTH) {
            let pub_key_vec = authority_pubkey_weight[..32].to_vec();
            let pub_key_point = AffinePoint::<Curve>::new_from_compressed_point(&pub_key_vec);
            authorities.push(pub_key_point);
            authories_pubkey_bytes.push(pub_key_vec);

            // Assert that the weight is 1 (weight is in LE representation).
            assert_eq!(authority_pubkey_weight[32], 1);
            for i in 33..VALIDATOR_LENGTH {
                assert_eq!(authority_pubkey_weight[i], 0);
            }
        }

        authories_pubkey_bytes
    }

    // Computes the authority_set_hash for a given block number.
    // This is the authority_set_hash of the next block.
    pub async fn compute_authority_set_hash(&mut self, block_number: u32) -> H256 {
        let authorities = self.get_authorities(block_number).await;

        let mut hash_so_far = Vec::new();
        for i in 0..authorities.len() {
            let authority = authorities[i].clone();
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash_so_far);
            hasher.update(authority);
            hash_so_far = hasher.finalize().to_vec();
        }
        H256::from_slice(&hash_so_far)
    }

    async fn get_justification_data<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        block_number: u32,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<bool>, Vec<u8>, u64, u64) {
        // Note: grandpa_proveFinality will serve the proof for the last justified block in an epoch.
        // This means that get_simple_justification should fail for any block that is not the last
        // justified block in an epoch.
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
            // TODO: verify above that signed_message = block_hash || block_number || round || set_id

            let mut pubkey_bytes_to_signature = HashMap::new();

            // Verify all the signatures of the justification.
            // TODO: panic if the justification is not not a simple justification
            justification
                .commit
                .precommits
                .iter()
                .for_each(|precommit| {
                    let pubkey = precommit.clone().id;
                    let signature = precommit.clone().signature.0;
                    let pubkey_bytes = pubkey.0.to_vec();

                    verify_signature(&pubkey_bytes, &signed_message, &signature);
                    pubkey_bytes_to_signature.insert(pubkey_bytes, signature);
                });

            let mut validator_signed = Vec::new();
            let mut padded_signatures = Vec::new();
            let mut padded_pubkeys = Vec::new();
            let mut voting_weight = 0;
            for pubkey_bytes in authorities_pubkey_bytes.iter() {
                let signature = pubkey_bytes_to_signature.get(pubkey_bytes);
                // let authority = AffinePoint::<Curve>::new_from_compressed_point(pubkey_bytes);

                if let Some(valid_signature) = signature {
                    verify_signature(pubkey_bytes, &signed_message, valid_signature);
                    validator_signed.push(true);
                    padded_pubkeys.push(pubkey_bytes.clone());
                    padded_signatures.push((*valid_signature).to_vec());
                    voting_weight += 1;
                } else {
                    validator_signed.push(false);
                    padded_pubkeys.push(pubkey_bytes.clone());
                    // Push a dummy signature, since this validator did not sign.
                    padded_signatures.push(DUMMY_SIGNATURE.to_vec());
                }
            }
            (
                padded_pubkeys,
                padded_signatures,
                validator_signed,
                signed_message,
                voting_weight,
                authorities_pubkey_bytes.len() as u64,
            )
        } else {
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
            (
                stored_justification_data.pubkeys,
                stored_justification_data.signatures,
                stored_justification_data.validator_signed,
                stored_justification_data.signed_message,
                voting_weight,
                stored_justification_data.num_authorities as u64,
            )
        }
    }

    // This function takes in a block_number as input, fetches the authority set for that block and the finality proof
    // for that block. If the finality proof is a simple justification, it will return a SimpleJustificationData
    // containing all the encoded precommit that the authorities sign, the validator signatures, and the authority pubkeys.
    pub async fn get_simple_justification<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        block_number: u32,
    ) -> SimpleJustificationData {
        let (
            pubkeys,
            signatures,
            mut validator_signed,
            signed_message,
            voting_weight,
            num_authorities,
        ) = self
            .get_justification_data::<VALIDATOR_SET_SIZE_MAX>(block_number)
            .await;

        let current_authority_set_id = self.get_authority_set_id(block_number - 1).await;
        let current_authority_set_hash = compute_authority_set_hash(&pubkeys);

        if voting_weight * 3 < num_authorities * 2 {
            panic!("Not enough voting power");
        }

        let mut padded_pubkeys = Vec::new();
        let mut padded_signatures = Vec::new();
        let mut padded_validator_signed = Vec::new();
        for i in 0..num_authorities as usize {
            padded_pubkeys.push(AffinePoint::new_from_compressed_point(&pubkeys[i]));
            padded_signatures.push(signatures[i].clone().as_slice().try_into().unwrap());
            padded_validator_signed.push(validator_signed[i]);
        }

        for _ in num_authorities as usize..VALIDATOR_SET_SIZE_MAX {
            validator_signed.push(false);
            // Push a dummy pubkey and signature, to pad the array to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY));
            padded_signatures.push(DUMMY_SIGNATURE);
        }

        SimpleJustificationData {
            authority_set_id: current_authority_set_id,
            signed_message,
            validator_signed,
            pubkeys: padded_pubkeys,
            signatures: padded_signatures,
            num_authorities: num_authorities as usize,
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
        let number_encoded = epoch_end_block.encode();
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
                        assert_eq!(*pubkey, new_authorities[i]);

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

        // Panic if we did not find the consensus log.
        if !found_correct_log {
            panic!(
                "Block: {:?} should be an epoch end block, but did not find corresponding consensus log!",
                epoch_end_block
            );
        }

        let new_authority_set_hash = compute_authority_set_hash(&new_authorities);
        let mut padded_pubkeys = Vec::new();
        for i in 0..new_authorities.len() {
            padded_pubkeys.push(H256::from_slice(&new_authorities[i].clone()));
        }
        for _ in new_authorities.len()..VALIDATOR_SET_SIZE_MAX {
            // Pad the array with dummy pubkeys to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(H256::from_slice(&DUMMY_PUBLIC_KEY));
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
        let headers = fetcher.get_block_headers_range(100000, 100009).await;
        assert_eq!(headers.len(), 10);
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
            .get_simple_justification::<VALIDATOR_SET_SIZE_MAX>(block)
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

        // Verify that we found an epoch end block.
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
        let mut data_fetcher = RpcDataFetcher::new().await;

        let mut start_epoch = 100;
        loop {
            if start_epoch > 617 {
                break;
            }
            let epoch_end_block = data_fetcher.last_justified_block(start_epoch).await;

            let _ = data_fetcher
                .get_header_rotate::<MAX_HEADER_SIZE, MAX_AUTHORITY_SET_SIZE>(epoch_end_block)
                .await;

            println!("epoch_end_block {:?}", epoch_end_block);

            let num_authorities = data_fetcher.get_authorities(epoch_end_block).await.len();
            println!("num authorities {:?}", num_authorities);

            start_epoch += 100;
        }
    }
}
