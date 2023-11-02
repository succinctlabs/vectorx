pub mod types;

use std::cmp::Ordering;
use std::collections::HashMap;

use avail_subxt::avail::Client;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use avail_subxt::rpc::RpcParams;
use avail_subxt::{api, build_client};
use codec::{Decode, Encode};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use ethers::types::H256;
use hex::encode;
use log::debug;
use plonky2x::frontend::ecc::ed25519::gadgets::verify::{DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE};
use sha2::Digest;

use self::types::{
    EncodedFinalityProof, FinalityProof, GrandpaJustification, HeaderRotateData, SignerMessage,
};
use crate::consts::{DELAY_LENGTH, HASH_SIZE, PUBKEY_LENGTH, VALIDATOR_LENGTH, WEIGHT_LENGTH};
use crate::input::types::SimpleJustificationData;
use crate::vars::{AffinePoint, Curve};

pub struct RpcDataFetcher {
    pub client: Client,
    pub save: Option<String>,
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
pub fn compute_authority_set_hash(authorities: Vec<Vec<u8>>) -> Vec<u8> {
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

impl RpcDataFetcher {
    pub async fn new() -> Self {
        // let mut url = env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env");
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        RpcDataFetcher { client, save: None }
    }

    // This function returns the last block justified by target_authority_set_id. This block
    // also specifies the new authority set, which starts justifying after this block.
    pub async fn last_justified_block(&self, target_authority_set_id: u64) -> u32 {
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

    // This function returns a vector of headers for a given range of block numbers, inclusive of the start and end block numbers.
    pub async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        let mut headers = Vec::new();
        for block_number in start_block_number..end_block_number + 1 {
            let block_hash = self.get_block_hash(block_number).await;
            let header_result = self.client.rpc().header(Some(block_hash)).await;
            let header: Header = header_result.unwrap().unwrap();
            headers.push(header);
        }
        headers
    }

    pub async fn get_header(&self, block_number: u32) -> Header {
        let block_hash = self.get_block_hash(block_number).await;
        let header_result = self.client.rpc().header(Some(block_hash)).await;
        header_result.unwrap().unwrap()
    }

    pub async fn get_head(&self) -> Header {
        let head_block_hash = self.client.rpc().finalized_head().await.unwrap();
        let header = self.client.rpc().header(Some(head_block_hash)).await;
        header.unwrap().unwrap()
    }

    pub async fn get_authority_set_id(&self, block_number: u32) -> u64 {
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
    pub async fn get_authorities(
        &self,
        block_number: u32,
    ) -> (Vec<AffinePoint<Curve>>, Vec<Vec<u8>>) {
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
        // The grandpa_authorities_bytes has the following format:
        // [V, X, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]
        // Where V is a "Version" number (right now it's 1u8)
        // Where XX is the compact scale encoding of the number of authorities
        // NOTE: In some cases the compact scale encoding might be only 1 byte if the number of authorities is <63
        // This is a reference on how compact scale encoding works: https://docs.substrate.io/reference/scale-codec/#fn-1
        // This is why we do the assert below to check that when we subtract the assumed prefix length of 3
        // that the remainder is divisible by 32 + 8, which represents the number of bytes in an authority public key
        // plus the number of bytes in the weight of the authority
        let offset = if grandpa_authorities_bytes.len() < ((32 + 8) * 63) + 3 {
            2
        } else {
            3
        };

        assert!((grandpa_authorities_bytes.len() - offset) % (32 + 8) == 0);

        let pubkey_and_weight_bytes = &grandpa_authorities_bytes[offset..];

        let mut authorities: Vec<AffinePoint<Curve>> = Vec::new();
        let mut authories_pubkey_bytes: Vec<Vec<u8>> = Vec::new();
        for authority_pubkey_weight in pubkey_and_weight_bytes.chunks(VALIDATOR_LENGTH) {
            let pub_key_vec = authority_pubkey_weight[..32].to_vec();
            let pub_key_point = AffinePoint::<Curve>::new_from_compressed_point(&pub_key_vec);
            authorities.push(pub_key_point);
            authories_pubkey_bytes.push(pub_key_vec);

            // Assert that the weight is 0x0100000000000000
            assert_eq!(authority_pubkey_weight[32], 1);
            for i in 33..VALIDATOR_LENGTH {
                assert_eq!(authority_pubkey_weight[i], 0);
            }
        }

        (authorities, authories_pubkey_bytes)
    }

    // This function takes in a block_number as input, fetches the authority set for that block and the finality proof
    // for that block. If the finality proof is a simple justification, it will return a SimpleJustificationData
    // containing all the encoded precommit that the authorities sign, the validator signatures, and the authority pubkeys.
    pub async fn get_simple_justification<const VALIDATOR_SET_SIZE_MAX: usize>(
        &self,
        block_number: u32,
    ) -> SimpleJustificationData {
        let mut params = RpcParams::new();
        let _ = params.push(block_number);
        let encoded_finality_proof = self
            .client
            .rpc()
            .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
            .await
            .unwrap();

        let hex_string = encode(&encoded_finality_proof.0 .0);
        // debug!(
        //     "returned justification for block {:?} has bytes 0x{:?}",
        //     block_number, hex_string
        // );

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        // The authority set for the current block is defined in the previous block.
        let authority_set_id = self.get_authority_set_id(block_number - 1).await;

        // The authorities for the current block are defined in the previous block.
        let (authorities, authorities_pubkey_bytes) = self.get_authorities(block_number - 1).await;

        if authorities.len() > VALIDATOR_SET_SIZE_MAX {
            panic!("Too many authorities");
        }

        // Form a message which is signed in the justification.
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
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

                log::debug!("Verifying signature for pubkey {:?}", pubkey_bytes);

                verify_signature(&pubkey_bytes, &signed_message, &signature);
                pubkey_bytes_to_signature.insert(pubkey_bytes, signature);
            });

        let mut validator_signed = Vec::new();
        let mut padded_signatures = Vec::new();
        let mut padded_pubkeys = Vec::new();
        let mut voting_weight = 0;
        for (i, authority) in authorities.iter().enumerate() {
            let pubkey_bytes = authorities_pubkey_bytes[i].clone();
            let signature = pubkey_bytes_to_signature.get(&pubkey_bytes);
            log::debug!("Verifying signature for pubkey {:?}", pubkey_bytes);

            if let Some(valid_signature) = signature {
                verify_signature(&pubkey_bytes, &signed_message, valid_signature);
                validator_signed.push(true);
                padded_pubkeys.push(*authority);
                padded_signatures.push(*valid_signature);
                voting_weight += 1;
            } else {
                validator_signed.push(false);
                padded_pubkeys.push(*authority);
                // Push a dummy signature, since this validator did not sign.
                padded_signatures.push(DUMMY_SIGNATURE);
            }
        }

        if voting_weight * 3 < authorities.len() * 2 {
            panic!("Not enough voting power");
        }

        for _ in authorities.len()..VALIDATOR_SET_SIZE_MAX {
            validator_signed.push(false);
            // Push a dummy pubkey and signature, to pad the array to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY));
            padded_signatures.push(DUMMY_SIGNATURE);
        }

        let current_authority_set_hash = compute_authority_set_hash(authorities_pubkey_bytes);

        SimpleJustificationData {
            authority_set_id,
            signed_message,
            validator_signed,
            pubkeys: padded_pubkeys,
            signatures: padded_signatures,
            num_authorities: authorities.len(),
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
        &self,
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

                    // TODO: What is value[1..3]?
                    let mut cursor = 3;
                    let authorities_bytes = &value[cursor..];

                    for (i, authority_chunk) in
                        authorities_bytes.chunks_exact(VALIDATOR_LENGTH).enumerate()
                    {
                        let pubkey = &authority_chunk[..PUBKEY_LENGTH];
                        let weight = &authority_chunk[PUBKEY_LENGTH..];

                        // Assert the pubkey in the encoded log is correct.
                        assert_eq!(*pubkey, new_authorities.1[i]);

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

        let new_authority_set_hash = compute_authority_set_hash(new_authorities.1.clone());
        let mut padded_pubkeys = Vec::new();
        for i in 0..new_authorities.1.len() {
            padded_pubkeys.push(H256::from_slice(&new_authorities.1[i].clone()));
        }
        for _ in new_authorities.1.len()..VALIDATOR_SET_SIZE_MAX {
            // Pad the array with dummy pubkeys to VALIDATOR_SET_SIZE_MAX.
            padded_pubkeys.push(H256::from_slice(&DUMMY_PUBLIC_KEY));
        }

        // 1 unknown, 1 consensus id, 4 consensus engine id, 2 unknown, 1 scheduled change, 2 unknown.
        let prefix_length = 11;
        // The end position is the position + prefix_length + encoded pubkeys len + 4 delay bytes.
        let end_position = position + prefix_length + ((32 + 8) * new_authorities.1.len()) + 4;

        HeaderRotateData {
            header_bytes,
            header_size,
            num_authorities: new_authorities.1.len(),
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
    use ethers::abi::{encode_packed, Tokenizable};

    use super::*;
    use crate::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE};

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_block_headers_range() {
        let fetcher = RpcDataFetcher::new().await;
        let headers = fetcher.get_block_headers_range(100000, 100009).await;
        assert_eq!(headers.len(), 10);
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_header_hash() {
        let fetcher = RpcDataFetcher::new().await;

        let target_block = 215495;
        let header = fetcher.get_header(target_block).await;
        println!("header hash {:?}", hex::encode(header.hash().0));
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_authority_set_id() {
        let fetcher = RpcDataFetcher::new().await;
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

            if curr_authorities.1.len() != next_authorities.1.len() {
                println!("genesis id {:?}", authority_set_id);
                println!(
                    "genesis authority set hash {:?}",
                    hex::encode(compute_authority_set_hash(curr_authorities.1))
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
        let fetcher = RpcDataFetcher::new().await;

        // This is an epoch end block where the authority set changes.
        let genesis_epoch_end_block = 215367;

        const VALIDATOR_SET_SIZE_MAX: usize = 100;
        let _ = fetcher
            .get_simple_justification::<VALIDATOR_SET_SIZE_MAX>(genesis_epoch_end_block)
            .await;
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_new_authority_set() {
        let fetcher = RpcDataFetcher::new().await;

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
}
