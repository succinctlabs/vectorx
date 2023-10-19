pub mod types;

use std::collections::HashMap;

use avail_subxt::primitives::Header;
use avail_subxt::{api, build_client, AvailConfig};
use codec::{Decode, Encode};
use ed25519_dalek::{PublicKey, Signature, Verifier};
use hex::encode;
use log::debug;
use pallet_grandpa::{AuthorityList, VersionedAuthorityList};
use plonky2x::frontend::ecc::ed25519::gadgets::verify::{DUMMY_PUBLIC_KEY, DUMMY_SIGNATURE};
use sp_application_crypto::RuntimeAppPublic;
use subxt::rpc::RpcParams;
use subxt::utils::H256;
use subxt::OnlineClient;

use self::types::{EncodedFinalityProof, FinalityProof, GrandpaJustification, SignerMessage};
use crate::input::types::SimpleJustificationData;
use crate::vars::{AffinePoint, Curve};

pub struct RpcDataFetcher {
    pub client: OnlineClient<AvailConfig>,
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

impl RpcDataFetcher {
    pub async fn new() -> Self {
        // let mut url = env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env");
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        RpcDataFetcher { client, save: None }
    }

    pub async fn get_block_hash(&self, block_number: u32) -> H256 {
        let block_hash = self
            .client
            .rpc()
            .block_hash(Some(block_number.into()))
            .await;
        block_hash.unwrap().unwrap()
    }

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
        println!("head_block_hash {:?}", head_block_hash);
        let header = self.client.rpc().header(Some(head_block_hash)).await;
        println!("header {:?}", header);
        header.unwrap().unwrap()
    }

    pub async fn get_authority_set_id(&self, block_number: u32) -> u64 {
        let block_hash = self.get_block_hash(block_number).await;

        let set_id_key = api::storage().grandpa().current_set_id();
        self.client
            .storage()
            .at(Some(block_hash))
            .await
            .unwrap()
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
            .at(Some(block_hash))
            .await
            .unwrap()
            .fetch_raw(b":grandpa_authorities")
            .await
            .unwrap()
            .unwrap();

        let grandpa_authorities =
            VersionedAuthorityList::decode(&mut grandpa_authorities_bytes.as_slice()).unwrap();

        // The grandpa_authorities_bytes has the following format:
        // [X, X, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]

        let authority_list: AuthorityList = grandpa_authorities.into();
        let mut authorities: Vec<AffinePoint<Curve>> = Vec::new();
        let mut authories_pubkey_bytes: Vec<Vec<u8>> = Vec::new();
        for (authority_key, weight) in authority_list.iter() {
            if *weight != 1 {
                panic!("Weight for authority is not 1");
            }
            let pub_key_vec = authority_key.to_raw_vec();
            let pub_key_point = AffinePoint::<Curve>::new_from_compressed_point(&pub_key_vec);
            authorities.push(pub_key_point);
            authories_pubkey_bytes.push(pub_key_vec);
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
        debug!(
            "returned justification for block {:?} has bytes 0x{:?}",
            block_number, hex_string
        );

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        let authority_set_id = self.get_authority_set_id(block_number).await;
        let (authorities, authorities_pubkey_bytes) = self.get_authorities(block_number).await;

        if authorities.len() > VALIDATOR_SET_SIZE_MAX {
            panic!("Too many authorities");
        }

        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id,
        ));
        // TODO: verify above that signed_message = block_hash || block_number || round || set_id

        let mut pubkey_bytes_to_signature = HashMap::new();

        // Verify all the signatures of the justification
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
        for (i, authority) in authorities.iter().enumerate() {
            let pubkey_bytes = authorities_pubkey_bytes[i].clone();
            let signature = pubkey_bytes_to_signature.get(&pubkey_bytes);
            if signature.is_none() {
                validator_signed.push(false);
                padded_pubkeys.push(*authority);
                // We push a dummy signature, since this validator didn't sign
                padded_signatures.push(DUMMY_SIGNATURE);
            } else {
                verify_signature(&pubkey_bytes, &signed_message, signature.unwrap());
                validator_signed.push(true);
                padded_pubkeys.push(*authority);
                padded_signatures.push(*signature.unwrap());
                voting_weight += 1;
            }
        }

        if voting_weight * 3 < authorities.len() * 2 {
            panic!("Not enough voting power");
        }

        for _ in authorities.len()..VALIDATOR_SET_SIZE_MAX {
            validator_signed.push(false);
            // We push a dummy pubkey and a dummy padded signature to fill out the rest of the padding
            padded_pubkeys.push(AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY));
            padded_signatures.push(DUMMY_SIGNATURE);
        }

        SimpleJustificationData {
            authority_set_id,
            signed_message,
            validator_signed,
            pubkeys: padded_pubkeys,
            signatures: padded_signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use avail_subxt::config::substrate::DigestItem;

    use super::*;

    #[tokio::test]
    async fn test_get_block_headers_range() {
        let fetcher = RpcDataFetcher::new().await;
        let headers = fetcher.get_block_headers_range(0, 10).await;
        assert_eq!(headers.len(), 10);
    }

    #[tokio::test]
    async fn test_get_authority_set_id() {
        let fetcher = RpcDataFetcher::new().await;
        let authority_set_id = fetcher.get_authority_set_id(485710).await;
        assert_eq!(authority_set_id, 458);
        fetcher.get_authorities(485710).await;
        let simple_justification_data = fetcher.get_simple_justification::<100>(485710).await;
        println!(
            "Number authorities {:?}",
            simple_justification_data.pubkeys.len()
        );
        println!(
            "signed_message len {:?}",
            simple_justification_data.signed_message.len()
        );
    }

    #[tokio::test]
    async fn test_get_new_authority_set() {
        let fetcher = RpcDataFetcher::new().await;

        // A binary search given a target_authority_set_id, returns the epoch end block number
        let target_authority_set_id = 300;
        println!("target_authority_set_id {:?}", target_authority_set_id);
        let mut low = 0;
        let head_block = fetcher.get_head().await;
        let mut high = head_block.number;
        let mut epoch_end_block_number = 0;

        while low <= high {
            let mid = (low + high) / 2;
            let mid_authority_set_id = fetcher.get_authority_set_id(mid).await;

            match mid_authority_set_id.cmp(&target_authority_set_id) {
                Ordering::Equal => {
                    if mid == 0 {
                        // Special case: there is no block "mid - 1", so we just return the found block.
                        epoch_end_block_number = mid;
                        break;
                    }
                    let prev_authority_set_id = fetcher.get_authority_set_id(mid - 1).await;
                    if prev_authority_set_id == target_authority_set_id - 1 {
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

        // TODO: handle the case where the authority set id is not found
        assert_ne!(epoch_end_block_number, 0);
        println!("epoch_end_block_number {:?}", epoch_end_block_number);

        // let epoch_end_block_number = 272535 + 180;
        let previous_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number - 1)
            .await;
        let authority_set_id = fetcher.get_authority_set_id(epoch_end_block_number).await;
        assert_eq!(previous_authority_set_id + 1, authority_set_id);
        assert_eq!(authority_set_id, target_authority_set_id);
        let authorities = fetcher.get_authorities(epoch_end_block_number).await;

        let header = fetcher.get_header(epoch_end_block_number).await;
        let mut position = 0;
        let number_encoded = header.number.encode();
        // skip past parent_hash, number, state_root, extrinsics_root
        position += 32 + number_encoded.len() + 32 + 32;

        for log in header.digest.logs {
            if let DigestItem::Consensus(consensus_id, value) = log {
                if consensus_id == [70, 82, 78, 75] {
                    println!("position {:?}", position);
                    // TODO: have to figure out what value[0,1,2] means?
                    println!("value prefix {:?}", &value[..3]);
                    assert_eq!(value[0], 1); // To denote that it is a `ScheduledChange`
                    let mut cursor = 3;
                    let value_authories = &value[cursor..];
                    println!("len {:?}", value_authories.len());
                    let mut num_authorities = 0;
                    for (i, authority_chunk) in value_authories.chunks_exact(32 + 8).enumerate() {
                        let pubkey = &authority_chunk[..32];
                        let weight = &authority_chunk[32..];

                        assert_eq!(*pubkey, authorities.1[i]);
                        // println!("pubkey {:?}", pubkey);
                        // println!("weight {:?}", weight);
                        // Assert weight's LE representation == 1
                        for j in 0..8 {
                            if j == 0 {
                                assert_eq!(weight[j], 1);
                            } else {
                                assert_eq!(weight[j], 0);
                            }
                        }

                        cursor += 32 + 8;
                        num_authorities += 1;
                    }
                    let delay = &value[cursor..];
                    println!("delay {:?}", delay);
                    println!("num_authorities {:?}", num_authorities);
                    // verify header[position..position+4] == [70, 82, 78, 75]
                    // verify header[position+4] == 1
                    // verify header[position+5..position+5+2] == random stuff, TODO what is this
                    // hash(header[position+5+2..position+5+2+num_authorities*(32+8)])
                    // verify[position+5+2+num_authorities*(32+8)..+4] == [0, 0, 0, 0] // delay = 0
                    break;
                }
            } else {
                let encoded = log.encode();
                println!("encoded {:?}", encoded);
                position += encoded.len();
            }
        }
    }
}
