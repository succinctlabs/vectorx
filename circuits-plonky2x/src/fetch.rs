use std::collections::HashMap;
use std::{env, fs};

use async_trait::async_trait;
use avail_subxt::primitives::Header;
use avail_subxt::{build_client, AvailConfig};
use codec::{Decode, Encode};
use pallet_grandpa::{AuthorityList, VersionedAuthorityList};
use sp_application_crypto::{RuntimeAppPublic, RuntimePublic};
use sp_core::ed25519::{Public as EdPublic, Signature};
use sp_core::storage::StorageKey;
use sp_core::{ed25519, twox_128, Pair};
use subxt::rpc::RpcParams;
use subxt::utils::H256;
use subxt::OnlineClient;
use succinct_avail_utils::get_justification::{
    Commit, EncodedFinalityProof, FinalityProof, GrandpaJustification, Precommit, SignedPrecommit,
    SignerMessage,
};

use crate::vars::{AffinePoint, Curve};

// use subxt::config::Header as XtHeader;

#[async_trait]
pub trait DataFetcher {
    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header>;
}

pub async fn new_fetcher() -> Box<dyn DataFetcher> {
    let fixture_path = format!("../fixtures");
    if cfg!(test) {
        return Box::new(FixtureDataFetcher { fixture_path });
    } else {
        // let mut url = env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env");
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        return Box::new(RpcDataFetcher { client, save: None });
    }
    // TODO: if in a test, return the FixtureDataFetcher with a const fixture path "test/fixtures/{chain_id{"
    // else, read the RpcDataFetch with the env var "RPC_{chain_id}" url from the .env file and panic if the RPC url is not present
}

pub struct RpcDataFetcher {
    pub client: OnlineClient<AvailConfig>,
    pub save: Option<String>,
}

impl RpcDataFetcher {
    async fn get_block_hash(&self, block_number: u32) -> H256 {
        let block_hash = self
            .client
            .rpc()
            .block_hash(Some(block_number.into()))
            .await;
        block_hash.unwrap().unwrap()
    }

    async fn get_authority_set_id(&self, block_number: u32) -> u32 {
        let block_hash = self.get_block_hash(block_number).await;
        // Construct the storage key for the "CurrentSetId"
        let mut epoch_index_storage_key = twox_128(b"Grandpa").to_vec();
        epoch_index_storage_key.extend(twox_128(b"CurrentSetId").to_vec());
        let sk = StorageKey(epoch_index_storage_key);
        let keys = [sk.0.as_slice()];

        // Retrieve the storage data for the event key
        let data = self
            .client
            .rpc()
            .storage(keys[0], Some(block_hash))
            .await
            .unwrap()
            .unwrap();
        u32::from_le_bytes(data.0[0..4].try_into().unwrap())
    }

    async fn get_authorities(&self, block_number: u32) -> (Vec<AffinePoint<Curve>>, Vec<Vec<u8>>) {
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

        // grandpa_authorities_bytes = [X, X, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]

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

    async fn get_simple_justification<const VALIDATOR_SET_SIZE_MAX: usize>(
        &self,
        block_number: u32,
    ) {
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

        let authority_set_id = self.get_authority_set_id(block_number).await;
        let (authorities, authorities_pubkey_bytes) = self.get_authorities(block_number).await;

        if authorities.len() > VALIDATOR_SET_SIZE_MAX {
            panic!("Too many authorities");
        }
        // Form a message which is signed in the justification
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id - 1,
        ));
        // TODO: verify above that signed_message = block_hash || block_number || round || set_id

        println!(
            "signed message is {:?}",
            hex::encode(signed_message.clone())
        );

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
                // TODO: put this check back in, some weird error with mismatched types
                // let is_ok = <ed25519::Pair as Pair>::verify(
                //     &precommit.signature,
                //     signed_message.as_slice(),
                //     &pubkey,
                // );
                // assert!(is_ok);
                let pubkey_bytes = pubkey.0.to_vec();
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
                // TODO: make this a real dummy
                padded_signatures.push([0u8; 64]);
            } else {
                validator_signed.push(true);
                padded_pubkeys.push(*authority);
                padded_signatures.push(*signature.unwrap());
                voting_weight += 1;
            }
        }

        if voting_weight * 3 < authorities.len() * 2 {
            panic!("Not enough voting power");
        }

        println!("voted {}, total {}", voting_weight, authorities.len());

        for _ in authorities.len()..VALIDATOR_SET_SIZE_MAX {
            validator_signed.push(false);
            // TODO: fill in the rest with actual dummies
            padded_pubkeys.push(AffinePoint::<Curve>::ZERO);
            padded_signatures.push([0u8; 64]);
        }

        let message_byte_lengths = vec![signed_message.len() as u32; VALIDATOR_SET_SIZE_MAX];
        let messages = vec![signed_message; VALIDATOR_SET_SIZE_MAX];

        println!("validator_signed {:?}", validator_signed);
        println!("padded_pubkeys {:?}", padded_pubkeys);
        println!("padded_signatures {:?}", padded_signatures);
    }
}

#[async_trait]
impl DataFetcher for RpcDataFetcher {
    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        let mut headers = Vec::new();
        for block_number in start_block_number..end_block_number {
            let block_hash = self.get_block_hash(block_number).await;
            let header_result = self.client.rpc().header(Some(block_hash)).await;
            let header: Header = header_result.unwrap().unwrap();
            headers.push(header);
        }
        if let Some(save_path) = &self.save {
            let file_name = format!(
                "{}/block_range/{}_{}.json",
                save_path, start_block_number, end_block_number
            );
            fs::write(file_name, serde_json::to_string(&headers).unwrap());
        }
        headers
    }
}

pub struct FixtureDataFetcher {
    pub fixture_path: String,
}

#[async_trait]
impl DataFetcher for FixtureDataFetcher {
    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        let file_name = format!(
            "{}/block_range/{}_{}.json",
            self.fixture_path.as_str(),
            start_block_number.to_string().as_str(),
            end_block_number.to_string().as_str()
        );
        let file_content = fs::read_to_string(file_name.as_str());
        let res = file_content.unwrap();
        // let blocks: Vec<TempSignedBlock> =
        //     serde_json::from_str(&res).expect("Failed to parse JSON");
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_block_headers_range() {
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        let fetcher = RpcDataFetcher { client, save: None };
        let headers = fetcher.get_block_headers_range(0, 10).await;
        assert_eq!(headers.len(), 10);
    }

    #[tokio::test]
    async fn test_get_authority_set_id() {
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        let fetcher = RpcDataFetcher { client, save: None };
        let authority_set_id = fetcher.get_authority_set_id(485710).await;
        assert_eq!(authority_set_id, 458);
        fetcher.get_authorities(485710).await;

        fetcher.get_simple_justification::<100>(485710).await;
    }
}
