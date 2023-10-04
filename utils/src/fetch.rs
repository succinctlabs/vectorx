use std::fs;

use avail_subxt::primitives::Header;
use avail_subxt::{api, build_client, AvailConfig};
use subxt::utils::H256;
use subxt::OnlineClient;

// use subxt::config::Header as XtHeader;

// pub struct SimpleJustificationData {
//     pub authority_set_id: U64,
//     pub signed_message: Vec<u8>,
//     pub validator_signed: Vec<bool>,
//     pub pubkeys: Vec<AffinePoint<Curve>>,
//     pub signatures: Vec<[u8; 64]>,
// }

pub struct RpcDataFetcher {
    pub client: OnlineClient<AvailConfig>,
    pub save: Option<String>,
}

// /// This function is useful for verifying that a Ed25519 signature is valid, it will panic if the signature is not valid
// pub fn verify_signature(pubkey_bytes: &[u8], signed_message: &[u8], signature: &[u8; 64]) {
//     let pubkey_dalek = PublicKey::from_bytes(pubkey_bytes).unwrap();
//     let verified = pubkey_dalek.verify(signed_message, &Signature::from_bytes(signature).unwrap());
//     if verified.is_err() {
//         panic!("Signature is not valid");
//     }
// }

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

    // Will download the blocks with block numbers from start_block_number to end_block_number
    // inclusive.
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
        if let Some(save_path) = &self.save {
            let file_name = format!(
                "{}/block_range/{}_{}.json",
                save_path, start_block_number, end_block_number
            );
            let _ = fs::write(file_name, serde_json::to_string(&headers).unwrap());
        }
        headers
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
        // Construct the storage key for the "CurrentSetId"
        // let mut epoch_index_storage_key = twox_128(b"Grandpa").to_vec();
        // epoch_index_storage_key.extend(twox_128(b"CurrentSetId").to_vec());
        // let sk = StorageKey(epoch_index_storage_key);
        // let keys = [sk.0.as_slice()];

        // // Retrieve the storage data for the event key
        // let data = self
        //     .client
        //     .rpc()
        //     .storage(keys[0], Some(block_hash))
        //     .await
        //     .unwrap()
        //     .unwrap();
        // u32::from_le_bytes(data.0[0..4].try_into().unwrap())
    }

    // pub async fn get_authorities(
    //     &self,
    //     block_number: u32,
    // ) -> (Vec<AffinePoint<Curve>>, Vec<Vec<u8>>) {
    //     let block_hash = self.get_block_hash(block_number).await;
    //     let grandpa_authorities_bytes = self
    //         .client
    //         .storage()
    //         .at(Some(block_hash))
    //         .await
    //         .unwrap()
    //         .fetch_raw(b":grandpa_authorities")
    //         .await
    //         .unwrap()
    //         .unwrap();

    //     let grandpa_authorities =
    //         VersionedAuthorityList::decode(&mut grandpa_authorities_bytes.as_slice()).unwrap();

    //     // grandpa_authorities_bytes = [X, X, X, <public_key_compressed>, <1, 0, 0, 0, 0, 0, 0, 0>, <public_key_compressed>, ...]

    //     let authority_list: AuthorityList = grandpa_authorities.into();
    //     let mut authorities: Vec<AffinePoint<Curve>> = Vec::new();
    //     let mut authories_pubkey_bytes: Vec<Vec<u8>> = Vec::new();
    //     for (authority_key, weight) in authority_list.iter() {
    //         if *weight != 1 {
    //             panic!("Weight for authority is not 1");
    //         }

    //         let pub_key_vec = authority_key.to_raw_vec();
    //         // Reversing causes problems
    //         // let reversed = pub_key_vec.clone().into_iter().rev().collect::<Vec<u8>>();
    //         let pub_key_point = AffinePoint::<Curve>::new_from_compressed_point(&pub_key_vec);
    //         authorities.push(pub_key_point);
    //         authories_pubkey_bytes.push(pub_key_vec);
    //     }

    //     (authorities, authories_pubkey_bytes)
    // }

    // pub async fn get_simple_justification<const VALIDATOR_SET_SIZE_MAX: usize>(
    //     &self,
    //     block_number: u32,
    // ) -> SimpleJustificationData {
    //     let mut params = RpcParams::new();
    //     let _ = params.push(block_number);
    //     let encoded_finality_proof = self
    //         .client
    //         .rpc()
    //         .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
    //         .await
    //         .unwrap();
    //     let finality_proof: FinalityProof =
    //         Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
    //     let justification: GrandpaJustification =
    //         Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

    //     let authority_set_id = self.get_authority_set_id(block_number).await;
    //     let (authorities, authorities_pubkey_bytes) = self.get_authorities(block_number).await;

    //     if authorities.len() > VALIDATOR_SET_SIZE_MAX {
    //         panic!("Too many authorities");
    //     }

    //     // Form a message which is signed in the justification
    //     let signed_message = Encode::encode(&(
    //         &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
    //         &justification.round,
    //         &authority_set_id,
    //     ));
    //     // TODO: verify above that signed_message = block_hash || block_number || round || set_id

    //     let mut pubkey_bytes_to_signature = HashMap::new();

    //     // Verify all the signatures of the justification
    //     // TODO: panic if the justification is not not a simple justification
    //     justification
    //         .commit
    //         .precommits
    //         .iter()
    //         .for_each(|precommit| {
    //             let pubkey = precommit.clone().id;
    //             let signature = precommit.clone().signature.0;
    //             let pubkey_bytes = pubkey.0.to_vec();

    //             verify_signature(&pubkey_bytes, &signed_message, &signature);
    //             pubkey_bytes_to_signature.insert(pubkey_bytes, signature);
    //         });

    //     let mut validator_signed = Vec::new();
    //     let mut padded_signatures = Vec::new();
    //     let mut padded_pubkeys = Vec::new();
    //     let mut voting_weight = 0;
    //     for (i, authority) in authorities.iter().enumerate() {
    //         let pubkey_bytes = authorities_pubkey_bytes[i].clone();
    //         let signature = pubkey_bytes_to_signature.get(&pubkey_bytes);
    //         if signature.is_none() {
    //             validator_signed.push(false);
    //             padded_pubkeys.push(*authority);
    //             // We push a dummy signature, since this validator didn't sign
    //             padded_signatures.push(DUMMY_SIGNATURE);
    //         } else {
    //             verify_signature(&pubkey_bytes, &signed_message, signature.unwrap());
    //             validator_signed.push(true);
    //             padded_pubkeys.push(*authority);
    //             padded_signatures.push(*signature.unwrap());
    //             voting_weight += 1;
    //         }
    //     }

    //     if voting_weight * 3 < authorities.len() * 2 {
    //         panic!("Not enough voting power");
    //     }

    //     for _ in authorities.len()..VALIDATOR_SET_SIZE_MAX {
    //         validator_signed.push(false);
    //         // We push a dummy pubkey and a dummy padded signature to fill out the rest of the padding
    //         padded_pubkeys.push(AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY));
    //         padded_signatures.push(DUMMY_SIGNATURE);
    //     }

    //     SimpleJustificationData {
    //         authority_set_id: authority_set_id.into(),
    //         signed_message,
    //         validator_signed,
    //         pubkeys: padded_pubkeys,
    //         signatures: padded_signatures,
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_block_headers_range() {
        let fetcher = RpcDataFetcher::new().await;
        let headers = fetcher.get_block_headers_range(0, 10).await;
        assert_eq!(headers.len(), 10);
    }

    // #[tokio::test]
    // async fn test_get_authority_set_id() {
    //     let fetcher = RpcDataFetcher::new().await;
    //     let authority_set_id = fetcher.get_authority_set_id(485710).await;
    //     assert_eq!(authority_set_id, 458);
    //     fetcher.get_authorities(485710).await;
    //     let simple_justification_data = fetcher.get_simple_justification::<100>(485710).await;
    //     println!(
    //         "Number authorities {:?}",
    //         simple_justification_data.pubkeys.len()
    //     );
    //     println!(
    //         "signed_message len {:?}",
    //         simple_justification_data.signed_message.len()
    //     );
    // }
}
