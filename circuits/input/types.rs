use avail_subxt::primitives::Header;
use codec::{Decode, Encode};
use ethers::types::H256;
use serde::{Deserialize, Serialize};
use sp_core::ed25519::{Public as EdPublic, Signature};
use sp_core::Bytes;

use crate::vars::{AffinePoint, Curve};

pub struct HeaderRotateData {
    pub header_bytes: Vec<u8>,
    pub header_size: usize,
    pub num_authorities: usize,
    pub start_position: usize,
    pub end_position: usize,
    pub new_authority_set_hash: Vec<u8>,
    pub padded_pubkeys: Vec<H256>,
}

// Stores the signed messages, valid signatures and pubkeys for a given block number justification.
// Note: There is a redis macros crate that can be used to serialize this.
// https://github.com/daniel7grant/redis-macros/#json-wrapper-with-redisjson

#[derive(Serialize, Deserialize)]
pub struct StoredJustificationData {
    pub block_number: u32,
    pub signed_message: Vec<u8>,
    pub pubkeys: Vec<Vec<u8>>,
    pub signatures: Vec<Vec<u8>>,
    pub validator_signed: Vec<bool>,
    pub num_authorities: usize,
}

pub struct SimpleJustificationData {
    pub authority_set_id: u64,
    pub signed_message: Vec<u8>,
    pub validator_signed: Vec<bool>,
    pub pubkeys: Vec<AffinePoint<Curve>>,
    pub signatures: Vec<[u8; 64]>,
    pub num_authorities: usize,
    pub current_authority_set_hash: Vec<u8>,
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

#[derive(Debug, Encode)]
pub enum SignerMessage {
    DummyMessage(u32),
    PrecommitMessage(Precommit),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncodedFinalityProof(pub Bytes);

#[derive(Debug, PartialEq, Encode, Decode, Clone, Deserialize)]
pub struct FinalityProof {
    /// The hash of block F for which justification is provided.
    pub block: H256,
    /// Justification of the block F.
    pub justification: Vec<u8>,
    /// The set of headers in the range (B; F] that we believe are unknown to the caller. Ordered.
    pub unknown_headers: Vec<Header>,
}
