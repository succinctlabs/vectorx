use avail_subxt::build_client;
use avail_subxt::primitives::Header;
use avail_subxt::config::substrate::BlakeTwo256;
use sp_state_machine::{read_proof_check, StorageProof};

use subxt::{
	ext::{
		sp_core::{storage::StorageKey, twox_128},
	},
};

use primitive_types::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, true).await.unwrap();

    // The block hash for block 34152 (https://kate.avail.tools/#/explorer/query/34152)
    let block_hash_vec = hex::decode("53e8246a378132e117657ddd11c21711256a38ec5360fc3b1d08eee76e4c633c").unwrap();

    let mut block_hash_array: [u8; 32] = [0; 32];
    for i in 0..block_hash_vec.len() {
        block_hash_array[i] = block_hash_vec[i];
    }
    let block_hash = Some(H256(block_hash_array));

    // Get the header from the RPC
    let header: Header = c.rpc().header(block_hash).await.unwrap().unwrap();

    // Construct the storage key for the epoch index
    let mut epoch_index_storage_key = twox_128(b"Grandpa").to_vec();
    epoch_index_storage_key.extend(twox_128(b"CurrentSetId").to_vec());
    let sk = StorageKey(epoch_index_storage_key);

    // Output the storage key as a byte array
    println!("storage key is {:?}\n\n\n", sk.0.as_slice());

    let keys = [sk.0.as_slice()];

    // Retrieve the storage data for the event key
    let data = c.rpc().storage(keys[0], block_hash).await.unwrap().unwrap();
    println!("data is {:?}\n\n\n", data.0);

    // Retrieve the storage proof for the event key
    let proof = c.rpc().read_proof(keys, block_hash).await.unwrap();

    // Convert the ReadProof type to StorageProof type
    // Sample conversion of ReadProof to StorageProof here: https://github.com/paritytech/substrate/blob/785115b3a13901b0c708af8166430bcc9c71f28f/client/rpc/src/state/state_full.rs#L365
    let mut sp_vec = Vec::new();
    for i in 0..proof.proof.len() {
        sp_vec.push(proof.proof[i].0.clone());
    }
    let sp = StorageProof::new(sp_vec);

    println!("sp is {:?}\n\n\n", sp);

    /*
    // Can also check proof here:  https://github.com/polytope-labs/solidity-merkle-trees/blob/main/src/MerklePatricia.sol#L31
    let proof_check_res = read_proof_check::<BlakeTwo256, _>(header.state_root, sp, keys).unwrap();
    */

    println!("state root is {:?}\n\n\n", header.state_root.as_bytes());

    /*
    println!("proof_check_res is {:?}\n\n\n", proof_check_res);
    */
}
