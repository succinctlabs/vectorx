use std::env;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::{Address, Filter};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use vectorx::input::types::MerkleTreeBranch;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

type HeaderRangeCommitmentStoredTuple = sol! { tuple(uint32, uint32, bytes32, bytes32) };

// total_num_leaves is the size of the merkle tree.
// Returns the path for the given index.
fn get_path_indices(index: usize, total_num_leaves: usize) -> Vec<bool> {
    let mut path_indices = Vec::new();
    let mut i = index;
    let mut level_leaves = total_num_leaves;
    while level_leaves > 1 {
        path_indices.push(i % 2 == 1);
        i /= 2;
        level_leaves /= 2;
    }
    path_indices
}

// Note: Not inclusive of start, but inclusive of end. Head in the contract matches end, so this
// is semantically correct.
async fn add_merkle_tree(
    trusted_block: u32,
    end: u32,
    expected_data_commitment: Vec<u8>,
    tree_num_leaves: usize,
) {
    // Listen to logs
    let mut data_fetcher = RpcDataFetcher::new().await;

    // Get all data_hashes for the range [start + 1, end].
    let mut data_hashes = Vec::new();
    for i in trusted_block + 1..end + 1 {
        let header = data_fetcher.get_header(i).await;
        data_hashes.push(header.data_root().0);
    }

    // Pad data_hashes with empty leaves, to match SimpleMerkleTree.
    data_hashes.resize(tree_num_leaves, [0u8; 32]);

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&data_hashes);
    let root = merkle_tree.root().unwrap();
    assert_eq!(root.to_vec(), expected_data_commitment);
    println!("root: {:?}", root);

    for i in 0..(end - trusted_block) {
        let proof = merkle_tree.proof(&[i as usize]);
        let proof_hashes = proof.proof_hashes();
        let branch = MerkleTreeBranch {
            // Starts at start + 1 (the first uncommitted header from the new range).
            block_number: trusted_block + i + 1,
            branch: proof_hashes.to_vec(),
            path_indices: get_path_indices(i as usize, tree_num_leaves),
            root: root.to_vec(),
            leaf: data_hashes[i as usize].to_vec(),
        };
        data_fetcher
            .redis_client
            .add_merkle_tree_branch(branch)
            .await;
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let ethereum_ws = env::var("ETHEREUM_WS").expect("ETHEREUM_WS must be set");

    let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
    let address = contract_address
        .parse::<Address>()
        .expect("invalid address");

    let client = Provider::<Ws>::connect(ethereum_ws).await.unwrap();
    let contract = VectorX::new(address.0, client.clone().into());

    // Note: This should be a power of 2, and is the size of the merkle tree.
    let step_range_max = contract.max_header_range().await.unwrap();

    let client = Arc::new(client);

    let header_range_filter = Filter::new()
        .address(address)
        .event("HeaderRangeCommitmentStored(uint32,uint32,bytes32,bytes32)");

    let mut stream = client.subscribe_logs(&header_range_filter).await.unwrap();
    while let Some(log) = stream.next().await {
        let log_bytes = log.data;
        let decoded = HeaderRangeCommitmentStoredTuple::abi_decode(&log_bytes.0, true).unwrap();

        let trusted_block = decoded.0;
        let end_block = decoded.1;
        let expected_data_commitment = decoded.2.to_vec();

        add_merkle_tree(
            trusted_block,
            end_block,
            expected_data_commitment,
            step_range_max as usize,
        )
        .await;
    }
}
