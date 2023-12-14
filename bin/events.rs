use std::env;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::{Address, BlockNumber, Filter};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use vectorx::input::types::MerkleTreeBranch;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

type HeaderRangeCommitmentStoredTuple = sol! { tuple(uint32, uint32, bytes32, bytes32) };

// fn next_power_of_two(n: usize) -> usize {
//     let mut power = 1;
//     while power < n {
//         power *= 2;
//     }
//     power
// }

// Not inclusive of start, but inclusive of end.
async fn add_merkle_tree(
    start: u32,
    end: u32,
    expected_data_commitment: Vec<u8>,
    tree_num_leaves: usize,
) {
    // Listen to logs
    let mut data_fetcher = RpcDataFetcher::new().await;

    // Get all data_hashes for the range
    let mut data_hashes = Vec::new();
    for i in start + 1..end + 1 {
        let header = data_fetcher.get_header(i).await;
        data_hashes.push(header.data_root().0);
    }

    // Pad data_hashes with empty leaves, to match SimpleMerkleTree.
    data_hashes.resize(tree_num_leaves, [0u8; 32]);

    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&data_hashes);
    let root = merkle_tree.root().unwrap();
    // assert_eq!(root.to_vec(), expected_data_commitment);
    println!("root: {:?}", root);

    for i in 0..(end - start) {
        let proof = merkle_tree.proof(&[i as usize]);
        let proof_hashes = proof.proof_hashes();
        let branch = MerkleTreeBranch {
            // Starts at start + 1
            block_number: start + i + 1,
            branch: proof_hashes.to_vec(),
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

    let last_block = client
        .get_block(BlockNumber::Latest)
        .await
        .unwrap()
        .unwrap()
        .number
        .unwrap();
    println!("last_block: {last_block}");

    // TODO: Use Header range commitment stored ABI type
    let header_range_filter = Filter::new()
        .address(address)
        // TODO: Remove from_block
        .from_block(last_block - 2000)
        .event("HeaderRangeCommitmentStored(uint32,uint32,bytes32,bytes32)");

    let mut stream = client.subscribe_logs(&header_range_filter).await.unwrap();
    while let Some(log) = stream.next().await {
        // println!("log: {:?}", log);
        let log_bytes = log.data;
        // Parse abi encoded logBytes (uint32, uint32, bytes32, bytes32)
        let decoded = HeaderRangeCommitmentStoredTuple::abi_decode(&log_bytes.0, true).unwrap();

        let start_block = decoded.0;
        let end_block = decoded.1;
        let expected_data_commitment = decoded.2.to_vec();

        add_merkle_tree(
            start_block,
            end_block,
            expected_data_commitment,
            step_range_max as usize,
        )
        .await;
    }
    // dotenv::dotenv().ok();
    // add_merkle_tree(1, 2, vec![0u8; 32], 4).await;
}
