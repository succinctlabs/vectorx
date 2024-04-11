use std::env;
use std::fs::File;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::{Address, Filter};
use ethers::providers::{Http, Middleware, Provider};
use log::info;
use serde::{Deserialize, Serialize};
use vectorx::input::{DataCommitmentRange, RedisClient};

// Necessary environment variables.
//  - REDIS_URL: The URL of the Redis server to connect to.
//  - RPC_{CHAIN_ID}'s: The RPC URL's corresponding to the deployments in deployments.json

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Deployment {
    source_chain_name: String,
    contract_chain_id: u64,
    contract_address: Address,
    cursor_start_block: u64,
}

// Read deployments.json and get the list of deployments.
fn get_deployments() -> Vec<Deployment> {
    let deployments_file = File::open("deployments.json").unwrap();
    let deployments_json: serde_json::Value = serde_json::from_reader(deployments_file).unwrap();
    let deployments_array = deployments_json["deployments"].as_array().unwrap();
    let deployments: Vec<Deployment> = deployments_array
        .iter()
        .map(|d| Deployment {
            source_chain_name: d["sourceChainName"]
                .as_str()
                .unwrap()
                .to_string()
                .to_uppercase(),
            contract_chain_id: d["contractChainId"].as_u64().unwrap(),
            contract_address: d["contractAddress"].as_str().unwrap().parse().unwrap(),
            cursor_start_block: d["cursorStartBlock"].as_u64().unwrap(),
        })
        .collect();
    deployments
}

// Read the RPC URL from the corresponding environment variable.
fn get_ethereum_rpc(chain_id: u64) -> Option<String> {
    let rpc_url = env::var(format!("RPC_{}", chain_id));
    if let Ok(ethereum_rpc_url) = rpc_url {
        Some(ethereum_rpc_url)
    } else {
        None
    }
}

type HeaderRangeCommitmentStoredTuple = sol! { tuple(uint32, uint32, bytes32, bytes32) };

sol! { struct RangeHashInput {
    uint32 trusted_block;
    uint32 end_block;
} }

async fn store_events(
    ethereum_rpc_url: &str,
    contract_address: Address,
    start_block: u64,
    end_block: u64,
    redis_client: &mut RedisClient,
) {
    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

    let chain_id = provider.get_chainid().await.unwrap();

    info!(
        "Storing VectorX events on chain {} at address: {:#x} from block {} to {}",
        chain_id, contract_address, start_block, end_block
    );

    let client = Arc::new(provider);

    let mut curr_start_block = start_block;
    while curr_start_block < end_block {
        // Max 100000 blocks per query.
        let mut batch_end_block = curr_start_block + 50000;
        if batch_end_block > end_block {
            batch_end_block = end_block;
        }
        let header_range_filter = Filter::new()
            .address(contract_address)
            .from_block(curr_start_block)
            .to_block(batch_end_block)
            .event("HeaderRangeCommitmentStored(uint32,uint32,bytes32,bytes32)");

        let logs = client.get_logs(&header_range_filter).await.unwrap();
        for log in logs {
            let log_bytes = log.data;
            let decoded = HeaderRangeCommitmentStoredTuple::abi_decode(&log_bytes.0, true).unwrap();

            let trusted_block = decoded.0;
            let end_block = decoded.1;
            let expected_data_commitment: Vec<u8> = decoded.2.to_vec();
            let expected_data_commitment: [u8; 32] = expected_data_commitment.try_into().unwrap();

            let data_commitment_range = DataCommitmentRange {
                start: trusted_block,
                end: end_block,
                data_commitment: expected_data_commitment.to_vec(),
            };

            redis_client
                .add_data_commitment_range(
                    chain_id.as_u64(),
                    contract_address.0.to_vec(),
                    data_commitment_range,
                )
                .await;
        }

        curr_start_block = batch_end_block;
    }
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let deployments = get_deployments();

    // Every minute, check if there are new events.
    const LOOP_INTERVAL: u64 = 60;

    // For each deployment:
    //  1. Get the Ethereum RPC corresponding to contractChainId. If it doesn't exist, error.
    //  2. Get the cursor corresponding to the contract address. If it doesn't exist, default to cursorStartBlock.
    //  3. Store all events from the cursor to the current block in Redis. Then, update the current block.
    //  4. Sleep for LOOP_INTERVAL seconds.

    loop {
        let mut redis_client = RedisClient::new().await;
        for deployment in &deployments {
            let rpc_url = match get_ethereum_rpc(deployment.contract_chain_id) {
                Some(url) => url,
                None => {
                    panic!(
                        "Ethereum RPC URL not found for chain ID: {}",
                        &deployment.contract_chain_id
                    );
                }
            };

            // Initialize Ethereum client.
            let provider =
                Provider::<Http>::try_from(rpc_url.clone()).expect("could not connect to client");
            let current_block = provider.get_block_number().await.unwrap().as_u64();

            let contract_address = deployment.contract_address;
            let cursor = redis_client
                .get_contract_cursor(deployment.contract_chain_id, contract_address)
                .await;

            // If the cursor is None, use the start block.
            let cursor = match cursor {
                Some(cursor) => cursor,
                None => deployment.cursor_start_block,
            };

            if current_block > cursor {
                store_events(
                    &rpc_url,
                    contract_address,
                    cursor,
                    current_block,
                    &mut redis_client,
                )
                .await;
                redis_client
                    .set_contract_cursor(
                        deployment.contract_chain_id,
                        contract_address,
                        current_block,
                    )
                    .await;
            }
        }
    }
}
