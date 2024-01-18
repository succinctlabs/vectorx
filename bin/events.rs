use std::env;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::{Address, Filter};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use vectorx::input::{DataCommitmentRange, RpcDataFetcher};

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

type HeaderRangeCommitmentStoredTuple = sol! { tuple(uint32, uint32, bytes32, bytes32) };

sol! { struct RangeHashInput {
    uint32 trusted_block;
    uint32 end_block;
} }

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
    let chain_id = client.get_chainid().await.unwrap();

    // let contract = VectorX::new(address.0, client.clone().into());

    let mut data_fetcher = RpcDataFetcher::new().await;

    // Note: This should be a power of 2, and is the size of the merkle tree.
    // let step_range_max = contract.max_header_range().await.unwrap();

    let client = Arc::new(client);

    let header_range_filter = Filter::new()
        .address(address)
        .from_block(5109076)
        .event("HeaderRangeCommitmentStored(uint32,uint32,bytes32,bytes32)");

    let mut stream = client.subscribe_logs(&header_range_filter).await.unwrap();
    while let Some(log) = stream.next().await {
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

        data_fetcher
            .redis_client
            .add_data_commitment_range(chain_id.as_u64(), address.0.to_vec(), data_commitment_range)
            .await;
    }
}
