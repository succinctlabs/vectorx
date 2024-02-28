use std::env;
use std::sync::Arc;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::{Address, Filter};
use ethers::providers::{Middleware, Provider, StreamExt, Ws};
use log::info;
use vectorx::input::{DataCommitmentRange, RpcDataFetcher};

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

type HeaderRangeCommitmentStoredTuple = sol! { tuple(uint32, uint32, bytes32, bytes32) };

sol! { struct RangeHashInput {
    uint32 trusted_block;
    uint32 end_block;
} }

async fn listen_for_events(ethereum_ws: &str, contract_address: &str) {
    let address = contract_address
        .parse::<Address>()
        .expect("invalid address");

    let client = Provider::<Ws>::connect(ethereum_ws)
        .await
        .expect("could not connect to client");

    let chain_id = client.get_chainid().await.unwrap();

    info!(
        "Listening for VectorX events on chain {} at address: {}",
        chain_id, contract_address
    );

    let mut data_fetcher = RpcDataFetcher::new().await;

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

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    // List of Avail chains to index.
    let chains = ["Couscous", "Goldberg"];

    // For each Avail chain `chainName` to index, set the following environment variables:
    //  {chainName}_ETHEREUM_WS: An Ethereum WS for the chain the deployed VectorX contract is on.
    //  {chainName}_CONTRACT_ADDRESS: The address of the deployed VectorX contract.
    // Note: Not all chains need to be indexed.
    let mut ethereum_ws_vec = Vec::new();
    let mut contract_addresses = Vec::new();
    for chain in &chains {
        let ethereum_ws_var = format!("{}_ETHEREUM_WS", chain.to_uppercase());
        let contract_address_var = format!("{}_CONTRACT_ADDRESS", chain.to_uppercase());

        let ethereum_ws = env::var(&ethereum_ws_var);
        let contract_address = env::var(&contract_address_var);

        if ethereum_ws.is_err() || contract_address.is_err() {
            info!("Not indexing {} for events!", chain);
            continue;
        }

        ethereum_ws_vec.push(ethereum_ws.unwrap());
        contract_addresses.push(contract_address.unwrap());
    }

    let mut join_handles = Vec::new();

    for (ethereum_ws, contract_address) in ethereum_ws_vec
        .into_iter()
        .zip(contract_addresses.into_iter())
    {
        let handle = tokio::spawn(async move {
            listen_for_events(&ethereum_ws, &contract_address).await;
        });
        join_handles.push(handle);
    }

    for handle in join_handles {
        handle.await.expect("Task panicked or failed");
    }
}
