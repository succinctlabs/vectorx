use std::env;
use std::sync::Arc;

use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::prelude::SignerMiddleware;
use ethers::providers::{Http, Provider};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::H256;
use log::info;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json");

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    let fetcher = RpcDataFetcher::new().await;

    let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");
    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()
        .expect("invalid private key")
        .with_chain_id(5u64);

    info!("Wallet address: {:?}", wallet.address());

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // VectorX on Goerli: https://goerli.etherscan.io/address/#code
    // Note; This should be in the config
    let address = "";
    let address = address.parse::<Address>().expect("invalid address");

    let vectorx = VectorX::new(address, client.clone());

    let head = fetcher.get_head().await;

    let head_block = head.number;
    let latest_block = vectorx.latest_block().await.unwrap();

    let latest_authority_set_id = fetcher.get_authority_set_id(latest_block).await;

    // Check if this authority set id is in the contract.
    let matching_authority_set_id = vectorx
        .authority_set_id_to_hash(latest_authority_set_id)
        .await
        .unwrap();

    if H256::from_slice(&matching_authority_set_id) == H256::zero() {
        info!("No matching authority set id found in contract");
        return;
    }
}
