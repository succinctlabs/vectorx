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
    let address = "";
    let address = address.parse::<Address>().expect("invalid address");

    let vectorx = VectorX::new(address, client.clone());
    let latest_header = get_latest_header(&tendermint_rpc_url).await;
    let latest_block = latest_header.height.value();

    let head = zk_blobstream
        .latest_block()
        .call()
        .await
        .expect("failed to get head");

    // TODO: Remove in prod
    // Set genesis header if we are more than 1000 blocks behind.
    if (head as u64) < latest_block - 1000 {
        let mut block_to_request = latest_block - 500;
        block_to_request = block_to_request - (block_to_request % 10);

        let genesis_header = get_header_from_number(&tendermint_rpc_url, block_to_request).await;
        zk_blobstream
            .set_genesis_header(
                block_to_request,
                H256::from_slice(genesis_header.hash().as_bytes()).0,
            )
            .send()
            .await
            .expect("failed to set genesis header");
    }

    let mut curr_head = head;

    // Loop every 30 minutes. Call request_combined_skip every 30 minutes with the latest block number.
    // Loop time is currently to the time it takes for a proof to be generated.
    // TODO: Update with prod loop time.
    // TODO: Can update this to only skip to multiples of 10/100.
    let increment = 30;
    loop {
        // Get latest_header
        let latest_header = get_latest_header(&tendermint_rpc_url).await;
        let latest_block = latest_header.height.value();

        // Round down to the nearest 10.
        let max_end_block = latest_block - 10;

        let target_block = find_request_block(&tendermint_rpc_url, curr_head, max_end_block).await;

        if target_block - curr_head == 1 {
            // Call step if necessary.
            zk_blobstream
                .request_combined_step()
                .send()
                .await
                .expect("failed to request combined skip");
        } else {
            // Verify the call succeeded.
            zk_blobstream
                .request_combined_skip(target_block)
                .send()
                .await
                .expect("failed to request combined skip");
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(60 * increment)).await;

        curr_head = target_block;
    }
}
