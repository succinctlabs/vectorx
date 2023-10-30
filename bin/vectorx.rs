use std::cmp::min;
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
abigen!(VectorX, "./abi/VectorX.abi.json",);

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    const STEP_THRESHOLD: usize = 100;

    let fetcher = RpcDataFetcher::new().await;

    let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

    let private_key = env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set");

    // TODO: Add chain id to config.
    let chain_id = 5u64;
    let wallet: LocalWallet = private_key
        .parse::<LocalWallet>()
        .expect("invalid private key")
        .with_chain_id(chain_id);

    info!("Wallet address: {:?}", wallet.address());

    let client = SignerMiddleware::new(provider, wallet);
    let client = Arc::new(client);

    // TODO: VectorX on Goerli: https://goerli.etherscan.io/address/#code
    // TODO: Add to config.
    let address = "";
    let address = address.parse::<Address>().expect("invalid address");

    let vectorx = VectorX::new(address, client.clone());

    // Source STEP_RANGE_MAX from the contract.
    let step_range_max = vectorx.max_header_range().await.unwrap();

    // The increment is used to determine how often to run the loop.
    // TODO: Add to config.
    let increment = 30;

    loop {
        let head = fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = fetcher.get_authority_set_id(head_block).await;

        let current_block = vectorx.latest_block().await.unwrap();
        let current_authority_set_id = fetcher.get_authority_set_id(current_block).await;

        // The logic is as follows:
        //      1. There is an existing current latest_block in the contract.
        //      2. We fetch the head of the chain, and corresponding head_authority_id.
        //      3. If current_authority_set_id == head_authority_set_id, then no rotate is needed.
        //          a) Step if (head - current_block) > STEP_THRESHOLD.
        //      4. If current_authority_set_id < head_authority_set_id, request next authority set.
        //          a) Step if current_block != the last block justified by current authority set.

        if current_authority_set_id == head_authority_set_id
            && head_block - current_block > STEP_THRESHOLD as u32
        {
            info!("Step to the latest block");
            let block_to_step_to = min(head_block, current_block + step_range_max);

            // The block to step to is the minimum of the latest_block block and the head block + STEP_RANGE_MAX.
            vectorx
                .request_header_range(head_block, head_authority_set_id, block_to_step_to)
                .await
                .unwrap();
        }

        if current_authority_set_id < head_authority_set_id {
            info!("Rotate is needed");

            let next_authority_set_id = current_authority_set_id + 1;

            // Get the hash of the next authority set id in the contract.
            // If the authority set id doesn't exist in the contract, the hash will be H256::zero().
            let next_authority_set_hash = vectorx
                .authority_set_id_to_hash(next_authority_set_id)
                .await
                .unwrap();

            // Get the last block justified by the current authority set id (also a rotate block).
            let last_justified_block = fetcher.last_justified_block(current_authority_set_id).await;

            if H256::from_slice(&next_authority_set_hash) == H256::zero() {
                info!("No matching authority set id, rotate is needed");
                // Request the next authority set id.
                vectorx
                    .request_next_authority_set_id(current_block, current_authority_set_id)
                    .await
                    .unwrap();

                // Check if step needed to the last justified block by the current authority set.
                if head_block < last_justified_block {
                    info!("Step to the rotate block");

                    // The block to step to is the minimum of the rotate block and the head block +
                    // STEP_RANGE_MAX.
                    let block_to_step_to = min(last_justified_block, head_block + step_range_max);

                    // Step to the rotate block.
                    vectorx
                        .request_header_range(head_block, head_authority_set_id, block_to_step_to)
                        .await
                        .unwrap();
                }
            }
        }

        // Sleep for N minutes.
        tokio::time::sleep(tokio::time::Duration::from_secs(60 * increment)).await;
    }
}
