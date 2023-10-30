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
    // Source this from the contract.
    const STEP_RANGE_MAX: usize = 128;

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
    let head_authority_set_id = fetcher.get_authority_set_id(head_block).await;

    let latest_block = vectorx.latest_block().await.unwrap();
    let latest_authority_set_id = fetcher.get_authority_set_id(latest_block).await;

    // The logic is as follows:
    //      1. There is an existing head_block, and it's corresponding head_authority_set_id in the contract.
    //      2. We fetch the latest block, and it's corresponding latest_authority_set_id.
    //      3. If latest_authority_set_id == head_authority_set_id, then no rotate is needed. Step to the latest block if > STEP_THRESHOLD.
    //      4. If latest_authority_set_id > head_authority_set_id, then rotate is needed. Request the head_authority_set_id + 1.
    //          a) Step from head_block to get_rotate_block(head_authority_set_id + 1).
    //
    // We can only launch one rotate at a time.
    //
    // TODO: A batch rotate function could make sense, for when the light client gets far out of sync, and we want to rotate from the
    // current authority set id to a future one. This posed in an issue in our old circom light client, that our new implementation can fix.

    if head_authority_set_id == latest_authority_set_id
        && latest_block - head_block > STEP_THRESHOLD as u32
    {
        info!("Step to the latest block");
        // TODO: Check for errors
        let block_to_step_to = min(latest_block, head_block + STEP_RANGE_MAX as u32);

        vectorx
            .request_header_range(head_block, head_authority_set_id, block_to_step_to)
            .await
            .unwrap();
        return;
    }

    if head_authority_set_id < latest_authority_set_id {
        info!("Rotate is needed");

        let next_authority_set_id = head_authority_set_id + 1;

        // Get the hash of the next authority set id in the contract.
        // If the authority set id doesn't exist in the contract, the hash will be H256::zero().
        let next_authority_set_id_hash = vectorx
            .authority_set_id_to_hash(next_authority_set_id)
            .await
            .unwrap();

        // Get the last block justified by the current authority set id (the rotate block).
        let rotate_block = fetcher
            .get_authority_rotate_block(next_authority_set_id)
            .await;

        if H256::from_slice(&next_authority_set_id_hash) == H256::zero() {
            info!("No matching authority set id, rotate is needed");
            // Request the next authority set id.
            vectorx
                .request_next_authority_set_id(latest_block, latest_authority_set_id)
                .await
                .unwrap();

            // Check if we need to step to the rotate block for the current authority set id.
            if head_block < rotate_block {
                info!("Step to the rotate block");

                // The block to step to is the minimum of the rotate block and the head block + STEP_RANGE_MAX.
                let block_to_step_to = min(rotate_block, head_block + STEP_RANGE_MAX as u32);

                // Step to the rotate block.
                vectorx
                    .request_header_range(head_block, head_authority_set_id, block_to_step_to)
                    .await
                    .unwrap();
            }

            return;
        }
    }
}
