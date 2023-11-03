use std::cmp::min;
use std::env;

use alloy_sol_types::{sol, SolType};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256};
use log::info;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

struct VectorConfig {
    address: Address,
    chain_id: u32,
    step_function_id: H256,
    rotate_function_id: H256,
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize)]
struct OffchainInput {
    chainId: u32,
    to: String,
    data: String,
    functionId: String,
    input: String,
}

type NextAuthoritySetCalldataTuple = sol! { tuple(uint64, uint32) };
type NextAuthoritySetInputTuple = sol! { tuple(uint64, bytes32, uint32) };

type HeaderRangeCalldataTuple = sol! { tuple(uint32, uint64, uint32) };
type HeaderRangeInputTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

// const VECTOR_CONFIG: VectorConfig = VectorConfig {
//     address: "0x0000000",
//     chain_id: 5,
//     step_function_id: "0x98a2381f5efeaf7c3e39d749d6f676df1432487578f393161cebd2b03934f43b",
//     rotate_function_id: "0xb3f1415062a3543bb1c48d9d6a49f9e005fe415d347a5ba63e40bb1235acfd86",
// };

fn get_config() -> VectorConfig {
    let step_function_id = H256::from_slice(
        &hex::decode("3503f80d2000a387d3f19ba5ae616ee31f8455e6d13c835ee4c4404db3bb449e").unwrap(),
    );
    let rotate_function_id = H256::from_slice(
        &hex::decode("d78926e1a401e80cff31715d3dbad782ff8e7cdc83fa436f6e03e3e07cd7a7b4").unwrap(),
    );
    let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
    // TODO: VectorX on Goerli: https://goerli.etherscan.io/address/#code
    let address = contract_address
        .parse::<Address>()
        .expect("invalid address");

    VectorConfig {
        address,
        chain_id: 5,
        step_function_id,
        rotate_function_id,
    }
}

async fn submit_request(
    config: &VectorConfig,
    function_data: Vec<u8>,
    input: Vec<u8>,
    function_id: H256,
) {
    // All data except for chainId is a string, and needs a 0x prefix.
    let data = OffchainInput {
        chainId: config.chain_id,
        to: Bytes::from(config.address.0).to_string(),
        data: Bytes::from(function_data).to_string(),
        functionId: Bytes::from(function_id.0).to_string(),
        input: Bytes::from(input).to_string(),
    };

    // Stringify the data into JSON format.
    let serialized_data = serde_json::to_string(&data).unwrap();

    // TODO: Update with config.
    let request_url = "https://alpha.succinct.xyz/api/request/new";

    // Submit POST request to the offchain worker.
    let client = reqwest::Client::new();
    let res = client
        .post(request_url)
        .header("Content-Type", "application/json")
        .body(serialized_data)
        .send()
        .await
        .expect("Failed to send request.");

    if res.status().is_success() {
        // TODO: Log success message. Find structure of output.
        info!("Successfully submitted request.");
    } else {
        // TODO: Log error message.
        info!("Failed to submit request.");
    }
}

async fn request_header_range(
    config: &VectorConfig,
    contract: &VectorX<Provider<Http>>,
    trusted_block: u32,
    trusted_authority_set_id: u64,
    target_block: u32,
) {
    let trusted_header_hash = contract
        .block_height_to_header_hash(trusted_block)
        .await
        .unwrap();

    let trusted_authority_set_hash = contract
        .authority_set_id_to_hash(trusted_authority_set_id)
        .await
        .unwrap();

    let input = HeaderRangeInputTuple::abi_encode_packed(&(
        trusted_block,
        trusted_header_hash,
        trusted_authority_set_id,
        trusted_authority_set_hash,
        target_block,
    ));

    // abi.encodeWithSelector(bytes4(keccak256("commitHeaderRange(uint32,uint64,uint32)")),
    //  trusted_block, trusted_authority_set_id, target_block);
    let function_signature = "commitHeaderRange(uint32,uint64,uint32)";
    let function_selector = ethers::utils::id(function_signature).to_vec();
    let encoded_parameters = HeaderRangeCalldataTuple::abi_encode_sequence(&(
        trusted_block,
        trusted_authority_set_id,
        target_block,
    ));
    // Concat function selector and encoded parameters.
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    submit_request(config, function_data, input, config.step_function_id).await;
}

async fn request_next_authority_set_id(
    config: &VectorConfig,
    contract: &VectorX<Provider<Http>>,
    current_authority_set_id: u64,
    epoch_end_block: u32,
) {
    info!("Current authority set id: {:?}", current_authority_set_id);
    let current_authority_set_hash = contract
        .authority_set_id_to_hash(current_authority_set_id)
        .await
        .unwrap();

    info!(
        "Current authority set hash: {:?}",
        current_authority_set_hash
    );

    let input = NextAuthoritySetInputTuple::abi_encode_packed(&(
        current_authority_set_id,
        current_authority_set_hash,
        epoch_end_block,
    ));

    // abi.encodeWithSelector(bytes4(keccak256("addNextAuthoritySetId(uint64,uint32)")),
    //  current_authority_set_id, epoch_end_block);
    let function_signature = "addNextAuthoritySetId(uint64,uint32)";
    let function_selector = ethers::utils::id(function_signature).to_vec();
    let encoded_parameters = NextAuthoritySetCalldataTuple::abi_encode_sequence(&(
        current_authority_set_id,
        epoch_end_block,
    ));
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    submit_request(config, function_data, input, config.rotate_function_id).await;
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    info!("Starting VectorX offchain worker");

    const LOOP_DELAY: u64 = 30;

    let config: VectorConfig = get_config();

    let mut fetcher = RpcDataFetcher::new().await;

    let lc_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider = Provider::<Http>::try_from(lc_rpc_url).expect("could not connect to client");
    let vectorx = VectorX::new(config.address, provider.into());

    // Source STEP_RANGE_MAX from the contract.
    let step_range_max = vectorx.max_header_range().await.unwrap();
    loop {
        let head = fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = fetcher.get_authority_set_id(head_block - 1).await;

        let current_block = vectorx.latest_block().await.unwrap();
        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = fetcher.get_authority_set_id(current_block - 1).await;

        // The logic for keeping the Vector LC up to date is as follows:
        //      1. Fetch the current latest_block in the contract and the head of the chain.
        //      2. If current_authority_set_id == head_authority_set_id, then no rotate is needed.
        //      3. If current_authority_set_id < head_authority_set_id, request next authority set.
        //          a) Step if current_block != the last block justified by current authority set.

        if current_authority_set_id == head_authority_set_id {
            let mut block_to_step_to = min(head_block, current_block + step_range_max);

            // If block_to_step_to is not the last justified block, use the Redis cache.
            if fetcher.last_justified_block(current_authority_set_id).await != block_to_step_to {
                let valid_blocks = fetcher
                    .find_justifications_in_range(current_block, block_to_step_to)
                    .await;
                if valid_blocks.is_empty() {
                    continue;
                }
                block_to_step_to = valid_blocks[valid_blocks.len() - 1];
            }

            info!("Stepping to block {:?}.", block_to_step_to);

            // The block to step to is the minimum of the latest_block block and the head block + STEP_RANGE_MAX.
            request_header_range(
                &config,
                &vectorx,
                current_block,
                current_authority_set_id,
                block_to_step_to,
            )
            .await;
        }

        if current_authority_set_id < head_authority_set_id {
            info!("Current authority set id is less than head authority set id.");

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
                info!(
                    "Requesting next authority set id, which is {:?}.",
                    current_authority_set_id + 1
                );
                // Request the next authority set id.
                request_next_authority_set_id(
                    &config,
                    &vectorx,
                    current_authority_set_id,
                    last_justified_block,
                )
                .await;
            }

            // Check if step needed to the last justified block by the current authority set.
            #[allow(clippy::comparison_chain)]
            if current_block < last_justified_block {
                // The block to step to is the minimum of the last justified block and the
                // head block + STEP_RANGE_MAX.
                let mut block_to_step_to =
                    min(last_justified_block, current_block + step_range_max);

                // If block_to_step_to is not the last justified block, use the Redis cache.
                if last_justified_block != block_to_step_to {
                    let valid_blocks = fetcher
                        .find_justifications_in_range(current_block, block_to_step_to)
                        .await;
                    if valid_blocks.is_empty() {
                        continue;
                    }
                    block_to_step_to = valid_blocks[valid_blocks.len() - 1];
                }

                info!("Stepping to block {:?}.", block_to_step_to);

                // Step to block_to_step_to.
                request_header_range(
                    &config,
                    &vectorx,
                    current_block,
                    current_authority_set_id,
                    block_to_step_to,
                )
                .await;
            } else if current_block == last_justified_block {
                // If the current block is the last justified block, then call step for the next
                // authority set id.

                let next_last_justified_block =
                    fetcher.last_justified_block(next_authority_set_id).await;

                let mut block_to_step_to = min(
                    next_last_justified_block,
                    last_justified_block + step_range_max,
                );

                // If block_to_step_to is not the last justified block, use the Redis cache.
                if next_last_justified_block != block_to_step_to {
                    let valid_blocks = fetcher
                        .find_justifications_in_range(current_block, block_to_step_to)
                        .await;
                    if valid_blocks.is_empty() {
                        continue;
                    }
                    block_to_step_to = valid_blocks[valid_blocks.len() - 1];
                }

                info!("Stepping to block {:?}.", block_to_step_to);
                // Step to block_to_step_to.
                request_header_range(
                    &config,
                    &vectorx,
                    last_justified_block,
                    next_authority_set_id,
                    block_to_step_to,
                )
                .await;
            }
        }

        // Sleep for N minutes.
        println!("Sleeping for {} minutes.", LOOP_DELAY);
        tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
    }
}
