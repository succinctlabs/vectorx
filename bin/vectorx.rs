use std::cmp::min;
use std::env;

use ethers::abi::{encode_packed, Tokenizable};
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::H256;
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

#[derive(serde::Serialize, serde::Deserialize)]
struct OffchainInput {
    chain_id: u32,
    to: Address,
    data: Vec<u8>,
    function_id: H256,
    input: Vec<u8>,
}

// const VECTOR_CONFIG: VectorConfig = VectorConfig {
//     address: "0x0000000",
//     chain_id: 5,
//     step_function_id: "0x98a2381f5efeaf7c3e39d749d6f676df1432487578f393161cebd2b03934f43b",
//     rotate_function_id: "0xb3f1415062a3543bb1c48d9d6a49f9e005fe415d347a5ba63e40bb1235acfd86",
// };

fn get_config() -> VectorConfig {
    let step_function_id = H256::from_slice(
        &hex::decode("98a2381f5efeaf7c3e39d749d6f676df1432487578f393161cebd2b03934f43b").unwrap(),
    );
    let rotate_function_id = H256::from_slice(
        &hex::decode("b3f1415062a3543bb1c48d9d6a49f9e005fe415d347a5ba63e40bb1235acfd86").unwrap(),
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

    let input = encode_packed(&[
        trusted_block.into_token(),
        trusted_header_hash.into_token(),
        trusted_authority_set_id.into_token(),
        trusted_authority_set_hash.into_token(),
        target_block.into_token(),
    ])
    .expect("Failed to encode packed data.");

    let function_signature = "commitHeaderRange(uint32,uint64,uint32)";
    let function_selector = ethers::utils::id(function_signature)[0..4].to_vec();
    let encoded_parameters = ethers::abi::encode(&[
        trusted_block.into_token(),
        trusted_authority_set_id.into_token(),
        target_block.into_token(),
    ]);
    // Concat function selector and encoded parameters.
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    let data = OffchainInput {
        chain_id: config.chain_id,
        to: config.address,
        data: function_data,
        function_id: config.step_function_id,
        input,
    };

    // TODO: Update with config.
    let request_url = "https://alpha.succinct.xyz/api/request/new";

    // Submit POST request to the offchain worker.
    let client = reqwest::Client::new();
    let res = client
        .post(request_url)
        .json(&data)
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

async fn request_next_authority_set_id(
    config: &VectorConfig,
    contract: &VectorX<Provider<Http>>,
    current_authority_set_id: u64,
    epoch_end_block: u32,
) {
    let current_authority_set_hash = contract
        .authority_set_id_to_hash(current_authority_set_id)
        .await
        .unwrap();

    let input = encode_packed(&[
        current_authority_set_id.into_token(),
        current_authority_set_hash.into_token(),
        epoch_end_block.into_token(),
    ])
    .expect("Failed to encode packed data.");

    let function_signature = "addNextAuthoritySetId(uint64,uint32)";
    let function_selector = ethers::utils::id(function_signature)[0..4].to_vec();
    let encoded_parameters = ethers::abi::encode(&[
        current_authority_set_id.into_token(),
        epoch_end_block.into_token(),
    ]);
    // Concat function selector and encoded parameters.
    let function_data = [&function_selector[..], &encoded_parameters[..]].concat();

    let data = OffchainInput {
        chain_id: config.chain_id,
        to: config.address,
        data: function_data,
        function_id: config.rotate_function_id,
        input,
    };

    // TODO: Update with config.
    let request_url = "https://alpha.succinct.xyz/api/request/new";

    // Submit POST request to the offchain worker.
    let client = reqwest::Client::new();
    let res = client
        .post(request_url)
        .json(&data)
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

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    const STEP_THRESHOLD: usize = 100;
    const LOOP_DELAY: u64 = 30;

    let config: VectorConfig = get_config();

    let fetcher = RpcDataFetcher::new().await;

    let lc_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
    let provider = Provider::<Http>::try_from(lc_rpc_url).expect("could not connect to client");
    let vectorx = VectorX::new(config.address, provider.into());

    // Source STEP_RANGE_MAX from the contract.
    let step_range_max = vectorx.max_header_range().await.unwrap();
    loop {
        let head = fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = fetcher.get_authority_set_id(head_block).await;

        let current_block = vectorx.latest_block().await.unwrap();
        let current_authority_set_id = fetcher.get_authority_set_id(current_block).await;

        // The logic for keeping the Vector LC up to date is as follows:
        //      1. Fetch the current latest_block in the contract and the head of the chain.
        //      2. If current_authority_set_id == head_authority_set_id, then no rotate is needed.
        //          a) Step if (head - current_block) > STEP_THRESHOLD.
        //      3. If current_authority_set_id < head_authority_set_id, request next authority set.
        //          a) Step if current_block != the last block justified by current authority set.

        if current_authority_set_id == head_authority_set_id
            && head_block - current_block > STEP_THRESHOLD as u32
        {
            info!("Step to the latest block");
            let block_to_step_to = min(head_block, current_block + step_range_max);

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
                request_next_authority_set_id(
                    &config,
                    &vectorx,
                    current_authority_set_id,
                    last_justified_block,
                )
                .await;

                // Check if step needed to the last justified block by the current authority set.
                if current_block < last_justified_block {
                    info!("Step to the last justified block");

                    // The block to step to is the minimum of the last justified block and the
                    // head block + STEP_RANGE_MAX.
                    let block_to_step_to =
                        min(last_justified_block, current_block + step_range_max);

                    // Step to block_to_step_to.
                    request_header_range(
                        &config,
                        &vectorx,
                        current_block,
                        current_authority_set_id,
                        block_to_step_to,
                    )
                    .await;
                }
            }
        }

        // Sleep for N minutes.
        tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
    }
}
