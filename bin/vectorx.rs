use std::cmp::min;
use std::env;

use alloy_sol_types::{sol, SolType};
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::core::types::Address;
use ethers::providers::{Http, Provider};
use ethers::types::{Bytes, H256};
use log::{error, info};
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

struct VectorXConfig {
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

type NextAuthoritySetInputTuple = sol! { tuple(uint64, bytes32, uint32) };

type HeaderRangeInputTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

struct VectorXOperator {
    config: VectorXConfig,
    contract: VectorX<Provider<Http>>,
    data_fetcher: RpcDataFetcher,
}

impl VectorXOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let config = Self::get_config();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = VectorX::new(config.address, provider.into());

        let data_fetcher = RpcDataFetcher::new().await;

        Self {
            config,
            contract,
            data_fetcher,
        }
    }

    fn get_config() -> VectorXConfig {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        // TODO: VectorX on Goerli: https://goerli.etherscan.io/address/#code
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Load the function IDs.
        let step_id_env = env::var("STEP_FUNCTION_ID").expect("STEP_FUNCTION_ID must be set");
        let step_function_id = H256::from_slice(
            &hex::decode(step_id_env.strip_prefix("0x").unwrap_or(&step_id_env))
                .expect("invalid hex for step_function_id, expected 0x prefix"),
        );
        let rotate_id_env = env::var("ROTATE_FUNCTION_ID").expect("ROTATE_FUNCTION_ID must be set");
        let rotate_function_id = H256::from_slice(
            &hex::decode(rotate_id_env.strip_prefix("0x").unwrap_or(&rotate_id_env))
                .expect("invalid hex for rotate_function_id, expected 0x prefix"),
        );

        VectorXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            step_function_id,
            rotate_function_id,
        }
    }

    async fn submit_request(&self, function_data: Vec<u8>, input: Vec<u8>, function_id: H256) {
        // All data except for chainId is a string, and needs a 0x prefix.
        let data = OffchainInput {
            chainId: self.config.chain_id,
            to: Bytes::from(self.config.address.0).to_string(),
            data: Bytes::from(function_data).to_string(),
            functionId: Bytes::from(function_id.0).to_string(),
            input: Bytes::from(input).to_string(),
        };

        // Stringify the data into JSON format.
        let serialized_data = serde_json::to_string(&data).unwrap();

        // TODO: Load from config.
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
            info!("Successfully submitted request.");
        } else {
            // TODO: Log more specific error message.
            error!("Failed to submit request.");
        }
    }

    async fn request_header_range(
        &self,
        trusted_block: u32,
        trusted_authority_set_id: u64,
        target_block: u32,
    ) {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let trusted_authority_set_hash = self
            .contract
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

        // Encode the call into calldata.
        let commit_header_range_call = CommitHeaderRangeCall {
            trusted_block,
            authority_set_id: trusted_authority_set_id,
            target_block,
        };
        let function_data = commit_header_range_call.encode();

        self.submit_request(function_data, input, self.config.step_function_id)
            .await;
    }

    async fn request_next_authority_set_id(
        &self,
        current_authority_set_id: u64,
        epoch_end_block: u32,
    ) {
        info!("Current authority set id: {:?}", current_authority_set_id);
        let current_authority_set_hash = self
            .contract
            .authority_set_id_to_hash(current_authority_set_id)
            .await
            .unwrap();

        info!(
            "Current authority set hash: {:?}",
            hex::encode(current_authority_set_hash)
        );

        let input = NextAuthoritySetInputTuple::abi_encode_packed(&(
            current_authority_set_id,
            current_authority_set_hash,
            epoch_end_block,
        ));

        // Encode the call into calldata.
        let add_next_authority_set_id_call = AddNextAuthoritySetIdCall {
            current_authority_set_id,
            epoch_end_block,
        };
        let function_data = add_next_authority_set_id_call.encode();

        self.submit_request(function_data, input, self.config.rotate_function_id)
            .await;
    }

    async fn run(&mut self) {
        info!("Starting VectorX offchain worker");

        // Sleep for N minutes.
        const LOOP_DELAY: u64 = 40;

        loop {
            // Source STEP_RANGE_MAX from the contract.
            let step_range_max = self.contract.max_header_range().await.unwrap();

            let head = self.data_fetcher.get_head().await;
            let head_block = head.number;
            let head_authority_set_id =
                self.data_fetcher.get_authority_set_id(head_block - 1).await;

            let current_block = self.contract.latest_block().await.unwrap();
            // The current authority set id is the authority set id of the block before the current block.
            let current_authority_set_id = self
                .data_fetcher
                .get_authority_set_id(current_block - 1)
                .await;

            // The logic for keeping the Vector LC up to date is as follows:
            //      1. Fetch the current latest_block in the contract and the head of the chain.
            //      2. If current_authority_set_id == head_authority_set_id, then no rotate is needed.
            //      3. If current_authority_set_id < head_authority_set_id, request next authority set.
            //          a) Step if current_block != the last block justified by current authority set.

            if current_authority_set_id == head_authority_set_id {
                let mut block_to_step_to = min(head_block, current_block + step_range_max);

                // Find all blocks in the range [current_block, block_to_step_to] that have a stored
                // justification.
                let valid_blocks = self
                    .data_fetcher
                    .find_justifications_in_range(current_block, block_to_step_to)
                    .await;
                if valid_blocks.is_empty() {
                    continue;
                }
                // Get the most recent valid block in the range.
                block_to_step_to = valid_blocks[valid_blocks.len() - 1];

                info!("Stepping to block {:?}.", block_to_step_to);

                self.request_header_range(
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
                let next_authority_set_hash = self
                    .contract
                    .authority_set_id_to_hash(next_authority_set_id)
                    .await
                    .unwrap();

                // Get the last block justified by the current authority set id (also a rotate block).
                let last_justified_block = self
                    .data_fetcher
                    .last_justified_block(current_authority_set_id)
                    .await;

                if H256::from_slice(&next_authority_set_hash) == H256::zero() {
                    info!(
                        "Requesting next authority set id, which is {:?}.",
                        current_authority_set_id + 1
                    );
                    // Request the next authority set id.
                    self.request_next_authority_set_id(
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

                    // Find all blocks in the range [current_block, block_to_step_to] that have a stored
                    // justification.
                    let valid_blocks = self
                        .data_fetcher
                        .find_justifications_in_range(current_block, block_to_step_to)
                        .await;
                    if valid_blocks.is_empty() {
                        continue;
                    }
                    block_to_step_to = valid_blocks[valid_blocks.len() - 1];

                    info!("Stepping to block {:?}.", block_to_step_to);

                    // Step to block_to_step_to.
                    self.request_header_range(
                        current_block,
                        current_authority_set_id,
                        block_to_step_to,
                    )
                    .await;
                } else if current_block == last_justified_block {
                    // If the current block is the last justified block, then call step for the next
                    // authority set id.

                    let next_last_justified_block = self
                        .data_fetcher
                        .last_justified_block(next_authority_set_id)
                        .await;

                    let mut block_to_step_to = min(
                        next_last_justified_block,
                        last_justified_block + step_range_max,
                    );

                    // Find all blocks in the range [current_block, block_to_step_to] that have a stored
                    // justification.
                    let valid_blocks = self
                        .data_fetcher
                        .find_justifications_in_range(current_block, block_to_step_to)
                        .await;
                    if valid_blocks.is_empty() {
                        continue;
                    }
                    block_to_step_to = valid_blocks[valid_blocks.len() - 1];

                    info!("Stepping to block {:?}.", block_to_step_to);
                    // Step to block_to_step_to.
                    self.request_header_range(
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
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let mut operator = VectorXOperator::new().await;
    operator.run().await;
}
