use std::cmp::min;
use std::env;

use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use log::{error, info};
use succinct_client::request::SuccinctClient;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

struct VectorXConfig {
    address: Address,
    chain_id: u32,
    header_range_function_id: B256,
    rotate_function_id: B256,
}

type NextAuthoritySetInputTuple = sol! { tuple(uint64, bytes32, uint32) };

type HeaderRangeInputTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

struct VectorXOperator {
    config: VectorXConfig,
    contract: VectorX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: RpcDataFetcher,
}

impl VectorXOperator {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let config = Self::get_config();

        let ethereum_rpc_url = env::var("ETHEREUM_RPC_URL").expect("ETHEREUM_RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = VectorX::new(config.address.0 .0, provider.into());

        let data_fetcher = RpcDataFetcher::new().await;

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");
        let client = SuccinctClient::new(succinct_rpc_url, succinct_api_key, false, false);

        Self {
            config,
            contract,
            client,
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
        let header_range_id_env =
            env::var("HEADER_RANGE_FUNCTION_ID").expect("HEADER_RANGE_FUNCTION_ID must be set");
        let header_range_function_id = B256::from_slice(
            &hex::decode(
                header_range_id_env
                    .strip_prefix("0x")
                    .unwrap_or(&header_range_id_env),
            )
            .expect("invalid hex for header_range_function_id, expected 0x prefix"),
        );
        let rotate_id_env = env::var("ROTATE_FUNCTION_ID").expect("ROTATE_FUNCTION_ID must be set");
        let rotate_function_id = B256::from_slice(
            &hex::decode(rotate_id_env.strip_prefix("0x").unwrap_or(&rotate_id_env))
                .expect("invalid hex for rotate_function_id, expected 0x prefix"),
        );

        VectorXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            header_range_function_id,
            rotate_function_id,
        }
    }

    async fn request_header_range(
        &self,
        trusted_block: u32,
        trusted_authority_set_id: u64,
        target_block: u32,
    ) -> Result<String> {
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

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.header_range_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn request_next_authority_set_id(
        &self,
        current_authority_set_id: u64,
        epoch_end_block: u32,
    ) -> Result<String> {
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

        let request_id = self
            .client
            .submit_platform_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                self.config.rotate_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn run(&mut self) {
        info!("Starting VectorX offchain worker");

        // Sleep for N minutes.
        const LOOP_DELAY: u64 = 240;

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
                    info!("No valid blocks found in range.");
                    continue;
                }
                // Get the most recent valid block in the range.
                block_to_step_to = valid_blocks[valid_blocks.len() - 1];

                info!("Stepping to block {:?}.", block_to_step_to);

                match self
                    .request_header_range(current_block, current_authority_set_id, block_to_step_to)
                    .await
                {
                    Ok(request_id) => {
                        info!("Header range request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Header range request failed: {}", e);
                        continue;
                    }
                };
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

                if B256::from_slice(&next_authority_set_hash) == B256::ZERO {
                    info!(
                        "Requesting next authority set id, which is {:?}.",
                        current_authority_set_id + 1
                    );
                    // Request the next authority set id.
                    match self
                        .request_next_authority_set_id(
                            current_authority_set_id,
                            last_justified_block,
                        )
                        .await
                    {
                        Ok(request_id) => {
                            info!("Next authority set request submitted: {}", request_id)
                        }
                        Err(e) => {
                            error!("Next authority set request failed: {}", e);
                            continue;
                        }
                    };
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
                    match self
                        .request_header_range(
                            current_block,
                            current_authority_set_id,
                            block_to_step_to,
                        )
                        .await
                    {
                        Ok(request_id) => {
                            info!("Header range request submitted: {}", request_id)
                        }
                        Err(e) => {
                            error!("Header range request failed: {}", e);
                            continue;
                        }
                    };
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
                    match self
                        .request_header_range(
                            current_block,
                            next_authority_set_id,
                            block_to_step_to,
                        )
                        .await
                    {
                        Ok(request_id) => {
                            info!("Header range request submitted: {}", request_id)
                        }
                        Err(e) => {
                            error!("Header range request failed: {}", e);
                            continue;
                        }
                    };
                }
            }

            // Sleep for N minutes.
            info!("Sleeping for {} minutes.", LOOP_DELAY);
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
