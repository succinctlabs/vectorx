use std::cmp::min;
use std::env;

use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use log::{error, info};
use succinct_client::request::SuccinctClient;
use vectorx::consts::MAX_AUTHORITY_SET_SIZE;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

#[derive(Clone, Debug)]
pub struct VectorXConfig {
    address: Address,
    chain_id: u32,
}

type RotateInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeInputTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

struct VectorXOperator {
    config: VectorXConfig,
    contract: VectorX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: RpcDataFetcher,
    is_dummy_operator: bool,
}

#[derive(Debug)]
struct HeaderRangeContractData {
    vectorx_latest_block: u32,
    avail_current_block: u32,
    header_range_commitment_tree_size: u32,
    next_authority_set_hash_exists: bool,
    header_range_function_id: B256,
}

#[derive(Debug)]
struct RotateContractData {
    current_block: u32,
    next_authority_set_hash_exists: bool,
    rotate_function_id: B256,
}

impl VectorXOperator {
    async fn new(data_fetcher: RpcDataFetcher) -> Self {
        dotenv::dotenv().ok();

        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        let ethereum_rpc_url = env::var("ETHEREUM_RPC_URL").expect("ETHEREUM_RPC_URL must be set");
        let provider =
            Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");

        let contract = VectorX::new(address.0 .0, provider.clone().into());

        let config = VectorXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
        };

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");
        let client = SuccinctClient::new(succinct_rpc_url, succinct_api_key, false, false);

        // is_dummy_operator defaults to false.
        let is_dummy_operator = env::var("IS_DUMMY_OPERATOR")
            .unwrap_or("false".to_string())
            .parse::<bool>()
            .unwrap();

        Self {
            config,
            contract,
            client,
            data_fetcher,
            is_dummy_operator,
        }
    }

    async fn request_header_range(
        &mut self,
        trusted_block: u32,
        trusted_authority_set_id: u64,
        target_block: u32,
        header_range_function_id: B256,
    ) -> Result<String> {
        let client = self.get_succinct_client();
        let config = self.get_config();

        let (trusted_header_hash, trusted_authority_set_hash) = self
            .get_header_range_input_data(trusted_block, trusted_authority_set_id)
            .await;

        let input = HeaderRangeInputTuple::abi_encode_packed(&(
            trusted_block,
            trusted_header_hash,
            trusted_authority_set_id,
            trusted_authority_set_hash,
            target_block,
        ));

        // Encode the call into calldata.
        // Note: Use vector_x because the calls are the same.
        let commit_header_range_call = vector_x::CommitHeaderRangeCall {
            authority_set_id: trusted_authority_set_id,
            target_block,
        };
        let function_data = commit_header_range_call.encode();

        let request_id = client
            .submit_platform_request(
                config.chain_id,
                config.address,
                function_data.into(),
                header_range_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn request_rotate(
        &mut self,
        current_authority_set_id: u64,
        rotate_function_id: B256,
    ) -> Result<String> {
        let client = self.get_succinct_client();
        let config = self.get_config();

        let current_authority_set_hash = self.get_rotate_input_data(current_authority_set_id).await;

        info!(
            "Current authority set hash: {:?}",
            hex::encode(current_authority_set_hash)
        );

        let input = RotateInputTuple::abi_encode_packed(&(
            current_authority_set_id,
            current_authority_set_hash,
        ));

        let rotate_call = vector_x::RotateCall {
            current_authority_set_id,
        };
        let function_data = rotate_call.encode();

        let request_id = client
            .submit_platform_request(
                config.chain_id,
                config.address,
                function_data.into(),
                rotate_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn find_and_request_rotate(&mut self) {
        let rotate_contract_data = self.get_contract_data_for_rotate().await;

        let head = self.data_fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = self.data_fetcher.get_authority_set_id(head_block - 1).await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(rotate_contract_data.current_block - 1)
            .await;

        if current_authority_set_id < head_authority_set_id
            && !rotate_contract_data.next_authority_set_hash_exists
        {
            info!(
                "Requesting rotate to next authority set id, which is {:?}.",
                current_authority_set_id + 1
            );

            // Request a rotate for the next authority set id.
            match self
                .request_rotate(
                    current_authority_set_id,
                    rotate_contract_data.rotate_function_id,
                )
                .await
            {
                Ok(request_id) => {
                    info!("Rotate request submitted: {}", request_id)
                }
                Err(e) => {
                    error!("Rotate request failed: {}", e);
                }
            };
        }
    }

    // Ideally, post a header range update every ideal_block_interval blocks.
    async fn find_and_request_header_range(&mut self, ideal_block_interval: u32) {
        let header_range_contract_data = self.get_contract_data_for_header_range().await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(header_range_contract_data.vectorx_latest_block - 1)
            .await;

        // Get the last justified block by the current authority set id.
        let last_justified_block = self
            .data_fetcher
            .last_justified_block(current_authority_set_id)
            .await;

        // If this is the last justified block, check for header range with next authority set.
        let mut request_authority_set_id = current_authority_set_id;
        if header_range_contract_data.vectorx_latest_block == last_justified_block {
            let next_authority_set_id = current_authority_set_id + 1;

            // Check if the next authority set id exists in the contract. If not, a rotate is needed.
            if !header_range_contract_data.next_authority_set_hash_exists {
                return;
            }
            request_authority_set_id = next_authority_set_id;
        }

        // Find the block to step to. If no block is returned, either 1) there is no block satisfying
        // the conditions that is available to step to or 2) something has gone wrong with the indexer.
        let block_to_step_to = self
            .find_block_to_step_to(
                ideal_block_interval,
                header_range_contract_data.header_range_commitment_tree_size,
                header_range_contract_data.vectorx_latest_block,
                header_range_contract_data.avail_current_block,
                request_authority_set_id,
            )
            .await;
        if block_to_step_to.is_none() {
            return;
        }

        info!(
            "Requesting header range with end block: {:?}.",
            block_to_step_to.unwrap()
        );

        // Request the header range proof to block_to_step_to.
        match self
            .request_header_range(
                header_range_contract_data.vectorx_latest_block,
                request_authority_set_id,
                block_to_step_to.unwrap(),
                header_range_contract_data.header_range_function_id,
            )
            .await
        {
            Ok(request_id) => {
                info!(
                    "Header range request submitted from block {} to block {} with request ID: {}",
                    header_range_contract_data.vectorx_latest_block,
                    block_to_step_to.unwrap(),
                    request_id
                )
            }
            Err(e) => {
                error!("Header range request failed: {}", e);
            }
        };
    }

    async fn get_header_range_input_data(
        &mut self,
        trusted_block: u32,
        trusted_authority_set_id: u64,
    ) -> (B256, B256) {
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

        (
            B256::from_slice(&trusted_header_hash),
            B256::from_slice(&trusted_authority_set_hash),
        )
    }

    // Current authority set hash.
    async fn get_rotate_input_data(&mut self, current_authority_set_id: u64) -> B256 {
        alloy_primitives::FixedBytes(
            self.contract
                .authority_set_id_to_hash(current_authority_set_id)
                .await
                .unwrap(),
        )
    }

    // Current block, step_range_max and whether next authority set hash exists.
    async fn get_contract_data_for_header_range(&mut self) -> HeaderRangeContractData {
        let header_range_function_id: B256 =
            FixedBytes(self.contract.header_range_function_id().await.unwrap());
        let vectorx_latest_block = self.contract.latest_block().await.unwrap();
        let header_range_commitment_tree_size = self
            .contract
            .header_range_commitment_tree_size()
            .await
            .unwrap();

        let avail_current_block = self.data_fetcher.get_head().await.number;

        let vectorx_current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(vectorx_latest_block - 1)
            .await;
        let next_authority_set_id = vectorx_current_authority_set_id + 1;

        let next_authority_set_hash = self
            .contract
            .authority_set_id_to_hash(next_authority_set_id)
            .await
            .unwrap();

        HeaderRangeContractData {
            vectorx_latest_block,
            avail_current_block,
            header_range_commitment_tree_size,
            next_authority_set_hash_exists: B256::from_slice(&next_authority_set_hash)
                != B256::ZERO,
            header_range_function_id,
        }
    }

    // Current block and whether next authority set hash exists.
    async fn get_contract_data_for_rotate(&mut self) -> RotateContractData {
        let rotate_function_id: B256 =
            FixedBytes(self.contract.rotate_function_id().await.unwrap());
        let current_block = self.contract.latest_block().await.unwrap();

        let current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(current_block - 1)
            .await;
        let next_authority_set_id = current_authority_set_id + 1;

        let next_authority_set_hash = self
            .contract
            .authority_set_id_to_hash(next_authority_set_id)
            .await
            .unwrap();

        RotateContractData {
            current_block,
            next_authority_set_hash_exists: B256::from_slice(&next_authority_set_hash)
                != B256::ZERO,
            rotate_function_id,
        }
    }

    fn get_succinct_client(&mut self) -> SuccinctClient {
        self.client.clone()
    }

    fn get_config(&mut self) -> VectorXConfig {
        self.config.clone()
    }

    // The logic for finding the block to step to is as follows:
    // 1. If the current epoch in the contract is not the latest epoch, step to the last justified block
    // of the epoch.
    // 2. If the block has a valid justification, return the block number.
    // 3. If the block has no valid justification, return None.
    async fn find_block_to_step_to(
        &mut self,
        ideal_block_interval: u32,
        header_range_commitment_tree_size: u32,
        vectorx_current_block: u32,
        avail_current_block: u32,
        authority_set_id: u64,
    ) -> Option<u32> {
        let last_justified_block = self
            .data_fetcher
            .last_justified_block(authority_set_id)
            .await;

        // Step to the last justified block of the current epoch if it is in range. When the last
        // justified block is 0, the VectorX contract's latest epoch is the current epoch on the
        // Avail chain.
        if last_justified_block != 0
            && last_justified_block <= vectorx_current_block + header_range_commitment_tree_size
        {
            return Some(last_justified_block);
        }

        // The maximum valid block to step to is the either header_range_commitment_tree_size blocks
        // ahead of the current block in the contract or the latest block on Avail.
        let max_valid_block_to_step_to = min(
            vectorx_current_block + header_range_commitment_tree_size,
            avail_current_block,
        );

        // Find the closest block to the maximum valid block to step to that is a multiple of
        // ideal_block_interval.
        let mut block_to_step_to =
            max_valid_block_to_step_to - (max_valid_block_to_step_to % ideal_block_interval);

        // If block_to_step_to is the current block, return None.
        if block_to_step_to == vectorx_current_block {
            return None;
        }

        // If dummy operator, return the block to step to.
        if self.is_dummy_operator {
            return Some(block_to_step_to);
        }

        // Check that block_to_step_to has a valid justification. If not, iterate up until the maximum_vectorx_target_block
        // to find a valid justification. If we're unable to find a justification, something has gone
        // deeply wrong with the jusitification indexer.
        loop {
            if block_to_step_to > vectorx_current_block + header_range_commitment_tree_size {
                info!(
                    "Unable to find any valid justifications after searching from block {} to block {}. This is likely caused by an issue with the justification indexer.",
                    vectorx_current_block + ideal_block_interval,
                    vectorx_current_block + header_range_commitment_tree_size
                );
                return None;
            }

            if self
                .data_fetcher
                .get_justification_from_block::<MAX_AUTHORITY_SET_SIZE>(block_to_step_to)
                .await
                .is_ok()
            {
                break;
            }
            block_to_step_to += 1;
        }

        Some(block_to_step_to)
    }

    async fn run(&mut self) {
        loop {
            let loop_delay_mins = get_loop_delay_mins();
            let block_interval = get_update_delay_blocks();

            // Check if there is a rotate available for the next authority set.
            self.find_and_request_rotate().await;

            // Check if there is a header range request available.
            self.find_and_request_header_range(block_interval).await;

            // Sleep for N minutes.
            info!("Sleeping for {} minutes.", loop_delay_mins);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }
}

fn get_loop_delay_mins() -> u64 {
    let loop_delay_mins_env = env::var("LOOP_DELAY_MINS");
    let mut loop_delay_mins = 15;
    if loop_delay_mins_env.is_ok() {
        loop_delay_mins = loop_delay_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_DELAY_MINS");
    }
    loop_delay_mins
}

fn get_update_delay_blocks() -> u32 {
    let update_delay_blocks_env = env::var("UPDATE_DELAY_BLOCKS");
    let mut update_delay_blocks = 180;
    if update_delay_blocks_env.is_ok() {
        update_delay_blocks = update_delay_blocks_env
            .unwrap()
            .parse::<u32>()
            .expect("invalid UPDATE_DELAY_BLOCKS");
    }
    update_delay_blocks
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let data_fetcher = RpcDataFetcher::new().await;

    let mut operator = VectorXOperator::new(data_fetcher).await;
    operator.run().await;
}
