use std::cmp::min;
use std::env;

use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::core::types::Filter;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::H160;
use log::{error, info};
use succinct_client::request::SuccinctClient;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(DummyVectorX, "./abi/DummyVectorX.abi.json",);

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
    provider: Provider<Http>,
    contract: DummyVectorX<Provider<Http>>,
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

        let contract = DummyVectorX::new(config.address.0 .0, provider.clone().into());

        let data_fetcher = RpcDataFetcher::new().await;

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");
        let client = SuccinctClient::new(succinct_rpc_url, succinct_api_key, false, false);

        Self {
            config,
            provider,
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
        let reset_counter = self.contract.reset_counter().await.unwrap();

        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(reset_counter, trusted_block)
            .await
            .unwrap();

        let trusted_authority_set_hash = self
            .contract
            .authority_set_id_to_hash(reset_counter, trusted_authority_set_id)
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
        let reset_counter = self.contract.reset_counter().await.unwrap();
        info!("Current authority set id: {:?}", current_authority_set_id);
        let current_authority_set_hash = self
            .contract
            .authority_set_id_to_hash(reset_counter, current_authority_set_id)
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

    // Finds and requests rotate if available.
    async fn find_and_request_rotate(&mut self) {
        let head = self.data_fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = self.data_fetcher.get_authority_set_id(head_block - 1).await;

        let current_block = self.contract.latest_block().await.unwrap();
        let reset_counter = self.contract.reset_counter().await.unwrap();

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(current_block - 1)
            .await;

        if current_authority_set_id < head_authority_set_id {
            let next_authority_set_id = current_authority_set_id + 1;
            // Get the hash of the next authority set id in the contract.
            // If the authority set id doesn't exist in the contract, the hash will be H256::zero().
            // The next authority set id can exist in the contract already if there has not been
            // a step within the next authority set yet.
            let next_authority_set_hash = self
                .contract
                .authority_set_id_to_hash(reset_counter, next_authority_set_id)
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
                    .request_next_authority_set_id(current_authority_set_id, last_justified_block)
                    .await
                {
                    Ok(request_id) => {
                        info!("Next authority set request submitted: {}", request_id)
                    }
                    Err(e) => {
                        error!("Next authority set request failed: {}", e);
                    }
                };
            }
        }
    }

    // Finds the highest block in the range [current_block, block_to_step_to] that has a stored
    // justification that can be stepped to.
    async fn find_block_to_step_to(
        &mut self,
        _current_block: u32,
        head_block: u32,
        max_block_to_request: u32,
        authority_set_id: u64,
    ) -> Option<u32> {
        let last_justified_block = self
            .data_fetcher
            .last_justified_block(authority_set_id)
            .await;

        // Last justified block will be 0 in this is the current authority set.
        if last_justified_block == 0 {
            return Some(min(max_block_to_request, head_block));
        }

        Some(min(max_block_to_request, last_justified_block))
    }

    // Finds and requests step if available.
    async fn find_and_request_step(&mut self) {
        // Source STEP_RANGE_MAX & resetCounter from the contract.
        let step_range_max = self.contract.max_header_range().await.unwrap();
        let reset_counter = self.contract.reset_counter().await.unwrap();

        let head_block = self.data_fetcher.get_head().await.number;

        let current_block = self.contract.latest_block().await.unwrap();
        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = self
            .data_fetcher
            .get_authority_set_id(current_block - 1)
            .await;

        // Get the last justified block by the current authority set id.
        let last_justified_block = self
            .data_fetcher
            .last_justified_block(current_authority_set_id)
            .await;

        // If this is the last justified block, check if we can do a step in the next authority set.
        let mut request_authority_set_id = current_authority_set_id;
        if current_block == last_justified_block {
            let next_authority_set_id = current_authority_set_id + 1;

            // Check if the next authority set id exists in the contract.
            let next_authority_set_hash = self
                .contract
                .authority_set_id_to_hash(reset_counter, next_authority_set_id)
                .await
                .unwrap();
            if B256::from_slice(&next_authority_set_hash) == B256::ZERO {
                return;
            }
            request_authority_set_id = next_authority_set_id;
        }

        // Step as far as we can within blocks attested by the requested authority set.
        let block_to_step_to = self
            .find_block_to_step_to(
                current_block,
                head_block,
                current_block + step_range_max,
                request_authority_set_id,
            )
            .await;
        if block_to_step_to.is_none() {
            return;
        }

        // Request the header range proof to block_to_step_to.
        match self
            .request_header_range(
                current_block,
                request_authority_set_id,
                block_to_step_to.unwrap(),
            )
            .await
        {
            Ok(request_id) => {
                info!(
                    "Header range request submitted from block {} to block {} with request ID: {}",
                    current_block,
                    block_to_step_to.unwrap(),
                    request_id
                )
            }
            Err(e) => {
                error!("Header range request failed: {}", e);
            }
        };
    }

    async fn run(&mut self) {
        info!("Starting VectorX offchain worker");

        // Loop every for N minutes.
        const LOOP_DELAY_MINS: u64 = 20;
        // Update if there hasn't been an event emitted for 3 hours.
        const UPDATE_DELAY_MINS: u64 = 20;

        loop {
            // Get latest block of the chain.
            let head = self.provider.get_block_number().await.unwrap();

            // Always check if there is a rotate available.
            self.find_and_request_rotate().await;

            // Check if there were any header range commitments in the last UPDATE_DELAY_MINS.
            let header_range_filter = Filter::new()
                .address(H160::from_slice(&self.config.address.0 .0))
                .from_block(head - (UPDATE_DELAY_MINS * 5))
                .event("HeaderRangeCommitmentStored(uint32,uint32,bytes32,bytes32)");

            let logs = self.provider.get_logs(&header_range_filter).await.unwrap();
            if logs.is_empty() {
                // Check if there is a step available, and submit a request if so.
                self.find_and_request_step().await;
            }

            // Sleep for N minutes.
            info!("Sleeping for {} minutes.", LOOP_DELAY_MINS);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY_MINS)).await;
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
