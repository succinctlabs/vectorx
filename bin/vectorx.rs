use std::cmp::min;
use std::env;

use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Middleware, Provider};
use log::{error, info};
use succinct_client::request::SuccinctClient;
use vectorx::input::RpcDataFetcher;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

#[derive(Clone, Debug)]
pub struct VectorXConfig {
    address: Address,
    chain_id: u32,
}

type NextAuthoritySetInputTuple = sol! { tuple(uint64, bytes32, uint32) };

type HeaderRangeInputTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

struct VectorXOperator {
    config: VectorXConfig,
    provider: Provider<Http>,
    contract: VectorX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: RpcDataFetcher,
}

#[derive(Debug)]
struct StepContractData {
    current_block: u32,
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

        Self {
            config,
            provider,
            contract,
            client,
            data_fetcher,
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

    async fn request_next_authority_set_id(
        &mut self,
        current_authority_set_id: u64,
        epoch_end_block: u32,
        rotate_function_id: B256,
    ) -> Result<String> {
        let client = self.get_succinct_client();
        let config = self.get_config();

        let current_authority_set_hash = self
            .get_next_authority_set_id_input_data(current_authority_set_id)
            .await;

        info!(
            "Current authority set hash: {:?}",
            hex::encode(current_authority_set_hash)
        );

        let input = NextAuthoritySetInputTuple::abi_encode_packed(&(
            current_authority_set_id,
            current_authority_set_hash,
            epoch_end_block,
        ));

        // Note: Use vector_x because the calls are the same.
        let add_next_authority_set_id_call = vector_x::AddNextAuthoritySetIdCall {
            current_authority_set_id,
            epoch_end_block,
        };
        let function_data = add_next_authority_set_id_call.encode();

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
        let mut data_fetcher = self.get_data_fetcher();

        let rotate_contract_data = self.get_contract_data_for_rotate().await;

        let head = data_fetcher.get_head().await;
        let head_block = head.number;
        let head_authority_set_id = data_fetcher.get_authority_set_id(head_block - 1).await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = data_fetcher
            .get_authority_set_id(rotate_contract_data.current_block - 1)
            .await;

        if current_authority_set_id < head_authority_set_id
            && !rotate_contract_data.next_authority_set_hash_exists
        {
            info!(
                "Requesting next authority set id, which is {:?}.",
                current_authority_set_id + 1
            );
            // Get the last block justified by the current authority set id (also a rotate block).
            let last_justified_block = data_fetcher
                .last_justified_block(current_authority_set_id)
                .await;

            // Request the next authority set id.
            match self
                .request_next_authority_set_id(
                    current_authority_set_id,
                    last_justified_block,
                    rotate_contract_data.rotate_function_id,
                )
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

    async fn find_and_request_step(&mut self, max_block_to_step_to: u32) {
        let mut data_fetcher = self.get_data_fetcher();

        let step_contract_data = self.get_contract_data_for_step().await;

        // The current authority set id is the authority set id of the block before the current block.
        let current_authority_set_id = data_fetcher
            .get_authority_set_id(step_contract_data.current_block - 1)
            .await;

        // Get the last justified block by the current authority set id.
        let last_justified_block = data_fetcher
            .last_justified_block(current_authority_set_id)
            .await;

        // If this is the last justified block, check for step with next authority set.
        let mut request_authority_set_id = current_authority_set_id;
        if step_contract_data.current_block == last_justified_block {
            let next_authority_set_id = current_authority_set_id + 1;

            // Check if the next authority set id exists in the contract. If not, a rotate is needed.
            if !step_contract_data.next_authority_set_hash_exists {
                return;
            }
            request_authority_set_id = next_authority_set_id;
        }

        // Step as far as possible within blocks attested by the requested authority set.
        let block_to_step_to = self
            .find_block_to_step_to(max_block_to_step_to, request_authority_set_id)
            .await;
        if block_to_step_to.is_none() {
            return;
        }

        info!("Requesting step to block: {:?}.", block_to_step_to.unwrap());

        // Request the header range proof to block_to_step_to.
        match self
            .request_header_range(
                step_contract_data.current_block,
                request_authority_set_id,
                block_to_step_to.unwrap(),
                step_contract_data.header_range_function_id,
            )
            .await
        {
            Ok(request_id) => {
                info!(
                    "Header range request submitted from block {} to block {} with request ID: {}",
                    step_contract_data.current_block,
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

    // Current authority set hash. (Implement!)
    async fn get_next_authority_set_id_input_data(
        &mut self,
        current_authority_set_id: u64,
    ) -> B256 {
        alloy_primitives::FixedBytes(
            self.contract
                .authority_set_id_to_hash(current_authority_set_id)
                .await
                .unwrap(),
        )
    }

    // Current block, step_range_max and whether next authority set hash exists. (Implement!)
    async fn get_contract_data_for_step(&mut self) -> StepContractData {
        let header_range_function_id: B256 =
            FixedBytes(self.contract.header_range_function_id().await.unwrap());
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

        StepContractData {
            current_block,
            next_authority_set_hash_exists: B256::from_slice(&next_authority_set_hash)
                != B256::ZERO,
            header_range_function_id,
        }
    }

    // Current block and whether next authority set hash exists. (Implement!)
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

    fn get_data_fetcher(&mut self) -> RpcDataFetcher {
        self.data_fetcher.clone()
    }

    fn get_provider(&self) -> Provider<Http> {
        self.provider.clone()
    }

    // If the authority_set_id is the current authority set, return the max_block_to_request. Else,
    // return the minimum of max_block_to_request and last_justified_block.
    async fn find_block_to_step_to(
        &mut self,
        max_block_to_request: u32,
        authority_set_id: u64,
    ) -> Option<u32> {
        let last_justified_block = self
            .data_fetcher
            .last_justified_block(authority_set_id)
            .await;

        // Last justified block will be 0 in this is the current authority set.
        if last_justified_block == 0 {
            return Some(max_block_to_request);
        }

        Some(min(max_block_to_request, last_justified_block))
    }

    async fn run(&mut self, loop_delay_mins: u64, update_delay_blocks: u32) {
        let provider = self.get_provider();

        loop {
            // Always check if there is a rotate available.
            self.find_and_request_rotate().await;

            // Get latest block of the chain.
            let chain_latest_block_nb = provider.get_block_number().await.unwrap();

            // Get latest block of contract.
            let contract_latest_block_nb = self.contract.latest_block().await.unwrap();

            // Attempt to step to contract_latest_block_nb + update_delay_blocks.
            let next_block_to_request: u32 = contract_latest_block_nb + update_delay_blocks;
            if chain_latest_block_nb.as_u32() > next_block_to_request {
                info!("Attempting to step to block: {}", next_block_to_request);
                self.find_and_request_step(next_block_to_request).await;
            }

            // Sleep for N minutes.
            info!("Sleeping for {} minutes.", loop_delay_mins);
            tokio::time::sleep(tokio::time::Duration::from_secs(60 * loop_delay_mins)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let data_fetcher = RpcDataFetcher::new().await;

    let loop_delay_mins_env = env::var("LOOP_DELAY_MINS");
    let mut loop_delay_mins = 5;
    if loop_delay_mins_env.is_ok() {
        loop_delay_mins = loop_delay_mins_env
            .unwrap()
            .parse::<u64>()
            .expect("invalid LOOP_DELAY_MINS");
    }
    let update_delay_blocks_env = env::var("UPDATE_DELAY_BLOCKS");
    let mut update_delay_blocks = 200;
    if update_delay_blocks_env.is_ok() {
        update_delay_blocks = update_delay_blocks_env
            .unwrap()
            .parse::<u32>()
            .expect("invalid UPDATE_DELAY_BLOCKS");
    }
    let mut operator = VectorXOperator::new(data_fetcher).await;
    operator.run(loop_delay_mins, update_delay_blocks).await;
}
