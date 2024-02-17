use alloy_primitives::Address;
use clap::Parser;
use ethers::abi::AbiEncode;
use ethers::middleware::SignerMiddleware;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::TransactionReceipt;
use log::info;
use subxt::config::Header;

// Note: Update ABI when updating contract.
abigen!(VectorX, "./abi/VectorX.abi.json",);

use std::cmp::min;
use std::env;
use std::str::FromStr;
use std::sync::Arc;

use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use vectorx::input::RpcDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Get the last block of the block range to fill and whether to post the data on-chain."
)]
pub struct FillBlockRangeArgs {
    #[arg(long, required = true)]
    pub end_block: u32,
    #[arg(long, default_value = "false")]
    pub post: bool,
}

pub struct BlockRangeData {
    pub start_blocks: Vec<u32>,
    pub end_blocks: Vec<u32>,
    pub header_hashes: Vec<[u8; 32]>,
    pub data_root_commitments: Vec<[u8; 32]>,
    pub state_root_commitments: Vec<[u8; 32]>,
    pub end_authority_set_id: u64,
    pub end_authority_set_hash: [u8; 32],
}

async fn get_block_range_data(start_block: u32, end_block: u32) -> BlockRangeData {
    let mut input_data_fetcher = RpcDataFetcher::new().await;

    let mut start_blocks = Vec::new();
    let mut end_blocks = Vec::new();
    let mut header_hashes = Vec::new();
    let mut data_root_commitments = Vec::new();
    let mut state_root_commitments = Vec::new();

    for i in (start_block..end_block).step_by(256) {
        let block_range_end = min(i + 256, end_block);
        let header = input_data_fetcher.get_header(block_range_end).await;
        let (state_root_commitment, data_root_commitment) = input_data_fetcher
            .get_merkle_root_commitments(i, block_range_end)
            .await;
        start_blocks.push(i);
        end_blocks.push(block_range_end);
        header_hashes.push(header.hash().as_bytes().try_into().unwrap());
        data_root_commitments.push(data_root_commitment.try_into().unwrap());
        state_root_commitments.push(state_root_commitment.try_into().unwrap());
    }
    let end_authority_set_id = input_data_fetcher.get_authority_set_id(end_block).await;
    let end_authority_set_hash = input_data_fetcher
        .compute_authority_set_hash(end_block)
        .await;
    BlockRangeData {
        start_blocks,
        end_blocks,
        header_hashes,
        data_root_commitments,
        state_root_commitments,
        end_authority_set_id,
        end_authority_set_hash: end_authority_set_hash.0,
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let args = FillBlockRangeArgs::parse();
    info!("Args: {:?}", args);

    let end_block = args.end_block;

    let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");

    let address = contract_address
        .parse::<Address>()
        .expect("invalid address");

    let ethereum_rpc_url = env::var("ETHEREUM_RPC_URL").expect("ETHEREUM_RPC_URL must be set");

    let private_key =
        env::var("PRIVATE_KEY").unwrap_or(String::from("0x00000000000000000000000000000000"));
    let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
    let wallet = LocalWallet::from_str(&private_key).expect("invalid private key");
    let wallet = wallet.with_chain_id(chain_id.parse::<u64>().unwrap());

    let provider =
        Provider::<Http>::try_from(ethereum_rpc_url).expect("could not connect to client");
    let client = Arc::new(SignerMiddleware::new(provider.clone(), wallet.clone()));

    let contract = VectorX::new(address.0 .0, client);

    let latest_block = contract.latest_block().await.unwrap();

    let block_range_data = get_block_range_data(latest_block, end_block).await;

    if args.post {
        let tx: Option<TransactionReceipt> = contract
            .update_block_range_data(
                block_range_data.start_blocks,
                block_range_data.end_blocks,
                block_range_data.header_hashes,
                block_range_data.data_root_commitments,
                block_range_data.state_root_commitments,
                block_range_data.end_authority_set_id,
                block_range_data.end_authority_set_hash,
            )
            .send()
            .await
            .unwrap()
            .await
            .unwrap();
        if let Some(tx) = tx {
            info!(
                "Proof relayed successfully! Transaction Hash: {:?}",
                tx.transaction_hash
            );
        }
    } else {
        // If we don't want to post the data on-chain, we can just print the data that would be posted.
        let update_block_range_call = vector_x::UpdateBlockRangeDataCall {
            start_blocks: block_range_data.start_blocks,
            end_blocks: block_range_data.end_blocks,
            header_hashes: block_range_data.header_hashes,
            data_root_commitments: block_range_data.data_root_commitments,
            state_root_commitments: block_range_data.state_root_commitments,
            end_authority_set_id: block_range_data.end_authority_set_id,
            end_authority_set_hash: block_range_data.end_authority_set_hash,
        };
        let calldata = update_block_range_call.encode();
        info!(
            "Calldata for update block range call:\n {:?}",
            hex::encode(calldata)
        );
    }
}
