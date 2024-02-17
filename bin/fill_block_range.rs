use alloy_primitives::Address;
use clap::Parser;
use ethers::abi::AbiEncode;
use ethers::middleware::SignerMiddleware;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::TransactionReceipt;
use log::info;

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

// Methods to query the subgraph and get the data to be posted on-chain.
// Here's the example subgraph query:
// {
// blocks(orderBy: TIMESTAMP_ASC, filter:{number:{greaterThan:410800 ,lessThanOrEqualTo:411000}}) {
//     nodes {
//       number
//       stateRoot
//       hash
//       headerExtensions {
//         nodes {
//           commitments {
//             nodes {
//               dataRoot
//             }
//           }
//         }
//       }
//     }
//   }
// }

#[derive(serde::Deserialize, Clone)]
struct SubgraphResponse {
    data: Blocks,
}

#[derive(serde::Deserialize, Clone)]
struct Blocks {
    blocks: Block,
}

#[derive(serde::Deserialize, Clone)]
struct Block {
    nodes: Vec<SubgraphBlock>,
}

#[derive(serde::Deserialize, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct SubgraphBlock {
    number: u32,
    stateRoot: String,
    hash: String,
    headerExtensions: HeaderExtensions,
}
#[derive(serde::Deserialize, Clone)]
struct HeaderExtensions {
    nodes: Vec<HeaderExtension>,
}
#[derive(serde::Deserialize, Clone)]
struct HeaderExtension {
    commitments: Commitments,
}
#[derive(serde::Deserialize, Clone)]
struct Commitments {
    nodes: Vec<Commitment>,
}
#[derive(serde::Deserialize, Clone)]
#[allow(non_snake_case)]
struct Commitment {
    dataRoot: String,
}

async fn query_subgraph(start_block: u32, end_block: u32) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let query = format!(
        r#"{{
        blocks(orderBy: TIMESTAMP_ASC, filter:{{number:{{greaterThan:{}, lessThanOrEqualTo:{}}}}}) {{
            nodes {{
            number
            stateRoot
            hash
            headerExtensions {{
                nodes {{
                commitments {{
                    nodes {{
                    dataRoot
                    }}
                }}
                }}
            }}
            }}
        }}
        }}"#,
        start_block, end_block
    );
    let url = "https://subquery.goldberg.avail.tools/";
    let response = reqwest::Client::new()
        .post(url)
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await
        .unwrap();
    let response: SubgraphResponse = response.json().await.unwrap();

    let mut data_roots = Vec::new();
    let mut state_roots = Vec::new();
    let mut header_hashes = Vec::new();
    response
        .data
        .blocks
        .nodes
        .clone()
        .into_iter()
        .for_each(|block| {
            // Strip 0x prefix (if present) from stateRoot, hash and dataRoot
            let (state_root, hash, data_root) = (
                block.stateRoot.trim_start_matches("0x"),
                block.hash.trim_start_matches("0x"),
                block.headerExtensions.nodes[0].commitments.nodes[0]
                    .dataRoot
                    .trim_start_matches("0x"),
            );

            header_hashes.push(hex::decode(hash).unwrap());
            state_roots.push(hex::decode(state_root).unwrap());
            data_roots.push(hex::decode(data_root).unwrap());
        });

    let data_root_commitment = vectorx::input::RpcDataFetcher::get_merkle_root(data_roots);
    let state_root_commitment = vectorx::input::RpcDataFetcher::get_merkle_root(state_roots);
    let header_hash = header_hashes[header_hashes.len() - 1].clone();
    (
        data_root_commitment.try_into().unwrap(),
        state_root_commitment.try_into().unwrap(),
        header_hash.try_into().unwrap(),
    )
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
        let (data_root_commitment, state_root_commitment, header) =
            query_subgraph(i, block_range_end).await;
        start_blocks.push(i);
        end_blocks.push(block_range_end);
        header_hashes.push(header);
        data_root_commitments.push(data_root_commitment);
        state_root_commitments.push(state_root_commitment);
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
