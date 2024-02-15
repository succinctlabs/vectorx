use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use ethers::abi::AbiEncode;
use ethers::utils::keccak256;
use log::info;
use primitive_types::H256;
use serde::Deserialize;
use vectorx::input::RpcDataFetcher;

#[allow(non_snake_case)]
#[derive(Deserialize)]
struct VectorXQuery {
    chainName: String,
    contractChainId: u64,
    contractAddress: String,
    blockNumber: Option<u32>,
    blockRoot: Option<String>,
}

async fn handle_vectorx_query(info: web::Query<VectorXQuery>) -> impl Responder {
    let mut fetcher = RpcDataFetcher::new().await;

    // Either blockNumber or blockRoot must be provided
    if info.blockNumber.is_none() && info.blockRoot.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Either blockNumber or blockRoot must be provided"
        }));
    }
    // If blockNumber is provided, fetch blockRoot
    let block_hash;
    let block_nb;
    if let Some(requested_block) = info.blockNumber {
        let requested_block_hash = fetcher.get_block_hash(requested_block).await;
        if requested_block_hash.is_none() {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Block not found"
            }));
        }
        block_hash = requested_block_hash.unwrap();
        block_nb = requested_block;
    } else {
        let supplied_block_hash =
            H256::from_slice(&hex::decode(info.blockRoot.clone().unwrap()).unwrap());

        let fetched_block = fetcher.get_block_number(supplied_block_hash).await;
        if let Some(block_number) = fetched_block {
            block_nb = block_number;
            block_hash = supplied_block_hash;
        } else {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Block not found"
            }));
        }
    }
    info!("Fetching commitment for block {}", block_nb);

    let key = format!("{}:{}:ranges", info.contractChainId, info.contractAddress);
    // Convert key to lowercase
    let key = key.to_lowercase();

    let (start_block, end_block, commitment) = fetcher
        .redis_client
        .get_commitment_with_block(&key, block_nb)
        .await;

    // Index of the block's data hash in the data commitment merkle tree.
    let index = block_nb - start_block - 1;

    // Get the data roots for the range of blocks.
    let headers = fetcher
        .get_block_headers_range(start_block + 1, end_block)
        .await;
    let mut data_roots = headers
        .iter()
        .map(|header| header.data_root().as_bytes().to_vec())
        .collect::<Vec<Vec<u8>>>();

    // Extend the data roots to MAX_NUM_HEADERS.
    data_roots.resize(vectorx::consts::MAX_NUM_HEADERS, vec![0u8; 32]);

    // Compute the merkle root of the data roots, and confirm that it matches the commitment.
    let computed_data_commitment =
        vectorx::input::RpcDataFetcher::get_merkle_root(data_roots.clone());

    // Assert the computed data commitment matches the commitment.
    let commitment_match = computed_data_commitment == commitment;
    if !commitment_match {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Data commitment mismatch"
        }));
    }

    // Get the merkle branch from the data commitment merkle tree.
    let merkle_branch =
        vectorx::input::RpcDataFetcher::get_merkle_branch(data_roots.clone(), index as usize);

    // Confirm the merkle branch is valid.
    let is_valid_branch = vectorx::input::RpcDataFetcher::verify_merkle_branch(
        commitment.clone(),
        data_roots.clone()[index as usize].clone(),
        merkle_branch.clone(),
        index as usize,
    );
    if !is_valid_branch {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid merkle branch"
        }));
    }

    // Get the range hash. keccak256(abi.encode(startBlock, endBlock))
    // Encode the start and end block numbers as big-endian bytes.

    let start_block_bytes = start_block.encode();
    let end_block_bytes = end_block.encode();

    let range_hash = keccak256([start_block_bytes, end_block_bytes].concat());

    let range_hash = format!("0x{}", hex::encode(range_hash));
    let data_commitment = format!("0x{}", hex::encode(commitment));

    HttpResponse::Ok().json(serde_json::json!({
        "blockNumber": block_nb,
        "blockHash": format!("0x{}", hex::encode(block_hash)),
        "rangeHash": range_hash,
        "dataCommitment": data_commitment,
        "merkleBranch": merkle_branch.iter().map(|x| format!("0x{}", hex::encode(x))).collect::<Vec<String>>(),
        "index": index,
        "dataRoot": format!("0x{}", hex::encode(data_roots[index as usize].clone())),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().route(
            "/api/integrations/vectorx",
            web::get().to(handle_vectorx_query),
        )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
