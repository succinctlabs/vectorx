use std::{env, fs};

use async_trait::async_trait;
use avail_subxt::primitives::Header;
use avail_subxt::{build_client, AvailConfig};
use subxt::config::{Hasher, Header as SPHeader};
use subxt::rpc::types::BlockNumber;
use subxt::rpc::{RpcParams, Subscription};
use subxt::utils::H256;
use subxt::OnlineClient;

// use subxt::config::Header as XtHeader;

#[async_trait]
pub trait DataFetcher {
    // async fn get_block(&self, block_number: u32) -> Box<u32>;
    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header>;
}

pub async fn new_fetcher() -> Box<dyn DataFetcher> {
    let fixture_path = format!("../fixtures");
    if cfg!(test) {
        return Box::new(FixtureDataFetcher { fixture_path });
    } else {
        // let mut url = env::var(format!("RPC_{}", chain_id)).expect("RPC url not set in .env");
        let url = "wss://kate.avail.tools:443/ws".to_string();
        let client = build_client(url.as_str(), false).await.unwrap();
        return Box::new(RpcDataFetcher { client, save: None });
    }
    // TODO: if in a test, return the FixtureDataFetcher with a const fixture path "test/fixtures/{chain_id{"
    // else, read the RpcDataFetch with the env var "RPC_{chain_id}" url from the .env file and panic if the RPC url is not present
}

pub struct RpcDataFetcher {
    pub client: OnlineClient<AvailConfig>,
    pub save: Option<String>,
}

impl RpcDataFetcher {
    async fn get_block_hash(&self, block_number: u32) -> H256 {
        let block_hash = self
            .client
            .rpc()
            .block_hash(Some(block_number.into()))
            .await;
        block_hash.unwrap().unwrap()
    }
}

#[async_trait]
impl DataFetcher for RpcDataFetcher {
    // async fn get_block(&self, block_number: u32) -> Box<u32> {
    // let block_hash = self.get_block_hash(block_number).await;
    // let block_result = self.client.rpc().block(Some(block_hash)).await;
    // let block = block_result.unwrap().unwrap();
    // if let Some(save_path) = &self.save {
    //     let file_name = format!("{}/block_by_number/{}.json", save_path, block_number);
    //     fs::write(file_name, serde_json::to_string(&block).unwrap());
    // }
    // todo!();
    // }

    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        let mut headers = Vec::new();
        for block_number in start_block_number..end_block_number {
            let block_hash = self.get_block_hash(block_number).await;
            let header_result = self.client.rpc().header(Some(block_hash)).await;
            let header: Header = header_result.unwrap().unwrap();
            headers.push(header);
        }
        if let Some(save_path) = &self.save {
            let file_name = format!(
                "{}/block_range/{}_{}.json",
                save_path, start_block_number, end_block_number
            );
            fs::write(file_name, serde_json::to_string(&headers).unwrap());
        }
        headers
    }
}

pub struct FixtureDataFetcher {
    pub fixture_path: String,
}

#[async_trait]
impl DataFetcher for FixtureDataFetcher {
    // async fn get_block(&self, block_number: u32) -> Box<u32> {
    //     let file_name = format!(
    //         "{}/block_by_number/{}.json",
    //         self.fixture_path.as_str(),
    //         block_number.to_string().as_str()
    //     );
    //     let file_content = fs::read_to_string(file_name.as_str());
    //     let res = file_content.unwrap();
    //     // let v: SignedBlockResponse = serde_json::from_str(&res).expect("Failed to parse JSON");
    //     // let temp_block = v.result;
    //     // Box::new(temp_block)
    //     todo!();
    // }

    async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        let file_name = format!(
            "{}/block_range/{}_{}.json",
            self.fixture_path.as_str(),
            start_block_number.to_string().as_str(),
            end_block_number.to_string().as_str()
        );
        let file_content = fs::read_to_string(file_name.as_str());
        let res = file_content.unwrap();
        // let blocks: Vec<TempSignedBlock> =
        //     serde_json::from_str(&res).expect("Failed to parse JSON");
        todo!();
    }
}
