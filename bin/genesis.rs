//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use std::env;

use avail_subxt::config::Header;
use clap::Parser;
use log::info;
use vectorx::input::RpcDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long, default_value = "1")]
    pub block: u32,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let mut fetcher = RpcDataFetcher::new().await;

    let args = GenesisArgs::parse();

    let genesis_block = args.block;

    let header = fetcher.get_header(genesis_block).await;
    let header_hash = header.hash();
    let authority_set_id = fetcher.get_authority_set_id(genesis_block).await;
    let authority_set_hash = fetcher.compute_authority_set_hash(genesis_block).await;
    info!("Block {}'s header hash: {:?}", genesis_block, header_hash);
    info!(
        "Block {}'s authority set id: {:?}",
        genesis_block, authority_set_id
    );
    info!(
        "Block {}'s authority set hash: {:?}",
        genesis_block, authority_set_hash
    );
}
