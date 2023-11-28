//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use std::env;

use clap::Parser;
use log::info;
use subxt::config::Header;
use vectorx::input::RpcDataFetcher;

#[derive(Parser, Debug, Clone)]
#[command(about = "Compile a program.")]
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
    let authority_set_hash = fetcher.compute_authority_set_hash(genesis_block).await;
    info!("Block {}'s header hash: {:?}", genesis_block, header_hash);
    info!(
        "Block {}'s authority set hash: {:?}",
        genesis_block, authority_set_hash
    );
}
