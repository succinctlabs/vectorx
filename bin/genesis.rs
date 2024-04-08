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
    #[arg(long)]
    pub block: Option<u32>,
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let mut fetcher = RpcDataFetcher::new().await;

    let args = GenesisArgs::parse();

    let header;
    if let Some(block) = args.block {
        header = fetcher.get_header(block).await;
    } else {
        header = fetcher.get_head().await;
    }
    let header_hash = header.hash();
    let authority_set_id = fetcher.get_authority_set_id(header.number).await;
    let authority_set_hash = fetcher.compute_authority_set_hash(header.number).await;

    info!(
        "\nGENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nGENESIS_AUTHORITY_SET_ID={}\nGENESIS_AUTHORITY_SET_HASH={}\n",
        header.number,
        format!("{:#x}", header_hash),
        authority_set_id,
        format!("{:#x}", authority_set_hash)
    );
}
