//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!

use std::env;

use vectorx::input::RpcDataFetcher;

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();
    let fetcher = RpcDataFetcher::new().await;

    let mut start_block = 10000;
    let mut valid_blocks = Vec::new();

    while start_block < 10400 {
        println!(
            "Fetching justification for blocks {} to {}...",
            start_block,
            start_block + 200
        );
        let mut futures = Vec::new();
        for block in start_block..start_block + 200 {
            futures.push(fetcher.get_justification_from_prove_finality_endpoint::<300>(block));
        }
        let results = futures::future::join_all(futures).await;

        for (i, result) in results.into_iter().enumerate() {
            if result.is_ok() {
                valid_blocks.push(start_block + i as u32);
            }
        }

        start_block += 200;
    }

    println!("Valid blocks: {:?}", valid_blocks);
}
