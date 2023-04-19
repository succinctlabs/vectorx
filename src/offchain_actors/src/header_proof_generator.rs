use std::{net::{IpAddr, Ipv6Addr}, time::{SystemTime, Duration}};

use avail_subxt::primitives::Header;
use avail_subxt::build_client;
use codec::Encode;

use service::ProofGeneratorClient;


use subxt::{
	ext::{
		sp_core::{blake2_256, H256},
	},
    rpc::RpcParams,
};
use tarpc::{client, context};
use tarpc::tokio_serde::formats::Json;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let server_addr = (IpAddr::V6(Ipv6Addr::LOCALHOST), 52356);

    let mut transport = tarpc::serde_transport::tcp::connect(server_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);
    let client = ProofGeneratorClient::new(client::Config::default(), transport.await?).spawn();

    let url: &str = "wss://testnet.avail.tools:443/ws";
    let c = build_client(url).await.unwrap();
    let t = c.rpc();
    let sub: Result<subxt::rpc::Subscription<Header>, subxt::Error> = t
        .subscribe(
            "chain_subscribeFinalizedHeads",
            RpcParams::new(),
            "chain_unsubscribeFinalizedHeads",
        )
        .await;

    let mut sub = sub.unwrap();
    let mut previous_block_hash = None;

    // Wait for headers
    while let Some(Ok(header)) = sub.next().await {
        let block_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
        println!("got a header with number {:?} and hash {:?}", header.number, block_hash);

        if !previous_block_hash.is_none() {
            let encoded_header = header.encode();
            let mut context = context::current();
            context.deadline = SystemTime::now() + Duration::from_secs(600);

            let res = client.generate_header_proof(context, previous_block_hash.unwrap(), block_hash, encoded_header.clone()).await;
        
            match res {
                Ok(_) => println!("Retrieved header validation for block: number - {:?}; hash - {:?}", header.number, block_hash),
                Err(e) => println!("{:?}", anyhow::Error::from(e)),
            }
        }

        println!("\n\n\n");

        previous_block_hash = Some(block_hash);
    }

    Ok(())
}
