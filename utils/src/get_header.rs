use avail_subxt::{build_client};
use codec::Encode;
use subxt::ext::sp_core::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://testnet.avail.tools:443/ws";    

    let c = build_client(url).await.unwrap();

    let block_hash_vec = hex::decode("b71429ef80257a25358e386e4ca1debe72c38ea69d833e23416a4225fabb1a78").unwrap();
    let mut block_hash_array: [u8; 32] = [0; 32];
    for i in 0..block_hash_vec.len() {
        block_hash_array[i] = block_hash_vec[i];
    }
    let block_hash = Some(H256(block_hash_array));

    let header = c
    .rpc()
    .header(block_hash)
    .await
    .unwrap()
    .unwrap();

    println!("header: {:?}\n\n\n", header);
    println!("encoded header: {:?}", header.encode());
}