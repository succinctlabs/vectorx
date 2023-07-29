use avail_subxt::{build_client};
use codec::Encode;
use primitive_types::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";  

    let c = build_client(url, false).await.unwrap();

    let block_hash_vec = hex::decode("1a3c929ec4479c7911c8acaeb4f140ed14499cfa49e7720c686f608f30934a1f").unwrap();
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
    println!("encoded header: {:?}", header.encode().len());
}