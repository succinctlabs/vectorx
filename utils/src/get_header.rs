use avail_subxt::build_client;
use codec::Encode;
use primitive_types::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws"; 

    let c = build_client(url, false).await.unwrap();

    let block_hash_vec = hex::decode("c63e6b7db7863b35b289b35349a8a488ae886a59c37d4825577ddb9470c4537f").unwrap();
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