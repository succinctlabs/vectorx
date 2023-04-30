use avail_subxt::{build_client};
use subxt::ext::sp_core::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://testnet.avail.tools:443/ws";    

    let c = build_client(url).await.unwrap();

    let block_hash_vec = hex::decode("bab8d5e1645fffdf50622ccc461f8b620d33ee30bb47ba6a81eaccda0cc737ec").unwrap();
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

    println!("header: {:?}", header);
}