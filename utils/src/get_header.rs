use avail_subxt::build_client;
use codec::Encode;
use primitive_types::H256;
use subxt::config::Header as XtHeader;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, false).await.unwrap();

    let num_blocks = 21;
    let mut block_hash_iter: String =
        "c63e6b7db7863b35b289b35349a8a488ae886a59c37d4825577ddb9470c4537f".to_string();
    let mut block_hashes = Vec::new();
    let mut parent_hashes = Vec::new();
    let mut state_roots = Vec::new();
    let mut data_roots = Vec::new();
    let mut encoded_blocks = Vec::new();

    for _ in 0..num_blocks {
        let block_hash_vec = hex::decode(block_hash_iter).unwrap();
        let block_hash_array: [u8; 32] = block_hash_vec.as_slice().try_into().unwrap();
        let block_hash = Some(H256(block_hash_array));

        let header = c.rpc().header(block_hash).await.unwrap().unwrap();

        encoded_blocks.push(hex::encode(header.encode()));
        block_hashes.push(header.clone().hash());
        parent_hashes.push(header.clone().parent_hash);
        state_roots.push(header.clone().state_root);
        data_roots.push(header.clone().data_root());

        block_hash_iter = hex::encode(header.parent_hash);
    }

    block_hashes.reverse();
    let block_hashes_str = block_hashes
        .iter()
        .map(|x| hex::encode(x.as_bytes()))
        .collect::<Vec<String>>();
    println!("block hashes");
    println!("{:?}", block_hashes_str);

    parent_hashes.reverse();
    let parent_hashes_str = parent_hashes
        .iter()
        .map(|x| hex::encode(x.as_bytes()))
        .collect::<Vec<String>>();
    println!("parent hashes");
    println!("{:?}", parent_hashes_str);

    state_roots.reverse();
    let state_roots_str = state_roots
        .iter()
        .map(|x| hex::encode(x.as_bytes()))
        .collect::<Vec<String>>();
    println!("state roots");
    println!("{:?}", state_roots_str);

    data_roots.reverse();
    let data_roots_str = data_roots
        .iter()
        .map(|x| hex::encode(x.as_bytes()))
        .collect::<Vec<String>>();
    println!("data roots");
    println!("{:?}", data_roots_str);

    encoded_blocks.reverse();
    println!("encoded blocks");
    println!("{:?}", encoded_blocks);

}
