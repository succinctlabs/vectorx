use avail_subxt::build_client;
use codec::Decode;
use pallet_grandpa::{VersionedAuthorityList, AuthorityList};

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";
    let c = build_client(url, false).await.unwrap();

    let head_block_hash = c
    .rpc()
    .finalized_head()
    .await
    .unwrap();

    let head_block = c.rpc().block(Some(head_block_hash)).await.unwrap().unwrap().block;
    println!("Finalized head block num: {:?}", head_block.header.number);
    println!("Finalized head block hash: {:?}", head_block_hash);

    let grandpa_authorities_bytes = c.storage().at(None).await.unwrap().fetch_raw(b":grandpa_authorities").await.unwrap().unwrap();
    let grandpa_authorities = VersionedAuthorityList::decode(&mut grandpa_authorities_bytes.as_slice()).unwrap();

    let authority_list:AuthorityList = grandpa_authorities.into();

    println!("num authorities: {:?}", authority_list.len());
    for authority in authority_list.iter() {
        println!("\tauthority: {:?}", authority.0);
    }
}