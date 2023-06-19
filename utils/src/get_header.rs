use avail_subxt::{build_client};
use codec::Encode;
use primitive_types::H256;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";    

    let c = build_client(url, true).await.unwrap();

    let mut header_roots = Vec::new();
    header_roots.push("79181c814463f2341f559565dc2d50cf8fe9b87b89e0b57633a038ccb6947e30");
    header_roots.push("74b8a2da62ccb34bbd8ed8ba9f6d92cb0d0f2ad797ddfcb8c61eeb7a0b7924d2");
    header_roots.push("7397858bbde385bc983581431b8b47d739f669e5e7c4a83059a4066e254030d6");
    header_roots.push("b2a810a97ff6b96a668695608fe44652baa47c025e7b7ac7ee239fb5996758b9");
    header_roots.push("8ddbc8eb36ede7321a07f6882f6ea75b6e8658af178a189b4381b23c4ec42bf1");
    header_roots.push("cb14a2f1b39bec5b4559cf366d7c3e581450f210e9d07326891e6061420e678c");
    header_roots.push("bb20339ac63dc54f38e556df2d764452492011f6414bd6ea0f850d61a58e970d");
    header_roots.push("b685610d5006059fdc2275bf3f77e1297791a219d33d99b491c93c7ff8f98f59");
    header_roots.push("1c8f7b27ca1091163cabc3cb8cc70ee9e0ea8745a3047414dd37f5d3f35b5f2a");
    header_roots.push("a14760fe417bb59be7ae1ade095e0cb1404ae89a3f25d625a0a1ccec419cb71d");
    header_roots.push("652e1cffd34170c7fc9cefd3d6b495cbb6c85c966832e120cd0c9ae04c49d03f");
    header_roots.push("a5e9d4f517806e0d760f5198b2b3828573ea08da0642c7e9b6f1bfbdeec0657f");
    header_roots.push("354ecc8f8b0da21bb5a0fdcd61b666b0af987ef02d07654d19348b1631170e8a");
    header_roots.push("092fdea4eb99c2956dec49c7b37828e9fbec54d44279ab49dd150102235a5bce");
    header_roots.push("92d0b8e0d47fe01e890381cb996608b42e1037182bc8b9add1bebef60ff72625");
    header_roots.push("2d86d0340fcaefe69d4eb9ae75253f4f4234fa21a3b0b2648ba98800a7f2b8a8");
    header_roots.push("fd5751b2ee68df6ba5c8976548052b4114e9c126a3ffc0789d409f7b6a65258c");
    header_roots.push("b6212ffe11c8b0b83f76f883baf407e171521c1352c33e6f4aefaa71d75cd2f5");

    let mut header_num = 34151;
    
    for header_root in header_roots.iter() {
        let block_hash_vec = hex::decode(*header_root).unwrap();
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

        println!("pub const BLOCK_{:?}_BLOCK_HASH: &str = {:?};", header_num, header_root);
        println!("pub const BLOCK_{:?}_HEADER: [u8; {:?}] = {:?};", header_num, header.encode().len(), header.encode());
        println!("pub const BLOCK_{:?}_PARENT_HASH: &str = \"{:?}\";", header_num, header.parent_hash);
        println!("pub const BLOCK_{:?}_STATE_ROOT: &str = \"{:?}\";", header_num, header.state_root);
        println!("\n");

        header_num -= 1;
    }
}