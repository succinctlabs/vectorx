use avail_subxt::build_client;
use avail_subxt::config::substrate::DigestItem;
use codec::Encode;
use primitive_types::H256;
use subxt::config::Header as XtHeader;

#[tokio::main]
pub async fn main() {
    let url: &str = "wss://kate.avail.tools:443/ws";

    let c = build_client(url, false).await.unwrap();

    let num_blocks = 1;
    let mut block_hash_iter: String =
        "c63e6b7db7863b35b289b35349a8a488ae886a59c37d4825577ddb9470c4537f".to_string();
    // let mut block_hashes = Vec::new();
    // let mut parent_hashes = Vec::new();
    // let mut state_roots = Vec::new();
    // let mut data_roots = Vec::new();
    // let mut encoded_blocks = Vec::new();

    for _ in 0..num_blocks {
        let block_hash_vec = hex::decode(block_hash_iter.clone()).unwrap();
        let block_hash_array: [u8; 32] = block_hash_vec.as_slice().try_into().unwrap();
        let block_hash = Some(H256(block_hash_array));

        let header = c.rpc().header(block_hash).await.unwrap().unwrap();
        let header_cloned = header.clone();

        println!(
            "parent_hash: {:?}",
            hex::encode(header_cloned.clone().parent_hash.as_bytes())
        );
        println!(
            "state_root: {:?}",
            hex::encode(header_cloned.clone().state_root.as_bytes())
        );
        println!(
            "extrinsics_root: {:?}",
            hex::encode(header_cloned.clone().extrinsics_root.as_bytes())
        );
        // println!("{:?}", header.digest);
        // println!("{:?}", header.digest.logs[0]);
        // println!("{:?}", header.digest.logs[1]);
        // println!("{:?}", header.digest.logs[2]);
        // println!("{:?}", header.digest.logs[3]);
        println!("{:?}", header.digest.encode().len());
        for log in header_cloned.digest.logs {
            match log {
                DigestItem::PreRuntime(pre_runtime, v) => {
                    println!("pre_runtime");
                    println!("{:?}", hex::encode(pre_runtime));
                    println!("{:?}", hex::encode(v));
                }
                DigestItem::Consensus(consensus_id, value) => {
                    println!("consensus");
                    println!("{:?}", hex::encode(consensus_id));
                    println!("{:?}", hex::encode(value));
                }
                DigestItem::Seal(seal, v) => {
                    println!("seal");
                    println!("{:?}", hex::encode(seal));
                    println!("{:?}", hex::encode(v));
                }
                DigestItem::Other(other) => {
                    println!("other");
                    println!("{:?}", hex::encode(other));
                }
                DigestItem::RuntimeEnvironmentUpdated => {
                    println!("runtime_environment_updated");
                }
            }
        }

        println!("{:?}", hex::encode(header.encode()));
        // encoded_blocks.push(hex::encode(header_cloned.encode()));
        // block_hashes.push(header_cloned.clone().hash());

        // state_roots.push(header_cloned.clone().state_root);
        // data_roots.push(header_cloned.clone().data_root());

        // block_hash_iter = hex::encode(header_cloned.parent_hash);
    }

    return;
    // block_hashes.reverse();
    // let block_hashes_str = block_hashes
    //     .iter()
    //     .map(|x| hex::encode(x.as_bytes()))
    //     .collect::<Vec<String>>();
    // println!("block hashes");
    // println!("{:?}", block_hashes_str);

    // parent_hashes.reverse();
    // let parent_hashes_str = parent_hashes
    //     .iter()
    //     .map(|x| hex::encode(x.as_bytes()))
    //     .collect::<Vec<String>>();
    // println!("parent hashes");
    // println!("{:?}", parent_hashes_str);

    // state_roots.reverse();
    // let state_roots_str = state_roots
    //     .iter()
    //     .map(|x| hex::encode(x.as_bytes()))
    //     .collect::<Vec<String>>();
    // println!("state roots");
    // println!("{:?}", state_roots_str);

    // data_roots.reverse();
    // let data_roots_str = data_roots
    //     .iter()
    //     .map(|x| hex::encode(x.as_bytes()))
    //     .collect::<Vec<String>>();
    // println!("data roots");
    // println!("{:?}", data_roots_str);

    // encoded_blocks.reverse();
    // println!("encoded blocks");
    // println!("{:?}", encoded_blocks);
}
