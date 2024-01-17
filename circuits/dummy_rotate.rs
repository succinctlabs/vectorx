use alloy_sol_types::{sol, SolType};
use rustx::program::Program;

use crate::input::RpcDataFetcher;

/// The tuple which encodes a VectorX Rotate request from the EVM.
type RotateRequestTuple = sol! { tuple(uint64, bytes32, uint32) };

#[derive(Debug, Clone)]
struct DummyRotate;
impl Program for DummyRotate {
    fn run(input_bytes: Vec<u8>) -> Vec<u8> {
        // Decode the input bytes into the request tuple.
        let (authority_set_id, authority_set_hash, epoch_end_block_number) =
            RotateRequestTuple::abi_decode_sequence(&input_bytes, true).unwrap();

        // Initialize tokio runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let new_authority_set_hash: Vec<u8> = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .compute_authority_set_hash(epoch_end_block_number)
                .await
                .0
                .to_vec()
        });

        new_authority_set_hash
    }
}
