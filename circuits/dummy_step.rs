use alloy_sol_types::{sol, SolType};
use rustx::program::Program;
use subxt::config::Header;

use crate::input::RpcDataFetcher;

/// The tuple which encodes a VectorX Rotate request from the EVM.
type StepRequestTuple = sol! { tuple(uint32, bytes32, uint64, bytes32, uint32) };

#[derive(Debug, Clone)]
struct DummyStep;
impl Program for DummyStep {
    fn run(input_bytes: Vec<u8>) -> Vec<u8> {
        // Decode the input bytes into the request tuple.
        let (
            trusted_block,
            trusted_header_hash,
            authority_set_id,
            authority_set_hash,
            target_block,
        ) = StepRequestTuple::abi_decode_sequence(&input_bytes, true).unwrap();

        // Initialize tokio runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result: (Vec<u8>, Vec<u8>, Vec<u8>) = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            let target_header_hash = data_fetcher
                .get_header(target_block)
                .await
                .hash()
                .0
                .to_vec();

            let (data_merkle_root, state_merkle_root) = data_fetcher
                .get_merkle_root_commitments(trusted_block, target_block)
                .await;

            (target_header_hash, data_merkle_root, state_merkle_root)
        });

        // Encode the result tuple into bytes by concatenating the fields.
        result
            .0
            .into_iter()
            .chain(result.1)
            .chain(result.2)
            .collect()
    }
}
