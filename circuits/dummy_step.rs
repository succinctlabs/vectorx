use rustx::program::Program;
use subxt::config::Header;

use crate::input::RpcDataFetcher;

#[derive(Debug, Clone)]
pub struct DummyStep;
impl Program for DummyStep {
    fn run(input_bytes: Vec<u8>) -> Vec<u8> {
        // First 4 bytes are the trusted block number.
        // Next 32 bytes are the trusted header hash.
        // Next 8 bytes are the authority set id.
        // Next 32 bytes are the authority set hash.
        // Next 4 bytes are the target block number.
        let trusted_block = u32::from_be_bytes(input_bytes[0..4].try_into().unwrap());
        let _trusted_header_hash = input_bytes[4..36].to_vec();
        let _authority_set_id = u64::from_be_bytes(input_bytes[36..44].try_into().unwrap());
        let _authority_set_hash = input_bytes[44..76].to_vec();
        let target_block = u32::from_be_bytes(input_bytes[76..80].try_into().unwrap());

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

#[cfg(test)]
mod tests {
    use rustx::program::Program;

    use crate::dummy_step::DummyStep;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_dummy_step() {
        // Assert that the encoding matches.
        let input = "0003c18695f303b01e4834da35e5fdc3971fe297d1b48feb0c3f330491639136a6ada5980000000000000075f2da06eb7ec36f683d2908648c431a1b3f968fa5212b72cc7e8eddce8b80958d0003c23a";
        let input_bytes = hex::decode(input).unwrap();

        // Compute the output.
        let output = DummyStep::run(input_bytes);

        let expected_output =
            hex::decode("3aaa82535ce715acb251047c280d5492d1330c41fe24c9841db508ba961dce464cb5c2a82cc64e401ac01ba85c471fe1dab4fe4baf7a96c306d4e94dcb428f47ead156d58c77adfa928845f048b50fd92e871776dfa76ed2f98c6ef823aa7a2d")
                .unwrap();
        assert_eq!(output, expected_output);
    }
}
