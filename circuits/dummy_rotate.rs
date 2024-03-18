use rustx::program::Program;

use crate::input::RpcDataFetcher;

#[derive(Debug, Clone)]
pub struct DummyRotate;
impl Program for DummyRotate {
    fn run(input_bytes: Vec<u8>) -> Vec<u8> {
        // Decode the input bytes into the request tuple.

        // First 8 bytes are the authority set id.
        // Next 32 bytes are the authority set hash.
        let authority_set_id = u64::from_be_bytes(input_bytes[0..8].try_into().unwrap());
        let _authority_set_hash = input_bytes[8..40].to_vec();

        // Initialize tokio runtime.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let new_authority_set_hash: Vec<u8> = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            let epoch_end_block_number = data_fetcher.last_justified_block(authority_set_id).await;
            data_fetcher
                .compute_authority_set_hash(epoch_end_block_number)
                .await
                .0
                .to_vec()
        });

        new_authority_set_hash
    }
}

#[cfg(test)]
mod tests {
    use rustx::program::Program;

    use crate::dummy_rotate::DummyRotate;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_dummy_rotate() {
        // Proof: https://alpha.succinct.xyz/explorer/a16e1261-7fc5-4642-b5f2-910a3fd11e70
        // Assert that the encoding matches.
        let input = "0000000000000075f2da06eb7ec36f683d2908648c431a1b3f968fa5212b72cc7e8eddce8b80958d0003c6f0";
        let input_bytes = hex::decode(input).unwrap();

        // Compute the output.
        let output = DummyRotate::run(input_bytes);

        // Assert that the output matches.
        let expected_output =
            hex::decode("21969829db96b6cc8171290a231a150fbf4b11911eea1edb7b1d785716797a7f")
                .unwrap();
        assert_eq!(output, expected_output);
    }
}
