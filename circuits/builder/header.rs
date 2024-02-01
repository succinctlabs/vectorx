use async_trait::async_trait;
use codec::Encode;
use log::debug;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, PlonkParameters, U32Variable, ValueStream,
};
use primitive_types::H256;
use serde::{Deserialize, Serialize};

use crate::input::RpcDataFetcher;
use crate::vars::*;

pub trait HeaderMethods {
    /// Get the Blake2b hash of an encoded header.
    fn hash_encoded_header<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
    ) -> Bytes32Variable;

    /// Get the Blake2b hashes of an array of encoded headers.
    fn hash_encoded_headers<
        const MAX_HEADER_SIZE: usize,
        const MAX_CHUNK_SIZE: usize,
        const N: usize,
    >(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, N>,
    ) -> ArrayVariable<Bytes32Variable, N>;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<L: PlonkParameters<D>, const D: usize> HeaderMethods for CircuitBuilder<L, D> {
    fn hash_encoded_header<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
    ) -> Bytes32Variable {
        assert!(MAX_CHUNK_SIZE * 128 == MAX_HEADER_SIZE);
        self.curta_blake2b_variable(header.header_bytes.as_slice(), header.header_size)
    }

    fn hash_encoded_headers<
        const MAX_HEADER_SIZE: usize,
        const MAX_CHUNK_SIZE: usize,
        const N: usize,
    >(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, N>,
    ) -> ArrayVariable<Bytes32Variable, N> {
        assert!(MAX_CHUNK_SIZE * 128 == MAX_HEADER_SIZE);
        headers
            .as_vec()
            .iter()
            .map(|x| self.hash_encoded_header::<MAX_HEADER_SIZE, MAX_CHUNK_SIZE>(x))
            .collect::<Vec<Bytes32Variable>>()
            .into()
    }
}

// Fetch a range of headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRangeFetcherHint<const HEADER_LENGTH: usize, const NUM_HEADERS: usize> {}

#[async_trait]
impl<
        const HEADER_LENGTH: usize,
        const NUM_HEADERS: usize,
        L: PlonkParameters<D>,
        const D: usize,
    > AsyncHint<L, D> for HeaderRangeFetcherHint<HEADER_LENGTH, NUM_HEADERS>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let start_block = input_stream.read_value::<U32Variable>();
        let mut last_block = input_stream.read_value::<U32Variable>();
        let max_block = input_stream.read_value::<U32Variable>();

        last_block = last_block.min(max_block);

        debug!(
            "HeaderFetcherHint: downloading header range of start_block={}, last_block={}",
            start_block, last_block
        );

        let mut headers = Vec::new();
        if last_block >= start_block {
            headers.extend({
                let mut data_fetcher = RpcDataFetcher::new().await;
                data_fetcher
                    .get_block_headers_range(start_block, last_block)
                    .await
            });
        }

        // We take the returned headers and pad them to the correct length to turn them into an `EncodedHeader` variable.
        let mut header_variables = Vec::new();
        let mut data_roots = Vec::new();
        for header in headers.iter() {
            // TODO: replace with `to_header_variable` from vars.rs
            let mut header_bytes = header.encode();
            let header_size = header_bytes.len();
            if header_size > HEADER_LENGTH {
                panic!(
                    "header size {} is greater than HEADER_LENGTH {}",
                    header_size, HEADER_LENGTH
                );
            }
            header_bytes.resize(HEADER_LENGTH, 0);
            let header_variable = EncodedHeader {
                header_bytes,
                header_size: header_size as u32,
            };
            header_variables.push(header_variable);
            data_roots.push(H256::from_slice(&header.data_root().0));
        }

        // We must pad the rest of `header_variables` with empty headers to ensure its length is NUM_HEADERS.
        for _i in headers.len()..NUM_HEADERS {
            let header_variable = EncodedHeader {
                header_bytes: vec![0u8; HEADER_LENGTH],
                header_size: 0u32,
            };
            header_variables.push(header_variable);
            data_roots.push(H256::zero());
        }
        output_stream
            .write_value::<ArrayVariable<EncodedHeaderVariable<HEADER_LENGTH>, NUM_HEADERS>>(
                header_variables,
            );
        output_stream.write_value::<ArrayVariable<Bytes32Variable, NUM_HEADERS>>(data_roots);
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use avail_subxt::config::Header;
    use codec::Encode;
    use ethers::types::H256;
    use plonky2x::prelude::{ArrayVariable, Bytes32Variable, DefaultBuilder, GoldilocksField};

    use crate::builder::header::HeaderMethods;
    use crate::consts::{MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE};
    use crate::input::RpcDataFetcher;
    use crate::vars::{EncodedHeader, EncodedHeaderVariable};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_hash_headers() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const HEAD_BLOCK_NUM: u32 = 1000;
        const NUM_HEADERS: usize = 1;

        type F = GoldilocksField;

        let mut builder = DefaultBuilder::new();

        let headers =
            builder.read::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_HEADERS>>();

        for i in 0..NUM_HEADERS {
            let calculated_hash =
                builder.hash_encoded_header::<MAX_HEADER_SIZE, MAX_HEADER_CHUNK_SIZE>(&headers[i]);
            builder.write::<Bytes32Variable>(calculated_hash);
        }

        let circuit = builder.build();

        let mut input = circuit.input();

        let rt = tokio::runtime::Runtime::new().unwrap();
        // Note: Returns NUM_BLOCKS + 1 headers.
        let headers = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .get_block_headers_range(HEAD_BLOCK_NUM, HEAD_BLOCK_NUM + NUM_HEADERS as u32)
                .await
        });

        let encoded_headers_values: Vec<EncodedHeader<MAX_HEADER_SIZE, F>> = headers
            [0..NUM_HEADERS]
            .iter()
            .map(|x| {
                let mut header: Vec<u8> = x.encode();
                let header_len = header.len();
                header.resize(MAX_HEADER_SIZE, 0);
                EncodedHeader {
                    header_bytes: header.as_slice().into(),
                    header_size: header_len as u32,
                }
            })
            .collect::<_>();

        input.write::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_HEADERS>>(
            encoded_headers_values,
        );

        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        let expected_block_hashes = headers
            .iter()
            .map(|x| H256::from_slice(&x.hash().0))
            .collect::<Vec<H256>>();

        for expected_hash in expected_block_hashes[0..NUM_HEADERS].iter() {
            let calculated_hash = output.read::<Bytes32Variable>();
            assert_eq!(calculated_hash, *expected_hash);
        }
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_max_header_len() {
        const START_BLOCK_NUM: u32 = 452578;
        const NUM_BLOCKS: usize = 10;
        let rt = tokio::runtime::Runtime::new().unwrap();
        // Note: Returns NUM_BLOCKS + 1 headers.
        let headers = rt.block_on(async {
            let mut data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .get_block_headers_range(START_BLOCK_NUM, START_BLOCK_NUM + NUM_BLOCKS as u32)
                .await
        });

        let mut max_size = 0;
        for i in 0..headers.len() {
            let encoded_header = headers[i].encode();
            if encoded_header.len() > max_size {
                max_size = encoded_header.len();
            }
        }
        println!("Max header size: {:?}", max_size);
    }
}
