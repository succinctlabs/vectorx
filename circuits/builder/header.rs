use async_trait::async_trait;
use codec::Encode;
use log::debug;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, PlonkParameters, U32Variable, ValueStream,
};
use serde::{Deserialize, Serialize};

use crate::consts::BLAKE2B_CHUNK_SIZE_BYTES;
use crate::input::RpcDataFetcher;
use crate::vars::*;

pub trait HeaderMethods {
    /// Get the Blake2b hash of an encoded header.
    fn hash_encoded_header<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> HeaderMethods for CircuitBuilder<L, D> {
    fn hash_encoded_header<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
    ) -> Bytes32Variable {
        assert!(MAX_CHUNK_SIZE * BLAKE2B_CHUNK_SIZE_BYTES == MAX_HEADER_SIZE);
        self.curta_blake2b_variable(header.header_bytes.as_slice(), header.header_size)
    }
}

// Fetch a range of headers with a hint. Used to generate a data commitment for step.
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

        // Pad `headers` to the correct length for `EncodedHeader` variables.
        let mut header_variables = Vec::new();
        for (i, header) in headers.iter().enumerate() {
            let mut header_bytes = header.encode();
            let header_size = header_bytes.len();
            if header_size > HEADER_LENGTH {
                panic!(
                    "Block {}'s header size is {}, which is greater than the maximum header size of {} bytes.",
                    start_block + i as u32,
                    header_size,
                    HEADER_LENGTH
                );
            }
            header_bytes.resize(HEADER_LENGTH, 0);
            let header_variable = EncodedHeader {
                header_bytes,
                header_size: header_size as u32,
            };
            header_variables.push(header_variable);
        }

        // Pad `header_variables` with empty headers to ensure its length is NUM_HEADERS.
        for _i in headers.len()..NUM_HEADERS {
            let header_variable = EncodedHeader {
                header_bytes: vec![0u8; HEADER_LENGTH],
                header_size: 0u32,
            };
            header_variables.push(header_variable);
        }
        output_stream
            .write_value::<ArrayVariable<EncodedHeaderVariable<HEADER_LENGTH>, NUM_HEADERS>>(
                header_variables,
            );
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use avail_subxt::config::Header;
    use codec::Encode;
    use ethers::types::H256;
    use plonky2x::frontend::vars::{ByteVariable, U32Variable};
    use plonky2x::prelude::{ArrayVariable, Bytes32Variable, DefaultBuilder, GoldilocksField};
    use sp_core::{Blake2Hasher, Hasher};

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

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_hash_output_check() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const HEAD_BLOCK_NUM: u32 = 397857;
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

        for (i, expected_hash) in expected_block_hashes[0..NUM_HEADERS].iter().enumerate() {
            let calculated_hash = output.read::<Bytes32Variable>();
            assert_eq!(
                calculated_hash,
                *expected_hash,
                "Hashes do not match for block: {:?}",
                HEAD_BLOCK_NUM + i as u32
            );
        }
    }

    // @kevin TODO: This is failing because of the incorrect computation of the header hash.
    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_blake2b_correctness() {
        // TODO: Failing block.
        let block_nbr = 397859;

        let mut data_fetcher = RpcDataFetcher::new().await;
        let header = data_fetcher.get_header(block_nbr).await;
        let header_bytes = header.encode();
        // println!("Header bytes: {:?}", hex::encode(&header_bytes));
        let header_size = header_bytes.len();
        println!("Header size: {:?}", header_size);

        println!("Header size mod 64: {:?}", header_size % 64);

        // Confirm the header hash computed by Avail is correct (i.e. matches the Blake2B hash of the
        // encoded bytes.
        // Hash the encoded bytes.
        let expected_hash = Blake2Hasher::hash(&header_bytes);
        // Hash from the header.
        let actual_hash = header.hash();
        assert_eq!(
            expected_hash, actual_hash,
            "Avail's actual header hash is incorrect! Doesn't match the computed Blake2B hash."
        );

        // For fixed blake2b, set a constant that is equal to the expected header size.
        const FAILING_HEADER_SIZE: usize = 15360;
        assert_eq!(
            header_size, FAILING_HEADER_SIZE,
            "Header size is not equal to the expected fixed size of {} bytes.",
            FAILING_HEADER_SIZE
        );

        // Confirm that the header hash computed by the circuit is correct. NOTE: IT IS CURRENTLY WRONG.
        let mut builder = DefaultBuilder::new();
        let var_header = builder.read::<ArrayVariable<ByteVariable, FAILING_HEADER_SIZE>>();
        let input_length = builder.constant::<U32Variable>(FAILING_HEADER_SIZE as u32);
        let calculated_hash = builder.curta_blake2b_variable(var_header.as_slice(), input_length);
        builder.write::<Bytes32Variable>(calculated_hash);
        let circuit = builder.build();
        let mut input = circuit.input();
        input.write::<ArrayVariable<ByteVariable, FAILING_HEADER_SIZE>>(header_bytes);
        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
        let calculated_hash = output.read::<Bytes32Variable>();

        assert_eq!(
            expected_hash.0,
            calculated_hash.0,
            "Header hash calculated by circuit is incorrect! Expected: {:?}, Calculated: {:?}",
            hex::encode(expected_hash.0),
            hex::encode(calculated_hash.0)
        );
    }
}
