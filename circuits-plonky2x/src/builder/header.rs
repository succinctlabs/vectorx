use async_trait::async_trait;
use codec::Encode;
use log::debug;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, U32Variable,
    ValueStream,
};
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
        self.curta_blake2b_variable::<MAX_CHUNK_SIZE>(
            header.header_bytes.as_slice(),
            header.header_size,
        )
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
            .try_into()
            .unwrap()
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
                let data_fetcher = RpcDataFetcher::new().await;
                data_fetcher
                    .get_block_headers_range(start_block, last_block)
                    .await
            });
        }

        // We take the returned headers and pad them to the correct length to turn them into an `EncodedHeader` variable.
        let mut header_variables = Vec::new();
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
                header_size: L::Field::from_canonical_usize(header_size),
            };
            header_variables.push(header_variable);
        }

        // We must pad the rest of `header_variables` with empty headers to ensure its length is NUM_HEADERS.
        for _i in headers.len()..NUM_HEADERS {
            let header_variable = EncodedHeader {
                header_bytes: vec![0u8; HEADER_LENGTH],
                header_size: L::Field::from_canonical_usize(0),
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

    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, DefaultBuilder, Field, GoldilocksField,
    };
    use plonky2x::utils::{bytes, bytes32};

    use crate::builder::header::HeaderMethods;
    use crate::consts::{MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE};
    use crate::testing_utils::tests::{BLOCK_HASHES, ENCODED_HEADERS};
    use crate::vars::{EncodedHeader, EncodedHeaderVariable};

    #[test]
    fn test_hash_blocks() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        type F = GoldilocksField;

        const NUM_HEADERS: usize = 16;

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
        let encoded_headers_values: Vec<EncodedHeader<MAX_HEADER_SIZE, F>> = ENCODED_HEADERS
            [0..NUM_HEADERS]
            .iter()
            .map(|x| {
                let mut header: Vec<u8> = bytes!(x);
                let header_len = header.len();
                header.resize(MAX_HEADER_SIZE, 0);
                EncodedHeader {
                    header_bytes: header.as_slice().try_into().unwrap(),
                    header_size: F::from_canonical_u64(header_len as u64),
                }
            })
            .collect::<_>();

        input.write::<ArrayVariable<EncodedHeaderVariable<MAX_HEADER_SIZE>, NUM_HEADERS>>(
            encoded_headers_values,
        );

        let (proof, mut output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        for expected_hash in BLOCK_HASHES[0..NUM_HEADERS].iter() {
            let calculated_hash = output.read::<Bytes32Variable>();
            assert_eq!(calculated_hash, bytes32!(expected_hash));
        }
    }
}
