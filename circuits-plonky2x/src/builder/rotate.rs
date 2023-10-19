use async_trait::async_trait;
use codec::Encode;
use log::debug;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, U32Variable,
    ValueStream,
};
use serde::{Deserialize, Serialize};

use super::decoder::DecodingMethods;
use crate::input::RpcDataFetcher;
use crate::vars::*;

pub trait RotateMethods {
    fn rotate<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
    ) -> Bytes32Variable;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<L: PlonkParameters<D>, const D: usize> RotateMethods for CircuitBuilder<L, D> {
    fn rotate<const MAX_HEADER_SIZE: usize, const MAX_CHUNK_SIZE: usize>(
        &mut self,
        header: &EncodedHeaderVariable<MAX_HEADER_SIZE>,
        header_hash: &Bytes32Variable,
    ) -> Bytes32Variable {
        let header_variable = self.decode_header::<MAX_HEADER_SIZE>(header, header_hash);

        *header_hash
    }
}

// Fetch a single header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleHeaderFetcherHint<const HEADER_LENGTH: usize> {}

#[async_trait]
impl<const HEADER_LENGTH: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for SingleHeaderFetcherHint<HEADER_LENGTH>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let block_number = input_stream.read_value::<U32Variable>();

        debug!(
            "SingleHeaderFetcherHint: downloading header range of block={}",
            block_number
        );

        let data_fetcher = RpcDataFetcher::new().await;

        let header = data_fetcher.get_header(block_number).await;

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

        output_stream.write_value::<EncodedHeaderVariable<HEADER_LENGTH>>(header_variable);
    }
}
