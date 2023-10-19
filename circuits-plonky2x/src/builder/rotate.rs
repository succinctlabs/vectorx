use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, U32Variable,
    ValueStream,
};

use super::decoder::DecodingMethods;
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
