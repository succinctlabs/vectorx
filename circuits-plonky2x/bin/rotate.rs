//! To build the binary:
//!
//!     `cargo build --release --bin rotate`
//!
//!
//!
//!
//!

use avail_plonky2x::consts::{
    MAX_AUTHORITY_SET_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE, VALIDATOR_LENGTH,
};
use avail_plonky2x::rotate::RotateCircuit;
use plonky2x::backend::function::Plonky2xFunction;

fn main() {
    const MAX_SUBARRAY_SIZE: usize = (MAX_AUTHORITY_SET_SIZE + 1) * VALIDATOR_LENGTH;

    RotateCircuit::<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_SIZE,
        MAX_HEADER_CHUNK_SIZE,
        MAX_SUBARRAY_SIZE,
    >::entrypoint();
}
