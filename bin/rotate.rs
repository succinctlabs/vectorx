//! To build the binary:
//!
//!     `cargo build --release --bin rotate`
//!
//!
//!
//!
//!

use plonky2x::backend::function::Plonky2xFunction;
use vectorx::consts::{
    DELAY_LENGTH, MAX_AUTHORITY_SET_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE, VALIDATOR_LENGTH,
};
use vectorx::rotate::RotateCircuit;

fn main() {
    // The maximum size of the subarray is the max length of the encoded
    // authorities + the delay length.
    const MAX_SUBARRAY_SIZE: usize = MAX_AUTHORITY_SET_SIZE * VALIDATOR_LENGTH + DELAY_LENGTH;

    RotateCircuit::<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_SIZE,
        MAX_HEADER_CHUNK_SIZE,
        MAX_SUBARRAY_SIZE,
    >::entrypoint();
}
