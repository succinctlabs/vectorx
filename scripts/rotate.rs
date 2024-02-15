//! To build the binary:
//!
//!     `cargo build --release --bin rotate`
//!
//!
//!
//!
//!

use circuits::consts::{
    MAX_AUTHORITY_SET_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE, MAX_SUBARRAY_SIZE,
};
use circuits::rotate::RotateCircuit;
use plonky2x::backend::function::Plonky2xFunction;

fn main() {
    RotateCircuit::<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_SIZE,
        MAX_HEADER_CHUNK_SIZE,
        MAX_SUBARRAY_SIZE,
    >::entrypoint();
}
