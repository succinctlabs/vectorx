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
    MAX_AUTHORITY_SET_SIZE, MAX_HEADER_CHUNK_SIZE, MAX_HEADER_SIZE, MAX_SUBARRAY_SIZE,
};
use vectorx::rotate::RotateCircuit;

fn main() {
    RotateCircuit::<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_SIZE,
        MAX_HEADER_CHUNK_SIZE,
        MAX_SUBARRAY_SIZE,
    >::entrypoint();
}
