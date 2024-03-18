//! To build the binary:
//!
//!     `cargo build --release --bin header_range`
//!
//!
//!
//!
//!

use plonky2x::backend::function::Plonky2xFunction;
use vectorx::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS};
use vectorx::header_range::HeaderRangeCircuit;

fn main() {
    HeaderRangeCircuit::<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>::entrypoint();
}
