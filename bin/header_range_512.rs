//! To build the binary:
//!
//!     `cargo build --release --bin header_range`
//!
//!
//!
//!
//!

use plonky2x::backend::function::Plonky2xFunction;
use vectorx::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE};
use vectorx::header_range::HeaderRangeCircuit;

fn main() {
    const HEADER_RANGE_COMMITMENT_TREE_SIZE: usize = 512;
    HeaderRangeCircuit::<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, HEADER_RANGE_COMMITMENT_TREE_SIZE>::entrypoint();
}
