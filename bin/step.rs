//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

use plonky2x::backend::function::Plonky2xFunction;
use vectorx::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS};
use vectorx::step::StepCircuit;

fn main() {
    StepCircuit::<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>::entrypoint();
}
