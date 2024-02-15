//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

use circuits::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS};
use circuits::step::StepCircuit;
use plonky2x::backend::function::Plonky2xFunction;

fn main() {
    StepCircuit::<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>::entrypoint();
}
