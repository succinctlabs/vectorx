//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

use avail_plonky2x::consts::{MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS};
use avail_plonky2x::step::StepCircuit;
use plonky2x::backend::function::VerifiableFunction;

fn main() {
    VerifiableFunction::<StepCircuit<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_SIZE, MAX_NUM_HEADERS>>::entrypoint(
    );
}
