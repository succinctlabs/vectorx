//! To build the binary:
//!
//!     `cargo build --release --bin step`
//!
//!
//!
//!
//!

fn main() {
    const MAX_AUTHORITY_SET_SIZE: usize = 76;
    const MAX_HEADER_CHUNK_SIZE: usize = 100;
    const MAX_HEADER_LENGTH: usize = MAX_HEADER_CHUNK_SIZE * 128;
    // At most one epoch (one hour) of headers
    const MAX_NUM_HEADERS: usize = 180;
    VerifiableFunction::<StepCircuit<MAX_AUTHORITY_SET_SIZE, MAX_HEADER_LENGTH, MAX_NUM_HEADERS>>::entrypoint(
    );
}
