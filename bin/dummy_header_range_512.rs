//! To build the binary:
//!
//!     `cargo build --release --bin dummy_header_range`
//!
//!
//!
//!
//!

use rustx::function::RustFunction;
use vectorx::dummy_header_range::DummyHeaderRange;

fn main() {
    const HEADER_RANGE_COMMITMENT_TREE_SIZE: usize = 512;
    DummyHeaderRange::<HEADER_RANGE_COMMITMENT_TREE_SIZE>::entrypoint();
}
