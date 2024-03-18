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
    DummyHeaderRange::entrypoint();
}
