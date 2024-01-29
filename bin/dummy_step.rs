//! To build the binary:
//!
//!     `cargo build --release --bin dummy_step`
//!
//!
//!
//!
//!

use rustx::function::RustFunction;
use vectorx::dummy_step::DummyStep;

fn main() {
    DummyStep::entrypoint();
}
