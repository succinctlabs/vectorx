//! To build the binary:
//!
//!     `cargo build --release --bin dummy_step`
//!
//!
//!
//!
//!

use circuits::dummy_step::DummyStep;
use rustx::function::RustFunction;

fn main() {
    DummyStep::entrypoint();
}
