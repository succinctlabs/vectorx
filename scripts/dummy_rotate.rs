//! To build the binary:
//!
//!     `cargo build --release --bin dummy_rotate`
//!
//!
//!
//!
//!

use circuits::dummy_rotate::DummyRotate;
use rustx::function::RustFunction;

fn main() {
    DummyRotate::entrypoint();
}
