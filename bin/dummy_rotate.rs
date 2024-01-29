//! To build the binary:
//!
//!     `cargo build --release --bin dummy_rotate`
//!
//!
//!
//!
//!

use rustx::function::RustFunction;
use vectorx::dummy_rotate::DummyRotate;

fn main() {
    DummyRotate::entrypoint();
}
