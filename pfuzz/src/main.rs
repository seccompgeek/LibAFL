
mod observer;
mod scheduler;
mod fuzzer;

// Re-export derive(SerdeAny)
#[cfg(feature = "libafl_derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate libafl_derive;
#[cfg(feature = "libafl_derive")]
#[doc(hidden)]
pub use libafl_derive::*;

fn main() {
    fuzzer::coverage_fuzz();
}
