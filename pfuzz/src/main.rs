
mod observer;
mod scheduler;
mod fuzzer;
mod cfgbuilder;
mod calibrate;
mod hooks;
mod forkfuzzer;

#[macro_use]
#[doc(hidden)]
pub extern crate alloc;

// Re-export derive(SerdeAny)
#[cfg(feature = "libafl_derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate libafl_derive;
#[cfg(feature = "libafl_derive")]
#[doc(hidden)]
pub use libafl_derive::*;

fn main() {
    forkfuzzer::fuzz_main();
}
