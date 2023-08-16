use std::{path::Path, fs, process::{Command, Stdio}, env, collections::HashMap};
use libafl_cc::{cfg, HasWeight, ControlFlowGraph};
use libafl_qemu::{Emulator, elf::EasyElf};
use std::error::Error;


mod cfgbuilder;
mod fuzzer;


fn main() {
    fuzzer::fuzz();
}
