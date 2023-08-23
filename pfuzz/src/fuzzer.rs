use libafl::bolts::cli;
use libafl::corpus::ondisk::{OnDiskCorpus, OnDiskMetadataFormat};
use libafl::Error;
use libafl::prelude::{BytesInput, Input};
use libafl_qemu::{self, ArchExtras};
use std::env;
use std::path::Path;
use libafl_qemu::elf::EasyElf;

use crate::main;

pub fn pfuzz() {

}

pub fn coverage_fuzz() -> Result<(), Error>{
    // parse the following:
    //   solutions dir
    //   input corpus dirs
    //   cores
    //   timeout
    //   verbosity
    //   broker port
    //   stdout file
    //   token files
    let mut fuzzer_options = cli::parse_args();
    //
    // Component: Corpus
    //

    // path to input corpus directory
    let corpus_dirs = fuzzer_options.input.as_slice();
    // corpus that will be evolved in memory, during fuzzing; metadata saved in json
    /*let input_corpus = OnDiskCorpus::with_meta_format(
        fuzzer_options.output.join("queue"),
        OnDiskMetadataFormat::JsonPretty,
    )?;*/

    // corpus in which we store solutions on disk so we can get them after stopping the fuzzer
    //let solutions_corpus = OnDiskCorpus::new(fuzzer_options.output)?;

    //
    // Component: Emulator
    //
    env::remove_var("LD_LIBRARY_PATH");

    let mut env: Vec<(String, String)> = env::vars().collect();

    // create an Emulator which provides the methods necessary to interact with the emulated target
    let emu = libafl_qemu::init_with_asan(&mut fuzzer_options.qemu_args, &mut env)?;

    // load our fuzz target from disk, the resulting `EasyElf` is used to do symbol lookups on the
    // binary. It handles address resolution in the case of PIE as well.
    let mut buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut buffer)?;


    // find the function of interest from the loaded elf. since we're not interested in parsing
    // command line stuff every time, we'll run until main, and then set our entrypoint to be past
    // the getopt stuff by adding a static offset found by looking at the disassembly. This is the
    // same concept as using AFL_ENTRYPOINT.
    let main_ptr = elf.resolve_symbol("main", emu.load_addr()).unwrap();

    emu.set_breakpoint(main_ptr);
    unsafe {emu.run()}

    emu.remove_breakpoint(main_ptr);
    let mut args = fuzzer_options.qemu_args.as_slice()[3..].to_vec();
    let arg_len = args.len();
    let mut harness = |input: &BytesInput| {
        let input_name = input.generate_name(0);
        let file_path = Path::new(&input_name);
        input.to_file(&file_path);
        let mut args = args.clone();
        args[arg_len-1] = input_name;
        emu.write_function_argument(libafl_qemu::CallingConvention::Cdecl, 1, args.as_ptr() as u64);
    };

    for arg in &fuzzer_options.qemu_args {
        println!("{arg}");
    }

    Ok(())
}