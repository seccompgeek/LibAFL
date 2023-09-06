//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
use core::{ptr::addr_of_mut, time::Duration};
use std::{
    env, 
    path::{PathBuf, Path}, 
    process,
    fs,
    collections::HashMap
};

use crate::cfgbuilder::Program;

use clap::{builder::Str, Parser};
use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
    },
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{EventConfig, LlmpRestartingEventManager},
    executors::{ExitKind, TimeoutExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::{HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler, PowerQueueScheduler, powersched::PowerSchedule},
    stages::StdMutationalStage,
    state::{HasCorpus, StdState},
    prelude::{StdMOptMutator, StdPowerMutationalStage, tokens_mutations, Merge},
    Error,
};
use libafl_qemu::{
    drcov::QemuDrCovHelper,
    edges::{edges_map_mut_slice, QemuEdgeCoverageHelper, MAX_EDGES_NUM},
    elf::EasyElf,
    emu::Emulator,
    ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, QemuExecutor, QemuHooks,
    QemuInstrumentationFilter, Regs,
    QemuAsanHelper,
    asan::QemuAsanOptions
};
use crate::observer::DistanceMapObserver;


#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct FuzzerOptions {
    #[arg(long, help = "Input directory")]
    input: String,

    #[arg(long, help = "Output directory")]
    output: String,

    #[arg(long, help = "Timeout in milli-seconds", default_value = "1000", value_parser = FuzzerOptions::parse_timeout)]
    timeout: Duration,

    #[arg(long = "port", help = "Broker port", default_value_t = 1337_u16)]
    port: u16,

    #[arg(long, help = "Cpu cores to use", default_value = "all", value_parser = Cores::from_cmdline)]
    cores: Cores,

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    verbose: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }
}

fn preprocess(binary: &str, load_addr: Option<GuestAddr>) -> Result<(), String>{
    let binary_path = Path::new(binary);
    if !binary_path.exists() {
        panic!("Binary {binary} not found!");
    }
    let binary_ = binary_path.file_name()
                            .unwrap();
    let binary = binary_
                            .to_str()
                            .unwrap();

    let binary = binary.to_string();

    let mut cwd = std::env::current_dir().unwrap();
    let cwd_str = cwd.to_str().unwrap();
    let mut cwd_str = cwd_str.to_string();

    let targets = binary.to_string() + ".tgt";

    let binary_path = cwd_str.clone()+"/tmp/"+&binary;
    let targets_path = cwd_str.clone()+"/"+&targets;
    cwd_str.push_str("/tmp");
    let cwd = Path::new(&cwd_str);

    if !cwd.exists() {
        panic!("No tmp folder found!");
    }
    let _ = fs::copy(targets_path, cwd_str.clone()+"/"+&targets);


    std::env::set_current_dir(&cwd_str).expect("Unable to change working directory");



    let funcs_file = binary.clone() + ".funcs";
    let funcs_path = Path::new(funcs_file.as_str());
    if !funcs_path.exists() {
        panic!("No funcs file found!");
    }
    let lines = fs::read_to_string(&funcs_file).unwrap();
    let lines = lines.lines();
    let mut functions = Vec::new();

    let mut graph_string = "".to_string();

    let mut program = Program::new(&binary);

    let to_real_addr = |addr: usize, load_addr: Option<GuestAddr> | -> usize {
        match load_addr {
            Some(la) => {
                addr + la as usize
            }
            _ => addr
        }
    };

    for line in lines {
        let t: Vec<&str> = line.split(",").collect();
        let (addr, func_name) = (t[0],t[1]);
        let addr = addr.trim_start_matches("0x");
        let addr = to_real_addr(usize::from_str_radix(addr, 16).unwrap(), load_addr);
        let more = "$$".to_string()+func_name+"+"+addr.to_string().as_str()+"\n";
        program.add_function(addr, func_name);
        functions.push(func_name);
    }

    let cfgs = fs::read_dir(cwd_str.clone() + "/cfgs/").expect("Unable to read cfgs folder");

    for func in &functions {
        let path = cwd_str.clone()+"/cfgs/" + func;
        let cfg_path = Path::new(&path);
        let func_addr = *program.get_func_addr(func).unwrap();
        let function = program.get_func_mut(func_addr).unwrap();
        if cfg_path.exists() {
            let lines = fs::read_to_string(cfg_path).unwrap();
            let lines = lines.lines();
            let mut ids_map: HashMap<&str, &str> = HashMap::default();
            let mut edges_map: HashMap<&str, Vec<&str>> = HashMap::default();
            for line in lines {
                if line.contains(" -> ") {
                    let edge = line.find(" -> ").unwrap();
                    let from = line[0..edge].trim();
                    let to = line[edge+" -> ".len()..line.len()-1].trim();
                    let from_addr = to_real_addr(usize::from_str_radix(from, 10).unwrap(), load_addr);
                    let to_addr = to_real_addr(usize::from_str_radix(to, 10).unwrap(), load_addr);
                    function.add_basic_block(from_addr);
                    function.add_basic_block(to_addr);
                    let from_bb = function.get_basic_block_mut(from_addr).unwrap();
                    from_bb.add_successor(to_addr);
                }
            }
        }
    }

    let cg_path_str = cwd_str.clone()+"/"+binary.as_str()+".cg";
    let cg_path = Path::new(&cg_path_str);
    if cg_path.exists() {
        let calls_str = fs::read_to_string(cg_path).unwrap();
        let calls = calls_str.lines();
        for line in calls {
            let entries: Vec<&str> = line.split('(').collect();
            let caller_info: Vec<&str> = entries[1].trim_end_matches(")-").split(';').collect();
            let caller_name = caller_info[0];
            let callee_info: Vec<&str> = entries[2].trim_end_matches(")").split(';').collect();
            let callee_name = callee_info[0];
            let callee_addr = to_real_addr(usize::from_str_radix(callee_info[1].trim_start_matches("0x"), 16).unwrap(), load_addr);
            program.add_function(callee_addr, callee_name);

            let callee_addr = *program.get_func_addr(callee_name).unwrap();
            let caller_addr = *program.get_func_addr(caller_name).unwrap();
            let caller_func = program.get_func_mut(caller_addr).unwrap();
            let caller_block_addr = to_real_addr(usize::from_str_radix(caller_info[1].trim_start_matches("0x"), 16).unwrap(), load_addr);
            let caller_block = caller_func.get_basic_block_mut(caller_block_addr).unwrap();
            caller_block.add_call(callee_addr);
        }
    }

    let target_funcs_ps = cwd_str.clone()+"/"+&targets;
    let target_func_path = Path::new(&target_funcs_ps);
    if target_func_path.exists() {
        let lines = fs::read_to_string(target_func_path).unwrap();
        let lines = lines.lines();
        for line in lines {
            let splits: Vec<&str> = line.split(',').collect();
            let target_func_name = splits[0];
            let target_func_weight = splits[1].parse().unwrap();
            program.add_target_func(target_func_name, target_func_weight);
        }
    }

    program.compute_distances();

    let cwd_str = cwd_str.clone() + "/../";
    std::env::set_current_dir(cwd_str);

    return Ok(());

}

pub fn fuzz() {
    let mut options = FuzzerOptions::parse();

    let output_dir = PathBuf::from(options.output);
    let corpus_dirs = [PathBuf::from(options.input)];

    let program = env::args().next().unwrap();
    println!("Program: {program:}");

    options.args.insert(0, program);
    println!("ARGS: {:#?}", options.args);

    env::remove_var("LD_LIBRARY_PATH");
    let mut env: Vec<(String, String)> = env::vars().collect();
    let emu = libafl_qemu::init_with_asan(&mut options.args, &mut env).unwrap();

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer).unwrap();

    let test_one_input_ptr = elf
        .resolve_symbol("LLVMFuzzerTestOneInput", emu.load_addr())
        .expect("Symbol LLVMFuzzerTestOneInput not found");
    println!("LLVMFuzzerTestOneInput @ {test_one_input_ptr:#x}");

    emu.set_breakpoint(test_one_input_ptr);
    unsafe { emu.run() };

    for m in emu.mappings() {
        println!(
            "Mapping: 0x{:016x}-0x{:016x}, {}",
            m.start(),
            m.end(),
            m.path().unwrap_or("<EMPTY>")
        );
    }

    let pc: GuestReg = emu.read_reg(Regs::Pc).unwrap();
    println!("Break at {pc:#x}");

    let ret_addr: GuestAddr = emu.read_return_address().unwrap();
    println!("Return address = {ret_addr:#x}");

    emu.remove_breakpoint(test_one_input_ptr);
    emu.set_breakpoint(ret_addr);

    let input_addr = emu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {input_addr:#x}");

    let stack_ptr: GuestAddr = emu.read_reg(Regs::Sp).unwrap();

    let reset = |buf: &[u8], len: GuestReg| -> Result<(), String> {
        unsafe {
            emu.write_mem(input_addr, buf);
            emu.write_reg(Regs::Pc, test_one_input_ptr)?;
            emu.write_reg(Regs::Sp, stack_ptr)?;
            emu.write_return_address(ret_addr)?;
            emu.write_function_argument(CallingConvention::Cdecl, 0, input_addr)?;
            emu.write_function_argument(CallingConvention::Cdecl, 1, len)?;
            emu.run();
            Ok(())
        }
    };

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target
            .as_slice()
            .chunks(4096)
            .next()
            .expect("Failed to get chunk");
        let len = buf.len() as GuestReg;
        reset(buf, len).unwrap();
        ExitKind::Ok
    };

    let mut run_client = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
        // Create an observation channel using the coverage map
        let edges_observer = unsafe {
            HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM),
            ))
        };

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::FAST));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut hooks = QemuHooks::new(
            &emu,
            tuple_list!(
                QemuEdgeCoverageHelper::default(),
                QemuAsanHelper::new(QemuInstrumentationFilter::None, QemuAsanOptions::None),
            ),
        );

        let distance_observer = DistanceMapObserver::new(edges_observer);

        // Create a QEMU in-process executor
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(distance_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )
        .expect("Failed to create QemuExecutor");

        // Wrap the executor to keep track of the timeout
        let mut executor = TimeoutExecutor::new(executor, options.timeout);

        if state.must_load_initial_inputs() {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
            println!("We imported {} inputs from disk.", state.corpus().count());
        }

        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations());
        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(options.port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&options.cores)
        .stdout_file(Some("/dev/null"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
