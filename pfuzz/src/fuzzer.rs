//! A libfuzzer-like fuzzer using qemu for binary-only coverage
//!
use core::{ptr::addr_of_mut, time::Duration};
use std::{
    env, 
    path::{PathBuf, Path}, 
    process,
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::fd::{AsRawFd, FromRawFd},
    cell::RefCell, str::FromStr, 
};

use crate::{cfgbuilder::Program, scheduler::{DistanceMinimizerScheduler, StdDistancePowerMutationalStage, DistancePowerScheduler}, calibrate::CalibrationStage, observer::{distance_map_mut,MAX_DYNAMIC_DISTANCE_MAP_SIZE, DYNAMIC_DISTANCE_MAP_PTR, INTER_DISTANCE_MAP_PTR}, hooks::{QemuDistanceCoverageHelper, QemuDistanceCoverageChildHelper}};

use clap::{builder::Str, Parser};
use goblin::elf64::header::ET_DYN;
use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::tuple_list,
        AsSlice,
        AsMutSlice
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
    state::{HasCorpus, StdState, HasMetadata},
    prelude::{current_time, SimpleMonitor, StdMOptMutator, SimpleRestartingEventManager, StdPowerMutationalStage, tokens_mutations, Merge, I2SRandReplace, InMemoryOnDiskCorpus, MinMapFeedback, ConstMapObserver, tui::{TuiMonitor, ui::TuiUI}, Input, dup2, ShadowTracingStage, Tokens, ShadowExecutor},
    Error, feedback_and_fast,
};
use libafl_qemu::{
    drcov::QemuDrCovHelper,
    edges::{edges_map_mut_slice, QemuEdgeCoverageHelper, QemuEdgeCoverageChildHelper, MAX_EDGES_NUM, EDGES_MAP_SIZE, EDGES_MAP_PTR},
    elf::EasyElf,
    emu::Emulator,
    ArchExtras, CallingConvention, GuestAddr, GuestReg, MmapPerms, QemuExecutor, QemuHooks,
    QemuForkExecutor,
    QemuInstrumentationFilter, Regs,
    QemuAsanHelper,
    asan::QemuAsanOptions,
    cmplog::{QemuCmpLogChildHelper, CmpLogObserver, CmpLogMap},
};

#[cfg(unix)]
use nix::{self, unistd::dup};

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

    #[clap(short, long, help = "Enable output from the fuzzer clients")]
    test_main: bool,

    #[arg(last = true, help = "Arguments passed to the target")]
    args: Vec<String>,
}

impl FuzzerOptions {
    fn parse_timeout(src: &str) -> Result<Duration, Error> {
        Ok(Duration::from_millis(src.parse()?))
    }
}

pub fn preprocess(binary: &str, load_addr: Option<GuestAddr>) -> Result<(), String>{
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
            let caller_block = match caller_func.get_basic_block_mut(caller_block_addr) {
                Some(block) => block,
                _ => { 
                    caller_func.add_basic_block(caller_block_addr);
                    caller_func.get_basic_block_mut(caller_block_addr).unwrap()
                }
            };
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

    match preprocess(emu.binary_path(), if elf.goblin().header.e_type == ET_DYN {Some(emu.load_addr())}else{None}){
        Ok(_) => {},
        Err(err) => {
            panic!("{err}");
        }
    }

    if options.test_main {
        fuzz_main(emu, corpus_dirs[0].clone(), corpus_dirs[0].clone(), output_dir.clone()).unwrap();
        return; 
    }

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
        let mut buf = target.as_slice();
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }
        let len = len as GuestReg;
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
        let coverage_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
        
        let distance_observer = DistanceMapObserver::new(ConstMapObserver::<_,MAX_DYNAMIC_DISTANCE_MAP_SIZE>::new("distances", distance_map_mut()));
        let distance_feedback = MinMapFeedback::tracking(&distance_observer, true, false);
        
    
        let calibration = CalibrationStage::new(&distance_feedback);
        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            coverage_feedback,
            distance_feedback
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = CrashFeedback::new();

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

        let power_scheduler = PowerQueueScheduler::new(&mut state, &distance_observer, PowerSchedule::FAST);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler = DistanceMinimizerScheduler::new(DistancePowerScheduler::new(&mut state, "distances", power_scheduler));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut hooks = QemuHooks::new(
            &emu,
            tuple_list!(
                QemuDistanceCoverageHelper::default(),
                QemuAsanHelper::new(QemuInstrumentationFilter::None, QemuAsanOptions::None),
            ),
        );

        // Create a QEMU in-process executor
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(distance_observer, edges_observer, time_observer),
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
        let power = StdDistancePowerMutationalStage::new(mutator);
        
        let mut stages = tuple_list!(calibration, power);

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    //let tui = TuiUI::new("Distance Fuzzing".to_string(), true);
    //let monitor = TuiMonitor::new(tui);
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
        .stderr_file(Some("./err_file.txt"))
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}

fn fuzz_main(emu: Emulator, corpus_dir: PathBuf, seed_dir: PathBuf, out_dir: PathBuf) -> Result<(), Error> {

    let mut elf_buffer = Vec::new();
    let elf = EasyElf::from_file(emu.binary_path(), &mut elf_buffer)?;

    let main_ptr = elf
        .resolve_symbol("main", emu.load_addr())
        .expect("Symbol main not found");
    println!("main @ {main_ptr:#x}");

    emu.set_breakpoint(main_ptr); // LLVMFuzzerTestOneInput
    unsafe { emu.run() };

    println!("Break at {:#x}", emu.read_reg::<_, u32>(Regs::Pc).unwrap());

    let stack_ptr: u32 = emu.read_reg(Regs::Sp).unwrap();
    let mut ret_addr = [0; 4];
    unsafe { emu.read_mem(stack_ptr, &mut ret_addr) };
    let ret_addr = u32::from_le_bytes(ret_addr);

    println!("Stack pointer = {stack_ptr:#x}");
    println!("Return address = {ret_addr:#x}");

    emu.remove_breakpoint(main_ptr); // LLVMFuzzerTestOneInput
    emu.set_breakpoint(ret_addr); // LLVMFuzzerTestOneInput ret addr

    let input_addr = emu.map_private(0, 4096, MmapPerms::ReadWrite).unwrap();
    println!("Placing input at {input_addr:#x}");

    let log = RefCell::new(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open("./log.txt")?,
    );

    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::with_user_monitor(
        |s| {
            #[cfg(unix)]
            writeln!(&mut stdout_cpy, "{s}").unwrap();
            #[cfg(windows)]
            println!("{s}");
            writeln!(log.borrow_mut(), "{:?} {s}", current_time()).unwrap();
        },
        true,
    );

    let mut shmem_provider = StdShMemProvider::new()?;

    let mut edges_shmem = shmem_provider.new_shmem(EDGES_MAP_SIZE).unwrap();
    let edges = edges_shmem.as_mut_slice();
    unsafe { EDGES_MAP_PTR = edges.as_mut_ptr() };

    let mut dynamic_distance_shem = shmem_provider.new_shmem(MAX_DYNAMIC_DISTANCE_MAP_SIZE * std::mem::size_of::<f64>()).unwrap();
    let dynamic_distances = dynamic_distance_shem.as_mut_slice();
    unsafe {DYNAMIC_DISTANCE_MAP_PTR = dynamic_distances.as_mut_ptr() as *mut f64};
    let dynamic_distances = distance_map_mut();

    let mut inter_distance_shem = shmem_provider.new_shmem(MAX_DYNAMIC_DISTANCE_MAP_SIZE * std::mem::size_of::<f64>()).unwrap();
    let inter_distances = inter_distance_shem.as_mut_slice();
    unsafe {INTER_DISTANCE_MAP_PTR = inter_distances.as_mut_ptr() as *mut f64};

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {err}");
            }
        },
    };

    // Create an observation channel using the coverage map
    let edges_observer = unsafe {
        HitcountsMapObserver::new(ConstMapObserver::<_, EDGES_MAP_SIZE>::from_mut_ptr(
            "edges",
            edges.as_mut_ptr(),
        ))
    };

    let distance_observer = unsafe {
        DistanceMapObserver::new(ConstMapObserver::<_, MAX_DYNAMIC_DISTANCE_MAP_SIZE>::from_mut_ptr("distances", dynamic_distances.as_mut_ptr()))
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let coverage_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);

    let distance_feedback = MinMapFeedback::tracking(&distance_observer, true, false);

    let calibration = CalibrationStage::new(&distance_feedback);
    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        coverage_feedback,
        distance_feedback
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(corpus_dir.clone()).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(out_dir.clone()).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    let power_scheduler = PowerQueueScheduler::new(&mut state, &distance_observer, PowerSchedule::FAST);
    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = DistanceMinimizerScheduler::new(DistancePowerScheduler::new(&mut state, "distances", power_scheduler));


    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut hooks = QemuHooks::new(
        &emu,
        tuple_list!(
            QemuDistanceCoverageChildHelper::default(),
            QemuAsanHelper::new(QemuInstrumentationFilter::None, QemuAsanOptions::None),
        ),
    );

    let input_file = std::path::Path::new("./infile.txt");
    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        //let target = input.target_bytes();
        input.to_file(&input_file);
        /*let mut buf = target.as_slice();
        
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }*/

        unsafe {
            //emu.write_mem(input_addr, buf);

            //emu.write_reg(Regs::Rdi, input_addr).unwrap();
            //emu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
            emu.write_reg(Regs::Pc, main_ptr).unwrap();
            emu.write_reg(Regs::Sp, stack_ptr).unwrap();

            emu.run();
        }

        ExitKind::Ok
    };

    let mut executor = QemuForkExecutor::new(
        &mut hooks,
        &mut harness,
        tuple_list!(edges_observer, distance_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
    )?;

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk at {:?}.", state.corpus().count(), & seed_dir);
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let power = StdDistancePowerMutationalStage::new(mutator);

    let mut stages = tuple_list!(calibration, power);

    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }
    // reopen file to make sure we're at the end
    log.replace(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open("./log.txt")?,
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    Ok(())
}


/* 
fn fuzz_main() -> Result<(), Error> {


    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::with_seed(current_nanos()),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });

    // Setup a randomic Input2State stage
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    // Setup a MOPT mutator
    let mutator = StdMOptMutator::new(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power = StdPowerMutationalStage::new(mutator);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(
        &mut state,
        &edges_observer,
        PowerSchedule::FAST,
    ));

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
    let input_file = std::path::Path::new("./infile.txt");
    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        //let target = input.target_bytes();
        input.to_file(&input_file);
        /*let mut buf = target.as_slice();
        
        let mut len = buf.len();
        if len > 4096 {
            buf = &buf[0..4096];
            len = 4096;
        }*/

        unsafe {
            //emu.write_mem(input_addr, buf);

            //emu.write_reg(Regs::Rdi, input_addr).unwrap();
            //emu.write_reg(Regs::Rsi, len as GuestReg).unwrap();
            emu.write_reg(Regs::Pc, main_ptr).unwrap();
            emu.write_reg(Regs::Sp, stack_ptr).unwrap();

            emu.run();
        }

        ExitKind::Ok
    };

    let mut hooks = QemuHooks::new(
        &emu,
        tuple_list!(
            QemuEdgeCoverageChildHelper::default(),
            QemuCmpLogChildHelper::default(),
        ),
    );

    let executor = QemuForkExecutor::new(
        &mut hooks,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        shmem_provider,
    )?;

    // Show the cmplog observer
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    // Read tokens
    if let Some(tokenfile) = tokenfile {
        if state.metadata_map().get::<Tokens>().is_none() {
            state.add_metadata(Tokens::from_file(tokenfile)?);
        }
    }

    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    let tracing = ShadowTracingStage::new(&mut executor);

    // The order of the stages matter!
    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }
    // reopen file to make sure we're at the end
    log.replace(
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(&logfile)?,
    );

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");

    // Never reached
    Ok(())
}
*/