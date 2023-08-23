use libafl::bolts::cli;
use libafl::corpus::ondisk::{OnDiskCorpus, OnDiskMetadataFormat};
use libafl::stages::StdMutationalStage;
use libafl::{Error, StdFuzzer, feedback_or, feedback_and_fast};
use libafl::prelude::{BytesInput, Input, VariableMapObserver, HitcountsMapObserver, TimeObserver, StdRand, Tokens, StdScheduledMutator, havoc_mutations, tokens_mutations, tuple_list, MultiMonitor, Launcher, StdShMemProvider, EventConfig, UsesInput};
use libafl::schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler};
use libafl::state::StdState;
use libafl_qemu::edges::{self, edges_map_mut_slice, MAX_EDGES_NUM};
use libafl_qemu::{self, ArchExtras, QemuHooks, QemuExecutor, QemuInstrumentationFilter, QemuAsanHelper, QemuHelper, Emulator};
use std::{env, process};
use std::path::Path;
use std::ptr::addr_of_mut;
use libafl_qemu::elf::EasyElf;
use libafl_qemu::asan::QemuAsanOptions;
use libafl::prelude::current_nanos;
use libafl::prelude::ShMemProvider;
use libafl::state::HasMetadata;
use libafl::executors::{ExitKind, TimeoutExecutor};
use libafl::state::HasCorpus;
use libafl::corpus::Corpus;
use libafl::feedbacks::{MaxMapFeedback, TimeFeedback, CrashFeedback};
use libafl::Fuzzer;
use libafl::prelude::Merge;

use crate::main;

pub fn pfuzz() {

}

/// wrapper around general purpose register resets, mimics AFL_QEMU_PERSISTENT_GPR
///   ref: https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md#24-resetting-the-register-state
#[derive(Default, Debug)]
struct QemuGPRegisterHelper {
    /// vector of values representing each registers saved value
    register_state: Vec<u64>,
}

/// implement the QemuHelper trait for QemuGPRegisterHelper
impl<UI> QemuHelper<UI> for QemuGPRegisterHelper
where
    UI: UsesInput<Input = BytesInput>,
{
    /// prepare helper for fuzz case; called before every fuzz case
    fn pre_exec(&mut self, emulator: &Emulator, _input: &<UI as UsesInput>::Input) {
        self.restore(emulator);
    }
}

/// QemuGPRegisterHelper implementation
impl QemuGPRegisterHelper {
    /// given an `Emulator`, save off all known register values
    fn new(emulator: &Emulator) -> Self {
        let register_state = (0..emulator.num_regs())
            .map(|reg_idx| emulator.read_reg(reg_idx).unwrap_or(0))
            .collect::<Vec<u64>>();

        Self { register_state }
    }

    /// restore emulator's registers to previously saved values
    fn restore(&self, emulator: &Emulator) {
        self.register_state
            .iter()
            .enumerate()
            .for_each(|(reg_idx, reg_val)| {
                if let Err(e) = emulator.write_reg(reg_idx as i32, *reg_val) {
                    println!(
                        "[ERR] Couldn't set register x{} ({}), skipping...",
                        reg_idx, e
                    )
                }
            })
    }
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
    let input_corpus = OnDiskCorpus::with_meta_format(
        fuzzer_options.output.join("queue"),
        OnDiskMetadataFormat::JsonPretty,
    )?;

    // corpus in which we store solutions on disk so we can get them after stopping the fuzzer
    let solutions_corpus = OnDiskCorpus::new(fuzzer_options.output)?;

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

    // point at which we want to stop execution, i.e. before return from main and before optind++
    let ret_addr = main_ptr + 0x33C;

    emu.set_breakpoint(main_ptr);
    unsafe {emu.run()}

    emu.remove_breakpoint(main_ptr);
    emu.set_breakpoint(ret_addr);

    let mut args = fuzzer_options.qemu_args.as_slice()[3..].to_vec();
    let arg_len = args.len();
    let mut harness = |_input: &BytesInput| {
        /*let mut input_name = "./solutions/files/".to_string();
        let input_file = input.generate_name(0);
        input_name.push_str(&input_file);
        let file_path = Path::new(&input_name);
        input.to_file(&file_path);
        let mut args = args.clone();
        args[arg_len-1] = input_name;
        emu.write_function_argument(libafl_qemu::CallingConvention::Cdecl, 1, args.as_ptr() as u64);
        */
        
        unsafe {emu.run();}

        ExitKind::Ok
    };

    let mut run_client = | state: Option<_>, mut mgr, _core_id | {
        //
        // Component: Observer
        //

        // Create an observation channel using the coverage map.
        //
        // the `libafl_qemu::edges` module re-exports the same `EDGES_MAP` and `MAX_EDGES_NUM`
        // from `libafl_targets`, meaning we're using the sancov backend for coverage
        let var_map_observer = unsafe {
            VariableMapObserver::from_mut_slice(
                "edges",
                edges_map_mut_slice(),
                addr_of_mut!(MAX_EDGES_NUM)
            )
        };
        let edges_observer = HitcountsMapObserver::new(var_map_observer);

        // Create an observation channel to keep track of the execution time and previous runtime
        let time_observer = TimeObserver::new("time");

        //
        // Component: Feedback
        //

        // A Feedback, in most cases, processes the information reported by one or more observers to
        // decide if the execution is interesting. This one is composed of two Feedbacks using a
        // logical OR.
        //
        // Due to the fact that TimeFeedback can never classify a testcase as interesting on its own,
        // we need to use it alongside some other Feedback that has the ability to perform said
        // classification. These two feedbacks are combined to create a boolean formula, i.e. if the
        // input triggered a new code path, OR, false.
        let mut feedback = feedback_or!(
            // New maximization map feedback (attempts to maximize the map contents) linked to the
            // edges observer and the feedback state. This one will track indexes, but will not track
            // novelties, i.e. new_tracking(... true, false).
            MaxMapFeedback::tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state, nor does it ever return true for
            // is_interesting, However, it does keep track of testcase execution time by way of its
            // TimeObserver
            TimeFeedback::with_observer(&time_observer)
        );

        // A feedback, when used as an Objective, determines if an input should be added to the
        // corpus or not. In the case below, we're saying that in order for a testcase's input to
        // be added to the corpus, it must:
        //
        //   1: be a crash
        //        AND
        //   2: have produced new edge coverage
        //
        // The feedback_and_fast macro combines the two feedbacks with a fast AND operation, which
        // means only enough feedback functions will be called to know whether or not the objective
        // has been met, i.e. short-circuiting logic.
        //
        // this is essentially the same crash deduplication strategy used by afl++
        let mut objective =
            feedback_and_fast!(CrashFeedback::new(), MaxMapFeedback::new(&edges_observer));

        //
        // Component: State
        //

        // Creates a new State, taking ownership of all of the individual components during fuzzing.
        //
        // On the initial pass, state will be None, and the `unwrap_or_else` will populate our
        // initial settings.
        //
        // On each successive execution, the state from the prior run that was saved
        // off in shared memory will be passed into the closure. The code below handles the
        // initial None value by providing a default StdState. After the first restart, we'll
        // simply unwrap the Some(StdState) passed in to the closure
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // random number generator with a time-based seed
                StdRand::with_seed(current_nanos()),
                // input corpus
                input_corpus.clone(),
                // solutions corpus
                solutions_corpus.clone(),
                &mut feedback,
                &mut objective,
            )
            .unwrap()
        });

        // populate tokens metadata from token files, if provided. Tokens are the LibAFL term for
        // what AFL et. al. call a Dictionary
        if state.metadata_map().get::<Tokens>().is_none() && !fuzzer_options.tokens.is_empty() {
            // metadata hasn't been populated with tokens yet, and we have token files that should
            // be read; populate the metadata from each token file
            let tokens = Tokens::new().add_from_files(&fuzzer_options.tokens)?;
            state.add_metadata(tokens);
        }

        let scheduler = IndexesLenTimeMinimizerScheduler::new(QueueScheduler::new());

        //
        // Component: Fuzzer
        //

        // A fuzzer with feedback, objectives, and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        //
        // Component: Executor
        //

        // the QemuHooks struct wraps the emulator and all the QemuHelpers we want to use during fuzzing
        let mut hooks = QemuHooks::new(
            &emu,
            tuple_list!(
                libafl_qemu::edges::QemuEdgeCoverageHelper::new(QemuInstrumentationFilter::None),
                QemuGPRegisterHelper::new(&emu),
                QemuAsanHelper::new(QemuInstrumentationFilter::None, QemuAsanOptions::None),
            ),
        );

        // Create an in-process executor backed by QEMU. The QemuExecutor wraps the
        // `InProcessExecutor`, all of the `QemuHelper`s and the `Emulator` (in addition to the
        // normal wrapped components). This gives us an executor that will execute a bunch of testcases
        // within the same process, eliminating a lot of the overhead associated with a fork/exec or
        // forkserver execution model.
        //
        // additionally, each of the helpers and the emulator will be accessible at other points
        // of execution, easing emulator/input interaction/modification
        let executor = QemuExecutor::new(
            &mut hooks,
            &mut harness,
            tuple_list!(edges_observer, time_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?;

        // wrap the `QemuExecutor` with a `TimeoutExecutor` that sets a timeout before each run
        let mut executor = TimeoutExecutor::new(executor, fuzzer_options.timeout);

        // In case the corpus is empty (i.e. on first run), load existing test cases from on-disk
        // corpus
        if state.corpus().count() < 1 {
            state
                .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                .unwrap_or_else(|_| {
                    println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                    process::exit(0);
                });
        }

        //
        // Component: Mutator
        //

        // Setup a havoc mutator and dictionary (token) mutator with a mutational stage
        let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

        //
        // Component: Stage
        //

        let mut stages = tuple_list!(StdMutationalStage::new(mutator));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };

    //
    // Component: Monitor
    //

    let monitor = MultiMonitor::new(|s| println!("{}", s));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .broker_port(fuzzer_options.broker_port)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&fuzzer_options.cores)
        //.stdout_file(Some(fuzzer_options.stdout.as_str()))
        .build()
        .launch()
    {
        Ok(()) => Ok(()),
        Err(Error::ShuttingDown) => {
            println!("Fuzzing stopped by user. Good bye.");
            Ok(())
        }
        Err(err) => panic!("Failed to run launcher: {:?}", err),
    }
}