//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
//! In this example, you will see the use of the `launcher` feature.
//! The `launcher` will spawn new processes for each cpu core.
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
use libafl::observers::CanTrack;
use libafl::HasMetadata;
use libafl_bolts::{
    current_nanos,
    impl_serdeany,
    os::dup2,
    rands::{Rand, StdRand},
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, NamedTuple},
    Named,
};

use clap::{Arg, Command};
use core::{num::NonZeroUsize, time::Duration};
#[cfg(unix)]
use nix::{self, unistd::dup};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    borrow::Cow,
    env,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
};

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId, InMemoryOnDiskCorpus, OnDiskCorpus, Testcase},
    events::SimpleRestartingEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{
        CrashFeedback, Feedback, MaxMapFeedback, NautilusChunksMetadata, NautilusFeedback,
        StateInitializer, TimeFeedback,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    generators::{NautilusContext, NautilusGenerator},
    inputs::{Input, NautilusInput},
    monitors::SimpleMonitor,
    mutators::{
        LogMutationMetadata, MutationResult, Mutator, MutatorsTuple, NautilusRandomMutator,
        NautilusRecursionMutator, NautilusSpliceMutator,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{IndexesLenTimeMinimizerScheduler, QueueScheduler},
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, HasExecutions, HasRand, HasStartTime, StdState},
    Error,
};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Lineage tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct MutationLog {
    pub names: Vec<Cow<'static, str>>,
    pub execs: u64,
    pub elapsed_ms: u64,
}
impl_serdeany!(MutationLog);

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ParentInfo {
    pub parent_id: Option<u64>,
    pub parent_file: Option<String>,
    pub execs: u64,
    pub elapsed_ms: u64,
}
impl_serdeany!(ParentInfo);

pub struct LineageMutator<MT> {
    name: Cow<'static, str>,
    mutations: MT,
    max_stack_pow: NonZeroUsize,
}

impl<MT: NamedTuple> LineageMutator<MT> {
    pub fn new(mutations: MT) -> Self {
        Self::with_max_stack_pow(mutations, 7)
    }

    pub fn with_max_stack_pow(mutations: MT, pow: usize) -> Self {
        Self {
            name: Cow::from(format!("LineageMutator[{}]", mutations.names().join(", "))),
            mutations,
            max_stack_pow: NonZeroUsize::new(pow).unwrap(),
        }
    }
}

impl<MT> Named for LineageMutator<MT> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<I, S, MT> Mutator<I, S> for LineageMutator<MT>
where
    S: HasRand + HasMetadata + HasExecutions + HasStartTime,
    MT: MutatorsTuple<I, S> + NamedTuple,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error> {
        let execs = *state.executions();
        let elapsed_ms = (libafl_bolts::current_time() - *state.start_time()).as_millis() as u64;

        if state.metadata_map().contains::<MutationLog>() {
            let log = state.metadata_map_mut().get_mut::<MutationLog>().unwrap();
            log.names.clear();
            log.execs = execs;
            log.elapsed_ms = elapsed_ms;
        } else {
            state.add_metadata(MutationLog { names: vec![], execs, elapsed_ms });
        }

        let num = 1 + state.rand_mut().below(self.max_stack_pow);
        let mutations_len =
            NonZeroUsize::new(self.mutations.len()).expect("mutations must be non-empty");
        let mut result = MutationResult::Skipped;

        for _ in 0..num {
            let idx = state.rand_mut().below(mutations_len);
            let outcome = self.mutations.get_and_mutate(idx.into(), state, input)?;
            if outcome == MutationResult::Mutated {
                result = MutationResult::Mutated;
                if let Some(name) = self.mutations.name(idx as usize) {
                    state
                        .metadata_map_mut()
                        .get_mut::<MutationLog>()
                        .unwrap()
                        .names
                        .push(name.clone());
                }
            }
        }
        Ok(result)
    }
}

pub struct LineageFeedback {
    name: Cow<'static, str>,
}

impl LineageFeedback {
    pub fn new() -> Self {
        Self { name: "LineageFeedback".into() }
    }
}

impl Named for LineageFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> StateInitializer<S> for LineageFeedback {}

impl<EM, OT, S> Feedback<EM, NautilusInput, OT, S> for LineageFeedback
where
    S: HasMetadata + HasCurrentCorpusId + HasCorpus + HasExecutions + HasStartTime,
{
    fn append_metadata(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<NautilusInput>,
    ) -> Result<(), Error> {
        if let Some(log) = state.metadata_map().get::<MutationLog>() {
            if !log.names.is_empty() {
                testcase.add_metadata(LogMutationMetadata::new(log.names.clone()));
            }
        }

        if let Some(parent_id) = state.current_corpus_id().ok().flatten() {
            let parent_file = state
                .corpus()
                .get(parent_id)
                .ok()
                .and_then(|tc| tc.borrow().filename().clone());

            let (execs, elapsed_ms) = state
                .metadata_map()
                .get::<MutationLog>()
                .map(|log| (log.execs, log.elapsed_ms))
                .unwrap_or_else(|| {
                    let execs = *state.executions();
                    let elapsed_ms =
                        (libafl_bolts::current_time() - *state.start_time()).as_millis() as u64;
                    (execs, elapsed_ms)
                });

            testcase.add_metadata(ParentInfo {
                parent_id: Some(usize::from(parent_id) as u64),
                parent_file,
                execs,
                elapsed_ms,
            });
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    //RegistryBuilder::register::<Tokens>();

    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AFLplusplus team")
        .about("LibAFL-based fuzzer for Fuzzbench")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("report")
                .short('r')
                .long("report")
                .help("The directory to place dumped testcases ('corpus')"),
        )
        .arg(
            Arg::new("grammar")
                .short('g')
                .long("grammar")
                .help("The grammar model"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("12000"),
        )
        .arg(
            Arg::new("dump")
                .short('d')
                .long("dump")
                .help("Dump serialized testcases to bytes"),
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, -o corpus_dir -g grammar.json\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );

    let grammar_path = PathBuf::from(
        res.get_one::<String>("grammar")
            .expect("The --grammar parameter is missing")
            .to_string(),
    );
    if !grammar_path.is_file() {
        println!("{:?} is not a valid file!", &grammar_path);
        return;
    }
    let context = NautilusContext::from_file(64, grammar_path);

    if let Some(filenames) = res.get_many::<String>("remaining") {
        let filenames: Vec<&str> = filenames.map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(context, &filenames);
            return;
        }
    }

    // For fuzzbench, crashes and finds are inside the same `corpus` directory, in the "queue" and "crashes" subdir.
    let mut out_dir = PathBuf::from(
        res.get_one::<String>("out")
            .expect("The --output parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut chunks = out_dir.clone();
    chunks.push("chunks");
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let report_dir = PathBuf::from(
        res.get_one::<String>("report")
            .expect("The --report parameter is missing")
            .to_string(),
    );
    if fs::create_dir(&report_dir).is_err() {
        println!("Report dir at {:?} already exists.", &report_dir);
        if !report_dir.is_dir() {
            println!("Report dir at {:?} is not a valid directory!", &report_dir);
            return;
        }
    }

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    fuzz(out_dir, crashes, chunks, report_dir, context, timeout)
        .expect("An error occurred while fuzzing");
}

fn run_testcases(context: NautilusContext, filenames: &[&str]) {
    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    println!(
        "You are not fuzzing, just executing {} testcases",
        filenames.len()
    );
    for fname in filenames {
        println!("Executing {}", fname);

        let input = NautilusInput::from_file(fname).unwrap();

        let mut bytes = vec![];
        input.unparse(&context, &mut bytes);
        if *bytes.last().unwrap() != 0 {
            bytes.push(0);
        }
        unsafe {
            println!("Testcase: {}", std::str::from_utf8_unchecked(&bytes));
        }
        unsafe { libfuzzer_test_one_input(&bytes) };
    }
}

/// The actual fuzzer
fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    chunks_dir: PathBuf,
    report_dir: PathBuf,
    context: NautilusContext,
    timeout: Duration,
) -> Result<(), Error> {
    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    // 'While the monitor are state, they are usually used in the broker - which is likely never restarted
    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
    });

    // We need a shared map to store our state before a crash.
    // This way, we are able to continue fuzzing afterwards.
    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
        // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
        Ok(res) => res,
        Err(err) => match err {
            Error::ShuttingDown => {
                return Ok(());
            }
            _ => {
                panic!("Failed to setup the restarter: {}", err);
            }
        },
    };

    // Create an observation channel using the coverage map
    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        MaxMapFeedback::new(&edges_observer),
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer),
        NautilusFeedback::new(&context),
        LineageFeedback::new()
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = CrashFeedback::new();

    // If not restarting, create a State from scratch
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
            // They are the data related to the feedbacks that you want to persist in the State.
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    if state
        .metadata_map()
        .get::<NautilusChunksMetadata>()
        .is_none()
    {
        state.add_metadata(NautilusChunksMetadata::new(
            chunks_dir.display().to_string(),
        ));
    }

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(&edges_observer, QueueScheduler::new());

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut bytes = vec![];
    let mut harness = |input: &NautilusInput| {
        input.unparse(&context, &mut bytes);
        unsafe { libfuzzer_test_one_input(&bytes) };
        ExitKind::Ok
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    let mut generator = NautilusGenerator::new(&context);

    // In case the corpus is empty (on first run), reset
    if state.corpus().count() < 1 {
        state
            .generate_initial_inputs_forced(
                &mut fuzzer,
                &mut executor,
                &mut generator,
                &mut mgr,
                4096,
            )
            .expect("Failed to generate the initial corpus");
    }

    // Setup a basic mutator with a mutational stage
    let mutator = LineageMutator::with_max_stack_pow(
        tuple_list!(
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRandomMutator::new(&context),
            NautilusRecursionMutator::new(&context),
            NautilusSpliceMutator::new(&context),
            NautilusSpliceMutator::new(&context),
            NautilusSpliceMutator::new(&context),
        ),
        3,
    );

    let fuzzbench = libafl::stages::DumpToDiskStage::new(
        |input: &NautilusInput, _state: &_| {
            let mut bytes = vec![];
            input.unparse(&context, &mut bytes);
            bytes
        },
        &report_dir.join("queue"),
        &report_dir.join("crashes"),
    )
    .unwrap();

    let mut stages = tuple_list!(fuzzbench, StdMutationalStage::new(mutator));

    // Remove target ouput (logs still survive)
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }

    fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
    Ok(())
}
