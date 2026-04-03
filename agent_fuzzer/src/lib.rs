//! A fuzzer that pauses on coverage plateaus and invokes an external agent
//! to perform blocker analysis and seed guessing.
//!
//! Protocol with external agent:
//!   1. Fuzzer detects plateau, writes seed queue info to `<agent_dir>/seeds/`
//!      and a `request.json` manifest.
//!   2. Fuzzer polls for `<agent_dir>/done` signal file (or budget timeout).
//!   3. Agent writes new seeds to `<agent_dir>/results/` and touches `done`.
//!   4. Fuzzer imports new seeds with highest scheduling priority, resumes.

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use libafl::observers::CanTrack;
use libafl::HasMetadata;
use libafl_bolts::{
    current_nanos,
    os::dup2,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{tuple_list, Merge},
    AsSlice, SerdeAny,
};

use clap::{Arg, Command};
use core::time::Duration;
#[cfg(unix)]
use nix::{self, unistd::dup};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};

use libafl::{
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{ProgressReporter, SimpleRestartingEventManager},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    fuzzer::{Fuzzer, StdFuzzer, Evaluator},
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{
        havoc_mutations::havoc_mutations, token_mutations::I2SRandReplace, tokens_mutations,
        StdMOptMutator, StdScheduledMutator, Tokens,
    },
    observers::{HitcountsMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, StdMutationalStage,
        TracingStage,
    },
    state::{HasCorpus, StdState},
    Error,
};
use libafl_targets::{
    libfuzzer_initialize, libfuzzer_test_one_input, std_edges_map_observer, CmpLogObserver,
};

#[cfg(target_os = "linux")]
use libafl_targets::autotokens;

const STATS_TIMEOUT_DEFAULT: Duration = Duration::from_secs(15);

/// Metadata stored in shared state to persist plateau detection across restarts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, SerdeAny)]
struct PlateauMetadata {
    /// Corpus count at last observed growth.
    last_corpus_count: usize,
    /// Unix timestamp (secs) when we last saw growth.
    last_growth_timestamp: u64,
    /// Number of agent cycles completed.
    agent_cycle: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Poll interval when waiting for agent completion.
const AGENT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The fuzzer main (as `no_mangle` C function)
#[no_mangle]
pub fn libafl_main() {
    let res = match Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("AnnabellaM")
        .about("LibAFL fuzzer with agent-based plateau breaker")
        .arg(
            Arg::new("out")
                .short('o')
                .long("output")
                .help("The directory to place finds in ('corpus')"),
        )
        .arg(
            Arg::new("in")
                .short('i')
                .long("input")
                .help("The directory to read initial inputs from ('seeds')"),
        )
        .arg(
            Arg::new("tokens")
                .short('x')
                .long("tokens")
                .help("A file to read tokens from, to be used during fuzzing"),
        )
        .arg(
            Arg::new("timeout")
                .short('t')
                .long("timeout")
                .help("Timeout for each individual execution, in milliseconds")
                .default_value("1200"),
        )
        .arg(
            Arg::new("plateau_secs")
                .long("plateau-secs")
                .help("Seconds of no new coverage before triggering agent")
                .default_value("300"),
        )
        .arg(
            Arg::new("agent_budget_secs")
                .long("agent-budget-secs")
                .help("Max seconds to wait for agent to finish")
                .default_value("600"),
        )
        .arg(
            Arg::new("agent_dir")
                .long("agent-dir")
                .help("Directory for agent communication (seeds export, results import)")
                .default_value("/tmp/agent_fuzzer_ipc"),
        )
        .arg(
            Arg::new("agent_cmd")
                .long("agent-cmd")
                .help("Command to invoke the external agent (optional). \
                       The agent dir path is appended as the first argument."),
        )
        .arg(Arg::new("remaining"))
        .try_get_matches()
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {}, [-x dictionary] -o corpus_dir -i seed_dir [--plateau-secs N] [--agent-budget-secs N] [--agent-dir DIR] [--agent-cmd CMD]\n{:?}",
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

    if let Some(filenames) = res.get_many::<String>("remaining") {
        let filenames: Vec<&str> = filenames.map(String::as_str).collect();
        if !filenames.is_empty() {
            run_testcases(&filenames);
            return;
        }
    }

    // For fuzzbench, crashes and finds are inside the same `corpus` directory
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
    let mut crashes = out_dir.clone();
    crashes.push("crashes");
    out_dir.push("queue");

    let in_dir = PathBuf::from(
        res.get_one::<String>("in")
            .expect("The --input parameter is missing")
            .to_string(),
    );
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let tokens = res.get_one::<String>("tokens").map(PathBuf::from);

    let timeout = Duration::from_millis(
        res.get_one::<String>("timeout")
            .unwrap()
            .to_string()
            .parse()
            .expect("Could not parse timeout in milliseconds"),
    );

    let plateau_duration = Duration::from_secs(
        res.get_one::<String>("plateau_secs")
            .unwrap()
            .parse()
            .expect("Could not parse plateau-secs"),
    );

    let agent_budget = Duration::from_secs(
        res.get_one::<String>("agent_budget_secs")
            .unwrap()
            .parse()
            .expect("Could not parse agent-budget-secs"),
    );

    let agent_dir = PathBuf::from(
        res.get_one::<String>("agent_dir").unwrap().to_string(),
    );

    let agent_cmd = res.get_one::<String>("agent_cmd").cloned();

    let config = AgentConfig {
        plateau_duration,
        agent_budget,
        agent_dir,
        agent_cmd,
    };

    fuzz(out_dir, crashes, in_dir, tokens, timeout, config)
        .expect("An error occurred while fuzzing");
}

/// Configuration for the agent-based plateau breaker.
struct AgentConfig {
    /// How long without new coverage before we trigger the agent.
    plateau_duration: Duration,
    /// Max time to wait for the agent phase.
    agent_budget: Duration,
    /// Directory used for IPC with the external agent.
    agent_dir: PathBuf,
    /// Optional command to invoke the agent.
    agent_cmd: Option<String>,
}

fn run_testcases(filenames: &[&str]) {
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
        let mut file = File::open(fname).expect("No file found");
        let mut buffer = vec![];
        file.read_to_end(&mut buffer).expect("Buffer overflow");
        unsafe { libfuzzer_test_one_input(&buffer) };
    }
}

// ─── Agent IPC helpers ───────────────────────────────────────────────────────

type FuzzerState = StdState<BytesInput, InMemoryOnDiskCorpus<BytesInput>, StdRand, OnDiskCorpus<BytesInput>>;

/// Export the current seed queue to `<agent_dir>/seeds/` and write a `request.json` manifest.
fn export_seeds_for_agent(state: &FuzzerState, agent_dir: &Path) -> Result<usize, Error> {
    let seeds_dir = agent_dir.join("seeds");
    let _ = fs::remove_dir_all(&seeds_dir); // clean previous run
    fs::create_dir_all(&seeds_dir)
        .map_err(|e| Error::os_error(e, "Failed to create agent seeds dir"))?;

    let mut exported = 0usize;
    for id in state.corpus().ids() {
        let testcase = state.corpus().get(id)?;
        let tc = testcase.borrow();
        if let Some(input) = tc.input() {
            let target = input.target_bytes();
            let bytes = target.as_slice();
            let path = seeds_dir.join(format!("id_{:06}", usize::from(id)));
            fs::write(&path, bytes)
                .map_err(|e| Error::os_error(e, "Failed to write seed for agent"))?;
            exported += 1;
        }
    }

    // Write manifest
    let manifest = serde_json::json!({
        "num_seeds": exported,
        "seeds_dir": seeds_dir.to_string_lossy(),
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
    let manifest_path = agent_dir.join("request.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest).unwrap())
        .map_err(|e| Error::os_error(e, "Failed to write agent manifest"))?;

    // Remove stale done signal
    let _ = fs::remove_file(agent_dir.join("done"));

    println!(
        "[Agent Fuzzer] Exported {} seeds to {:?}",
        exported, seeds_dir
    );

    Ok(exported)
}

/// Invoke the external agent process (if configured).
fn invoke_agent(config: &AgentConfig) {
    if let Some(ref cmd) = config.agent_cmd {
        let agent_dir_str = config.agent_dir.to_string_lossy().to_string();
        println!("[Agent Fuzzer] Invoking agent: {} {}", cmd, agent_dir_str);
        match process::Command::new(cmd)
            .arg(&agent_dir_str)
            .spawn()
        {
            Ok(child) => {
                println!("[Agent Fuzzer] Agent started (pid: {})", child.id());
                // Don't wait — we poll for the done signal.
            }
            Err(e) => {
                println!("[Agent Fuzzer] Failed to invoke agent: {}", e);
            }
        }
    } else {
        println!(
            "[Agent Fuzzer] No --agent-cmd configured. Waiting for external agent to process {:?}",
            config.agent_dir
        );
    }
}

/// Wait for the agent to signal completion or for the budget to expire.
/// Returns true if the agent completed, false if budget ran out.
fn wait_for_agent(config: &AgentConfig) -> bool {
    let done_path = config.agent_dir.join("done");
    let start = std::time::Instant::now();

    while start.elapsed() < config.agent_budget {
        if done_path.exists() {
            println!(
                "[Agent Fuzzer] Agent completed in {:.1}s",
                start.elapsed().as_secs_f64()
            );
            return true;
        }
        std::thread::sleep(AGENT_POLL_INTERVAL);
    }

    println!(
        "[Agent Fuzzer] Agent budget expired ({:.0}s). Resuming fuzzing.",
        config.agent_budget.as_secs_f64()
    );
    false
}

/// Import seeds from `<agent_dir>/results/` into the corpus.
/// Uses `add_input` so seeds always enter the queue regardless of novelty.
/// Returns the number of seeds imported.
fn import_agent_seeds<E, EM, CS, F, OF>(
    fuzzer: &mut StdFuzzer<CS, F, OF, FuzzerState>,
    executor: &mut E,
    state: &mut FuzzerState,
    mgr: &mut EM,
    agent_dir: &Path,
) -> Result<usize, Error>
where
    StdFuzzer<CS, F, OF, FuzzerState>: Evaluator<E, EM, State = FuzzerState>,
{
    let results_dir = agent_dir.join("results");
    if !results_dir.is_dir() {
        println!("[Agent Fuzzer] No results directory found at {:?}", results_dir);
        return Ok(0);
    }

    let mut imported = 0usize;
    let mut entries: Vec<_> = fs::read_dir(&results_dir)
        .map_err(|e| Error::os_error(e, "Failed to read agent results dir"))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                println!("[Agent Fuzzer] Skipping {:?}: {}", path, e);
                continue;
            }
        };

        let input = BytesInput::new(bytes);

        // Use add_input to force-add to corpus regardless of coverage feedback.
        // This ensures agent-guessed seeds always enter the queue.
        match fuzzer.add_input(state, executor, mgr, input) {
            Ok(id) => {
                println!("[Agent Fuzzer] Imported seed {:?} -> corpus id {:?}", path.file_name().unwrap_or_default(), id);
                // Set scheduled_count to 0 so the scheduler treats it as fresh/high-priority.
                // Most power schedulers give more energy to less-fuzzed seeds.
                if let Ok(tc) = state.corpus().get(id) {
                    tc.borrow_mut().set_scheduled_count(0);
                }
                imported += 1;
            }
            Err(e) => {
                println!("[Agent Fuzzer] Failed to import {:?}: {}", path.file_name().unwrap_or_default(), e);
            }
        }
    }

    println!("[Agent Fuzzer] Imported {} seeds from agent", imported);
    Ok(imported)
}

// ─── Main fuzzer ─────────────────────────────────────────────────────────────

fn fuzz(
    corpus_dir: PathBuf,
    objective_dir: PathBuf,
    seed_dir: PathBuf,
    tokenfile: Option<PathBuf>,
    timeout: Duration,
    agent_config: AgentConfig,
) -> Result<(), Error> {
    #[cfg(unix)]
    let mut stdout_cpy = unsafe {
        let new_fd = dup(io::stdout().as_raw_fd())?;
        File::from_raw_fd(new_fd)
    };
    #[cfg(unix)]
    let file_null = File::open("/dev/null")?;

    let monitor = SimpleMonitor::new(|s| {
        #[cfg(unix)]
        writeln!(&mut stdout_cpy, "{}", s).unwrap();
        #[cfg(windows)]
        println!("{}", s);
    });

    let mut shmem_provider = StdShMemProvider::new()?;

    let (state, mut mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
    {
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

    // Create observers
    let edges_observer =
        HitcountsMapObserver::new(unsafe { std_edges_map_observer("edges") }).track_indices();
    let time_observer = TimeObserver::new("time");
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let map_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&map_feedback);

    let mut feedback = feedback_or!(map_feedback, TimeFeedback::new(&time_observer));
    let mut objective = CrashFeedback::new();

    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            StdRand::with_seed(current_nanos()),
            InMemoryOnDiskCorpus::new(corpus_dir).unwrap(),
            OnDiskCorpus::new(objective_dir).unwrap(),
            &mut feedback,
            &mut objective,
        )
        .unwrap()
    });

    println!("[Agent Fuzzer] Let's fuzz :)");

    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1")
    }

    // Setup stages (same as generic)
    let i2s = StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

    let mutator = StdMOptMutator::new::<BytesInput, _>(
        &mut state,
        havoc_mutations().merge(tokens_mutations()),
        7,
        5,
    )?;

    let power: StdPowerMutationalStage<_, _, BytesInput, _, _> =
        StdPowerMutationalStage::new(mutator);

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        PowerQueueScheduler::new(&mut state, &edges_observer, PowerSchedule::fast()),
    );

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        unsafe { libfuzzer_test_one_input(buf) };
        ExitKind::Ok
    };

    let mut tracing_harness = harness;

    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout,
    )?;

    let tracing = TracingStage::new(InProcessExecutor::with_timeout(
        &mut tracing_harness,
        tuple_list!(cmplog_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
        timeout * 10,
    )?);

    let mut stages = tuple_list!(calibration, tracing, i2s, power);

    // Read tokens
    if state.metadata_map().get::<Tokens>().is_none() {
        let mut toks = Tokens::default();
        if let Some(tokenfile) = tokenfile {
            toks.add_from_file(tokenfile)?;
        }
        #[cfg(target_os = "linux")]
        {
            toks += autotokens()?;
        }
        if !toks.is_empty() {
            state.add_metadata(toks);
        }
    }

    // Load initial corpus
    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[seed_dir.clone()])
            .unwrap_or_else(|_| {
                println!("Failed to load initial corpus at {:?}", &seed_dir);
                process::exit(0);
            });
        println!("[Agent Fuzzer] Imported {} inputs from disk.", state.corpus().count());
    }

    // Suppress target output
    #[cfg(unix)]
    {
        let null_fd = file_null.as_raw_fd();
        dup2(null_fd, io::stdout().as_raw_fd())?;
        dup2(null_fd, io::stderr().as_raw_fd())?;
    }

    // ─── Custom fuzz loop with plateau detection ─────────────────────────
    //
    // Instead of `fuzzer.fuzz_loop()`, we run our own loop that tracks
    // corpus size and detects when coverage growth stalls.
    //
    // Plateau state is stored in shared metadata so it survives restarts
    // (the SimpleRestartingEventManager respawns the process on crashes).

    // Initialize or recover plateau metadata from shared state
    if state.metadata_map().get::<PlateauMetadata>().is_none() {
        state.add_metadata(PlateauMetadata {
            last_corpus_count: state.corpus().count(),
            last_growth_timestamp: now_secs(),
            agent_cycle: 0,
        });
    }

    // Prepare agent communication directory
    fs::create_dir_all(&agent_config.agent_dir)
        .map_err(|e| Error::os_error(e, "Failed to create agent dir"))?;

    loop {
        // Run one fuzzing iteration
        mgr.maybe_report_progress(&mut state, STATS_TIMEOUT_DEFAULT)?;
        fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, &mut mgr)?;

        // Check if corpus grew (new coverage found)
        let current_count = state.corpus().count();
        let meta = state.metadata_map().get::<PlateauMetadata>().unwrap();
        let prev_count = meta.last_corpus_count;
        let last_growth_ts = meta.last_growth_timestamp;
        let agent_cycle = meta.agent_cycle;

        if current_count > prev_count {
            let meta = state.metadata_map_mut().get_mut::<PlateauMetadata>().unwrap();
            meta.last_corpus_count = current_count;
            meta.last_growth_timestamp = now_secs();
            continue;
        }

        // Plateau detection: no new coverage for `plateau_duration`
        let elapsed_secs = now_secs().saturating_sub(last_growth_ts);
        if elapsed_secs >= agent_config.plateau_duration.as_secs() {
            let new_cycle = agent_cycle + 1;

            // Use stderr since stdout may be suppressed
            eprintln!(
                "[Agent Fuzzer] Coverage plateau detected (cycle {}). \
                 Corpus size: {}. No growth for {}s. Entering agent phase.",
                new_cycle, current_count, elapsed_secs,
            );

            // Phase 1: Export seeds for the agent
            let _ = export_seeds_for_agent(&state, &agent_config.agent_dir);

            // Phase 2: Invoke external agent
            invoke_agent(&agent_config);

            // Phase 3: Wait for agent completion or budget timeout
            let _agent_completed = wait_for_agent(&agent_config);

            // Phase 4: Import agent results into corpus
            let imported = import_agent_seeds(
                &mut fuzzer,
                &mut executor,
                &mut state,
                &mut mgr,
                &agent_config.agent_dir,
            )?;

            eprintln!(
                "[Agent Fuzzer] Agent phase complete (cycle {}). Imported {} seeds. Resuming fuzzing.",
                new_cycle, imported,
            );

            // Reset plateau timer
            let new_count = state.corpus().count();
            let meta = state.metadata_map_mut().get_mut::<PlateauMetadata>().unwrap();
            meta.last_corpus_count = new_count;
            meta.last_growth_timestamp = now_secs();
            meta.agent_cycle = new_cycle;
        }
    }
}
