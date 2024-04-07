//! # Reprof
//!
//! `reprof` is a simple example of how to use the `jemalloc-pprof` crate and firefox profiler to
//! visualize jemalloc heap profiles.
use std::{
    collections::{hash_map::Entry, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use clap::{Args, Parser, Subcommand};
use fxprof_processed_profile::{
    debugid::DebugId, CategoryHandle, Frame, FrameFlags, FrameInfo, LibraryInfo, Profile,
    SamplingInterval, Symbol, SymbolTable, Timestamp,
};
use jemalloc_pprof::{internal::Mapping, JemallocProfCtl, PROF_CTL};
use tikv_jemallocator::Jemalloc;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wholesym::{samply_symbols::DebugIdExt, SymbolManager, SymbolManagerConfig};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    // init tracing to stdout with info
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_ansi(false))
        .init();

    let Some(_ctl) = PROF_CTL.as_ref() else {
        tracing::warn!("jemalloc profiling is disabled and cannot be activated");
        return;
    };

    let opt = Opt::parse();
    match opt.action {
        Action::Load(_load_args) => {
            todo!()
        }

        #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
        Action::Analyze(analyze_args) => {
            let path = Path::new(&analyze_args.command[0]);
            let heap_file_name = analyze_args
                .heap_files
                .first()
                .expect("No heap files specified");
            let heap_file = File::open(heap_file_name).expect("Could not open heap file");

            // Open and read the profile.
            let dump_reader = BufReader::new(heap_file);

            tracing::info!(
                "Profiling command {command:?} with args {args:?}",
                command = analyze_args.command[0],
                args = &analyze_args.command
            );

            let profile = analyze_jemalloc_profile(path, dump_reader).await;

            // println the profile first
            println!("PROFILE: {profile:#?}");

            // output profile to file
            let mut output_file = std::fs::File::create(analyze_args.output).unwrap();
            serde_json::to_writer(&mut output_file, &profile).unwrap();
        }

        #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
        Action::Record(record_args) => {
            if let Some(pid) = record_args.pid {
                tracing::info!("Profiling process with pid {pid}");
                todo!();
                // profiler::start_profiling_pid(pid, recording_props, conversion_props, server_props);
            } else {
                // get the symbol map for this binary
                let _path = Path::new(&record_args.command[0]);

                tracing::info!(
                    "Profiling command {command:?} with args {args:?}",
                    command = record_args.command[0],
                    args = &record_args.command[1..]
                );

                // TODO: launch command etc
                // let ff_profile = analyze_jemalloc_profile(path, dump_reader).await;

                todo!()
            }
        }
    };
}

pub async fn analyze_jemalloc_profile<R: BufRead>(
    binary_path: &Path,
    jemalloc_profile_reader: R,
) -> Profile {
    let profile = jemalloc_pprof::internal::parse_jeheap(jemalloc_profile_reader).unwrap();
    println!("{:#?}", profile);

    // convert the profile to the ff format
    let mut ff_profile = Profile::new(
        "reprof cli startup",
        SystemTime::now().into(),
        SamplingInterval::from_millis(1),
    );

    let curr_pid = std::process::id();
    let process = ff_profile.add_process(
        "App process",
        curr_pid,
        Timestamp::from_millis_since_reference(0.0),
    );
    let memory_counter =
        ff_profile.add_counter(process, "jemalloc", "Memory", "Amount of allocated memory");

    let symbol_manager_config = SymbolManagerConfig::new();
    tracing::info!(?symbol_manager_config, "printing symbol manager config");
    let symbol_manager = SymbolManager::with_config(symbol_manager_config);

    // jemalloc prof doesnt work on macos
    let map = symbol_manager
        .load_symbol_map_for_binary_at_path(binary_path, None)
        .await
        .unwrap();
    tracing::info!("got symbol map for mapping");

    let mut mapped_symbols = HashMap::new();

    for (weighted_stack, _something) in profile.iter() {
        // we'll add this weight to all addrs

        for addr in &weighted_stack.addrs {
            for mapping in &profile.mappings {
                if *addr > mapping.memory_start && *addr < mapping.memory_end {
                    let rel_addr = addr - mapping.memory_start;

                    // new way: add to memory offset
                    let new_rel_addr = rel_addr + mapping.memory_offset;
                    tracing::info!(
                        ?mapping,
                        "FOUND ADDRESS IN MAPPING: addr=0x{:x?}, new_rel_addr=0x{:x?}",
                        addr,
                        new_rel_addr
                    );
                    let symbol_svma = map.lookup_svma(new_rel_addr as u64);
                    let symbol_relative = map.lookup_relative_address(new_rel_addr as u32);
                    // tracing::info!("CHECKING, symbol_svma={:#?}, symbol_relative={:#?}", symbol_svma, symbol_relative);

                    let symbol_info = symbol_relative.or(symbol_svma);
                    if let Some(info) = symbol_info {
                        let new_symbol = Symbol {
                            address: info.symbol.address,
                            size: info.symbol.size,
                            name: info.symbol.name,
                        };

                        tracing::info!(
                            "GOT ONE, in_symbol_addr=0x{:x?}, current_addr=0x{:x?}",
                            new_symbol.address,
                            new_rel_addr
                        );
                        match mapped_symbols.entry(mapping.memory_offset) {
                            Entry::Vacant(vacant) => {
                                vacant.insert(vec![new_symbol]);
                            }
                            Entry::Occupied(mut occupied) => {
                                occupied.get_mut().push(new_symbol);
                            }
                        }
                    }
                    // TODO: else panic or error? extract into fn to allow proper reasoning
                }
            }
        }
    }

    tracing::info!(?mapped_symbols, "CONSTRUCTED MAPPED SYMBOLS");

    for mapping in &profile.mappings {
        println!("ADDING THIS MAPPING: {mapping:?}");
        let Mapping {
            memory_start,
            memory_end,
            memory_offset,
            file_offset: _,
            pathname,
            build_id,
        } = mapping;

        // convert buildid to debugid
        let debug_id = build_id
            .clone()
            .map(|build_id| {
                // TODO: why do we have to know / specify little endian?
                DebugId::from_identifier(&build_id.0, true)
            })
            .unwrap();

        // TODO: we're pre-symbolicating here, but we should create the wholesym symbol manager
        // and run the server just like how samply does it
        //
        // but need to test that out
        let symbol_table_for_map = mapped_symbols
            .get(&mapping.memory_offset)
            .cloned()
            .map(SymbolTable::new)
            .map(Arc::new);
        let library_info = LibraryInfo {
            name: pathname.to_string_lossy().to_string(),
            debug_name: pathname.to_string_lossy().to_string(),
            path: pathname.to_string_lossy().to_string(),
            code_id: None,
            debug_path: pathname.to_string_lossy().to_string(),
            debug_id,
            arch: None,
            symbol_table: symbol_table_for_map.clone(),
        };

        println!("ADDING LIBRARY INFO: {:#?}", library_info);

        let lib_handle = ff_profile.add_lib(library_info);

        let offset = (*memory_offset).try_into().unwrap();
        ff_profile.add_lib_mapping(
            process,
            lib_handle,
            *memory_start as u64,
            *memory_end as u64,
            offset,
        );

        // TODO: can we even get the symbol table rn? the mappings are all we have
        // do we even need it?
    }

    // TODO: thread ids later, when we can parse them properly out of the profile
    //
    // tid: u32,
    let tid = 0;
    let thread_handle = ff_profile.add_thread(
        process,
        tid,
        Timestamp::from_millis_since_reference(0.0),
        true,
    );
    ff_profile.set_thread_name(thread_handle, "Main thread");

    for (weighted_stack, _something) in profile.iter() {
        // we'll add this weight to all addrs
        let weight = weighted_stack.weight;

        let mut frames = vec![];
        'addrs: for addr in &weighted_stack.addrs {
            println!("considering addr: {:?}", addr);
            for mapping in &profile.mappings {
                if *addr > mapping.memory_start && *addr < mapping.memory_end {
                    let rel_addr = addr - mapping.memory_start;
                    // new way: add to memory offset
                    let new_rel_addr = rel_addr + mapping.memory_offset;
                    let symbol_svma = map.lookup_svma(new_rel_addr as u64);
                    let symbol_relative = map.lookup_relative_address(new_rel_addr as u32);

                    let symbol_info = symbol_relative.or(symbol_svma);

                    if let Some(info) = &symbol_info {
                        let new_symbol = Symbol {
                            address: new_rel_addr as u32,
                            // TODO: idk what this is really
                            // size: info.symbol.size,
                            // this fucks up the binary search for some reason
                            size: None,
                            name: info.symbol.name.clone(),
                        };
                        let return_addr_frame = Frame::ReturnAddress(*addr as u64);
                        println!(
                            "symbol={:?}, in_symbol_addr=0x{:?}, current_addr=0x{:?}, addr={:?}",
                            new_symbol, new_symbol.address, new_rel_addr, return_addr_frame
                        );
                    }

                    let this_frame = FrameInfo {
                        frame: Frame::ReturnAddress(*addr as u64),
                        category_pair: CategoryHandle::OTHER.into(),
                        flags: FrameFlags::empty(),
                    };

                    println!(
                        "pushing frame with symbol ({:?}): {:?}",
                        symbol_info.is_some(),
                        this_frame
                    );
                    frames.push(this_frame);
                    continue 'addrs;
                }
            }
        }

        tracing::info!("PUSHING FRAMES frame={:#?}", frames);
        ff_profile.add_memory_sample(
            thread_handle,
            Timestamp::from_millis_since_reference(0.0),
            frames.into_iter(),
            None,
            weight as i32,
        );

        // ff_profile.add_sample(thread, timestamp, frames, cpu_delta, weight)
    }

    // we just have a single profile, we're doing this once, just to see the number in the UI
    let allocated = tikv_jemalloc_ctl::stats::allocated::mib().unwrap();
    // TODO: this is supposed to refer to a total malloc call, although I'm not sure we have
    // that from jemalloc dumps
    let total_mallocs = 1;
    ff_profile.add_counter_sample(
        memory_counter,
        Timestamp::from_millis_since_reference(0.0),
        allocated.read().unwrap() as f64,
        total_mallocs,
    );

    ff_profile
}

/// Activate jemalloc profiling.
pub async fn activate_jemalloc_profiling(ctl: Arc<Mutex<JemallocProfCtl>>) {
    let mut ctl = ctl.lock().await;
    if ctl.activated() {
        return;
    }

    match ctl.activate() {
        Ok(()) => tracing::info!("jemalloc profiling activated"),
        Err(err) => tracing::warn!("could not activate jemalloc profiling: {err}"),
    }
}

/// Dump a jemalloc profile.
pub async fn dump_jemalloc_profile(ctl: Arc<Mutex<JemallocProfCtl>>) -> Option<File> {
    let mut ctl = ctl.lock().await;

    match ctl.dump() {
        Ok(file) => {
            tracing::info!("jemalloc profile dumped to {file:?}");
            Some(file)
        }
        Err(err) => {
            tracing::warn!("could not dump jemalloc profile: {err}");
            None
        }
    }
}

/// Deactivate jemalloc profiling.
pub async fn deactivate_jemalloc_profiling(ctl: Arc<Mutex<JemallocProfCtl>>) {
    let mut ctl = ctl.lock().await;
    if !ctl.activated() {
        return;
    }

    match ctl.deactivate() {
        Ok(()) => tracing::info!("jemalloc profiling deactivated"),
        Err(err) => tracing::warn!("could not deactivate jemalloc profiling: {err}"),
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "reprof",
    version,
    about = r#"
reprof is a sampling Memory profiler.
Run a command, record a Memory profile of its execution, and open the profiler UI.
Recording is currently supported on Linux and macOS.
On other platforms, reprof can only load existing profiles.

EXAMPLES:
    # Default usage:
    reprof record ./yourcommand yourargs

    # On Linux, you can also profile existing processes by pid:
    reprof record -p 12345 # Linux only

    # Alternative usage: Save profile to file for later viewing, and then load it.
    reprof record --save-only -o prof.json -- ./yourcommand yourargs
    reprof load prof.json # Opens in the browser and supplies symbols
"#
)]
struct Opt {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Load a profile from a file and display it.
    Load(LoadArgs),

    #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
    /// Record a profile and display it.
    Record(RecordArgs),

    #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
    /// Analyze an existing heap profile.
    Analyze(AnalyzeArgs),
}

#[derive(Debug, Args)]
struct LoadArgs {
    /// Path to the file that should be loaded.
    file: PathBuf,

    #[command(flatten)]
    conversion_args: ConversionArgs,

    #[command(flatten)]
    server_args: ServerArgs,
}

// TODO: actually achieve this
/// Analyze an existing jemalloc profile. This allows specifying multiple heap files to load. This
/// must be done on the same platform that the profile was recorded on.
///
/// # Example
/// ```sh
/// reprof analyze --command ~/.cargo/bin/reth --heap-files reth.123456.1.i1.heap reth.123456.2.i2.heap
/// ```
#[allow(unused)]
#[derive(Debug, Args)]
struct AnalyzeArgs {
    /// Do not run a local server after recording.
    #[arg(short, long)]
    save_only: bool,

    /// Output filename.
    #[arg(short, long, default_value = "profile.json")]
    output: PathBuf,

    #[command(flatten)]
    conversion_args: ConversionArgs,

    #[command(flatten)]
    server_args: ServerArgs,

    /// Profile the execution of this command.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    command: Vec<std::ffi::OsString>,

    /// Specify the heap files to load.
    #[arg(short, long, allow_hyphen_values = true, trailing_var_arg = true)]
    heap_files: Vec<PathBuf>,
}

// TODO: actually achieve this
// TODO: encode jemalloc profiling params in help menu in a more sensible way (ie, good docs) and auto enable
// TODO: add a way to specify time based dumps?
// TODO: ensure profiling is enabled for the binary before running record
/// Record the execution of a program with jemalloc profiling enabled.
///
/// # Example
/// ```sh
/// reprof record --command ~/.cargo/bin/reth
/// ```
#[allow(unused)]
#[derive(Debug, Args)]
struct RecordArgs {
    /// Do not run a local server after recording.
    #[arg(short, long)]
    save_only: bool,

    /// Output filename.
    #[arg(short, long, default_value = "profile.json")]
    output: PathBuf,

    /// How many times to run the profiled command.
    #[arg(long, default_value = "1")]
    iteration_count: u32,

    #[command(flatten)]
    conversion_args: ConversionArgs,

    #[command(flatten)]
    server_args: ServerArgs,

    /// Profile the execution of this command.
    #[arg(
        required_unless_present = "pid",
        conflicts_with = "pid",
        allow_hyphen_values = true,
        trailing_var_arg = true
    )]
    command: Vec<std::ffi::OsString>,

    // TODO: is this possible with jemalloc? I guess you can just take existing files and attach to
    // the binary that the pid is running
    /// Process ID of existing process to attach to (Linux only).
    #[arg(short, long)]
    pid: Option<u32>,
}

#[derive(Debug, Args)]
struct ServerArgs {
    /// Do not open the profiler UI.
    #[arg(short, long)]
    no_open: bool,

    /// The port to use for the local web server
    #[arg(short = 'P', long, default_value = "3000+")]
    port: String,

    /// Print debugging output.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Args, Clone)]
pub struct ConversionArgs {
    /// Set a custom name for the recorded profile.
    /// By default it is either the command that was run or the process pid.
    #[arg(long)]
    profile_name: Option<String>,

    /// Merge non-overlapping threads of the same name.
    #[arg(long)]
    merge_threads: bool,

    /// Fold repeated frames at the base of the stack.
    #[arg(long)]
    fold_recursive_prefix: bool,
}

impl LoadArgs {
    // fn conversion_props(&self) -> ConversionProps {
    //     let profile_name = if let Some(profile_name) = &self.conversion_args.profile_name {
    //         profile_name.clone()
    //     } else {
    //         "Imported perf profile".to_string()
    //     };
    //     ConversionProps {
    //         profile_name,
    //         merge_threads: self.conversion_args.merge_threads,
    //         fold_recursive_prefix: self.conversion_args.fold_recursive_prefix,
    //     }
    // }
}

impl RecordArgs {
    // #[allow(unused)]
    // pub fn recording_props(&self) -> RecordingProps {
    //     let time_limit = self.duration.map(Duration::from_secs_f64);
    //     if self.rate <= 0.0 {
    //         eprintln!(
    //             "Error: sampling rate must be greater than zero, got {}",
    //             self.rate
    //         );
    //         std::process::exit(1);
    //     }
    //     let interval = Duration::from_secs_f64(1.0 / self.rate);

    //     RecordingProps {
    //         output_file: self.output.clone(),
    //         time_limit,
    //         interval,
    //     }
    // }

    // #[allow(unused)]
    // pub fn conversion_props(&self) -> ConversionProps {
    //     let profile_name = match (self.conversion_args.profile_name.clone(), self.pid, self.command.first()) {
    //         (Some(profile_name), _, _) => profile_name,
    //         (None, Some(pid), _) => format!("PID {pid}"),
    //         (None, None, Some(command)) => command.to_string_lossy().to_string(),
    //         (None, None, None) => panic!("Either pid or command is guaranteed to be present (clap should have done the validation)"),
    //     };
    //     ConversionProps {
    //         profile_name,
    //         merge_threads: self.conversion_args.merge_threads,
    //         fold_recursive_prefix: self.conversion_args.fold_recursive_prefix,
    //     }
    // }
}

impl ServerArgs {
    // pub fn server_props(&self) -> ServerProps {
    //     let open_in_browser = !self.no_open;
    //     let port_selection = match PortSelection::try_from_str(&self.port) {
    //         Ok(p) => p,
    //         Err(e) => {
    //             eprintln!(
    //                 "Could not parse port as <u16> or <u16>+, got port {}, error: {}",
    //                 self.port, e
    //             );
    //             std::process::exit(1)
    //         }
    //     };
    //     ServerProps {
    //         port_selection,
    //         verbose: self.verbose,
    //         open_in_browser,
    //     }
    // }
}

// fn attempt_conversion(
//     filename: &Path,
//     input_file: &File,
//     conversion_props: ConversionProps,
// ) -> Option<NamedTempFile> {
//     let path = Path::new(filename)
//         .canonicalize()
//         .expect("Couldn't form absolute path");
//     let reader = BufReader::new(input_file);
//     let output_file = tempfile::NamedTempFile::new().ok()?;
//     let profile = import::perf::convert(reader, path.parent(), conversion_props).ok()?;
//     let writer = BufWriter::new(output_file.as_file());
//     serde_json::to_writer(writer, &profile).ok()?;
//     Some(output_file)
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Opt::command().debug_assert();
    }

    #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
    #[test]
    fn verify_cli_record() {
        let opt = Opt::parse_from(["reprof", "record", "rustup", "show"]);
        assert!(
            matches!(opt.action, Action::Record(record_args) if record_args.command == ["rustup", "show"])
        );

        let opt = Opt::parse_from(["reprof", "record", "rustup", "--no-open"]);
        assert!(
        matches!(opt.action, Action::Record(record_args) if record_args.command == ["rustup", "--no-open"]),
        "Arguments of the form --arg should be considered part of the command even if they match reprof options."
    );

        let opt = Opt::parse_from(["reprof", "record", "--no-open", "rustup"]);
        assert!(
            matches!(opt.action, Action::Record(record_args) if record_args.command == ["rustup"] && record_args.server_args.no_open),
            "Arguments which come before the command name should be treated as reprof arguments."
        );

        // Make sure you can't pass both a pid and a command name at the same time.
        let opt_res = Opt::try_parse_from(["reprof", "record", "-p", "1234", "rustup"]);
        assert!(opt_res.is_err());
    }
}
