//! # Reprof
//!
//! `reprof` is a simple example of how to use the `jemalloc-pprof` crate and firefox profiler to
//! visualize jemalloc heap profiles.
use std::{
    fs::File,
    io::{BufReader, Read},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::Arc,
    time::SystemTime,
};

use clap::{Args, Parser, Subcommand};
use fxprof_processed_profile::{LibraryInfo, Profile, SamplingInterval, Timestamp, debugid::DebugId, FrameInfo, Frame, CategoryHandle, FrameFlags};
use jemalloc_pprof::{JemallocProfCtl, PROF_CTL, internal::Mapping};
use tikv_jemallocator::Jemalloc;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use wholesym::{FramesLookupResult, SymbolManager, SymbolManagerConfig, samply_symbols::DebugIdExt};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() {
    // init tracing to stdout with info
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let Some(ctl) = PROF_CTL.as_ref() else {
        tracing::warn!("jemalloc profiling is disabled and cannot be activated");
        return;
    };

    // https://profiler.firefox.com/public/ac5355fa6136208d527d908406e90b20e36d0fd9/flame-graph/?ctSummary=native-allocations&globalTrackOrder=0w4&hiddenGlobalTracks=1w3&hiddenLocalTracksByPid=17998-0~17955-0~17977-0&thread=5&timelineType=category&v=10

    activate_jemalloc_profiling(ctl.clone()).await;

    // Enable jemalloc profiling.
    println!("Hello, world!");

    // create a huge vec
    let mut v: Vec<u64> = Vec::with_capacity(1024 * 1024 * 1024);
    let v2: Vec<u64> = Vec::with_capacity(1024 * 1024 * 1024);
    let mut v3: Vec<u64> = Vec::with_capacity(1024 * 1024 * 1024);

    v3.extend(v2);
    v3.extend([1, 2, 3].iter().cloned());

    let _half = alloc_then_dealloc();
    let v4 = v.clone();
    let v5 = v.clone();
    let v6 = v.clone();

    let v4 = v.clone();
    drop(v5);
    let v5 = v.clone();
    drop(v6);
    let v6 = v.clone();

    _ = alloc_then_dealloc();
    let mut v7: Vec<u64> = Vec::with_capacity(1024 * 1024 * 1024);

    let file = dump_jemalloc_profile(ctl.clone()).await.unwrap();

    // Open and read the profile.
    let mut dump_reader = BufReader::new(file);

    let profile = jemalloc_pprof::internal::parse_jeheap(dump_reader).unwrap();
    println!("{:#?}", profile);

    // convert the profile to the ff format
    let mut ff_profile = Profile::new(
        "reprof cli startup",
        SystemTime::now().into(),
        SamplingInterval::from_millis(1),
    );

    // example of a mapping:
    //
    // mappings: [
    //     Mapping {
    //         memory_start: 94260335046656,
    //         memory_end: 94260336416825,
    //         memory_offset: 0,
    //         file_offset: 0,
    //         pathname: "/home/dan/projects/reprof/target/debug/reprof",
    //         build_id: Some(
    //             BuildId(
    //                 [
    //                     245,
    //                     154,
    //                     188,
    //                     220,
    //                     169,
    //                     204,
    //                     72,
    //                     36,
    //                     41,
    //                     200,
    //                     105,
    //                     11,
    //                     154,
    //                     93,
    //                     218,
    //                     55,
    //                     77,
    //                     22,
    //                     83,
    //                     87,
    //                 ],
    //             ),
    //         ),
    //     },
    //
    // ok, let's just try to get the same information from the samply code

    let curr_pid = std::process::id();
    let process = ff_profile.add_process(
        "App process",
        curr_pid,
        Timestamp::from_millis_since_reference(0.0),
    );
    let memory_counter =
        ff_profile.add_counter(process, "jemalloc", "Memory", "Amount of allocated memory");

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

    for mapping in &profile.mappings {
        let Mapping {
            memory_start,
            memory_end,
            memory_offset,
            file_offset,
            pathname,
            build_id,
        } = mapping;

        // convert buildid to debugid
        let debug_id = build_id.clone().map(|build_id| {
            // TODO: why do we have to know / specify little endian?
            DebugId::from_identifier(&build_id.0, true)
        }).unwrap();

        let lib_handle = ff_profile.add_lib(LibraryInfo {
            name: pathname.to_string_lossy().to_string(),
            debug_name: pathname.to_string_lossy().to_string(),
            path: pathname.to_string_lossy().to_string(),
            code_id: None,
            debug_path: pathname.to_string_lossy().to_string(),
            debug_id,
            arch: None,
            symbol_table: None,
        });

        ff_profile.add_lib_mapping(process, lib_handle, *memory_start as u64, *memory_end as u64, (*memory_offset).try_into().unwrap());

        // TODO: can we even get the symbol table rn? the mappings are all we have
        // do we even need it?
    }

    // profile.add_sample(
    //     thread,
    //     Timestamp::from_millis_since_reference(0.0),
    //     vec![].into_iter(),
    //     CpuDelta::ZERO,
    //     1,
    // );
    // let libc_handle = profile.add_lib(LibraryInfo {
    //     name: "libc.so.6".to_string(),
    //     debug_name: "libc.so.6".to_string(),
    //     path: "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
    //     code_id: Some("f0fc29165cbe6088c0e1adf03b0048fbecbc003a".to_string()),
    //     debug_path: "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
    //     debug_id: DebugId::from_breakpad("1629FCF0BE5C8860C0E1ADF03B0048FB0").unwrap(),
    //     arch: None,
    //     symbol_table: Some(Arc::new(SymbolTable::new(vec![
    //         Symbol {
    //             address: 1700001,
    //             size: Some(180),
    //             name: "libc_symbol_1".to_string(),
    //         },
    //         Symbol {
    //             address: 674226,
    //             size: Some(44),
    //             name: "libc_symbol_3".to_string(),
    //         },
    //         Symbol {
    //             address: 172156,
    //             size: Some(20),
    //             name: "libc_symbol_2".to_string(),
    //         },
    //     ]))),
    // });
    // profile.add_lib_mapping(
    //     process,
    //     libc_handle,
    //     0x00007f76b7e85000,
    //     0x00007f76b8019000,
    //     (0x00007f76b7e85000u64 - 0x00007f76b7e5d000u64) as u32,
    // );

    // ff_profile.add_lib(library)
    // ff_profile.add_lib_mapping(process, lib, start_avma, end_avma, relative_address_at_start)

    for (weighted_stack, something) in profile.iter() {
        // we'll add this weight to all addrs
        let weight = weighted_stack.weight;

        // let me create unresolved stacks from this

        // for sample in samples {
        //     lib_mappings_hierarchy.process_ops(sample.timestamp_mono);
        //     let UnresolvedSampleOrMarker {
        //         thread_handle,
        //         timestamp,
        //         stack,
        //         sample_or_marker,
        //         extra_label_frame,
        //         ..
        //     } = sample;
        //     stack_frame_scratch_buf.clear();
        //     stacks.convert_back(stack, stack_frame_scratch_buf);
        //     let frames = stack_converter.convert_stack(
        //         stack_frame_scratch_buf,
        //         &lib_mappings_hierarchy,
        //         extra_label_frame,
        //     );

        // let stack = vec![
        //     FrameInfo { frame: Frame::Label(profile.intern_string("Root node")), category_pair: CategoryHandle::OTHER.into(), flags: FrameFlags::empty() },
        //     FrameInfo { frame: Frame::Label(profile.intern_string("First callee")), category_pair: CategoryHandle::OTHER.into(), flags: FrameFlags::empty() }
        // ];
        let mut frames = vec![];
        for addr in &weighted_stack.addrs {
            let this_frame = FrameInfo {
                frame: Frame::ReturnAddress(*addr as u64),
                category_pair: CategoryHandle::OTHER.into(),
                flags: FrameFlags::empty(),
            };

            frames.push(this_frame);

            // &mut self,
            // thread: ThreadHandle,
            // timestamp: Timestamp,
            // frames: impl Iterator<Item = FrameInfo>,
            // memory_address: u64,
            // weight: i32,
            // ff_profile.add_memory_sample(thread_handle, Timestamp::from_millis_since_reference(0.0), frames, addr, weight);

            // oh, we already have the memory address
            // ff_profile.add_memory_sample(thread, timestamp, weight)
        }

        ff_profile.add_memory_sample(thread_handle, Timestamp::from_millis_since_reference(0.0), frames.into_iter(), None, weight as i32)
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

    // output profile to file
    let output_file = std::fs::File::create("profile.json").unwrap();
    serde_json::to_writer(output_file, &ff_profile).unwrap();

    let opt = Opt::parse();
    match opt.action {
        Action::Load(load_args) => {
            let input_file = match File::open(&load_args.file) {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Could not open file {:?}: {}", load_args.file, err);
                    std::process::exit(1)
                }
            };

            // let conversion_props = load_args.conversion_props();
            // let converted_temp_file =
            //     attempt_conversion(&load_args.file, &input_file, conversion_props);
            // let filename = match &converted_temp_file {
            //     Some(temp_file) => temp_file.path(),
            //     None => &load_args.file,
            // };
            // start_server_main(filename, load_args.server_args.server_props());
        }

        #[cfg(any(target_os = "android", target_os = "macos", target_os = "linux"))]
        Action::Record(record_args) => {
            // let server_props = if record_args.save_only {
            //     None
            // } else {
            //     Some(record_args.server_args.server_props())
            // };

            // let recording_props = record_args.recording_props();
            // let conversion_props = record_args.conversion_props();

            if let Some(pid) = record_args.pid {
                tracing::info!("Profiling process with pid {pid}");
                todo!();
                // profiler::start_profiling_pid(pid, recording_props, conversion_props, server_props);
            } else {
                // get the symbol map for this binary
                let symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());
                let path = Path::new(&record_args.command[0]);

                tracing::info!(
                    "Profiling command {command:?} with args {args:?}",
                    command = record_args.command[0],
                    args = &record_args.command[1..]
                );

                let map = symbol_manager
                    .load_symbol_map_for_binary_at_path(path, None)
                    .await
                    .unwrap();

                // iter thru symbols
                let iter_symbols = map.iter_symbols();
                for symbol in iter_symbols {
                    // println!("{:#?}", symbol);
                }

                for (weighted_stack, something) in profile.iter() {
                    for addr in &weighted_stack.addrs {
                        // example of how to add samples

                        // tracing::info!("Looking up {:#x} in {path}", addr, path = path.display());
                        // if let Some(address_info) = map.lookup_relative_address(*addr as u32) {
                        //     tracing::info!(
                        //         "Symbol: {:#x} {name}",
                        //         address_info.symbol.address,
                        //         name = address_info.symbol.name
                        //     );
                        // } else {
                        //     // tracing::info!("No symbol for {:#x} was found.", addr);
                        //     // convert to u64
                        //     // let addr: u64 = (*addr).try_into().unwrap();
                        //     // let offset_res = map.lookup_offset(addr);
                        //     // if let Some(offset) = offset_res {
                        //     //     tracing::info!("Offset map: {:#?}", offset);
                        //     // } else {
                        //     //     tracing::info!("No offset for {:#x} was found.", addr);
                        //     // }

                        //     // let svma_res = map.lookup_svma(addr);
                        //     // if let Some(svma) = svma_res {
                        //     //     tracing::info!("SVMA map: {:#?}", svma);
                        //     // } else {
                        //     //     tracing::info!("No SVMA for {:#x} was found.", addr);
                        //     // }
                        // }
                    }
                }

                // println!("Looking up 0xd6f4 in /usr/bin/ls. Results:");
                // if let Some(address_info) = symbol_map.lookup_relative_address(0xd6f4) {
                //     println!(
                //         "Symbol: {:#x} {}",
                //         address_info.symbol.address, address_info.symbol.name
                //     );
                //     let frames = match address_info.frames {
                //         FramesLookupResult::Available(frames) => Some(frames),
                //         FramesLookupResult::External(ext_ref) => {
                //             symbol_manager
                //                 .lookup_external(&symbol_map.symbol_file_origin(), &ext_ref)
                //                 .await
                //         }
                //         FramesLookupResult::Unavailable => None,
                //     };
                //     if let Some(frames) = frames {
                //         for (i, frame) in frames.into_iter().enumerate() {
                //             let function = frame.function.unwrap();
                //             let file = frame.file_path.unwrap().display_path();
                //             let line = frame.line_number.unwrap();
                //             println!("  #{i:02} {function} at {file}:{line}");
                //         }
                //     }
                // } else {
                //     println!("No symbol for 0xd6f4 was found.");
                // }

                // let exit_status = match profiler::start_recording(
                //     record_args.command[0].clone(),
                //     &record_args.command[1..],
                //     record_args.iteration_count,
                //     recording_props,
                //     conversion_props,
                //     server_props,
                // ) {
                //     Ok(exit_status) => exit_status,
                //     Err(err) => {
                //         eprintln!("Encountered an error during profiling: {err:?}");
                //         std::process::exit(1);
                //     }
                // };
                let exit_status = ExitStatus::from_raw(0);
                std::process::exit(exit_status.code().unwrap_or(0));
            }
        }
    }

    tracing::info!("Goodbye, world deallocating vec of cap {}!", v.capacity());
    tracing::info!("Goodbye, world deallocating vec of cap {}!", v3.capacity());
    tracing::info!("Goodbye, world deallocating vec of cap {}!", v4.capacity());
    tracing::info!("Goodbye, world deallocating vec of cap {}!", v5.capacity());
    tracing::info!("Goodbye, world deallocating vec of cap {}!", v6.capacity());
    tracing::info!("Goodbye, world deallocating vec of cap {}!", v7.capacity());
    v.clear();
    deactivate_jemalloc_profiling(ctl.clone()).await;
}

pub fn alloc_then_dealloc() -> usize {
    let mut v: Vec<u64> = Vec::with_capacity(1024 * 1024 * 1024);
    let half = v.capacity() / 2;
    v.clear();
    half
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

#[allow(unused)]
#[derive(Debug, Args)]
struct RecordArgs {
    /// Do not run a local server after recording.
    #[arg(short, long)]
    save_only: bool,

    /// Sampling rate, in Hz
    #[arg(short, long, default_value = "1000")]
    rate: f64,

    /// Limit the recorded time to the specified number of seconds
    #[arg(short, long)]
    duration: Option<f64>,

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
