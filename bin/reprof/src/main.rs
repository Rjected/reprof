//! # Reprof
//!
//! `reprof` is a simple example of how to use the `jemalloc-pprof` crate and firefox profiler to
//! visualize jemalloc heap profiles.
use std::{
    fs::File, io::BufReader, os::unix::process::ExitStatusExt, path::PathBuf, process::ExitStatus,
    sync::Arc,
};

use clap::{Args, Parser, Subcommand};
use jemalloc_pprof::{JemallocProfCtl, PROF_CTL};
use tikv_jemallocator::Jemalloc;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    if let Some(file) = dump_jemalloc_profile(ctl.clone()).await {
        // Open and read the profile.
        let dump_reader = BufReader::new(file);
        let profile = jemalloc_pprof::internal::parse_jeheap(dump_reader).unwrap();
        println!("{:#?}", profile);

        // Open the profile in firefox.
    }

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
    v.clear();
    deactivate_jemalloc_profiling(ctl.clone()).await;
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
