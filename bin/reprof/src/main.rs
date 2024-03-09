//! # Reprof
//!
//! `reprof` is a simple example of how to use the `jemalloc-pprof` crate and firefox profiler to
//! visualize jemalloc heap profiles.
use std::{fs::File, sync::Arc, io::BufReader};

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
    // let mut v: Vec<u64> = Vec::new();

    if let Some(file) = dump_jemalloc_profile(ctl.clone()).await {
        // Open and read the profile.
        let dump_reader = BufReader::new(file);
        let profile = jemalloc_pprof::internal::parse_jeheap(dump_reader).unwrap();
        println!("{:#?}", profile);

        // Open the profile in firefox.
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
