// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::puriel_utils::{Cli, PurielStatistics, puriel_main};

use chrono::Local;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
//use rafael::syslog_utility::send_syslog_message;

fn main() {
    //Benchmarking variable
    let start = std::time::Instant::now();

    let mut args = Cli::parse();

    //Create log directory from command line arguments with current date and time
    args.pr_log_dir = PathBuf::from(format!(
        "{}_{}",
        args.pr_log_dir.display(),
        Local::now().format("%m-%d-%Y_%H:%M:%S").to_string()
    ));
    let _ = fs::create_dir(&args.pr_log_dir);

    //Create our Puriel statistics
    let puriel_stats = PurielStatistics {
        targets_found: AtomicUsize::new(0),
        targets_purged: AtomicUsize::new(0),
    };

    puriel_main(&args, &puriel_stats, start);
}
