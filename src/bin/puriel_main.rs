// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::puriel_utils::{Cli, puriel_main, display_puriel_results};
use rafael::syslog_utility::send_puriel_syslog_message;

use chrono::Local;
use clap::Parser;
use std::fs;
use std::path::PathBuf;

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



    send_puriel_syslog_message(None, &args, true);

    let results = puriel_main(&args, start);

    display_puriel_results(results, &args);


}
