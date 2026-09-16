// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::puriel_utils::{Cli, display_puriel_results, purge_fs};
use rafael::syslog::send_puriel_syslog_message;

use clap::Parser;
use std::io;

fn main() -> io::Result<()> {
    //Benchmarking variable
    let start = std::time::Instant::now();

    let mut args = Cli::parse();

    let mut argument_error: bool = false;
    if args.age <= 0 {
        eprintln!("Invalid puriel age, Exiting.");
        argument_error = true;
    }

    if argument_error {
        std::process::exit(1);
    }

    //Send Puriel syslog start message
    send_puriel_syslog_message(None, &args, true);

    //Start puriel purge
    let results = purge_fs(&mut args, start);

    display_puriel_results(results, &args);
    Ok(())
}
