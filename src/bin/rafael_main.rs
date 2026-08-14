// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::purger::{Cli, display_purge_results};
use rafael::purger_main::purge_fs;
use rafael::syslog_utility::send_syslog_message;

use clap::Parser;
use std::io;

fn main() -> io::Result<()> {
    let now = std::time::Instant::now();

    //Extract command line arguments from clap struct
    let mut args = Cli::parse();
    let mut argument_error: bool = false;

    if args.verbosity > 2 {
        eprintln!("Error: Verbosity level must be between 0 and 2.");
        argument_error = true;
    }

    //Ensure that either age or erase option was passed and not both
    if args.age >= 0 && args.erase {
        eprintln!("Error: Cannot specify both --age and --erase.");
        argument_error = true;
    } else if args.age <= -1 && !args.erase {
        eprintln!("Error: Must specify --age or --erase.");
        argument_error = true;
    }

    if argument_error {
        std::process::exit(1);
    }

    //Send Syslog start message
    send_syslog_message(None, &args, true);

    //Set up our environment logger
    env_logger::init();

    //Start purge
    let results = purge_fs(&mut args);

    //Display our results and send a syslog message with our results
    display_purge_results(&mut args, results, now);
    Ok(())
}
