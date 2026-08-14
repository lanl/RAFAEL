// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::puriel_utils::{Cli, display_puriel_results, puriel_main};
use rafael::syslog_utility::send_puriel_syslog_message;

use clap::Parser;

fn main() {
    //Benchmarking variable
    let start = std::time::Instant::now();

    let mut args = Cli::parse();

    send_puriel_syslog_message(None, &args, true);

    let results = puriel_main(&mut args, start);

    display_puriel_results(results, &args);
}
