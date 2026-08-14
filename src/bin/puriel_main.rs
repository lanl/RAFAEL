// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use rafael::puriel_utils::{Cli, display_puriel_results, puriel_main};

use clap::Parser;

fn main() {
    //Benchmarking variable
    let start = std::time::Instant::now();

    let mut args = Cli::parse();

    let results = puriel_main(&mut args, start);

    display_puriel_results(results, &args);
}
