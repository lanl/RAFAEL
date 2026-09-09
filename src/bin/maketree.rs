// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use clap::Parser;
use rafael::maketree::{Cli, make_tree};
use std::io;

fn main() -> io::Result<()> {
    let args = Cli::parse();

    let _ = make_tree(args)?;

    Ok(())
}
