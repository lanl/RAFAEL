// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

pub fn write_to_puriel_target_file(
    puriel_target_file: &mut Option<BufWriter<fs::File>>,
    target_path: &PathBuf
){
    if let Err(e) = writeln!(
        match puriel_target_file{
            Some(f) => f,
            None => {
                eprintln!("Error Unwraping puriel target file");
                return
            },
        },
        "{}", target_path.display()
    ) {
        eprintln!("Error writing to puriel target file: {}", e);
    }
}