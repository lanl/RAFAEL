// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use clap::Parser;
use filetime::{FileTime, set_file_times};
use rayon::prelude::*;
use std::{
    fs,
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const THIRTY_DAYS_IN_SECS: i64 = 2592000;

#[derive(Parser, Debug)]
pub struct Cli {
    /// Root of tree to generate.
    pub root: String,

    /// Depth of tree.
    #[arg(short = 'd', long, default_value_t = 2)]
    pub depth: u32,

    /// Branching factor.
    #[arg(short = 'b', long, default_value_t = 2)]
    pub branching_factor: u32,

    /// File count per directory.
    #[arg(short = 'c', long, default_value_t = 2)]
    pub file_count: u32,

    /// Verbose
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Interactive
    #[arg(short = 'i', long)]
    pub interactive: bool,

    /// Force creation even if root directory already exists.
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Deterministic purgable output, even dirs will be purgable and odd dirs will not
    #[arg(short = 'p', long)]
    pub purgable: bool,

    /// Write data to each file (in bytes), can view total size of file you will create with -i flag
    #[arg(short = 'w', long, default_value_t = 0)]
    pub data_size: u32,
}

pub struct MakeTreeStatistics {
    pub num_files: u64,
    pub num_dirs: u64,
}

pub fn make_tree(args: Cli) -> io::Result<MakeTreeStatistics> {
    let root = &args.root;

    let mut total_dirs: u64 = 0;
    for i in 0..=args.depth {
        total_dirs += u64::from(args.branching_factor).pow(i as u32);
    }
    let number_of_files = (total_dirs as i64 - 1) as u64 * args.file_count as u64;
    let total_size_of_files = (total_dirs - 1) * args.file_count as u64 * args.data_size as u64;

    let return_stats = MakeTreeStatistics {
        num_files: number_of_files,
        num_dirs: total_dirs,
    };

    if args.verbose || args.interactive {
        println!(
            "Make tree will produce {} directories with current parameters\n\
                Make tree will produce {} files with current parameters\n",
            total_dirs,
            (total_dirs as i64 - 1) as u64 * args.file_count as u64
        );
        if args.data_size > 0 {
            println!(
                "Make tree will produce {} worth of file data with current parameters",
                display_size(total_size_of_files)
            );
        }
    }
    if args.interactive {
        println!("Press any key to conintue...");
        let _ = io::stdin().read(&mut [0u8]).unwrap();
    }

    match fs::create_dir(&root) {
        Ok(()) => {}
        Err(e) => {
            if !(e.kind() == io::ErrorKind::AlreadyExists && args.force) {
                return Err(e);
            }
        }
    };

    make_subtree(&root, args.depth, &args, None)?;
    Ok(return_stats)
}

/// Creates a subtree of depth `depth` under `parent`.
///
/// Assumes `parent` exists.
fn make_subtree(
    parent: &str,
    depth: u32,
    args: &Cli,
    purgable_recursion_flag: Option<bool>,
) -> io::Result<()> {
    if depth == 0 {
        return Ok(());
    }
    (0..args.branching_factor).into_par_iter().for_each(|i| {
        let path = format!("{}/subdir_{}", parent, i);
        // TODO: do something about errors here...
        let _ = fs::create_dir(&path);

        //Generate files for directory
        (0..args.file_count).into_par_iter().for_each(|j| {
            let fpath = format!("{}/{}.txt", path, j);

            let mut file = fs::File::create(&fpath).unwrap();

            if args.data_size > 0 {
                file.write_all(&vec![0u8; args.data_size as usize]).unwrap();
            }

            //Even directoires will have purgable files
            //Odd dirs will have purgable even numbered files and nonpurgable odd numbered files
            match purgable_recursion_flag {
                None => {
                    if i % 2 == 0 {
                        set_timestamps(&fpath, args)
                    } else if i % 2 != 0 && j % 2 == 0 {
                        set_timestamps(&fpath, args)
                    } else {
                    }
                }
                Some(true) => {
                    set_timestamps(&fpath, args);
                }
                Some(false) => {
                    if j % 2 == 0 {
                        set_timestamps(&fpath, args);
                    } else {
                    }
                }
            }
        });
        //Handle directory timestamps
        match purgable_recursion_flag {
            //First loop
            None => {
                //Even Directories
                if i % 2 == 0 {
                    let _ = make_subtree(&path, depth - 1, args, Some(true));
                    set_timestamps(&path, args);
                }
                //Odd Directories
                else {
                    let _ = make_subtree(&path, depth - 1, args, Some(false));
                }
            }
            //Additional Loops
            //Even Directories
            Some(true) => {
                let _ = make_subtree(&path, depth - 1, args, Some(true));
                set_timestamps(&path, args);
            }
            //Odd Directories
            Some(false) => {
                let _ = make_subtree(&path, depth - 1, args, Some(false));
            }
        }
    });
    Ok(())
}

/// If a file or directory should be purgeable, then sets its timestamps to > 30 days ago.
fn set_timestamps(path: &str, args: &Cli) {
    if !args.purgable {
        return;
    }
    let purgable_time = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Epoch calculation error")
        .as_secs() as i64)
        - THIRTY_DAYS_IN_SECS * 2;

    let a_time = FileTime::from_unix_time(purgable_time, 0);
    let m_time = FileTime::from_unix_time(purgable_time, 0);

    set_file_times(&path, a_time, m_time).unwrap();
}

fn display_size(size: u64) -> String {
    let suffixes = ["B", "KiB", "MiB", "GiB", "TiB"];

    let mut i = 0;
    let mut size = size as f64;
    while size >= 1024. && i < suffixes.len() - 1 {
        size = size / 1024.;
        i += 1;
    }

    format!("{:.2}{}", size, suffixes[i])
}
