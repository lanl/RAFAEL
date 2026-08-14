// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::metadata_utils::EntryPurgeState;

use clap::Parser;
use filetime::{FileTime, set_file_times};
use rayon::prelude::*;
use std::{
    fs,
    io::{self, Read, Write},
    time::{SystemTime, UNIX_EPOCH},
};

const DAY_IN_SECS: i64 = 86_400;

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

    /// Create an unbalanced purgable tree, where some files will be purgable now and others will be purgable at later date, to be used for puriel testing.
    #[arg(short = 'u', long)]
    pub unbalanced: bool,
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
                        //Within our even directories if we are making an unbalanced tree then all even numbered files will be purgable later
                        if j % 2 == 0 && args.unbalanced {
                            set_timestamps(&fpath, EntryPurgeState::PurgeLater)
                        } else {
                            set_timestamps(&fpath, EntryPurgeState::PurgeNow);
                        }
                    } else if i % 2 != 0 && j % 2 == 0 {
                        set_timestamps(&fpath, EntryPurgeState::PurgeNow);
                    } else {
                    }
                }
                Some(true) => {
                    //Within our even directories if we are making an unbalanced tree then all even numbered files will be purgable later
                    if j % 2 == 0 && args.unbalanced {
                        set_timestamps(&fpath, EntryPurgeState::PurgeLater)
                    } else {
                        set_timestamps(&fpath, EntryPurgeState::PurgeNow);
                    }
                }
                Some(false) => {
                    if j % 2 == 0 {
                        set_timestamps(&fpath, EntryPurgeState::PurgeNow);
                    } else {
                    }
                }
            }
        });
        //Handle directory timestamps
        match purgable_recursion_flag {
            //First loop
            None => {
                //Even Directories will be purgable
                if i % 2 == 0 {
                    let _ = make_subtree(&path, depth - 1, args, Some(true));
                    set_timestamps(&path, EntryPurgeState::PurgeNow);
                }
                //Odd Directories will not be purgable
                else {
                    let _ = make_subtree(&path, depth - 1, args, Some(false));
                }
            }
            //Additional Loops
            //Even Directories
            Some(true) => {
                let _ = make_subtree(&path, depth - 1, args, Some(true));
                set_timestamps(&path, EntryPurgeState::PurgeNow);
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
fn set_timestamps(path: &str, state: EntryPurgeState) {
    match state {
        //Not Purgable will only return as that will be the non-purgable entries
        EntryPurgeState::NotPurgable => {
            return;
        }
        //Purgable Now will be 31 Days old, this is because in production and therefor in our tests we do a purge time of 30 days
        EntryPurgeState::PurgeNow => {
            let purgable_time = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Epoch calculation error")
                .as_secs() as i64)
                - DAY_IN_SECS * 31;

            let a_time = FileTime::from_unix_time(purgable_time, 0);
            let m_time = FileTime::from_unix_time(purgable_time, 0);

            set_file_times(&path, a_time, m_time).unwrap();
        }
        //Purge later, for puriel testing and unbalanced trees, will be 24 Days old.
        //Because puriel is run a week after the main purger in 7 days these entries will be 31 days old and therefor purgable in the future
        EntryPurgeState::PurgeLater => {
            let purgable_time = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Epoch calculation error")
                .as_secs() as i64)
                - DAY_IN_SECS * 24;

            let a_time = FileTime::from_unix_time(purgable_time, 0);
            let m_time = FileTime::from_unix_time(purgable_time, 0);

            set_file_times(&path, a_time, m_time).unwrap();
        }
    }
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
