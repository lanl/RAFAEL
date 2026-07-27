// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::purger::{write_to_log_file, Cli, PurgeStatistics, SharedLog};

use rustix::fd::BorrowedFd;
use rustix::fs::{statx, AtFlags, Statx, StatxFlags};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY_IN_SECS: i64 = 86_400;

//Run a statx operation on the specified path (File, Symlink, or Dir)
pub fn do_statx(dir_fd: BorrowedFd<'_>, file_path: &PathBuf) -> Result<Statx, String> {
    //Get the specified fields of file metadata
    let Ok(entry_metadata) = statx(
        dir_fd,
        file_path,
        AtFlags::SYMLINK_NOFOLLOW,
        StatxFlags::ATIME
            | StatxFlags::CTIME
            | StatxFlags::MTIME
            | StatxFlags::UID
            | StatxFlags::MODE,
    ) else {
        return Err("Entry statx operation failed".to_string());
    };
    Ok(entry_metadata)
}

pub fn process_file_statx(
    args: &Cli,
    file_path: PathBuf,
    stats: &PurgeStatistics,
    file_metadata: &Statx,
    worker_log_file: &SharedLog,
) -> bool {
    //Increment Statistics for files checked
    stats.files_checked.fetch_add(1, Ordering::Relaxed);

    //Check if the file is purgable
    let purgable = is_entry_purgable(args, &file_metadata, 0, false);

    if purgable {
        if !args.dry_run {
            match fs::remove_file(&file_path) {
                Ok(_) => {
                    stats.files_purged.fetch_add(1, Ordering::Relaxed);

                    //Write to local log file
                    write_to_log_file(
                        false,
                        &worker_log_file,
                        &file_path,
                        file_metadata.stx_atime.tv_sec,
                        file_metadata.stx_ctime.tv_sec,
                        file_metadata.stx_mtime.tv_sec,
                        file_metadata.stx_uid,
                    );
                    return true;
                }
                Err(e) => {
                    eprintln!("Error deleting {}: {}", file_path.display().to_string(), e);
                    return false;
                }
            }
        } else {
            //Increment number of files that would have been purged
            stats.files_purged.fetch_add(1, Ordering::Relaxed);

            //Write to local log file
            write_to_log_file(
                true,
                &worker_log_file,
                &file_path,
                file_metadata.stx_atime.tv_sec,
                file_metadata.stx_ctime.tv_sec,
                file_metadata.stx_mtime.tv_sec,
                file_metadata.stx_uid,
            );
            return true;
        }
        //File was not purged and the directory was found to be purgable at the start
        //So now this directory we are in is no longer purgable
    } else {
        return false;
    }
}

pub fn is_entry_purgable(
    args: &Cli,
    metadata: &Statx,
    components_count: usize,
    is_dir: bool,
) -> bool {
    if is_dir && (args.root.components().count() + args.depth_protection >= components_count) {
        return false;
    }

    if args.erase {
        return true;
    }

    if metadata.stx_uid == 0 {
        return false;
    }

    let age = if args.ignore_ctime {
        std::cmp::max(metadata.stx_atime.tv_sec, metadata.stx_mtime.tv_sec)
    } else {
        three_way_max(
            metadata.stx_atime.tv_sec,
            metadata.stx_ctime.tv_sec,
            metadata.stx_mtime.tv_sec,
        )
    };

    //Might make this a statment later on rather than assigning to a variable
    let threshold = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Epoch calculation error")
        .as_secs() as i64
        - (DAY_IN_SECS * args.age);

    //check if any timestamps are older than age specific in command line arguments
    age < threshold
}

fn three_way_max(t1: i64, t2: i64, t3: i64) -> i64 {
    std::cmp::max(t1, std::cmp::max(t2, t3))
}
