// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::purger::{write_to_log_file, Cli, PurgeStatistics, SharedLog};
use crate::puriel_utils::write_to_puriel_target_file;

use rustix::fd::BorrowedFd;
use rustix::fs::{statx, AtFlags, Statx, StatxFlags};
use std::fs;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

const DAY_IN_SECS: i64 = 86_400;

pub enum EntryPurgeState {
    NotPurgable,
    PurgeNow,
    PurgeLater,
}

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
    worker_puriel_target_file: &mut Option<BufWriter<fs::File>>,
) -> bool {
    //Increment Statistics for files checked
    stats.files_checked.fetch_add(1, Ordering::Relaxed);

    //Check if the file is purgable
    let purge_state = is_entry_purgable(args, &file_metadata, 0, false);

    //Check if we need to purge the file now, later, or if it is not purgable at all.
    match purge_state {
        EntryPurgeState::PurgeNow => {
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
        }
        //If We received a file that is eligible for a later purge we write it to a puriel target file.
        //We will still return false for the function so as to update any parent dirs to no longer be purgable.
        EntryPurgeState::PurgeLater => {
            write_to_puriel_target_file(worker_puriel_target_file, &file_path);
            return false;
        }
        //File was not purged and the directory was found to be purgable at the start
        //So now this directory we are in is no longer purgable
        EntryPurgeState::NotPurgable => {
            return false;
        }
    }
}

pub fn is_entry_purgable(
    args: &Cli,
    metadata: &Statx,
    components_count: usize,
    is_dir: bool,
) -> EntryPurgeState {
    if is_dir && (args.root.components().count() + args.depth_protection >= components_count) {
        return EntryPurgeState::NotPurgable;
    }

    if args.erase {
        return EntryPurgeState::PurgeNow;
    }

    if metadata.stx_uid == 0 {
        return EntryPurgeState::NotPurgable;
    }

    let newest_file_time = if args.ignore_ctime {
        std::cmp::max(metadata.stx_atime.tv_sec, metadata.stx_mtime.tv_sec)
    } else {
        three_way_max(
            metadata.stx_atime.tv_sec,
            metadata.stx_ctime.tv_sec,
            metadata.stx_mtime.tv_sec,
        )
    };

    //Check if any timestamps are older than age specific in command line arguments.
    //If puriel is enabled check if the entry will be purgable in X amount of days in the future.
    if args.enable_puriel && !is_dir{
        //If puriel is enabled then initialize a current epoch time variable as it will also be used for puriel calculations.
        let current_epoch_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Epoch calculation error")
            .as_secs() as i64;

        //If the entry was found to be purgable right now then there is no need to do a puriel calculation.
        if newest_file_time < (current_epoch_time - (DAY_IN_SECS * args.age)) {
            return EntryPurgeState::PurgeNow;
        } else {
            //Do Puriel Calculations, I.E. if we are x days in the future is the entry older than our current age threshold in days
            if newest_file_time
                < (current_epoch_time + (DAY_IN_SECS * args.puriel_days - DAY_IN_SECS * args.age))
            {
                return EntryPurgeState::PurgeLater;
            } else {
                //Entry was found to not be purgable now or x days into the future
                return EntryPurgeState::NotPurgable;
            }
        }
    //If we do not have puriel enabled then we will calulate if the age of entry qualifies for purging without initializing the threshold variable.
    } else {
        if newest_file_time
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Epoch Calcuation error")
                .as_secs() as i64
                - (DAY_IN_SECS * args.age)
        {
            return EntryPurgeState::PurgeNow;
        } else {
            return EntryPurgeState::NotPurgable;
        }
    }
}

fn three_way_max(t1: i64, t2: i64, t3: i64) -> i64 {
    std::cmp::max(t1, std::cmp::max(t2, t3))
}

