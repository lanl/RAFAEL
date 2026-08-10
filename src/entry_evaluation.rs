// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::metadata_utils::*;
use crate::purge_tree_utils::PurgeCandidate;
use crate::purger::{Cli, PurgeStatistics, SharedLog, WorkItem, is_dir_an_exception};

use crossbeam::queue::SegQueue;
use log::debug;
use nix::dir::Entry;
use nix::errno::Errno;
use nix::sys::stat::SFlag;
use rustix::fd::BorrowedFd;
use std::ffi::CStr;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn evaluate_entry(
    entry_result: Result<Entry, Errno>,
    args: &Cli,
    dir_fd: BorrowedFd,
    count: &usize,
    current_local_dir_path: &PathBuf,
    exceptions: &Vec<String>,
    is_directory_purgable: &mut bool,
    stats: &PurgeStatistics,
    worker_queues: &Vec<SegQueue<WorkItem>>,
    worker_log_file: &SharedLog,
    worker_puriel_target_file: &mut Option<BufWriter<fs::File>>,
    new_parent: &Option<Arc<PurgeCandidate>>,
) {
    let entry = match entry_result {
        Ok(e) => e,
        Err(err) => {
            eprintln!("ERROR READING ENTRY: {}", err);
            *is_directory_purgable = false;
            return;
        }
    };

    //When we get the . and .. directories just return from the function
    let entry_name = entry.file_name();
    if entry_name == c"." || entry_name == c".." {
        return;
    }

    //Create our full entry path only after we have gone thorugh the "." and ".." case as those are gurantees
    let entry_path = cstr_to_pathbuf_with_dir(&entry_name, current_local_dir_path);

    //Run statx on the entry
    match do_statx(dir_fd, &entry_path) {
        Ok(entry_metadata) => {
            //Use S_IFMT, the bitmask for file type, to extract our file type
            let entry_file_type =
                SFlag::from_bits_truncate(entry_metadata.stx_mode.into()) & SFlag::S_IFMT;
            match entry_file_type {
                //Directory
                SFlag::S_IFDIR => {
                    let temp_item = WorkItem {
                        path: cstr_to_pathbuf_with_dir(
                            &entry_name.to_owned(),
                            current_local_dir_path,
                        ),
                        parent: new_parent.clone(),
                    };
                    //Check if directory is an exception/prunable, if so dont add it to a work queue
                    //Or if the directory is owned by root, if so also don't add it to a work queue
                    if is_dir_an_exception(
                        exceptions,
                        &cstr_to_pathbuf_with_dir(&entry_name, current_local_dir_path)
                            .display()
                            .to_string()
                            .to_lowercase(),
                    ) {
                        //Because the dir was either an exception or owned by root, we have to
                        //Update the temp_items parent, I.E. the current dir, to not be deletable
                        if let Some(ref parent) = temp_item.parent {
                            parent.set_delete_flag();
                        }
                    //Otherwise add the dir to a work queue
                    } else {
                        //ROUND ROBIN ASSIGNMENT:
                        worker_queues[count % args.thread_count].push(temp_item);
                    }
                }
                //Regular File, Socket, or Symlink
                SFlag::S_IFREG | SFlag::S_IFSOCK | SFlag::S_IFLNK => {
                    match process_file_statx(
                        args,
                        cstr_to_pathbuf_with_dir(&entry_name, current_local_dir_path),
                        stats,
                        &entry_metadata,
                        worker_log_file,
                        worker_puriel_target_file,
                    ) {
                        true => {
                            debug!("PURGABLE ENTRY: {}", entry_path.display());
                        }
                        false => {
                            if *is_directory_purgable {
                                debug!(
                                    "DIR {}, NO LONGER PURGABLE, NON-PURGABLE ENTRY: {}",
                                    current_local_dir_path.display(),
                                    entry_path.display()
                                );
                            } else {
                                debug!("NON-PURGABLE ENTRY: {}", entry_path.display());
                            }
                            *is_directory_purgable = false;
                        }
                    }
                }
                //Block Device, Character, or FIFO
                SFlag::S_IFBLK | SFlag::S_IFCHR | SFlag::S_IFIFO => {
                    //Since we do not delete block, character, or FIFO devices we have to update the directory to not be purgable.
                    debug!(
                        "DIR {}, NO LONGER PURGABLE DUE TO {} being a block, character, or FIFO file.",
                        current_local_dir_path.display(),
                        entry_path.display()
                    );
                    *is_directory_purgable = false;
                }
                //Unkown File type
                _ => {
                    debug!("UKNOWN FILE TYPE FOR ENTRY: {}", entry_path.display());
                    *is_directory_purgable = false;
                }
            }
        }
        Err(err) => {
            //If we cannot get the metadata for an entry then the directory can no longer be purgable.
            debug!(
                "CANNOT AQUIRE METADATA FOR ENTRY: {}, Error: {}",
                entry_path.display(),
                err
            );
            *is_directory_purgable = false;
        }
    }
}

fn cstr_to_pathbuf_with_dir(cstr: &CStr, dir: &Path) -> PathBuf {
    use std::ffi::{CString, OsString};

    let mut path = PathBuf::from(dir);
    let basename =
        unsafe { OsString::from_encoded_bytes_unchecked(CString::from(cstr).as_bytes().to_vec()) };
    path.push(&basename);
    path
}
