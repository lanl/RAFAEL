// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::purger::{write_to_log_file, SharedLog};

use rustix::fs::Statx;
use std::fs;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

//Custom MetaData Struct to reduce memory consumption
struct PurgerMetadata {
    atime: i64,
    ctime: i64,
    mtime: i64,
    uid: u32,
}

//Takes a std::fs Metadata Struct and pulls out what we need for comparisons, logs, and statistics
impl PurgerMetadata {
    fn new(atime: i64, ctime: i64, mtime: i64, uid: u32) -> PurgerMetadata {
        PurgerMetadata {
            atime,
            ctime,
            mtime,
            uid,
        }
    }
}

//Purge Candidate Tree
//#[derive(Debug)]
pub struct PurgeCandidate {
    path: PathBuf,
    parent: Option<Arc<PurgeCandidate>>,
    directories_purged_stats: Arc<(AtomicUsize, AtomicUsize)>,
    delete: AtomicBool,
    dry_run: bool,
    worker_log_file: SharedLog,
    md: PurgerMetadata,
}

impl std::fmt::Display for PurgeCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Node path: {}, Parent Path: {}, Deleteable: {}",
            self.path.display(),
            if let Some(ref parent) = self.parent {
                parent.path.display().to_string()
            } else {
                "NO PARENT".to_string()
            },
            self.delete.load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}
impl PurgeCandidate {
    pub fn new(
        path: &PathBuf,
        parent: Option<Arc<PurgeCandidate>>,
        directories_purged_stats: Arc<(AtomicUsize, AtomicUsize)>,
        dry_run: bool,
        worker_log_file: SharedLog,
        statx_md: Statx,
    ) -> PurgeCandidate {
        PurgeCandidate {
            path: path.clone(),
            parent,
            directories_purged_stats,
            delete: AtomicBool::new(true),
            dry_run,
            worker_log_file,
            md: PurgerMetadata::new(
                statx_md.stx_atime.tv_sec,
                statx_md.stx_ctime.tv_sec,
                statx_md.stx_mtime.tv_sec,
                statx_md.stx_uid,
            ),
        }
    }

    //Will only ever be called when setting delete to false
    //Delete cannot go back to true after it has become false
    //Calling this funciton will also update parents delete flag to be false
    pub fn set_delete_flag(&self) {
        //Set atomic bool delete to false
        let _ = &self
            .delete
            .store(false, std::sync::atomic::Ordering::Relaxed);

        //Since we have set our delete flag as false we must do it to our parent(if it exists)
        let _ = &self.set_parent_delete_false();
    }

    fn set_parent_delete_false(&self) {
        //Check for parents existence
        if let Some(parent) = &self.parent {
            //Lock parent and set its delete flag to false
            parent
                .delete
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl Drop for PurgeCandidate {
    fn drop(&mut self) {
        if self.delete.load(std::sync::atomic::Ordering::Relaxed) {
            if !self.dry_run {
                // println!("Dropping a node from the purge tree");
                match fs::remove_dir(&self.path) {
                    Ok(_) => {
                        //Increment Number of directories purged
                        self.directories_purged_stats
                            .0
                            .fetch_add(1, Ordering::Relaxed);

                        //Write to log file
                        write_to_log_file(
                            false,
                            &self.worker_log_file,
                            &self.path,
                            self.md.atime,
                            self.md.ctime,
                            self.md.mtime,
                            self.md.uid,
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "Error PurgeCandidate DROP trait: {}: {}",
                            e,
                            &self.path.display()
                        );
                    }
                }
            } else {
                //Increment Number of directories purged
                self.directories_purged_stats
                    .0
                    .fetch_add(1, Ordering::Relaxed);

                //Write to log file
                write_to_log_file(
                    true,
                    &self.worker_log_file,
                    &self.path,
                    self.md.atime,
                    self.md.ctime,
                    self.md.mtime,
                    self.md.uid,
                );
            }
        //If the node is not deletable then it must update the parent before it is dropped
        //To ensure both its directory and its parents directory are not deleted
        } else {
            self.set_parent_delete_false();
        }
    }
}
