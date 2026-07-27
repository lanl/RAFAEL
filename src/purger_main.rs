// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::purger::{
    get_used_inodes, root_dir_walk, thread_main, Cli, PurgeResults, PurgeStatistics, WorkItem,
};
use crate::safra::SafraTerminator;

// use rafael::syslog_utility::send_syslog_message;
use chrono::Local;
use crossbeam::queue::SegQueue;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

pub fn purge_fs(args: &mut Cli) -> PurgeResults {
    //Benchmarking variable
    let start = std::time::Instant::now();

    // Directory Statistics (Directories purged, Directory Size Purged)
    let directories_purged_stats = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));

    // Statistics and performance metrics
    // Wrap them in Arc and Mutex
    // 0 in front of u32 is the initial value of the mutex
    let stats = PurgeStatistics {
        files_checked: AtomicUsize::new(0),
        files_purged: AtomicUsize::new(0),
        directories_checked: AtomicUsize::new(0),
        directories_purged: AtomicUsize::new(0),
    };

    // Create a Vector of worker queues to be shared among threads
    let top_level_queues: Vec<SegQueue<WorkItem>> = (0..args.thread_count)
        .map(|_| SegQueue::<WorkItem>::new())
        .collect();

    //Create log directory from command line arguments with current date and time
    args.rp_log_dir = PathBuf::from(format!(
        "{}_{}",
        args.rp_log_dir.display(),
        Local::now().format("%m-%d-%Y_%H:%M:%S").to_string()
    ));
    let _ = fs::create_dir(&args.rp_log_dir);

    //Check if an exception/purning file was passed
    let mut exceptions: Vec<String> = Vec::new();

    //Using unwrap on open(path) because we want the program to panic if the
    //Exception file cannot be read, we have no idea what it would delete at that point.
    let buf = BufReader::new(fs::File::open(&args.exception).unwrap());
    for exception in buf.lines() {
        match exception {
            //Lowercase strings from exception file to follow case insensitive exceptions
            Ok(content) => exceptions.push(content.to_lowercase()),
            //Same here we want it to panic if it cannot read a line
            //As that could end up deleting someones entire directory.
            Err(e) => panic!(
                "Error reading line in exception/pruning file.\
            \nCannot proceed safely with program: {}",
                e
            ),
        }
    }

    //Check if the status bar is set and if an entry count was pass, otherwise calculate the used inodes in the root dir
    if args.show_progress && args.entry_count == 0 {
        args.entry_count = get_used_inodes(&args.root);
    }

    // First "thread" that reads directories in root path
    let _ = root_dir_walk(&args, &stats, &top_level_queues, &exceptions);

    let term = SafraTerminator::new();

    // Main thread function
    thread_main(
        &args,
        &stats,
        &Arc::clone(&directories_purged_stats),
        &top_level_queues,
        &exceptions,
        &term,
        &start,
    );

    let return_results = PurgeResults {
        purge_statistics: stats,
        time: start.elapsed(),
        directories_purged_statistics: directories_purged_stats,
    };

    return_results
}
