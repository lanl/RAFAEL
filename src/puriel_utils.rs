// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::metadata_utils::{EntryPurgeState, do_statx_cwd, process_puriel_statx};
use crate::syslog_utility::send_puriel_syslog_message;

use clap::Parser;
use crossbeam::queue::SegQueue;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "puriel",
    version = "0.1",
    about = "\nPuriel: Purge Utility for Removing Indexed and Expired Leftovers"
)]

pub struct Cli {
    /// Puriel Targets Directory, should contain absolute path of files rafael has marked to investiage.
    #[arg(short = 'd', long)]
    pub puriel_target_dir: PathBuf,

    /// Log directory, default of pr_log_dir in current directory.
    #[arg(short = 'l', long)]
    #[arg(default_value = "pr_log_dir")]
    pub pr_log_dir: PathBuf,

    /// Age of files to delete, in days
    #[arg(short = 'a', long)]
    #[arg(default_value_t = -1)]
    pub age: i64,

    /// Thread count, Default of 4 threads.
    #[arg(short = 't', long)]
    #[arg(default_value_t = 4)] // Default of 4 threads
    pub thread_count: usize,

    /// Dry Run mode, will not delete directories or files that are purgable
    #[arg(long)]
    pub dry_run: bool,
}

pub struct PurielStatistics {
    pub targets_found: AtomicUsize,
    pub targets_purged: AtomicUsize,
    pub target_statx_errors: AtomicUsize,
}

pub struct PurielResults {
    pub stats: PurielStatistics,
    pub time: Duration,
}

// Reads in our puriel files and loads the targets into multiple segqueues based on number of threads
fn populate_worker_queues(
    args: &Cli,
) -> Result<(usize, Vec<crossbeam::queue::SegQueue<PathBuf>>), String> {
    //Creat our vector of targets, absolute paths
    let mut target_paths = Vec::new();

    //Get the target files from the puriel target directory
    for entry in fs::read_dir(&args.puriel_target_dir).unwrap() {
        let puriel_target_file = entry.unwrap();
        let ptf_path = puriel_target_file.path();

        //Open our target file in read only
        let file = match File::open(&ptf_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "Error opening puriel target file {}, {}",
                    ptf_path.display(),
                    e
                );
                std::process::exit(1);
            }
        };
        for line in BufReader::new(file).lines() {
            match line {
                Ok(target) => {
                    target_paths.push(target);
                }
                Err(e) => {
                    eprintln!(
                        "Error reading line from target file {}, {}",
                        ptf_path.display(),
                        e
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    //Get the number of targets we have collected
    let number_of_targets = target_paths.len();

    // Create a Vector of worker queues to be shared among threads
    let worker_queues: Vec<SegQueue<PathBuf>> = (0..args.thread_count)
        .map(|_| SegQueue::<PathBuf>::new())
        .collect();

    // Loop through our targets and add them to our various segqueues
    for (index, target) in target_paths.iter().enumerate() {
        worker_queues[index % args.thread_count].push(PathBuf::from(target))
    }
    Ok((number_of_targets, worker_queues))
}

fn launch_workers(
    args: &Cli,
    mut worker_queues: Vec<SegQueue<PathBuf>>,
    puriel_stats: &PurielStatistics,
) {
    thread::scope(|s| {
        for i in 0..args.thread_count {
            let worker_queue = match worker_queues.pop() {
                Some(sq) => sq,
                None => {
                    eprintln!("Error: on worker queues empty.");
                    std::process::exit(1);
                }
            };
            s.spawn(move || worker_main(&args, i as usize, worker_queue, puriel_stats));
        }
    })
}

fn worker_main(
    args: &Cli,
    thread_index: usize,
    worker_queue: SegQueue<PathBuf>,
    puriel_stats: &PurielStatistics,
) {
    //Create Thread x's log file
    let mut worker_log_file = match OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(
            &args
                .pr_log_dir
                .join(format!("worker-{}-age-{}.log", thread_index, &args.age)),
        ) {
        Ok(f) => BufWriter::new(f),
        Err(e) => {
            eprintln!("Thread {} failed to create log file: {}", thread_index, e);
            return;
        }
    };

    //Begin going through our non-shared worker queue and evaluating targets
    while let Some(target) = worker_queue.pop() {
        let target_metadata = match do_statx_cwd(&target) {
            Ok(metadata) => metadata,
            Err(_) => {
                puriel_stats
                    .target_statx_errors
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        match process_puriel_statx(&target_metadata, args) {
            EntryPurgeState::PurgeNow => match args.dry_run {
                false => match fs::remove_file(&target) {
                    Ok(_) => {
                        puriel_stats.targets_purged.fetch_add(1, Ordering::Relaxed);
                        write_to_puriuel_log_file(
                            args.dry_run,
                            &mut worker_log_file,
                            &target,
                            target_metadata.stx_atime.tv_sec,
                            target_metadata.stx_ctime.tv_sec,
                            target_metadata.stx_mtime.tv_sec,
                            target_metadata.stx_uid,
                        )
                    }
                    Err(e) => {
                        eprintln!("Error deleting target {}: {}", &target.display(), e);
                    }
                },
                true => {
                    puriel_stats.targets_purged.fetch_add(1, Ordering::Relaxed);
                    write_to_puriuel_log_file(
                        args.dry_run,
                        &mut worker_log_file,
                        &target,
                        target_metadata.stx_atime.tv_sec,
                        target_metadata.stx_ctime.tv_sec,
                        target_metadata.stx_mtime.tv_sec,
                        target_metadata.stx_uid,
                    )
                }
            },

            EntryPurgeState::NotPurgable => {
                continue;
            }
            EntryPurgeState::PurgeLater => {
                unreachable!("Cannot have a PurgeLater state in a puriel run")
            }
        }
    }
}

//Used by rafael to populate puriel targets
pub fn write_to_puriel_target_file(
    puriel_target_file: &mut Option<BufWriter<fs::File>>,
    target_path: &PathBuf,
) {
    if let Err(e) = writeln!(
        match puriel_target_file {
            Some(f) => f,
            None => {
                eprintln!("Error Unwraping puriel target file");
                return;
            }
        },
        "{}",
        target_path.display()
    ) {
        eprintln!("Error writing to puriel target file: {}", e);
    }
}

fn write_to_puriuel_log_file<W: Write>(
    dry_run: bool,
    log_file_writer: &mut BufWriter<W>,
    target_path: &PathBuf,
    atime: i64,
    ctime: i64,
    mtime: i64,
    uid: u32,
) {
    let msg = if dry_run { "WOULD DELETE" } else { "DELETING" };
    if let Err(e) = writeln!(
        log_file_writer,
        "{}: {msg} {}: atime={} ctime={} mtime={} UID={}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Epoch Calcuation error")
            .as_secs(),
        target_path.display(),
        atime,
        ctime,
        mtime,
        uid,
    ) {
        eprintln!("Error writing to log file: {}", e);
    }
}

pub fn display_puriel_results(results: PurielResults, args: &Cli) {
    println!("\nPURIEL STATISTICS");
    println!("{}", "*".repeat(50));
    println!(
        "* Targets Found: {}",
        results.stats.targets_found.load(Ordering::Relaxed)
    );
    println!(
        "* Targets {} Purged: {}",
        match args.dry_run {
            true => {
                "That Would Be"
            }
            false => {
                ""
            }
        },
        results.stats.targets_purged.load(Ordering::Relaxed)
    );
    println!(
        "* Target statx Errors: {}",
        results.stats.target_statx_errors.load(Ordering::Relaxed)
    );
    println!("{}", "*".repeat(50));
    println!("\n* Puriel Execution Time: {:.4?}", results.time);

    send_puriel_syslog_message(Some(results), args, false);
}

pub fn puriel_main(args: &Cli, start: std::time::Instant) -> PurielResults {
    //Create our Puriel statistics
    let puriel_stats = PurielStatistics {
        targets_found: AtomicUsize::new(0),
        targets_purged: AtomicUsize::new(0),
        target_statx_errors: AtomicUsize::new(0),
    };

    //Benchmarking value for time to read in puriel targets
    let read_in_time = std::time::Instant::now();

    //Get the number of targets we have and populate our worker queues
    let Ok((number_of_targets, worker_queues)) = populate_worker_queues(args) else {
        todo!()
    };

    println!("Puriel targets read in time: {:?}", read_in_time.elapsed());

    //Set the number of targets we found in our puriel statistics
    puriel_stats
        .targets_found
        .store(number_of_targets, Ordering::Relaxed);

    //Launch our workers
    launch_workers(args, worker_queues, &Arc::new(&puriel_stats));

    let return_results = PurielResults {
        stats: puriel_stats,
        time: start.elapsed(),
    };

    return_results
}
