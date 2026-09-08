use crate::puriel_utils::puriel_utils::{
    Cli, PurielResults, PurielStatistics, launch_workers, populate_worker_queues,
};

use chrono::Local;
use std::sync::{Arc, atomic::{AtomicUsize,Ordering}};
use std::fs;
use std::path::PathBuf;

pub fn purge_fs(args: &mut Cli, start: std::time::Instant) -> PurielResults {
    //Create log directory from command line arguments with current date and time
    args.pr_log_dir = PathBuf::from(format!(
        "{}_{}",
        args.pr_log_dir.display(),
        Local::now().format("%m-%d-%Y_%H:%M:%S").to_string()
    ));
    let _ = fs::create_dir(&args.pr_log_dir);

    //Create our Puriel statistics
    let puriel_stats = PurielStatistics {
        targets_found: AtomicUsize::new(0),
        targets_purged: AtomicUsize::new(0),
        target_statx_errors: AtomicUsize::new(0),
    };

    //Benchmarking value for time to read in puriel targets
    let read_in_time = std::time::Instant::now();

    //Get the number of targets we have and populate our worker queues
    let (number_of_targets, worker_queues) = match populate_worker_queues(args) {
        Ok((targets, queues)) => {
            println!("Puriel targets read in time: {:?}", read_in_time.elapsed());
            (targets, queues)
        }
        Err(e) => {
            eprintln!(
                "Error acquiring targets and populating worker queues: {}",
                e
            );
            std::process::exit(1);
        }
    };

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