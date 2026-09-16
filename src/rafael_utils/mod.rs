// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::metadata_evaluation::entry_evaluation::evaluate_entry;
use crate::metadata_evaluation::metadata_utils::*;
use crate::pct::PurgeCandidate;
use crate::syslog::send_rafael_syslog_message;
use crate::thread_termination::safra::SafraTerminator;
use crate::thread_termination::safra::*;

use chrono::Local;
use clap::{ArgAction, Parser};
use crossbeam::queue::SegQueue;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use log::debug;
use nix::dir::{Dir, Entry};
use nix::errno::Errno;
use nix::fcntl::{AT_FDCWD, OFlag};
use nix::sys::stat::Mode;
use nix::sys::stat::SFlag;
use nix::sys::statfs::statfs;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rustix::fd::BorrowedFd;
use rustix::fs::{AtFlags, StatxFlags, statx};
use std::fs;
use std::io::{BufRead, BufReader};
use std::io::{BufWriter, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(
    name = "rafael",
    version = "2.4.2",
    about = "\nRafael: Rust-Based Automated File-System Analyzer and Erasure Logger\n"
)]
pub struct Cli {
    /// Root of tree to traverse and purge.
    pub root: PathBuf,

    /// Thread count, Default of 4 threads.
    #[arg(short = 't', long)]
    #[arg(default_value_t = 4)] // Default of 4 threads
    pub thread_count: usize,

    /// Log directory, default of rp_log_dir in current directory
    #[arg(short = 'l', long)]
    #[arg(default_value = "rp_log_dir")]
    pub rp_log_dir: PathBuf,

    /// Age of files to delete, in days
    #[arg(short = 'a', long)]
    #[arg(default_value_t = -1)]
    pub age: i64,

    /// Exception file, list of directory names to prune or not purge, (REQUIRED, BUT CAN BE EMPTY)
    #[arg(short = 'e', long, required = true)]
    pub exception: PathBuf,

    /// Ignore change time of files and only evaluate modify and access times
    #[arg(long)]
    pub ignore_ctime: bool,

    //Level of depth Protection to apply with a default value of 1
    #[arg(short = 'd')]
    #[arg(default_value_t = 1)]
    pub depth_protection: usize,

    /// Dry Run mode, will not delete directories or files that are purgable
    #[arg(long)]
    pub dry_run: bool,

    /// Verbosity level (-v and -vv) for path traversal of threads
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbosity: u8,

    /// Visual Progress bar, uses total number of inodes on a file system as estimate, unless an entry count is passed
    #[arg(long)]
    pub show_progress: bool,

    /// Set in order to read all the contents of a dir before evaluating its contents.
    #[arg(long)]
    pub read_entire_dir: bool,

    /// Entry count used to gauge progress bar, defautl value will be used inode count of root filesystem
    #[arg(short = 'c', long)]
    #[arg(default_value_t = 0)]
    pub entry_count: u64,

    /// Individual Thread Statistics, work done and work stolen
    #[arg(short = 'i', long)]
    pub thread_stats: bool,

    /// Delete all contents of specified root directory
    #[arg(long)]
    pub erase: bool,

    /// Disable shuffling for the contents of our inital root directory
    #[arg(short = 's', long)]
    pub no_shuffle_root: bool,

    #[arg(
        long,
        long_help = "Enable Puriel premptive purge calculations, This is argument is to be used in conjuntion with the program Puriel\n
Puriel is a program that, at an admin determined time after Rafael has run, will run in order to purge files that were calculated\n"
    )]
    pub enable_puriel: bool,

    /// Number of days ahead to evaluate whether currently non-purgeable items will become purgeable based on age constraints.
    #[arg(long)]
    #[arg(default_value_t = -1)]
    pub puriel_days: i64,

    /// With Puriel enabled a directory must be specified to output potential targets that each thread has found.
    #[arg(long)]
    #[arg(default_value = "pr_targets")]
    pub pr_target_dir: PathBuf,
}

pub type SharedLog = Arc<Mutex<BufWriter<fs::File>>>;

pub struct PurgeStatistics {
    pub files_checked: AtomicUsize,
    pub files_purged: AtomicUsize,
    pub directories_checked: AtomicUsize,
    pub directories_purged: AtomicUsize,
    pub puriel_items: Option<AtomicUsize>,
}

impl PurgeStatistics {
    pub fn get_puriel_items(&self) -> &AtomicUsize {
        self.puriel_items.as_ref().unwrap()
    }
}

pub struct WorkItem {
    pub path: PathBuf,
    pub parent: Option<Arc<PurgeCandidate>>,
}

pub struct PurgeResults {
    pub purge_statistics: PurgeStatistics,
    //(Dirs Purged, Size of Dirs Purged (bytes))
    pub directories_purged_statistics: Arc<(AtomicUsize, AtomicUsize)>,
    pub time: Duration,
}

////////////////////////////////
//MAIN RAFAEL PURGER FUNCTIONS//
////////////////////////////////
pub fn root_dir_walk(
    args: &Cli,
    stats: &PurgeStatistics,
    worker_queues: &[SegQueue<WorkItem>],
    exceptions: &[String],
) -> Result<(), String> {
    // Attempt to read the entries in the root path
    let mut entries: Vec<PathBuf> = match fs::read_dir(&args.root) {
        Ok(entry_iterator) => entry_iterator.map(|res| res.unwrap().path()).collect(),
        Err(e) => {
            eprintln!("Failed to read root directory: {}", e);
            std::process::exit(1);
        }
    };

    // Shuffle the contents of our root directory walk to balance out workloads for extremely large file systems
    if !args.no_shuffle_root {
        entries.shuffle(&mut thread_rng());
    }

    // Increment number of directories scanned for statistics for the root level directory
    stats.directories_checked.fetch_add(1, Ordering::Relaxed);
    for (index, path) in entries.into_iter().enumerate() {
        //Run statx on top level item to ensure it is a directory and also not a directory symlink
        match do_statx(AT_FDCWD, &path) {
            Ok(entry_metadata) => {
                if SFlag::from_bits_truncate(entry_metadata.stx_mode.into()) & SFlag::S_IFMT
                    == SFlag::S_IFDIR
                {
                    //Check if entry is an exception
                    if is_dir_an_exception(exceptions, &path.display().to_string().to_lowercase()) {
                        continue;
                    } else {
                        //Regardless of if the entry is a file, dir, or symlink put it in the work queues as we will handle that later.
                        //Otherwise we have to run statx for each item in the root dir, when we will have to do that later anyway.
                        //It will be handled later by the inital open call to the work item.
                        let item = WorkItem { path, parent: None };
                        worker_queues[index % args.thread_count].push(item)
                    }
                }
            }
            Err(err) => {
                //If we cannot get the metadata for an entry then the directory can no longer be purgable.
                debug!(
                    "CANNOT AQUIRE METADATA FOR ENTRY: {}, Error: {}",
                    path.display(),
                    err
                );
                continue;
            }
        }
    }
    Ok(())
}

pub fn thread_main(
    args: &Cli,
    stats: &PurgeStatistics,
    dirs_purged_stats: &Arc<(AtomicUsize, AtomicUsize)>,
    work_queues: &[SegQueue<WorkItem>],
    exceptions: &[String],
    term: &SafraTerminator,
    start: &Instant,
) {
    thread::scope(|s| {
        for i in 0..args.thread_count {
            /////////////////
            //START THREADS//
            /////////////////
            s.spawn(move || {
                worker_main(
                    args,
                    i,
                    stats,
                    dirs_purged_stats,
                    work_queues,
                    exceptions,
                    term,
                )
            });
        }

        //Progress bar
        if args.show_progress {
            show_progress(stats, args.entry_count, args.dry_run, term, start);
        }
    });
}
fn worker_main(
    args: &Cli,
    thread_index: usize,
    stats: &PurgeStatistics,
    dirs_purged_stats: &Arc<(AtomicUsize, AtomicUsize)>,
    work_queues: &[SegQueue<WorkItem>],
    exceptions: &[String],
    term: &SafraTerminator,
) {
    //Thread x's local token/color
    //Start white/passive i.e. idle
    let mut local_term_state = TermState::Idle;

    //Create Thread x's log file
    let worker_dlog_file: SharedLog = match fs::OpenOptions::new().create(true).append(true).open(
        args.rp_log_dir
            .join(format!("worker-{}-age-{}.log", thread_index, args.age)),
    ) {
        Ok(f) => Arc::new(Mutex::new(BufWriter::new(f))),
        Err(e) => {
            eprintln!("Thread {} failed to create log file: {}", thread_index, e);
            return;
        }
    };

    //Create Thread x's puriel file if puriel is enabled
    let mut puriel_target_file: Option<BufWriter<fs::File>> = match args.enable_puriel {
        true => {
            match fs::OpenOptions::new().create(true).append(true).open(
                args.pr_target_dir
                    .join(format!("worker-{}-puriel.target", thread_index)),
            ) {
                Ok(f) => Some(BufWriter::new(f)),
                Err(e) => {
                    eprintln!("Failed to create puriel log file: {}", e);
                    return;
                }
            }
        }
        false => None,
    };

    //Check or verbose level, 1 we should print our traversal to stdout, 2 we should be writing our path to a file
    let mut path_traversal_log: Option<BufWriter<fs::File>> = if args.verbosity == 2 {
        match fs::OpenOptions::new().create(true).append(true).open(
            args.rp_log_dir
                .join(format!("worker-{}-traversal.log", thread_index)),
        ) {
            Ok(f) => Some(BufWriter::new(f)),
            Err(e) => {
                eprintln!("Failed to create traversl log file: {}", e);
                None
            }
        }
    } else {
        None
    };

    //Local number of directories scanned per thread
    let mut local_thread_dir_count: usize = 0;
    let mut local_stolen_count: usize = 0;

    //Loop handle to break out of thread execution once thread realizes no other thread has work to steal
    'thread_scan_loop: loop {
        //Grab Thread x's VecDeque
        let current_local_dir = match work_queues[thread_index].pop() {
            Some(work) => work,
            None => {
                let Some(work) = try_stealing_work(args, work_queues) else {
                    if term.check_termination(thread_index, local_term_state, args.thread_count) {
                        break 'thread_scan_loop;
                    }
                    local_term_state = TermState::Idle;
                    continue 'thread_scan_loop;
                };
                local_stolen_count += 1;
                work
            }
        };
        //Change color to Active i.e. black/working
        local_term_state = TermState::Active;

        check_verbose_level(
            args.verbosity,
            &mut path_traversal_log,
            current_local_dir.path.display().to_string(),
            thread_index,
        );

        match thread_directory_scan(
            args,
            thread_index,
            current_local_dir,
            stats,
            dirs_purged_stats,
            work_queues,
            &worker_dlog_file,
            &mut puriel_target_file,
            exceptions,
        ) {
            Ok(()) => {
                //Increment number of directories thread x has scanned
                local_thread_dir_count += 1;
            }
            Err(e) => {
                eprintln!("thread dir scan, {}", e);
                continue 'thread_scan_loop;
            }
        }

        //Flush the bufwriters after scanning a directory to catch any I/O errors
        match worker_dlog_file.lock() {
            Ok(mut log_file_writer) => match log_file_writer.flush() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "Error, failed to flush buffer for thread {} rafael log file: {}",
                        thread_index, e
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Mutex lock error for thread {}, rafael log file: {}",
                    thread_index, e
                );
            }
        }
        if let Some(ref mut target_file) = puriel_target_file {
            match target_file.flush() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "Error, failed to flush buffer for thread {} puriel log file: {}",
                        thread_index, e
                    );
                }
            }
        }
        if let Some(ref mut traversal_log) = path_traversal_log {
            match traversal_log.flush() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!(
                        "Error, failed to flush buffer for thread {} traversal log file: {}",
                        thread_index, e
                    );
                }
            }
        }
    }

    //Extra Thread Work Information
    if args.thread_stats {
        thread::sleep(Duration::from_millis(1));
        println!(
            "Thread {} Dirs: \n\tScanned: {}\n\tStole: {}",
            thread_index, local_thread_dir_count, local_stolen_count
        );
    }
}

fn thread_directory_scan(
    args: &Cli,
    thread_position: usize,
    current_local_dir: WorkItem,
    stats: &PurgeStatistics,
    dirs_purged_stats: &Arc<(AtomicUsize, AtomicUsize)>,
    worker_queues: &[SegQueue<WorkItem>],
    worker_log_file: &SharedLog,
    worker_puriel_target_file: &mut Option<BufWriter<fs::File>>,
    exceptions: &[String],
) -> Result<(), String> {
    //Open dir at a low level to get file descriptor along with NO_ATIME
    let mut dir = match Dir::open(
        &current_local_dir.path,
        OFlag::O_DIRECTORY | OFlag::O_RDONLY | OFlag::O_NOATIME | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        //This is where, if we initally got a file/symlink instead of a dir, will be handled.
        //Since we specify `OFlag::O_DIRECTORY` this function will fail and got back to the worker loop in the caller function.
        Ok(open_dir) => open_dir,
        Err(err) => {
            return Err(format!(
                "Failed to open entry as a dir: {}, Error: {:?}",
                current_local_dir.path.display(),
                err,
            )
            .to_string());
        }
    };

    let dir_fd = unsafe { BorrowedFd::borrow_raw(dir.as_raw_fd()) };

    //Get the specified fields of dir metadata
    let Ok(dir_metadata) = statx(
        dir_fd,
        &current_local_dir.path,
        AtFlags::empty(), //The only AtFlag we would care about would be NOFOLLOW for symlinks, but that will be done on files
        StatxFlags::ATIME | StatxFlags::CTIME | StatxFlags::MTIME | StatxFlags::UID,
    ) else {
        return Err(format!(
            "Directory statx operation failed: {}",
            current_local_dir.path.display()
        )
        .to_string());
    };

    //Check if dir is purgable
    let mut is_directory_purgable = match is_entry_purgable(
        args,
        &dir_metadata,
        current_local_dir.path.components().count(),
        true,
    ) {
        EntryPurgeState::PurgeNow => true,
        EntryPurgeState::PurgeLater => {
            unreachable!("Should Never return purge later for dir")
        }
        EntryPurgeState::NotPurgable => false,
    };

    //First check if the dir is purgable and that it is NOT one of the root dirs children
    let new_parent = if is_directory_purgable {
        //Create PCT node for current dir
        let purge_candidate = PurgeCandidate::new(
            &current_local_dir.path,
            current_local_dir.parent,
            Arc::clone(dirs_purged_stats),
            args.dry_run,
            Arc::clone(worker_log_file),
            dir_metadata,
        );
        Some(Arc::new(purge_candidate))

    //If current dir is not purgable then the parent cannot be purgable
    //So check if parent is purgable and if so change it
    } else {
        if let Some(ref parent) = current_local_dir.parent {
            parent.set_delete_flag();
        }
        None
    };

    // Increment number of directories scanned for statistics
    stats.directories_checked.fetch_add(1, Ordering::Relaxed);

    //Assign count for index position for round robin
    let mut count = 1 + thread_position;

    match args.read_entire_dir {
        true => {
            let entry_list: Vec<Result<Entry, Errno>> = dir.iter().collect::<Vec<_>>();
            for entry_result in entry_list {
                evaluate_entry(
                    entry_result,
                    args,
                    dir_fd,
                    &count,
                    &current_local_dir.path,
                    exceptions,
                    &mut is_directory_purgable,
                    stats,
                    worker_queues,
                    worker_log_file,
                    worker_puriel_target_file,
                    &new_parent,
                );
                count += 1;
            }
        }
        false => {
            for entry_result in dir.iter() {
                evaluate_entry(
                    entry_result,
                    args,
                    dir_fd,
                    &count,
                    &current_local_dir.path,
                    exceptions,
                    &mut is_directory_purgable,
                    stats,
                    worker_queues,
                    worker_log_file,
                    worker_puriel_target_file,
                    &new_parent,
                );
                count += 1;
            }
        }
    }
    //Check if dir is still purgable after evaluating all of its entries.
    //If not then update the dir to no longer be purgable along with its parent.
    if !is_directory_purgable && let Some(ref parent) = new_parent {
        parent.set_delete_flag();
    }
    Ok(())
}

/////////////
//UTILITIES//
/////////////
fn try_stealing_work(
    args: &Cli,
    work_queues: &[crossbeam::queue::SegQueue<WorkItem>],
) -> Option<WorkItem> {
    for i in 0..=args.thread_count - 1 {
        if let Some(work) = work_queues[i].pop() {
            return Some(work);
        }
    }
    None
}

pub fn write_to_log_file(
    dry_run: bool,
    log_file: &SharedLog,
    target_path: &Path,
    atime: i64,
    ctime: i64,
    mtime: i64,
    uid: u32,
) {
    let mut file = log_file.lock().unwrap();
    let msg = if dry_run { "WOULD DELETE" } else { "DELETING" };

    if let Err(e) = writeln!(
        file,
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

pub fn is_dir_an_exception(exceptions: &[String], directory_to_check: &str) -> bool {
    exceptions
        .iter()
        .any(|exception| directory_to_check.contains(exception))
}

pub fn get_used_inodes(root_path: &Path) -> u64 {
    let stat = statfs(root_path).unwrap();
    stat.files() - stat.files_free()
}

/// Displays purge results at the end of a run
pub fn display_purge_results(args: &Cli, purge_results: PurgeResults, now: std::time::Instant) {
    if args.dry_run {
        println!("\nDRY RUN STATISTICS:");
    } else {
        println!("\nSTATISTICS")
    }
    println!("{}", "*".repeat(50));
    // Statistics after thread exectuion
    println!("* FILES: ");
    println!(
        "* Files checked: {}",
        purge_results
            .purge_statistics
            .files_checked
            .load(Ordering::Relaxed)
    );
    println!(
        "{} {}",
        if args.dry_run {
            "* Files that would be purged:"
        } else {
            "* Files purged:"
        },
        purge_results
            .purge_statistics
            .files_purged
            .load(Ordering::Relaxed)
    );

    if args.enable_puriel {
        println!(
            "\n* PURIEL FILES:\n* Puriel Items logged: {}",
            match purge_results.purge_statistics.puriel_items {
                Some(ref items) => {
                    items.load(Ordering::Relaxed)
                }
                None => {
                    unreachable!("Error: Trying to output puriel stats when not enabled");
                }
            }
        )
    }

    println!("\n* DIRECTORIES: ");
    println!(
        "* Directories checked: {}",
        purge_results
            .purge_statistics
            .directories_checked
            .load(Ordering::Relaxed)
    );
    println!(
        "{} {}",
        if args.dry_run {
            "* Directories that would be purged:"
        } else {
            "* Directories purged:"
        },
        purge_results
            .directories_purged_statistics
            .0
            .load(Ordering::Relaxed)
    );

    if args.verbosity > 0 {
        println!("\n* VERBOSE INFORMATION:");
        println!(
            "* Files scanned per second: {:.3}",
            purge_results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed) as f64
                / purge_results.time.as_secs_f64()
        );
        println!(
            "* Files deleted per second: {:.3}",
            purge_results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed) as f64
                / purge_results.time.as_secs_f64()
        );
        println!(
            "* Directories scanned per second: {:.3}",
            purge_results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed) as f64
                / purge_results.time.as_secs_f64()
        );
        println!(
            "* Directories deleted per second: {:.3}",
            purge_results
                .directories_purged_statistics
                .1
                .load(Ordering::Relaxed) as f64
                / purge_results.time.as_secs_f64()
        );
    }
    println!("\n* Traversal and Purging Time: {:.4?}", purge_results.time);
    println!("* Total Execution Time: {:.4?}", now.elapsed());
    println!("{}", "*".repeat(50));

    //Additionally if we successfully got our purge results also send a syslog info message to the local server
    send_rafael_syslog_message(Some(purge_results), args, false)
}

fn show_progress(
    stats: &PurgeStatistics,
    entry_count: u64,
    dry_run: bool,
    term: &SafraTerminator,
    start: &Instant,
) {
    let m = MultiProgress::new();
    let sb1 = m.add(ProgressBar::new(entry_count));
    let sb2 = m.add(ProgressBar::new(0));
    let sb3 = m.add(ProgressBar::new(0));
    let sb4 = m.add(ProgressBar::new(0));

    // Set the style of the progress bar
    sb1.set_style(
        ProgressStyle::default_bar()
            .template(
                "{prefix} {msg} {wide_bar} {pos}/{len} ({percent}%) | Elapsed: {elapsed_precise}",
            )
            .unwrap()
            .progress_chars("=>-"), // Progress chars for the filled portion
    );

    sb2.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());

    sb3.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());

    sb4.set_style(ProgressStyle::default_bar().template("{msg}").unwrap());

    let mut last_update = std::time::Instant::now();
    let mut files_at_last_update = 0;

    sb1.set_message("Processing File System Items...");
    sb2.set_message("Calculating Files scanned in last 5 Seconds...");
    sb3.set_message("Calculating average Files scanned per second...");
    sb4.set_message("Calculating average Directories scanned per second...");
    while !term.is_done() {
        std::thread::sleep(std::time::Duration::from_millis(100));

        let elapsed = start.elapsed().as_secs_f64();
        let now = std::time::Instant::now();
        let time_since_last_update = now.duration_since(last_update).as_secs_f64();

        let files_checked = stats.files_checked.load(Ordering::Relaxed);
        let dirs_checked = stats.directories_checked.load(Ordering::Relaxed);

        sb1.set_position(files_checked as u64 + dirs_checked as u64);

        if time_since_last_update >= 5.0 {
            sb2.set_message(format!(
                "Files scanned in past 5 seconds: {}",
                files_checked - files_at_last_update
            ));
            sb3.set_message(format!(
                "Files Scanned Per Second: {:.2}",
                (files_checked - files_at_last_update) as f64 / time_since_last_update
            ));
            sb4.set_message(format!(
                "Dirs Scanned Per Second: {:.2}",
                dirs_checked as f64 / elapsed
            ));

            //Update last number of files checked
            files_at_last_update = files_checked;

            //Update last recorded time
            last_update = now;
        }
    }
    if dry_run {
        sb1.finish_with_message("Dry-Run Complete!");
    } else {
        sb1.finish_with_message("File System Purge Complete!");
    }
}

fn check_verbose_level(
    verbosity: u8,
    path_traversal_log: &mut Option<BufWriter<fs::File>>,
    path: String,
    thread_index: usize,
) {
    if verbosity == 1 {
        println!("Thread {} has traveled to: {}", thread_index, path);
    } else if verbosity == 2
        && let Some(path_traversal_log_file) = path_traversal_log
    {
        //Not including thread id on travel log file write because it will have the thread id in the file name
        if let Err(e) = writeln!(path_traversal_log_file, "{}", path) {
            eprintln!(
                "Error writing to path traversal file for thread {}: {}",
                thread_index, e
            );
        }
    }
}

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
        puriel_items: match args.enable_puriel {
            true => Some(AtomicUsize::new(0)),
            false => None,
        },
    };

    // Create a Vector of worker queues to be shared among threads
    let top_level_queues: Vec<SegQueue<WorkItem>> = (0..args.thread_count)
        .map(|_| SegQueue::<WorkItem>::new())
        .collect();

    //Create log directory from command line arguments with current date and time
    args.rp_log_dir = PathBuf::from(format!(
        "{}_{}",
        args.rp_log_dir.display(),
        Local::now().format("%m-%d-%Y_%H:%M:%S")
    ));
    let _ = fs::create_dir(&args.rp_log_dir);

    //If puriel is enabled then create the puriel target directory with current date and time
    if args.enable_puriel {
        args.pr_target_dir = PathBuf::from(format!(
            "{}_{}",
            args.pr_target_dir.display(),
            Local::now().format("%m-%d-%Y")
        ));
        let _ = fs::create_dir(&args.pr_target_dir);
    }

    //Check if an exception/purning file was passed
    //let mut exceptions: Vec<String> = Vec::new();

    //Using unwrap on open(path) because we want the program to panic if the
    //Exception file cannot be read, we have no idea what it would delete at that point.

    let (exception_reader, mut exceptions) = match fs::File::open(&args.exception) {
        Ok(open_exception_file) => (BufReader::new(open_exception_file), Vec::new()),
        Err(e) => {
            eprintln!(
                "Error reading exception file, {}, cannot safely proceed, Exiting: {e}",
                args.exception.display()
            );
            std::process::exit(1);
        }
    };
    for exception in exception_reader.lines() {
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
    let _ = root_dir_walk(args, &stats, &top_level_queues, &exceptions);

    let term = SafraTerminator::new();

    // Main thread function
    thread_main(
        args,
        &stats,
        &Arc::clone(&directories_purged_stats),
        &top_level_queues,
        &exceptions,
        &term,
        &start,
    );

    PurgeResults {
        purge_statistics: stats,
        time: start.elapsed(),
        directories_purged_statistics: directories_purged_stats,
    }
}
