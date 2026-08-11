// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use crate::purger::{Cli, PurgeResults};
use crate::puriel_utils::{Cli as PurielCli, PurielResults};

use std::sync::atomic::Ordering;
use syslog::{Facility, Formatter3164};

pub fn send_syslog_message(results: Option<PurgeResults>, args: &Cli, start: bool) {
    //Define syslog formatter
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "Rafael:".into(),
        pid: 0,
    };

    //Generate log message to send to syslog server
    let message = if start {
        generate_start_log(
            args.root.display().to_string(),
            args.age.to_string(),
            args.dry_run.to_string(),
        )
    } else {
        generate_finished_log(results.unwrap(), args.age, args.dry_run)
    };

    match syslog::unix(formatter) {
        Err(e) => eprintln!("Error connecting to syslog: {:?}", e),
        Ok(mut writer) => {
            if let Err(we) = writer.err(&message) {
                eprintln!("Error writing to syslog: {:?}", we);
            }
        }
    }
}

fn generate_start_log(root: String, age: String, dry_run: String) -> String {
    let fields = vec![
        ("Status", "Started"),
        ("Target", &root),
        ("Age", &age),
        ("Dry_Run", &dry_run),
    ];
    let mut message = String::from("");
    for (key, value) in fields {
        message.push_str(&format!("{}={} ", key, value));
    }
    message
}

fn generate_finished_log(results: PurgeResults, age: i64, dry_run: bool) -> String {
    let fields = vec![
        ("Status", "Finished".to_string()),
        (
            if results.time.as_secs() < 10_000 {
                "Execution_Time(ms)"
            } else {
                "Execution_Time(S)"
            },
            if results.time.as_secs() < 10_000 {
                results.time.as_millis().to_string()
            } else {
                results.time.as_secs().to_string()
            },
        ),
        ("Age", age.to_string()),
        ("Dry_Run", dry_run.to_string()),
        (
            "Files_Checked",
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed)
                .to_string(),
        ),
        (
            "Files_Purged",
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed)
                .to_string(),
        ),
        (
            "Files_Checked_Per_Second",
            format!(
                "{:.2}",
                results
                    .purge_statistics
                    .files_checked
                    .load(Ordering::Relaxed) as f64
                    / results.time.as_secs_f64()
            ),
        ),
        (
            "Files_Purged_Per_Second",
            format!(
                "{:.2}",
                results
                    .purge_statistics
                    .files_purged
                    .load(Ordering::Relaxed) as f64
                    / results.time.as_secs_f64()
            ),
        ),
        (
            "Directories_Checked",
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed)
                .to_string(),
        ),
        (
            "Directories_Purged",
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed)
                .to_string(),
        ),
        (
            "Directories_Checked_Per_Second",
            format!(
                "{:.2}",
                results
                    .purge_statistics
                    .directories_checked
                    .load(Ordering::Relaxed) as f64
                    / results.time.as_secs_f64()
            ),
        ),
        (
            "Directories_Purged_Per_Second",
            format!(
                "{:.2}",
                results
                    .directories_purged_statistics
                    .0
                    .load(Ordering::Relaxed) as f64
                    / results.time.as_secs_f64()
            ),
        ),
    ];
    let mut message = String::from("");
    for (key, value) in fields {
        message.push_str(&format!("{}={} ", key, value));
    }
    message
}

pub fn send_puriel_syslog_message(results: Option<PurielResults>, args: &PurielCli, start: bool) {
    //Define syslog formatter
    let formatter = Formatter3164 {
        facility: Facility::LOG_USER,
        hostname: None,
        process: "Puriel:".into(),
        pid: 0,
    };

    //Generate log message to send to syslog server
    let message = if start {
        generate_puriel_start_log(args.age.to_string(), args.dry_run.to_string())
    } else {
        generate_puriel_finished_log(results.unwrap(), args.age, args.dry_run)
    };

    match syslog::unix(formatter) {
        Err(e) => eprintln!("Error connecting to syslog: {:?}", e),
        Ok(mut writer) => {
            if let Err(we) = writer.err(&message) {
                eprintln!("Error writing to syslog: {:?}", we);
            }
        }
    }
}

fn generate_puriel_start_log(age: String, dry_run: String) -> String {
    let fields = vec![("Status", "Started"), ("Age", &age), ("Dry_Run", &dry_run)];
    let mut message = String::from("");
    for (key, value) in fields {
        message.push_str(&format!("{}={} ", key, value));
    }
    message
}

fn generate_puriel_finished_log(results: PurielResults, age: i64, dry_run: bool) -> String {
    let fields = vec![
        ("Status", "Finished".to_string()),
        (
            if results.time.as_secs() < 10_000 {
                "Execution_Time(ms)"
            } else {
                "Execution_Time(S)"
            },
            if results.time.as_secs() < 10_000 {
                results.time.as_millis().to_string()
            } else {
                results.time.as_secs().to_string()
            },
        ),
        ("Age", age.to_string()),
        ("Dry_Run", dry_run.to_string()),
        (
            "Targets_Found",
            results
                .stats
                .targets_found
                .load(Ordering::Relaxed)
                .to_string(),
        ),
        (
            "Targets_Purged",
            results
                .stats
                .targets_purged
                .load(Ordering::Relaxed)
                .to_string(),
        ),
    ];

    let mut message = String::from("");
    for (key, value) in fields {
        message.push_str(&format!("{}={} ", key, value));
    }
    message
}
