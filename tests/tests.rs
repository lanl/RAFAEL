// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

#[cfg(test)]
mod tests {
    use rafael::maketree::{make_tree, Cli};
    use rafael::purger::Cli as PurgeCli;
    use rafael::purger_main::purge_fs;

    use std::fs::{canonicalize, File};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::Ordering;

    fn maketree_test(root_path: String) {
        let args = Cli {
            root: root_path,
            depth: 4,
            branching_factor: 4,
            file_count: 4,
            verbose: false,
            interactive: false,
            purgable: true,
            data_size: 0,
            force: true,
        };
        let result = make_tree(args);
        match result {
            Ok(values) => {
                assert_eq!(values.num_dirs, 341);
                assert_eq!(values.num_files, 1360);
            }
            Err(e) => {
                eprintln!("Error getting return values: {}", e);
            }
        }
    }

    fn verify_with_find(dirs: bool, dir_to_count: String) -> usize {
        if dirs {
            let find_output = Command::new("find")
                .arg(dir_to_count)
                .arg("-type")
                .arg("d")
                .stdout(Stdio::piped())
                .spawn()
                .expect("Error with find command");
            let wc_output = Command::new("wc")
                .arg("-l")
                .stdin(find_output.stdout.unwrap())
                .output()
                .expect("Error with wc command");
            String::from_utf8_lossy(&wc_output.stdout)
                .trim()
                .parse::<usize>()
                .unwrap()
        } else {
            let find_output = Command::new("find")
                .arg(dir_to_count)
                .arg("-type")
                .arg("f")
                .stdout(Stdio::piped())
                .spawn()
                .expect("Error with find command");
            let wc_output = Command::new("wc")
                .arg("-l")
                .stdin(find_output.stdout.unwrap())
                .output()
                .expect("Error with wc command");
            String::from_utf8_lossy(&wc_output.stdout)
                .trim()
                .parse::<usize>()
                .unwrap()
        }
    }

    fn testdir_setup(root_path: &str) {
        std::fs::create_dir_all(root_path.to_string()).unwrap();
        maketree_test(root_path.to_owned() + "fake_data_test");
    }

    fn find_input(test_name: &str) -> String {
        format!("testing_artifacts/{test_name}/fake_data_test")
    }

    fn test_input_absolute(test_name: &str) -> PathBuf {
        let x = format!("testing_artifacts/{}/fake_data_test", test_name);
        canonicalize(x).expect("Failed to resolve absolute path")
    }

    fn test_output(test_name: &str) -> PathBuf {
        format!("testing_artifacts/{test_name}/PURGER_TEST_RESULTS").into()
    }

    fn test_puriel_output(test_name: &str) -> PathBuf {
        format!("testing_artifacts/{test_name}/PURIEL_TEST_RESULTS").into()
    }

    fn test_exception(test_name: &str) -> PathBuf {
        format!("testing_artifacts/{test_name}/exceptions.txt").into()
    }

    #[test]
    fn purge_test_01_dry_run() {
        testdir_setup("testing_artifacts/test_01/");
        let _exception_file = File::create("testing_artifacts/test_01/exceptions.txt").unwrap();
        let mut args = PurgeCli {
            root: test_input_absolute("test_01"),
            thread_count: 4,
            rp_log_dir: test_output("test_01"),
            age: 5,
            exception: test_exception("test_01"),
            ignore_ctime: true,
            depth_protection: 1,
            dry_run: true,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: false,
            read_entire_dir: false,
            enable_puriel: false,
            puriel_days: -1,
            pr_target_dir: "pr_targets".into(),
        };
        let results = purge_fs(&mut args);

        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            1360
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            1020
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            341
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            168
        );
    }

    #[test]
    fn purge_test_02_normal_run() {
        testdir_setup("testing_artifacts/test_02/");
        let _exception_file = File::create("testing_artifacts/test_02/exceptions.txt").unwrap();
        let mut args = PurgeCli {
            root: test_input_absolute("test_02"),
            thread_count: 4,
            rp_log_dir: test_output("test_02"),
            age: 5,
            exception: test_exception("test_02"),
            ignore_ctime: true,
            depth_protection: 1,
            dry_run: false,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: false,
            read_entire_dir: false,
            enable_puriel: false,
            puriel_days: -1,
            pr_target_dir: "pr_targets".into(),

        };

        let results = purge_fs(&mut args);
        //Gather find results
        let file_count = verify_with_find(false, find_input("test_02"));
        let dir_count = verify_with_find(true, find_input("test_02"));

        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            1360
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            1020
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            341
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            168
        );
        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed)
                - results
                    .purge_statistics
                    .files_purged
                    .load(Ordering::Relaxed),
            file_count
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed)
                - results
                    .directories_purged_statistics
                    .0
                    .load(Ordering::Relaxed),
            dir_count
        );
    }

    #[test]
    fn purge_test_03_erase_run() {
        testdir_setup("testing_artifacts/test_03/");
        let _exception_file = File::create("testing_artifacts/test_03/exceptions.txt").unwrap();
        let mut args = PurgeCli {
            root: test_input_absolute("test_03"),
            thread_count: 4,
            rp_log_dir: test_output("test_03"),
            age: -1,
            exception: test_exception("test_03"),
            ignore_ctime: false,
            depth_protection: 1,
            dry_run: false,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: true,
            read_entire_dir: false,
            enable_puriel: false,
            puriel_days: -1,
            pr_target_dir: "pr_targets".into(),

        };

        let results = purge_fs(&mut args);
        //Gather find results
        let file_count = verify_with_find(false, find_input("test_03"));
        let dir_count = verify_with_find(true, find_input("test_03"));

        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            1360
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            1360
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            341
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            336
        );
        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed)
                - results
                    .purge_statistics
                    .files_purged
                    .load(Ordering::Relaxed),
            file_count
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed)
                - results
                    .directories_purged_statistics
                    .0
                    .load(Ordering::Relaxed),
            dir_count
        );
    }

    #[test]
    fn purge_test_04_prune_all_run() {
        testdir_setup("testing_artifacts/test_04/");
        let mut exception_file = File::create("testing_artifacts/test_04/exceptions.txt").unwrap();
        exception_file.write_all("0\n1\n2\n3\n".as_bytes()).unwrap();
        let mut args = PurgeCli {
            root: test_input_absolute("test_04"),
            thread_count: 4,
            rp_log_dir: test_output("test_04"),
            age: 5,
            exception: test_exception("test_04"),
            ignore_ctime: true,
            depth_protection: 1,
            dry_run: false,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: false,
            read_entire_dir: false,
            enable_puriel: false,
            puriel_days: -1,
            pr_target_dir: "pr_targets".into(),

        };

        let results = purge_fs(&mut args);
        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn purge_test_05_prune_specifc_run() {
        testdir_setup("testing_artifacts/test_05/");
        let mut exception_file = File::create("testing_artifacts/test_05/exceptions.txt").unwrap();
        exception_file.write_all("1\n2\n".as_bytes()).unwrap();

        //Gather find results
        // let pre_file_count = verify_with_find(false, find_input("test_05"));
        // let pre_dir_count = verify_with_find(true, find_input("test_05"));

        let mut args = PurgeCli {
            root: test_input_absolute("test_05"),
            thread_count: 4,
            rp_log_dir: test_output("test_05"),
            age: 5,
            exception: test_exception("test_05"),
            ignore_ctime: true,
            depth_protection: 1,
            dry_run: false,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: false,
            read_entire_dir: false,
            enable_puriel: false,
            puriel_days: -1,
            pr_target_dir: "pr_targets".into(),

        };

        let results = purge_fs(&mut args);
        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            120
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            90
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            31
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            8
        );

        //Gather find results
        let file_count = verify_with_find(false, find_input("test_05"));
        let dir_count = verify_with_find(true, find_input("test_05"));

        assert_eq!(
            1360 - results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            file_count
        );
        assert_eq!(
            341 - results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            dir_count
        );
    }

    #[test]
    fn purge_test_06_normal_run_puriel_enabled() {
        testdir_setup("testing_artifacts/test_06/");
        let _exception_file = File::create("testing_artifacts/test_06/exceptions.txt").unwrap();
        let mut args = PurgeCli {
            root: test_input_absolute("test_06"),
            thread_count: 4,
            rp_log_dir: test_output("test_06"),
            age: 5,
            exception: test_exception("test_06"),
            ignore_ctime: true,
            depth_protection: 1,
            dry_run: false,
            verbosity: 0,
            show_progress: false,
            entry_count: 0,
            thread_stats: false,
            erase: false,
            read_entire_dir: false,
            enable_puriel: true,
            // By having puriel days set to 7, it is saying "What will be older than 5 days in 7 days", which should be all the files left over.
            puriel_days: 7,
            pr_target_dir: test_puriel_output("test_06"),

        };

        let results = purge_fs(&mut args);
        //Gather find results
        let file_count = verify_with_find(false, find_input("test_06"));
        let dir_count = verify_with_find(true, find_input("test_06"));

        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed),
            1360
        );
        assert_eq!(
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed),
            1020
        );
        assert_eq!(
            results
                .purge_statistics
                .puriel_items.unwrap()
                .load(Ordering::Relaxed),
            (results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed)
            -
            results
                .purge_statistics
                .files_purged
                .load(Ordering::Relaxed)
            )
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed),
            341
        );
        assert_eq!(
            results
                .directories_purged_statistics
                .0
                .load(Ordering::Relaxed),
            168
        );
        assert_eq!(
            results
                .purge_statistics
                .files_checked
                .load(Ordering::Relaxed)
                - results
                    .purge_statistics
                    .files_purged
                    .load(Ordering::Relaxed),
            file_count
        );
        assert_eq!(
            results
                .purge_statistics
                .directories_checked
                .load(Ordering::Relaxed)
                - results
                    .directories_purged_statistics
                    .0
                    .load(Ordering::Relaxed),
            dir_count
        );
    }
}
