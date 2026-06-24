//! Git integration tests for gnaw
//!
//! This module tests git-related functionality including gitignore handling
//! and git repository integration using rstest fixtures.

mod common;

use common::fixtures::*;
use common::*;
use log::debug;
use predicates::prelude::*;
use predicates::str::contains;
use rstest::*;
use std::fs;

/// Test gitignore functionality - files should be ignored by default
#[rstest]
fn test_gitignore(git_test_env: GitTestEnv) {
    let mut cmd = git_test_env.command();
    cmd.assert().success();

    let output = git_test_env.read_output();
    debug!("Test gitignore output:\n{}", output);

    // Should include files not in gitignore
    assert!(contains("included.txt").eval(&output));
    assert!(contains("Included file").eval(&output));

    // Should exclude files in gitignore
    assert!(contains("ignored.txt").not().eval(&output));
    assert!(contains("Ignored file").not().eval(&output));
}

/// Test --no-ignore flag - should include gitignored files
#[rstest]
fn test_gitignore_no_ignore(git_test_env: GitTestEnv) {
    let mut cmd = git_test_env.command();
    cmd.arg("--no-ignore").assert().success();

    let output = git_test_env.read_output();
    debug!("Test --no-ignore flag output:\n{}", output);

    // Should include all files when ignoring gitignore
    assert!(contains("included.txt").eval(&output));
    assert!(contains("Included file").eval(&output));
    assert!(contains("ignored.txt").eval(&output));
    assert!(contains("Ignored file").eval(&output));
}

/// Test that git repository is properly initialized in fixture
#[rstest]
fn test_git_repo_initialization(git_test_env: GitTestEnv) {
    // Verify that the git repository exists
    let git_dir = git_test_env.dir.path().join(".git");
    assert!(git_dir.exists(), "Git repository should be initialized");
    assert!(git_dir.is_dir(), "Git directory should be a directory");
}

/// Test gitignore with different patterns
#[rstest]
#[case("*.log", "test.log", "Log file content")]
#[case("build/", "build/output.txt", "Build output")]
#[case("*.tmp", "temp.tmp", "Temporary content")]
fn test_gitignore_patterns(
    #[case] pattern: &str,
    #[case] file_path: &str,
    #[case] file_content: &str,
) {
    let env = GitTestEnv::new();

    // Create the test file
    create_temp_file(env.dir.path(), file_path, file_content);

    // Create gitignore with the pattern
    let gitignore_path = env.dir.path().join(".gitignore");
    std::fs::write(&gitignore_path, pattern).expect("Failed to write gitignore");

    let mut cmd = env.command();
    cmd.assert().success();

    let output = env.read_output();
    debug!("Test gitignore pattern '{}' output:\n{}", pattern, output);

    // File should be ignored
    assert!(
        contains(file_content).not().eval(&output),
        "File with pattern '{}' should be ignored",
        pattern
    );

    // Test with --no-ignore
    let mut cmd_no_ignore = env.command();
    cmd_no_ignore.arg("--no-ignore").assert().success();

    let output_no_ignore = env.read_output();
    assert!(
        contains(file_content).eval(&output_no_ignore),
        "File with pattern '{}' should be included with --no-ignore",
        pattern
    );
}

#[test]
fn nested_gitignore_files_are_each_honored() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // A real git repo: the `ignore` crate's gitignore handling only kicks in
    // when it detects a repository (or you opt in). Initializing one makes the
    // test reflect what a user actually has on disk.
    std::process::Command::new("git")
        .arg("init")
        .current_dir(root)
        .output()
        .expect("git init");

    // --- ROOT .gitignore: ignore a top-level build dir ---
    fs::write(root.join(".gitignore"), "build/\n").unwrap();

    // --- a nested package with its OWN .gitignore ---
    fs::create_dir_all(root.join("pkg/src")).unwrap();
    fs::write(root.join("pkg/.gitignore"), "generated/\n").unwrap();

    // Files that MUST be excluded by the respective .gitignore:
    fs::create_dir_all(root.join("build")).unwrap();
    fs::write(root.join("build/ROOT_IGNORED.js"), "ROOT_IGNORED_CONTENT").unwrap();

    fs::create_dir_all(root.join("pkg/generated")).unwrap();
    fs::write(
        root.join("pkg/generated/NESTED_IGNORED.js"),
        "NESTED_IGNORED_CONTENT",
    )
    .unwrap();

    // A file that the ROOT pattern must NOT reach into the nested dir for:
    // `build/` at root should not ignore `pkg/build_helper.rs` (different name,
    // and the root pattern is anchored to root anyway).
    fs::write(root.join("pkg/src/KEEP_ME.rs"), "KEEP_ME_CONTENT").unwrap();

    // And a top-level real file that must survive.
    fs::write(root.join("main.rs"), "MAIN_CONTENT").unwrap();

    let mut cmd = assert_cmd::cargo::cargo_bin_cmd!("gnaw");
    cmd.arg(root)
        .args(["-O", "-", "--no-clipboard"])
        .assert()
        .success()
        // kept
        .stdout(predicate::str::contains("MAIN_CONTENT"))
        .stdout(predicate::str::contains("KEEP_ME_CONTENT"))
        // excluded by ROOT .gitignore
        .stdout(predicate::str::contains("ROOT_IGNORED_CONTENT").not())
        // excluded by NESTED pkg/.gitignore — this is the real question
        .stdout(predicate::str::contains("NESTED_IGNORED_CONTENT").not());
}
