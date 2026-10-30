use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_otserver-otter");

fn temporary_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "otter-{label}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn run(arguments: &[&str]) -> Output {
    Command::new(BINARY).args(arguments).output().unwrap()
}

fn isolated_binary(directory: &Path, configuration: &[u8]) -> PathBuf {
    let executable = directory.join("otserver-otter");
    std::fs::copy(BINARY, &executable).unwrap();
    std::fs::write(directory.join("otter.json"), configuration).unwrap();
    executable
}

#[test]
fn doctor_dispatches_from_the_real_cli_entry_point() {
    let output = run(&["doctor"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Capture interfaces:"));
    assert!(stdout.contains("Native ARP and OT protocol modules: available"));
}

#[test]
fn interfaces_json_is_valid_json() {
    let output = run(&["interfaces", "--json"]);

    assert!(output.status.success());
    let interfaces: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(interfaces.is_array());
}

#[test]
fn validate_command_reports_a_valid_contract_export() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts/otserver-scan-v2-valid.json");
    let output = Command::new(BINARY)
        .args(["validate"])
        .arg(fixture)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("Valid otserver-scan v2 file")
    );
}

#[test]
fn validate_command_returns_a_nonzero_exit_for_a_missing_file() {
    let directory = temporary_directory("missing-export");
    let missing = directory.join("missing.json");
    let expected_error = std::fs::read(&missing).unwrap_err();
    assert_eq!(expected_error.kind(), std::io::ErrorKind::NotFound);

    let output = Command::new(BINARY)
        .args(["validate"])
        .arg(&missing)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&expected_error.to_string()), "{stderr}");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scan_with_all_probes_disabled_writes_a_valid_export_without_using_local_config() {
    let directory = temporary_directory("no-probes");
    let executable = isolated_binary(&directory, b"{}");
    let output_path = directory.join("scan.json");
    let output = Command::new(executable)
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--interface",
            "lo",
            "--source-mac",
            "00:11:22:33:44:55",
            "--output",
        ])
        .arg(&output_path)
        .args([
            "--ack-authorized",
            "--no-protocols",
            "--no-arp",
            "--no-profinet",
            "--no-snmp",
            "--no-lldp",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let export: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(export["format"], "otserver-scan");
    assert_eq!(export["schemaVersion"], 2);
    assert!(export["devices"].as_array().unwrap().is_empty());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scan_failure_takes_precedence_over_a_successful_batch_configuration() {
    let directory = temporary_directory("batch-config-error");
    let executable = isolated_binary(
        &directory,
        br#"[
            {"name":"valid","targets":["127.0.0.1"],"interface":"lo","sourceMac":"00:11:22:33:44:55","noProtocols":true,"noArp":true,"noProfinet":true,"noSnmp":true,"noLldp":true},
            {"name":"invalid","interface":"lo","sourceMac":"00:11:22:33:44:55"}
        ]"#,
    );
    let output_path = directory.join("scan.json");
    let output = Command::new(executable)
        .args(["scan", "--ack-authorized", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(output_path.exists());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("1 configuration(s) failed")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scan_partial_results_use_the_documented_partial_exit_status() {
    let directory = temporary_directory("partial-scan");
    let executable = isolated_binary(
        &directory,
        br#"{"targets":["127.0.0.1"],"interface":"lo","sourceMac":"00:11:22:33:44:55","noProtocols":true,"noArp":true,"noProfinet":true,"noLldp":true,"snmp":{"version":"unsupported"}}"#,
    );
    let output_path = directory.join("partial.json");
    let output = Command::new(executable)
        .args(["scan", "--ack-authorized", "--output"])
        .arg(&output_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let export: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
    assert_eq!(export["scan"]["partial"], true);
    assert_eq!(export["warnings"].as_array().unwrap().len(), 1);
    std::fs::remove_dir_all(directory).unwrap();
}
