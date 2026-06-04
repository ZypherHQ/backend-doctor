use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn backend_doctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_backend-doctor"))
}

fn fixture_path(name: &str) -> String {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn workspace_root() -> PathBuf {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn count_ansi_csi_sequences(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut index = 0;

    while index + 1 < bytes.len() {
        if bytes[index] == 0x1b && bytes[index + 1] == b'[' {
            let mut cursor = index + 2;
            while cursor < bytes.len() {
                let byte = bytes[cursor];
                if (0x40..=0x7e).contains(&byte) {
                    count += 1;
                    index = cursor;
                    break;
                }
                if !(0x20..=0x3f).contains(&byte) {
                    break;
                }
                cursor += 1;
            }
        }
        index += 1;
    }

    count
}

fn temp_fixture_copy(name: &str) -> PathBuf {
    let source = PathBuf::from(fixture_path(name));
    let target = unique_temp_path(&format!("fixture-{name}"));
    let _ = fs::remove_dir_all(&target);
    copy_dir(&source, &target);
    target
}

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "backend-doctor-cli-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn copy_dir(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create fixture copy");
    for entry in fs::read_dir(source).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir(&source_path, &target_path);
        } else {
            fs::copy(&source_path, &target_path).expect("copy fixture file");
        }
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let target = unique_temp_path(name);
    let _ = fs::remove_dir_all(&target);
    fs::create_dir_all(&target).expect("create temp dir");
    target
}

fn path_with_front(front: &Path) -> String {
    let existing = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(
        std::iter::once(front.as_os_str().to_owned())
            .chain(std::env::split_paths(&existing).map(|path| path.into_os_string())),
    )
    .expect("join PATH")
    .to_string_lossy()
    .into_owned()
}

fn isolated_tool_path(bin_dir: &Path) -> String {
    bin_dir.to_string_lossy().into_owned()
}

fn sorted_rule_ids(report: &serde_json::Value) -> Vec<String> {
    let mut ids = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .filter_map(|finding| finding["ruleId"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn assert_order(haystack: &str, earlier: &str, later: &str) {
    let earlier_index = haystack
        .find(earlier)
        .unwrap_or_else(|| panic!("missing earlier text: {earlier}"));
    let later_index = haystack
        .find(later)
        .unwrap_or_else(|| panic!("missing later text: {later}"));
    assert!(
        earlier_index < later_index,
        "expected '{earlier}' before '{later}'"
    );
}

fn assert_cache_hit_ratio(
    fixture: &str,
    run_label: &str,
    executions: &[serde_json::Value],
    expected_ratio: f64,
) {
    let cache_statuses = executions
        .iter()
        .filter_map(|execution| execution["cache"]["status"].as_str())
        .collect::<Vec<_>>();
    assert!(
        !cache_statuses.is_empty(),
        "{fixture} {run_label} must include cache status evidence"
    );

    let hits = cache_statuses
        .iter()
        .filter(|status| **status == "hit")
        .count();
    let hit_ratio = hits as f64 / cache_statuses.len() as f64;

    assert!(
        (hit_ratio - expected_ratio).abs() < f64::EPSILON,
        "{fixture} {run_label} cache hit_ratio expected {expected_ratio}, got {hit_ratio} ({hits}/{} statuses: {cache_statuses:?})",
        cache_statuses.len()
    );
}

#[test]
fn rules_command_lists_and_filters_builtin_rules() {
    let output = backend_doctor()
        .arg("rules")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("go/http-client-no-timeout"));
    assert!(stdout.contains("security/hardcoded-secret"));
    assert!(!stdout.contains("core/bootstrap-placeholder"));

    let output = backend_doctor()
        .args(["rules", "--language", "Go", "--json"])
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let rules: serde_json::Value = serde_json::from_str(&stdout).expect("rules json is valid");
    let rules = rules.as_array().expect("rules array");
    assert!(!rules.is_empty());
    assert!(rules.iter().all(|rule| rule["languages"]
        .as_array()
        .is_some_and(|languages| languages.iter().any(|language| language == "Go"))));
    assert!(rules
        .iter()
        .all(|rule| rule["id"] != "core/bootstrap-placeholder"));
}

#[test]
fn explain_known_rule_prints_metadata_and_unknown_rule_fails() {
    let output = backend_doctor()
        .args(["explain", "go/http-client-no-timeout"])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Rule: go/http-client-no-timeout"));
    assert!(stdout.contains("Category: reliability"));
    assert!(stdout.contains("Explanation:"));
    assert!(stdout.contains("Remediation:"));
    assert!(!stdout.contains("stub"));

    let output = backend_doctor()
        .args(["explain", "missing/rule"])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown rule id 'missing/rule'"));

    let output = backend_doctor()
        .args(["explain", "core/bootstrap-placeholder"])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("unknown rule id 'core/bootstrap-placeholder'"));
}

#[test]
fn explain_file_line_reports_matching_finding_and_no_finding_fails() {
    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service"),
            "explain".to_string(),
            "internal/client/client.go:8".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Rule: go/http-client-no-timeout"));
    assert!(stdout.contains("Location: internal/client/client.go:8"));
    assert!(stdout.contains("Evidence: client := &http.Client{}"));
    assert!(stdout.contains("Explanation:"));
    assert!(stdout.contains("Remediation:"));
    assert!(stdout.contains("Config status: enabled by config"));
    assert!(stdout.contains("Suppression status: active"));

    let output = backend_doctor()
        .args([
            "explain",
            "fixtures/go-bad-service/internal/client/client.go:8",
        ])
        .current_dir(workspace_root())
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Rule: go/http-client-no-timeout"));

    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service"),
            "explain".to_string(),
            "internal/client/client.go:6".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no finding found"));
}

#[test]
fn init_yes_creates_default_config_without_overwriting() {
    let target = temp_dir("init");
    let output = backend_doctor()
        .args(["init", "--yes"])
        .current_dir(&target)
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config_path = target.join(".backend-doctor.toml");
    let config = fs::read_to_string(&config_path).expect("config written");
    assert!(config.contains("include-gitignored = false"));
    assert!(config.contains("network = false"));
    assert!(config.contains("[external-tools]"));
    assert!(config.contains("deep = false"));
    assert!(config.contains("run-tests = false"));
    assert!(config.contains("scan-history = false"));
    assert!(config.contains("install-missing-tools = false"));
    assert!(config.contains("default-timeout-ms = 30000"));
    assert!(config.contains("output-mode = \"summary\""));
    assert!(config.contains("min-score = 75"));

    fs::write(&config_path, "sentinel = true\n").expect("overwrite temp config");
    let output = backend_doctor()
        .args(["init", "--yes"])
        .current_dir(&target)
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&config_path).expect("config readable"),
        "sentinel = true\n"
    );
    let _ = fs::remove_dir_all(target);
}

#[test]
fn install_codex_yes_prints_deterministic_instructions() {
    let output = backend_doctor()
        .args(["install", "--agent", "codex", "--yes"])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Codex skill installation instructions"));
    assert!(stdout.contains("skills/backend-doctor/SKILL.md"));
    assert!(stdout.contains("No files were written"));
    assert!(!stdout.contains("stub"));
}

#[test]
fn external_gate_flags_are_reported_in_json_config() {
    let mut args = vec![
        fixture_path("empty"),
        "--json".to_string(),
        "--network".to_string(),
    ];
    args.extend(
        [
            "--deep",
            "--run-tests",
            "--scan-history",
            "--install-missing-tools",
        ]
        .into_iter()
        .map(str::to_string),
    );

    let output = backend_doctor()
        .args(&args)
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");
    assert_eq!(report["config"]["network"], true);
    assert_eq!(report["config"]["externalTools"]["network"], true);
    assert_eq!(report["config"]["externalTools"]["deep"], true);
    assert_eq!(report["config"]["externalTools"]["runTests"], true);
    assert_eq!(report["config"]["externalTools"]["scanHistory"], true);
    assert_eq!(
        report["config"]["externalTools"]["installMissingTools"],
        true
    );
    assert_eq!(
        report["externalToolExecutions"].as_array().map(Vec::len),
        Some(0)
    );
    assert_eq!(
        report["externalToolVersions"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn deep_external_tool_cache_reports_miss_hit_disabled_and_stable_results() {
    let target = temp_fixture_copy("go-bad-service");
    let bin_dir = temp_dir("fake-deep-tools");
    write_fake_tool(
        &bin_dir.join("go"),
        r#"#!/bin/sh
case "$1" in
  version) printf 'go version go1.99.0 test\n' ;;
  list) printf '{"ImportPath":"example.test","Dir":"%s","GoFiles":["main.go"]}\n' "$PWD" ;;
  vet) exit 0 ;;
  test) exit 0 ;;
  *) exit 0 ;;
esac
"#,
    );
    write_fake_tool(&bin_dir.join("gofmt"), "#!/bin/sh\nexit 0\n");
    write_fake_tool(
        &bin_dir.join("staticcheck"),
        "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then printf 'staticcheck 2099.1\\n'; fi\nexit 0\n",
    );

    let first = run_json_with_path(&target, &bin_dir);
    let second = run_json_with_path(&target, &bin_dir);

    let first_executions = first["externalToolExecutions"]
        .as_array()
        .expect("executions array");
    let second_executions = second["externalToolExecutions"]
        .as_array()
        .expect("executions array");
    assert!(!first_executions.is_empty());
    let first_cache_statuses = first_executions
        .iter()
        .filter_map(|execution| execution["cache"]["status"].as_str())
        .collect::<Vec<_>>();
    let second_cache_statuses = second_executions
        .iter()
        .filter_map(|execution| execution["cache"]["status"].as_str())
        .collect::<Vec<_>>();
    assert!(!first_cache_statuses.is_empty());
    assert!(!second_cache_statuses.is_empty());
    assert!(first_cache_statuses.iter().all(|status| *status == "miss"));
    assert!(second_cache_statuses.iter().all(|status| *status == "hit"));
    assert_cache_hit_ratio("go-bad-service", "first run", first_executions, 0.0);
    assert_cache_hit_ratio("go-bad-service", "second run", second_executions, 1.0);
    assert_eq!(first["findings"], second["findings"]);
    assert_eq!(
        execution_digests(first_executions),
        execution_digests(second_executions)
    );
    let cache_debug = serde_json::to_string(
        &second_executions
            .iter()
            .map(|execution| execution["cache"].clone())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!cache_debug.contains(target.to_str().unwrap()));
    assert!(!cache_debug.contains("secret"));

    fs::write(
        target.join(CONFIG_FILE_NAME_FOR_TEST),
        "include-gitignored = false\nnetwork = false\noutput-mode = \"summary\"\ndisabled-rules = []\n\n[external-tools]\ndeep = false\nrun-tests = false\nscan-history = false\ninstall-missing-tools = false\nnetwork = false\ndefault-timeout-ms = 30000\n\n[cache]\nenabled = false\nlocation = \"repo-local\"\n\n[thresholds]\nmin-score = 75\n",
    )
    .expect("write disabled cache config");
    let disabled = run_json_with_path(&target, &bin_dir);
    assert!(disabled["externalToolExecutions"]
        .as_array()
        .expect("executions array")
        .iter()
        .all(|execution| execution["cache"]["status"] == "disabled"));

    let _ = fs::remove_dir_all(target);
    let _ = fs::remove_dir_all(bin_dir);
}

const CONFIG_FILE_NAME_FOR_TEST: &str = ".backend-doctor.toml";

fn write_fake_tool(path: &Path, script: &str) {
    fs::write(path, script).expect("write fake tool");
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(path)
        .output()
        .expect("chmod runs");
    assert!(chmod.status.success());
}

fn run_json_with_path(target: &Path, bin_dir: &Path) -> serde_json::Value {
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--json".to_string(),
            "--deep".to_string(),
        ])
        .env("PATH", isolated_tool_path(bin_dir))
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout is valid json")
}

fn run_deep_json_out_with_path(
    target: &Path,
    json_out: &Path,
    bin_dir: &Path,
) -> serde_json::Value {
    let output = backend_doctor()
        .args([
            "--no-fail".to_string(),
            "--deep".to_string(),
            "--json-out".to_string(),
            json_out.to_string_lossy().into_owned(),
            target.to_string_lossy().into_owned(),
        ])
        .env("PATH", isolated_tool_path(bin_dir))
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = fs::read(json_out).expect("json-out report exists");
    serde_json::from_slice(&raw).expect("json-out is valid json")
}

fn finding_rule_categories(report: &serde_json::Value) -> Vec<(String, String)> {
    let mut identities = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|finding| {
            (
                finding["ruleId"].as_str().unwrap_or_default().to_string(),
                finding["category"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<Vec<_>>();
    identities.sort();
    identities
}

fn execution_digests(executions: &[serde_json::Value]) -> Vec<(String, String, String)> {
    executions
        .iter()
        .map(|execution| {
            (
                execution["invocation"]["command"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                execution["stdoutDigest"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                execution["stderrDigest"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect()
}

#[test]
fn security_bad_fixture_deep_json_out_cache_replay_is_deterministic() {
    let target = temp_fixture_copy("security-bad-service");
    let _ = fs::remove_dir_all(target.join(".backend-doctor"));
    let output_dir = temp_dir("security-cache-replay-json");
    let bin_dir = temp_dir("security-cache-replay-tools");

    let first = run_deep_json_out_with_path(&target, &output_dir.join("miss.json"), &bin_dir);
    let second = run_deep_json_out_with_path(&target, &output_dir.join("hit.json"), &bin_dir);

    let first_executions = first["externalToolExecutions"]
        .as_array()
        .expect("executions array");
    let second_executions = second["externalToolExecutions"]
        .as_array()
        .expect("executions array");
    assert!(!first_executions.is_empty());
    let first_cache_statuses = first_executions
        .iter()
        .filter_map(|execution| execution["cache"]["status"].as_str())
        .collect::<Vec<_>>();
    let second_cache_statuses = second_executions
        .iter()
        .filter_map(|execution| execution["cache"]["status"].as_str())
        .collect::<Vec<_>>();
    assert!(!first_cache_statuses.is_empty());
    assert!(!second_cache_statuses.is_empty());
    assert!(first_cache_statuses.iter().all(|status| *status == "miss"));
    assert!(second_cache_statuses.iter().all(|status| *status == "hit"));
    assert_cache_hit_ratio(
        "security-bad-service",
        "first json-out run",
        first_executions,
        0.0,
    );
    assert_cache_hit_ratio(
        "security-bad-service",
        "second json-out run",
        second_executions,
        1.0,
    );

    assert_eq!(
        finding_rule_categories(&first),
        finding_rule_categories(&second)
    );
    assert_eq!(first["score"], second["score"]);
    assert_eq!(first["categoryScores"], second["categoryScores"]);
    assert!(!finding_rule_categories(&second)
        .iter()
        .any(|(rule_id, _)| rule_id == "infra/port-mismatch"));

    let _ = fs::remove_dir_all(target);
    let _ = fs::remove_dir_all(output_dir);
    let _ = fs::remove_dir_all(bin_dir);
}

#[test]
fn reserved_scan_flags_before_subcommands_fail_instead_of_nooping() {
    let cases = [
        vec!["--deep", "rules"],
        vec!["--run-tests", "explain", "go/http-client-no-timeout"],
    ];
    for args in cases {
        let output = backend_doctor()
            .args(&args)
            .output()
            .expect("backend-doctor runs");
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(args[0]),
            "args {args:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("unsupported advanced scan option"),
            "args {args:?}"
        );
        assert!(output.stdout.is_empty(), "args {args:?}");
    }
}

#[test]
fn binary_help_exits_successfully() {
    let output = backend_doctor()
        .arg("--help")
        .output()
        .expect("backend-doctor runs");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("explain"));
    assert!(stdout.contains("rules"));
    assert!(stdout.contains("Project directory to scan"));
    assert!(stdout.contains("Print only the numeric score"));
    assert!(stdout.contains("Print trace diagnostics"));
    assert!(stdout.contains("Explain a rule id or findings"));
}

#[test]
fn missing_or_file_scan_roots_fail_before_scanning() {
    let missing = unique_temp_path("missing-root");
    let _ = fs::remove_dir_all(&missing);

    for args in [
        vec![missing.to_string_lossy().into_owned()],
        vec![
            "--score".to_string(),
            missing.to_string_lossy().into_owned(),
        ],
        vec![
            missing.to_string_lossy().into_owned(),
            "--score".to_string(),
        ],
    ] {
        let output = backend_doctor()
            .args(&args)
            .output()
            .expect("backend-doctor runs");
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("scan path does not exist"),
            "args {args:?}, stderr: {stderr}"
        );
        assert!(output.stdout.is_empty(), "args {args:?}");
    }

    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service/internal/client/client.go"),
            "--json".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("scan path is not a directory"));
    assert!(output.stdout.is_empty());
}

#[test]
fn empty_fixture_json_report_has_score_100_and_no_findings() {
    let output = backend_doctor()
        .args([fixture_path("empty"), "--json".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert_eq!(report["schemaVersion"], "1.0.0");
    assert_eq!(report["score"]["value"], 100);
    assert_eq!(report["label"], "Excellent");
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
    assert_eq!(report["summary"]["totalFindings"], 0);
}

#[test]
fn json_stdout_mode_stays_machine_readable_when_json_out_is_written() {
    let json_path =
        std::env::temp_dir().join(format!("backend-doctor-empty-{}.json", std::process::id()));
    let output = backend_doctor()
        .args([
            fixture_path("empty"),
            "--json".to_string(),
            "--json-out".to_string(),
            json_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(!stdout.contains("Reports"));
    let stdout_report: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout remains valid json");
    assert_eq!(stdout_report["schemaVersion"], "1.0.0");

    let sidecar = fs::read_to_string(&json_path).expect("json out written");
    let sidecar_report: serde_json::Value =
        serde_json::from_str(&sidecar).expect("json out remains valid");
    assert_eq!(sidecar_report["schemaVersion"], "1.0.0");
    let _ = fs::remove_file(json_path);
}

#[test]
fn empty_fixture_score_output_is_exactly_numeric_line() {
    let output = backend_doctor()
        .args([fixture_path("empty"), "--score".to_string()])
        .env("BACKEND_DOCTOR_COLOR", "always")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout is utf8"),
        "100\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn trace_mode_emits_debug_trace_without_polluting_score_stdout() {
    let output = backend_doctor()
        .args([fixture_path("empty"), "--trace".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("backend-doctor v"));
    assert!(stdout.contains("✔ Calculating Backend Doctor score"));
    assert!(stdout.contains("No issues found!"));
    assert!(stdout.contains("100 / 100 Excellent"));
    assert!(!stdout.contains("Services"));
    assert!(!stdout.contains("Project graph"));
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    assert!(stderr.contains("Backend Doctor trace"));
    assert!(stderr.contains("inventory:"));
    assert!(stderr.contains("decision:"));

    let output = backend_doctor()
        .args([
            fixture_path("empty"),
            "--trace".to_string(),
            "--score".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("stdout is utf8"),
        "100\n"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    assert!(stderr.contains("Backend Doctor trace"));
    assert!(stderr.contains("inventory:"));
    assert!(stderr.contains("decision:"));
}

#[test]
fn empty_fixture_default_summary_is_human_terminal_report() {
    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("backend-doctor v"));
    assert!(stdout.contains("✔ Select projects to scan › empty"));
    assert!(stdout.contains("Scanning "));
    assert!(stdout.contains("✔ Detecting backend stack"));
    assert!(stdout.contains("• Running Backend Doctor analysis..."));
    assert!(!stdout.contains("✔ Running Backend Doctor analysis..."));
    assert!(stdout.contains("✔ Calculating Backend Doctor score"));
    assert!(!stdout.contains("✔ Running dependency and security checks"));
    assert!(!stdout.contains("✔ Checking infrastructure, API, and configuration surfaces"));
    assert!(!stdout.contains("✔ Running configured external and deep checks"));
    assert!(!stdout.contains("✔ Skipping external and deep checks; not enabled"));
    assert!(stdout.contains("No issues found!"));
    assert!(stdout.contains("100 / 100 Excellent"));
    assert!(stdout.contains("--score for numeric-only output"));
    assert_order(
        &stdout,
        "• Running Backend Doctor analysis...",
        "✔ Calculating Backend Doctor score",
    );
    assert_order(
        &stdout,
        "• Running Backend Doctor analysis...",
        "backend-doctor v",
    );
    let analysis_task = stdout
        .lines()
        .find(|line| line.contains("Running Backend Doctor analysis..."))
        .expect("analysis task line");
    assert_eq!(analysis_task, "• Running Backend Doctor analysis...");
    assert!(!analysis_task.starts_with('✔'));
    assert_order(
        &stdout,
        "✔ Calculating Backend Doctor score",
        "backend-doctor v",
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.contains("Calculating Backend Doctor score"))
            .count(),
        1
    );
}

#[test]
fn default_summary_can_force_color_but_no_color_disables_it() {
    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .env("BACKEND_DOCTOR_COLOR", "always")
        .env_remove("NO_COLOR")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("\u{1b}[32m✔\u{1b}[0m"));
    assert!(stdout.contains("\u{1b}[32m100\u{1b}[0m / 100"));
    assert!(count_ansi_csi_sequences(&stdout) > 0);

    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .env_remove("BACKEND_DOCTOR_COLOR")
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("\u{1b}[32m✔\u{1b}[0m"));
    assert!(stdout.contains("\u{1b}[32m100\u{1b}[0m / 100"));
    assert!(count_ansi_csi_sequences(&stdout) > 0);

    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .env_remove("BACKEND_DOCTOR_COLOR")
        .env("NO_COLOR", "1")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert_eq!(count_ansi_csi_sequences(&stdout), 0);

    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .env("BACKEND_DOCTOR_COLOR", "always")
        .env("NO_COLOR", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert_eq!(count_ansi_csi_sequences(&stdout), 0);

    let output = backend_doctor()
        .arg(fixture_path("empty"))
        .env_remove("BACKEND_DOCTOR_COLOR")
        .env("NO_COLOR", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert_eq!(count_ansi_csi_sequences(&stdout), 0);
}

#[test]
fn empty_service_fixture_forced_color_matches_dist_style_invocation() {
    let output = backend_doctor()
        .arg(fixture_path("empty-service"))
        .env("BACKEND_DOCTOR_COLOR", "always")
        .env_remove("NO_COLOR")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("empty-service"));
    assert!(count_ansi_csi_sequences(&stdout) > 0);

    let output = backend_doctor()
        .arg(fixture_path("empty-service"))
        .env("BACKEND_DOCTOR_COLOR", "always")
        .env("NO_COLOR", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("✔ Select projects to scan › empty-service"));
    assert_eq!(count_ansi_csi_sequences(&stdout), 0);
}

#[test]
fn empty_fixture_verbose_succeeds_without_findings() {
    let output = backend_doctor()
        .args([fixture_path("empty"), "--verbose".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Backend Doctor"));
    assert!(stdout.contains("Services"));
    assert!(stdout.contains("Findings"));
    assert!(stdout.contains("  none"));
}

#[test]
fn node_bad_fixture_default_summary_groups_and_truncates_findings() {
    let output = backend_doctor()
        .arg(fixture_path("node-express-bad-service"))
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Security"));
    assert!(stdout.contains("✔ Detecting backend stack"));
    assert!(stdout.contains("• Running Backend Doctor analysis..."));
    assert!(!stdout.contains("✔ Running Backend Doctor analysis..."));
    assert!(!stdout.contains("✔ Running dependency and security checks"));
    assert!(!stdout.contains("✔ Checking infrastructure, API, and configuration surfaces"));
    let analysis_task = stdout
        .lines()
        .find(|line| line.contains("Running Backend Doctor analysis..."))
        .expect("analysis task line");
    assert_eq!(analysis_task, "• Running Backend Doctor analysis...");
    assert!(!analysis_task.starts_with('✔'));
    let score_task = stdout
        .lines()
        .find(|line| line.contains("Calculating Backend Doctor score"))
        .expect("score calculation task line");
    assert_eq!(score_task, "✔ Calculating Backend Doctor score");
    assert!(!score_task.contains("Slop Index"));
    assert!(!score_task.contains("findings"));
    assert_order(
        &stdout,
        "• Running Backend Doctor analysis...",
        "✔ Calculating Backend Doctor score",
    );
    assert_order(&stdout, "✔ Calculating Backend Doctor score", "Security");
    assert!(stdout.contains("⚠"));
    assert!(stdout.contains("Backend Doctor"));
    assert!(stdout.contains("Run with --verbose"));
}

#[test]
fn json_stdout_has_no_progress_or_ansi_even_with_forced_color() {
    let output = backend_doctor()
        .args([fixture_path("security-bad-service"), "--json".to_string()])
        .env_remove("BACKEND_DOCTOR_COLOR")
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");
    assert_eq!(report["score"]["value"], 0);
    assert!(!stdout.contains("Detecting backend stack"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn fix_safe_dry_run_output_has_no_progress_or_ansi_even_with_forced_color() {
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--fix-safe".to_string(),
            "--dry-run".to_string(),
        ])
        .env("BACKEND_DOCTOR_COLOR", "always")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix plan (dry run)"));
    assert!(!stdout.contains("Detecting backend stack"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn plan_fixes_dry_run_infra_fixture_reports_stable_summary_counts() {
    let output = backend_doctor()
        .args([
            fixture_path("infra-bad-config"),
            "--plan-fixes".to_string(),
            "--dry-run".to_string(),
            "--no-fail".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix plan (dry run)"));
    assert!(stdout.contains("safe=2 guided=84 patch=2"));
}

#[test]
fn polyglot_fixture_json_includes_project_graph() {
    let output = backend_doctor()
        .args([fixture_path("polyglot-monorepo"), "--json".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert_eq!(report["projectGraph"]["monorepo"], true);
    assert_eq!(
        report["projectGraph"]["services"].as_array().map(Vec::len),
        Some(3)
    );
    assert!(report["projectGraph"]["infra"]["dockerfiles"]
        .as_array()
        .is_some_and(|files| !files.is_empty()));
    assert_eq!(
        report["projectGraph"]["infra"]["openApiSpecs"],
        serde_json::json!(["api/openapi.yaml"])
    );
    assert_eq!(
        report["projectGraph"]["infra"]["migrationFiles"],
        serde_json::json!(["db/migrations/001_init.sql"])
    );
    assert!(report["projectGraph"]["languages"]
        .as_array()
        .is_some_and(|languages| languages.iter().any(|language| language["name"] == "Go")));
}

#[test]
fn polyglot_fixture_debug_includes_detection_details() {
    let output = backend_doctor()
        .args([fixture_path("polyglot-monorepo"), "--debug".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");

    assert!(stdout.contains("Project graph"));
    assert!(stdout.contains("services/go-api"));
    assert!(stdout.contains("Spring Boot"));
    assert!(stdout.contains("infra: docker=1"));
    assert!(stdout.contains("openApiSpecs=1"));
    assert!(stdout.contains("migrationFiles=1"));
    assert!(!stdout.contains("DATABASE_URL"));
}

#[test]
fn go_bad_fixture_json_has_go_findings_and_score_below_100() {
    let output = backend_doctor()
        .args([fixture_path("go-bad-service"), "--json".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert!(report["score"]["value"]
        .as_u64()
        .is_some_and(|score| score < 100));
    let findings = report["findings"].as_array().expect("findings array");
    assert!(findings
        .iter()
        .any(|finding| finding["ruleId"] == "go/http-client-no-timeout"));
    assert!(findings.iter().any(|finding| finding["language"] == "Go"));
    assert!(findings
        .iter()
        .all(|finding| finding["location"]["line"].is_u64()));
    assert!(!stdout.contains("DATABASE_URL"));
    assert!(!stdout.contains("SECRET="));
}

#[test]
fn go_bad_fixture_json_has_stable_normalized_snapshot_fields() {
    let output = backend_doctor()
        .args([fixture_path("go-bad-service"), "--json".to_string()])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");
    let root = report["root"].as_str().expect("root string");
    assert!(root.ends_with("fixtures/go-bad-service"));
    assert_eq!(report["mode"], "full");
    assert_eq!(report["coverage"]["languages"][0]["language"], "Go");
    assert_eq!(report["slop"]["placeholderTests"], 1);
    assert_eq!(report["slop"]["productionPlaceholders"], 1);
    assert_eq!(report["summary"]["safeFixes"], 2);
    assert_eq!(
        sorted_rule_ids(&report),
        vec![
            "agent/placeholder-test",
            "agent/production-placeholder",
            "agent/swallowed-error",
            "go/channel-send-without-select",
            "go/context-background-in-request-path",
            "go/error-ignored",
            "go/fake-test-coverage",
            "go/fiber-cors-wildcard",
            "go/gin-route-missing-auth",
            "go/gofmt-required",
            "go/goroutine-without-cancellation",
            "go/handler-bypasses-service-layer",
            "go/http-client-no-timeout",
            "go/log-fatal-in-library",
            "go/missing-health-endpoint",
            "go/panic-in-handler",
            "go/request-without-context-deadline",
            "go/response-body-not-closed",
            "go/sql-string-concat",
            "go/transaction-across-remote-call",
            "go/unbounded-retry-loop",
        ]
    );
}

#[test]
fn go_bad_fixture_verbose_and_json_out_work() {
    let json_path =
        std::env::temp_dir().join(format!("backend-doctor-go-{}.json", std::process::id()));
    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service"),
            "--verbose".to_string(),
            "--json-out".to_string(),
            json_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("go/http-client-no-timeout"));
    assert!(stdout.contains("Recommended fix"));
    assert!(stdout.contains("Agent Slop Index"));
    assert!(stdout.contains("100 / 100"));
    assert!(stdout.contains("Coverage"));
    assert!(stdout.contains("Go  tier: mvp  maturity: mvp"));
    assert!(stdout.contains("Project graph"));
    assert!(stdout.contains("Reports"));
    assert!(stdout.contains(&format!("JSON report written to {}", json_path.display())));
    let json = fs::read_to_string(&json_path).expect("json out written");
    let report: serde_json::Value = serde_json::from_str(&json).expect("json out valid");
    assert!(report["findings"]
        .as_array()
        .is_some_and(|findings| findings.len() > 5));
    let _ = fs::remove_file(json_path);
}

#[test]
fn go_bad_fixture_writes_sarif_report() {
    let sarif_path =
        std::env::temp_dir().join(format!("backend-doctor-go-{}.sarif", std::process::id()));
    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service"),
            "--sarif".to_string(),
            sarif_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Reports"));
    assert!(stdout.contains(&format!("SARIF report written to {}", sarif_path.display())));
    let sarif = fs::read_to_string(&sarif_path).expect("sarif out written");
    let report: serde_json::Value = serde_json::from_str(&sarif).expect("sarif out valid");
    assert_eq!(report["version"], "2.1.0");
    assert_eq!(
        report["runs"][0]["tool"]["driver"]["name"],
        "Backend Doctor"
    );
    assert_eq!(
        report["runs"][0]["automationDetails"]["id"],
        "backend-doctor/fixtures/go-bad-service"
    );
    assert!(report["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .is_some_and(|rules| !rules.is_empty()));
    assert!(report["runs"][0]["results"]
        .as_array()
        .is_some_and(|results| results
            .iter()
            .any(|result| result["ruleId"] == "go/http-client-no-timeout"
                && result["partialFingerprints"]["backendDoctorFingerprint"].is_string())));
    assert!(!sarif.contains("DATABASE_URL"));
    assert!(!sarif.contains("SECRET="));
    let _ = fs::remove_file(sarif_path);
}

#[test]
fn fixture_sarif_reports_have_unique_run_automation_ids() {
    let output_dir =
        std::env::temp_dir().join(format!("backend-doctor-sarif-ids-{}", std::process::id()));
    let _ = fs::remove_dir_all(&output_dir);
    fs::create_dir_all(&output_dir).expect("create sarif output dir");

    let fixtures = ["go-bad-service", "node-express-bad-service"];
    let mut ids = Vec::new();
    for fixture in fixtures {
        let sarif_path = output_dir.join(format!("{fixture}.sarif"));
        let output = backend_doctor()
            .args([
                fixture_path(fixture),
                "--no-fail".to_string(),
                "--sarif".to_string(),
                sarif_path.to_string_lossy().into_owned(),
            ])
            .output()
            .expect("backend-doctor runs");

        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let sarif = fs::read_to_string(&sarif_path).expect("sarif out written");
        let report: serde_json::Value = serde_json::from_str(&sarif).expect("sarif out valid");
        let id = report["runs"][0]["automationDetails"]["id"]
            .as_str()
            .expect("automationDetails.id is present")
            .to_string();
        assert_eq!(id, format!("backend-doctor/fixtures/{fixture}"));
        ids.push(id);
    }

    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), fixtures.len());
    let _ = fs::remove_dir_all(output_dir);
}

#[test]
fn go_bad_fixture_fix_safe_dry_run_reports_plan_without_modifying_files() {
    let target = fixture_path("go-bad-service/internal/client/client.go");
    let before = fs::read_to_string(&target).expect("fixture readable");
    let output = backend_doctor()
        .args([
            fixture_path("go-bad-service"),
            "--fix-safe".to_string(),
            "--dry-run".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix plan (dry run)"));
    assert!(stdout.contains("go/gofmt-required"));
    assert!(stdout.contains("safe"));
    let after = fs::read_to_string(target).expect("fixture readable");
    assert_eq!(before, after);
}

#[test]
fn go_bad_fixture_fix_safe_yes_applies_to_temp_copy_and_verifies() {
    let target = temp_fixture_copy("go-bad-service");
    let go_file = target.join("internal/client/client.go");
    let before = fs::read_to_string(&go_file).expect("fixture readable");
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-safe".to_string(),
            "--yes".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix application: applied="));
    assert!(stdout.contains("Targeted rescan"));
    let after = fs::read_to_string(&go_file).expect("fixture readable");
    assert_ne!(before, after);
    assert!(after.contains("func BadSpacing() { return }"));
    assert!(after.contains("client := &http.Client{}"));
    let _ = fs::remove_dir_all(target);
}

#[test]
fn guided_fix_dry_run_reports_plan_without_modifying_fixture_copy() {
    let target = temp_fixture_copy("node-express-bad-service");
    let app_file = target.join("src/app.ts");
    let before = fs::read_to_string(&app_file).expect("fixture readable");
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-guided".to_string(),
            "--dry-run".to_string(),
            "--fix-rule".to_string(),
            "node/unbounded-json-body".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix plan (dry run)"));
    assert!(stdout.contains("node/unbounded-json-body"));
    assert!(stdout.contains("express.json({ limit: \"1mb\" })"));
    assert_eq!(
        fs::read_to_string(&app_file).expect("fixture readable"),
        before
    );
    let _ = fs::remove_dir_all(target);
}

#[test]
fn guided_fix_yes_applies_and_targeted_rescan_reports_remaining_matches() {
    let target = temp_fixture_copy("node-express-bad-service");
    let app_file = target.join("src/app.ts");
    let before = fs::read_to_string(&app_file).expect("fixture readable");
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-guided".to_string(),
            "--yes".to_string(),
            "--fix-rule".to_string(),
            "node/unbounded-json-body".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix application: applied=1"));
    assert!(stdout.contains("Applied change: src/app.ts"));
    assert!(stdout.contains("Targeted rescan: remaining matching findings=0"));
    let after = fs::read_to_string(&app_file).expect("fixture readable");
    assert_ne!(before, after);
    assert!(after.contains("app.use(express.json({ limit: \"1mb\" }));"));
    let _ = fs::remove_dir_all(target);
}

#[test]
fn guided_fix_conflict_is_rejected_without_partial_change() {
    let target = temp_fixture_copy("node-express-bad-service");
    let app_file = target.join("src/app.ts");
    let before = fs::read_to_string(&app_file).expect("fixture readable");
    let conflicted = before.replace(
        "app.use(express.json());\n",
        "app.use(express.json());\napp.use(express.json());\n",
    );
    fs::write(&app_file, &conflicted).expect("make conflict fixture");

    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-guided".to_string(),
            "--yes".to_string(),
            "--fix-rule".to_string(),
            "node/unbounded-json-body".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("fix error"));
    assert_eq!(
        fs::read_to_string(&app_file).expect("fixture readable"),
        conflicted
    );
    let _ = fs::remove_dir_all(target);
}

#[test]
fn guided_go_fix_missing_goimports_is_non_fatal_with_guidance() {
    let target = temp_fixture_copy("go-bad-service");
    let empty_path = temp_dir("empty-path");
    let go_file = target.join("internal/client/client.go");
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-guided".to_string(),
            "--yes".to_string(),
            "--fix-rule".to_string(),
            "go/http-client-no-timeout".to_string(),
        ])
        .env("PATH", empty_path.as_os_str())
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    assert!(stderr.contains("goimports not found"));
    let after = fs::read_to_string(&go_file).expect("fixture readable");
    assert!(after.contains("\"time\""));
    assert!(after.contains("Timeout: 10 * time.Second"));
    let _ = fs::remove_dir_all(target);
    let _ = fs::remove_dir_all(empty_path);
}

#[test]
fn guided_go_formatter_failure_rolls_back_formatter_changes() {
    let target = temp_fixture_copy("go-bad-service");
    let bin_dir = temp_dir("fake-goimports");
    let goimports = bin_dir.join("goimports");
    fs::write(
        &goimports,
        "#!/bin/sh\nprintf 'formatter touched\\n' > \"$2\"\nprintf 'boom\\n' >&2\nexit 1\n",
    )
    .expect("write fake goimports");
    let chmod = Command::new("chmod")
        .arg("+x")
        .arg(&goimports)
        .output()
        .expect("chmod runs");
    assert!(chmod.status.success());

    let go_file = target.join("internal/client/client.go");
    let output = backend_doctor()
        .args([
            target.to_string_lossy().into_owned(),
            "--fix-guided".to_string(),
            "--yes".to_string(),
            "--fix-rule".to_string(),
            "go/http-client-no-timeout".to_string(),
        ])
        .env("PATH", path_with_front(&bin_dir))
        .output()
        .expect("backend-doctor runs");

    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&output.stderr).contains("goimports failed"));
    let after = fs::read_to_string(&go_file).expect("fixture readable");
    assert!(after.contains("Timeout: 10 * time.Second"));
    assert!(!after.contains("formatter touched"));
    assert!(!go_file.with_extension("bd-fix-format-backup").exists());
    let _ = fs::remove_dir_all(target);
    let _ = fs::remove_dir_all(bin_dir);
}

#[test]
fn node_bad_fixture_json_has_node_findings_and_redacted_evidence() {
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--json".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert!(report["score"]["value"]
        .as_u64()
        .is_some_and(|score| score < 100));
    let findings = report["findings"].as_array().expect("findings array");
    for rule in [
        "node/floating-promise",
        "node/express-async-error-unhandled",
        "node/route-missing-validation",
        "node/cors-wildcard-production",
        "node/eval-or-function-constructor",
        "node/child-process-shell-injection",
        "node/sql-string-concat",
    ] {
        assert!(
            findings.iter().any(|finding| finding["ruleId"] == rule),
            "missing {rule}"
        );
    }
    let floating_promise = findings
        .iter()
        .find(|finding| finding["ruleId"] == "node/floating-promise")
        .expect("node/floating-promise finding");
    assert_eq!(floating_promise["confidence"], "medium");
    assert_eq!(floating_promise["fix"]["available"], true);
    assert_eq!(floating_promise["fix"]["safety"], "guided");
    assert!(floating_promise["location"]["line"].is_u64());
    assert!(floating_promise["evidence"]["snippet"]
        .as_str()
        .is_some_and(|snippet| snippet.contains("saveLoginAttempt")));
    assert!(floating_promise["remediation"]
        .as_str()
        .is_some_and(|remediation| remediation.contains("Await the promise")));
    assert!(findings
        .iter()
        .any(|finding| finding["language"] == "Node/TypeScript"));
    assert!(findings
        .iter()
        .all(|finding| finding["location"]["line"].is_u64()));
    assert!(!stdout.contains("./ship-order ${req.body.orderId}"));
}

#[test]
fn node_bad_fixture_verbose_json_out_and_fix_dry_run_work() {
    let json_path =
        std::env::temp_dir().join(format!("backend-doctor-node-{}.json", std::process::id()));
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--verbose".to_string(),
            "--json-out".to_string(),
            json_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("node/route-missing-validation"));
    assert!(stdout.contains("Recommended fix"));
    assert!(stdout.contains(&format!("JSON report written to {}", json_path.display())));
    let json = fs::read_to_string(&json_path).expect("json out written");
    let report: serde_json::Value = serde_json::from_str(&json).expect("json out valid");
    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 37);
    for rule in [
        "node/dead-export",
        "node/circular-import-risk",
        "agent/spaghetti-control-flow",
    ] {
        assert!(
            findings.iter().any(|finding| finding["ruleId"] == rule),
            "missing {rule}"
        );
    }
    let _ = fs::remove_file(json_path);

    let target = fixture_path("node-express-bad-service/src/app.ts");
    let before = fs::read_to_string(&target).expect("fixture readable");
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--fix-safe".to_string(),
            "--dry-run".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("Fix plan (dry run)"));
    assert!(stdout.contains("node/console-log-production"));
    assert!(stdout.contains("ESLint"));
    let after = fs::read_to_string(target).expect("fixture readable");
    assert_eq!(before, after);
}

#[test]
fn node_fix_rule_filter_only_plans_console_log() {
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--fix-safe".to_string(),
            "--dry-run".to_string(),
            "--fix-rule".to_string(),
            "node/console-log-production".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("node/console-log-production"));
    assert!(!stdout.contains("config/init"));
}

#[test]
fn java_bad_fixture_json_has_java_findings_and_redacted_evidence() {
    let output = backend_doctor()
        .args([
            fixture_path("java-spring-bad-service"),
            "--json".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert!(report["score"]["value"]
        .as_u64()
        .is_some_and(|score| score < 100));
    let findings = report["findings"].as_array().expect("findings array");
    for rule in [
        "java/http-client-no-timeout",
        "java/missing-request-validation",
        "java/sql-string-concat",
        "java/hardcoded-spring-secret",
        "java/actuator-exposed-sensitive-endpoints",
        "java/open-session-in-view-enabled",
    ] {
        assert!(
            findings.iter().any(|finding| finding["ruleId"] == rule),
            "missing {rule}"
        );
    }
    assert!(findings.iter().any(|finding| finding["language"] == "Java"));
    assert!(findings
        .iter()
        .all(|finding| finding["location"]["line"].is_u64()));
    assert!(findings
        .iter()
        .find(|finding| finding["ruleId"] == "java/missing-request-validation")
        .and_then(|finding| finding["fix"]["description"].as_str())
        .is_some_and(|fix| fix.contains("@Valid")));
    assert!(!stdout.contains("fake-secret-value-for-tests"));
    assert!(!stdout.contains("fake-webhook-secret-for-tests"));
}

#[test]
fn java_no_service_layer_fixture_triggers_service_boundary_rule() {
    let output = backend_doctor()
        .args([
            fixture_path("java-no-service-layer-bad-service"),
            "--json".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(findings.iter().any(|finding| {
        finding["ruleId"] == "java/controller-service-layer-missing"
            && finding["language"] == "Java"
            && finding["metadata"]["buildTool"] == "maven"
    }));
}

#[test]
fn java_bad_fixture_verbose_and_json_out_work() {
    let json_path =
        std::env::temp_dir().join(format!("backend-doctor-java-{}.json", std::process::id()));
    let output = backend_doctor()
        .args([
            fixture_path("java-spring-bad-service"),
            "--verbose".to_string(),
            "--json-out".to_string(),
            json_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("java/missing-request-validation"));
    assert!(stdout.contains("Recommended fix"));
    let json = fs::read_to_string(&json_path).expect("json out written");
    let report: serde_json::Value = serde_json::from_str(&json).expect("json out valid");
    assert!(report["findings"]
        .as_array()
        .is_some_and(|findings| findings.len() > 10));
    assert!(!json.contains("fake-secret-value-for-tests"));
    let _ = fs::remove_file(json_path);
}

#[test]
fn security_bad_fixture_github_annotations_are_redacted() {
    let output = backend_doctor()
        .args([
            fixture_path("security-bad-service"),
            "--github-annotations".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("::error "));
    assert!(stdout.contains("title=security/hardcoded-secret%3A"));
    assert!(stdout.contains("::warning "));
    for raw in [
        "bd_test_1234567890abcdefSECRET",
        "FakeDbPassword12345",
        "fake-oauth-secret-9876543210",
        "fake-yaml-password-123456",
        "fake-yaml-token-abcdef123456",
    ] {
        assert!(!stdout.contains(raw), "annotation output leaked {raw}");
    }
}

#[test]
fn security_bad_fixture_json_with_github_annotations_keeps_stdout_parseable() {
    let output = backend_doctor()
        .args([
            fixture_path("security-bad-service"),
            "--json".to_string(),
            "--github-annotations".to_string(),
        ])
        .env("BACKEND_DOCTOR_COLOR", "always")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr is utf8");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid json");

    assert!(report["findings"]
        .as_array()
        .is_some_and(|findings| !findings.is_empty()));
    assert!(!stdout.contains("::error "));
    assert!(!stdout.contains("::warning "));
    assert!(!stdout.contains("Detecting backend stack"));
    assert!(!stdout.contains("Calculating Backend Doctor score"));
    assert!(!stdout.contains("\u{1b}["));
    assert!(stderr.contains("::error "));
    assert!(stderr.contains("title=security/hardcoded-secret%3A"));
}

#[test]
fn ci_no_fail_summary_has_no_progress_or_ansi_even_with_forced_color() {
    let output = backend_doctor()
        .args([
            fixture_path("node-express-bad-service"),
            "--ci".to_string(),
            "--no-fail".to_string(),
        ])
        .env_remove("BACKEND_DOCTOR_COLOR")
        .env_remove("NO_COLOR")
        .env("CLICOLOR_FORCE", "1")
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("backend-doctor v"));
    assert!(stdout.contains("Security"));
    assert!(stdout.contains("37 issues across 13 files"));
    assert!(!stdout.contains("Detecting backend stack"));
    assert!(!stdout.contains("Running dependency and security checks"));
    assert!(!stdout.contains("Calculating Backend Doctor score"));
    assert!(!stdout.contains("\u{1b}["));
}

#[test]
fn ci_thresholds_and_fail_on_control_exit_status() {
    let empty = backend_doctor()
        .args([fixture_path("empty"), "--ci".to_string()])
        .output()
        .expect("backend-doctor runs");
    assert!(
        empty.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&empty.stderr)
    );

    let bad_score = backend_doctor()
        .args([fixture_path("go-bad-service"), "--ci".to_string()])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(bad_score.status.code(), Some(1));

    let fail_on_security = backend_doctor()
        .args([
            fixture_path("security-bad-service"),
            "--fail-on".to_string(),
            "security".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(fail_on_security.status.code(), Some(1));

    let invalid_fail_on = backend_doctor()
        .args([
            fixture_path("empty"),
            "--fail-on".to_string(),
            "unknown-gate".to_string(),
        ])
        .output()
        .expect("backend-doctor runs");
    assert_eq!(invalid_fail_on.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid_fail_on.stderr)
        .contains("unsupported --fail-on value 'unknown-gate'"));
}

#[test]
fn security_bad_fixture_json_and_verbose_redact_secrets_and_explain_caps() {
    let json_path = std::env::temp_dir().join(format!(
        "backend-doctor-security-{}.json",
        std::process::id()
    ));
    let output = backend_doctor()
        .args([
            fixture_path("security-bad-service"),
            "--verbose".to_string(),
            "--json-out".to_string(),
            json_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("security/hardcoded-secret"));
    assert!(stdout.contains("security/private-key-material"));
    assert!(stdout.contains("supply-chain/vulnerable-dependency"));
    assert!(stdout.contains("Score capped at"));
    for raw in [
        "bd_test_1234567890abcdefSECRET",
        "FakeDbPassword12345",
        "fake-oauth-secret-9876543210",
        "fake-yaml-password-123456",
        "fake-yaml-token-abcdef123456",
        "fake-key-material-for-redaction-only",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ] {
        assert!(!stdout.contains(raw), "verbose leaked {raw}");
    }

    let json = fs::read_to_string(&json_path).expect("json out written");
    let report: serde_json::Value = serde_json::from_str(&json).expect("json out valid");
    let findings = report["findings"].as_array().expect("findings array");
    assert!(findings
        .iter()
        .any(|finding| finding["ruleId"] == "security/hardcoded-secret"));
    assert!(findings.iter().any(
        |finding| finding["ruleId"] == "security/private-key-material"
            && finding["evidence"]["redacted"] == true
    ));
    assert!(findings
        .iter()
        .any(|finding| finding["ruleId"] == "supply-chain/wildcard-version"));
    assert!(findings
        .iter()
        .filter(|finding| finding["ruleId"] == "security/hardcoded-secret")
        .all(|finding| finding["evidence"]["redacted"] == true
            && finding["evidence"]["secretFingerprint"].is_string()));
    assert!(report["score"]["caps"].as_array().is_some_and(|caps| caps
        .iter()
        .any(|cap| cap["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("raw secret")))));
    for raw in [
        "bd_test_1234567890abcdefSECRET",
        "FakeDbPassword12345",
        "fake-oauth-secret-9876543210",
        "fake-yaml-password-123456",
        "fake-yaml-token-abcdef123456",
        "fake-key-material-for-redaction-only",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ] {
        assert!(!json.contains(raw), "json leaked {raw}");
    }
    let _ = fs::remove_file(json_path);

    let output = backend_doctor()
        .args([fixture_path("security-bad-service"), "--json".to_string()])
        .output()
        .expect("backend-doctor runs");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("security/hardcoded-secret"));
    assert!(stdout.contains("supply-chain/vulnerable-dependency"));
    assert!(!stdout.contains("bd_test_1234567890abcdefSECRET"));
}
