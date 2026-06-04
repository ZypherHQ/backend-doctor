use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_GATE_FIXTURES: &[&str] = &[
    "empty",
    "security-bad-service",
    "go-bad-service",
    "node-express-bad-service",
    "java-spring-bad-service",
    "python-bad-service",
    "python-fastapi-bad-service",
    "python-good-service",
    "csharp-bad-service",
    "csharp-good-service",
    "php-bad-service",
    "php-good-service",
    "rust-bad-service",
    "rust-good-service",
    "ruby-bad-service",
    "ruby-rails-bad-service",
    "kotlin-bad-service",
    "kotlin-ktor-bad-service",
    "scala-bad-service",
    "elixir-bad-service",
    "c-bad-service",
    "cpp-bad-service",
    "infra-bad-config",
    "polyglot-monorepo",
    "unsupported-language-bad-service",
];

struct CoverageFixture {
    fixture: &'static str,
    language: &'static str,
    tier: &'static str,
}

struct Tier2FixtureExpectation {
    fixture: &'static str,
    language: &'static str,
    source_tool: &'static str,
    expected_rule_ids: &'static [&'static str],
}

struct CleanTier2FixtureExpectation {
    fixture: &'static str,
    language: &'static str,
    prefix: &'static str,
    rule_ids: &'static [&'static str],
}

struct CleanTier3FixtureExpectation {
    fixture: &'static str,
    language: &'static str,
    prefix: &'static str,
    rule_ids: &'static [&'static str],
}

struct BadTier3FixtureExpectation {
    fixture: &'static str,
    language: &'static str,
    source_tool: &'static str,
    rule_id: &'static str,
    path: &'static str,
    line: u64,
    column: u64,
    json_severity: &'static str,
    sarif_level: &'static str,
    evidence_snippet: Option<&'static str>,
}

const RELEASE_SCOPE_LANGUAGE_FIXTURES: &[CoverageFixture] = &[
    CoverageFixture {
        fixture: "go-bad-service",
        language: "Go",
        tier: "mvp",
    },
    CoverageFixture {
        fixture: "node-express-bad-service",
        language: "Node/TypeScript",
        tier: "mvp",
    },
    CoverageFixture {
        fixture: "java-spring-bad-service",
        language: "Java",
        tier: "mvp",
    },
    CoverageFixture {
        fixture: "python-bad-service",
        language: "Python",
        tier: "tier2",
    },
    CoverageFixture {
        fixture: "python-fastapi-bad-service",
        language: "Python",
        tier: "tier2",
    },
    CoverageFixture {
        fixture: "csharp-bad-service",
        language: "C#",
        tier: "tier2",
    },
    CoverageFixture {
        fixture: "php-bad-service",
        language: "PHP",
        tier: "tier2",
    },
    CoverageFixture {
        fixture: "rust-bad-service",
        language: "Rust",
        tier: "tier2",
    },
    CoverageFixture {
        fixture: "ruby-bad-service",
        language: "Ruby",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "ruby-rails-bad-service",
        language: "Ruby",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "kotlin-bad-service",
        language: "Kotlin",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "kotlin-ktor-bad-service",
        language: "Kotlin",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "scala-bad-service",
        language: "Scala",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "elixir-bad-service",
        language: "Elixir",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "c-bad-service",
        language: "C",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "cpp-bad-service",
        language: "C++",
        tier: "tier3",
    },
    CoverageFixture {
        fixture: "unsupported-language-bad-service",
        language: "Clojure",
        tier: "generic",
    },
];

const TIER2_FIXTURE_EXPECTATIONS: &[Tier2FixtureExpectation] = &[
    Tier2FixtureExpectation {
        fixture: "python-bad-service",
        language: "Python",
        source_tool: "builtin-python",
        expected_rule_ids: &[
            "python/requests-without-timeout",
            "python/sql-string-format",
            "python/subprocess-shell-true",
            "python/unsafe-yaml-load",
        ],
    },
    Tier2FixtureExpectation {
        fixture: "python-fastapi-bad-service",
        language: "Python",
        source_tool: "builtin-python",
        expected_rule_ids: &[
            "python/requests-without-timeout",
            "python/sql-string-format",
            "python/subprocess-shell-true",
            "python/unsafe-yaml-load",
        ],
    },
    Tier2FixtureExpectation {
        fixture: "csharp-bad-service",
        language: "C#",
        source_tool: "builtin-csharp",
        expected_rule_ids: &[
            "csharp/cors-allow-any-origin",
            "csharp/httpclient-without-timeout",
            "csharp/sensitive-endpoint-missing-authorize",
            "csharp/sql-string-interpolation",
        ],
    },
    Tier2FixtureExpectation {
        fixture: "php-bad-service",
        language: "PHP",
        source_tool: "builtin-php",
        expected_rule_ids: &[
            "php/display-errors-enabled",
            "php/pdo-query-string-concat",
            "php/shell-exec-user-input",
            "php/unserialize-user-input",
        ],
    },
    Tier2FixtureExpectation {
        fixture: "rust-bad-service",
        language: "Rust",
        source_tool: "builtin-rust",
        expected_rule_ids: &[
            "rust/command-shell-format",
            "rust/cors-allow-any-origin",
            "rust/reqwest-client-without-timeout",
            "rust/sql-format-string",
        ],
    },
];

const CLEAN_TIER2_FIXTURE_EXPECTATIONS: &[CleanTier2FixtureExpectation] = &[
    CleanTier2FixtureExpectation {
        fixture: "python-good-service",
        language: "Python",
        prefix: "python/",
        rule_ids: &[
            "python/requests-without-timeout",
            "python/sql-string-format",
            "python/unsafe-yaml-load",
            "python/subprocess-shell-true",
        ],
    },
    CleanTier2FixtureExpectation {
        fixture: "csharp-good-service",
        language: "C#",
        prefix: "csharp/",
        rule_ids: &[
            "csharp/httpclient-without-timeout",
            "csharp/sql-string-interpolation",
            "csharp/cors-allow-any-origin",
            "csharp/sensitive-endpoint-missing-authorize",
        ],
    },
    CleanTier2FixtureExpectation {
        fixture: "php-good-service",
        language: "PHP",
        prefix: "php/",
        rule_ids: &[
            "php/pdo-query-string-concat",
            "php/unserialize-user-input",
            "php/shell-exec-user-input",
            "php/display-errors-enabled",
        ],
    },
    CleanTier2FixtureExpectation {
        fixture: "rust-good-service",
        language: "Rust",
        prefix: "rust/",
        rule_ids: &[
            "rust/reqwest-client-without-timeout",
            "rust/command-shell-format",
            "rust/sql-format-string",
            "rust/cors-allow-any-origin",
        ],
    },
];

const CLEAN_TIER3_FIXTURE_EXPECTATIONS: &[CleanTier3FixtureExpectation] = &[
    CleanTier3FixtureExpectation {
        fixture: "ruby-good-service",
        language: "Ruby",
        prefix: "ruby/",
        rule_ids: &["ruby/sql-string-interpolation"],
    },
    CleanTier3FixtureExpectation {
        fixture: "kotlin-good-service",
        language: "Kotlin",
        prefix: "kotlin/",
        rule_ids: &["kotlin/unsafe-sql-string-template"],
    },
    CleanTier3FixtureExpectation {
        fixture: "scala-good-service",
        language: "Scala",
        prefix: "scala/",
        rule_ids: &["scala/unsafe-sql-interpolation"],
    },
    CleanTier3FixtureExpectation {
        fixture: "elixir-good-service",
        language: "Elixir",
        prefix: "elixir/",
        rule_ids: &["elixir/unsafe-atom-conversion"],
    },
    CleanTier3FixtureExpectation {
        fixture: "c-good-service",
        language: "C",
        prefix: "c/",
        rule_ids: &["c/unsafe-gets"],
    },
    CleanTier3FixtureExpectation {
        fixture: "cpp-good-service",
        language: "C++",
        prefix: "cpp/",
        rule_ids: &["cpp/unsafe-strcpy"],
    },
];

const BAD_TIER3_FIXTURE_EXPECTATIONS: &[BadTier3FixtureExpectation] = &[
    BadTier3FixtureExpectation {
        fixture: "ruby-bad-service",
        language: "Ruby",
        source_tool: "builtin-ruby",
        rule_id: "ruby/sql-string-interpolation",
        path: "app.rb",
        line: 3,
        column: 5,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "ruby-rails-bad-service",
        language: "Ruby",
        source_tool: "builtin-ruby",
        rule_id: "ruby/sql-string-interpolation",
        path: "app/controllers/users_controller.rb",
        line: 4,
        column: 7,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "kotlin-bad-service",
        language: "Kotlin",
        source_tool: "builtin-kotlin",
        rule_id: "kotlin/unsafe-sql-string-template",
        path: "src/main/kotlin/App.kt",
        line: 2,
        column: 5,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "kotlin-ktor-bad-service",
        language: "Kotlin",
        source_tool: "builtin-kotlin",
        rule_id: "kotlin/unsafe-sql-string-template",
        path: "src/main/kotlin/com/example/bad/Application.kt",
        line: 25,
        column: 13,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "scala-bad-service",
        language: "Scala",
        source_tool: "builtin-scala",
        rule_id: "scala/unsafe-sql-interpolation",
        path: "src/main/scala/App.scala",
        line: 3,
        column: 5,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "elixir-bad-service",
        language: "Elixir",
        source_tool: "builtin-elixir",
        rule_id: "elixir/unsafe-atom-conversion",
        path: "lib/bad_service.ex",
        line: 3,
        column: 5,
        json_severity: "error",
        sarif_level: "error",
        evidence_snippet: Some("String.to_atom(name)"),
    },
    BadTier3FixtureExpectation {
        fixture: "c-bad-service",
        language: "C",
        source_tool: "builtin-c",
        rule_id: "c/unsafe-gets",
        path: "main.c",
        line: 5,
        column: 3,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
    BadTier3FixtureExpectation {
        fixture: "cpp-bad-service",
        language: "C++",
        source_tool: "builtin-c",
        rule_id: "cpp/unsafe-strcpy",
        path: "main.cpp",
        line: 4,
        column: 3,
        json_severity: "critical",
        sarif_level: "error",
        evidence_snippet: None,
    },
];

const TIER2_AND_TIER3_GOLDEN_FIXTURES: &[&str] = &[
    "python-bad-service",
    "python-fastapi-bad-service",
    "python-good-service",
    "csharp-bad-service",
    "csharp-good-service",
    "php-bad-service",
    "php-good-service",
    "rust-bad-service",
    "rust-good-service",
    "ruby-bad-service",
    "ruby-rails-bad-service",
    "ruby-good-service",
    "kotlin-bad-service",
    "kotlin-ktor-bad-service",
    "kotlin-good-service",
    "scala-bad-service",
    "scala-good-service",
    "elixir-bad-service",
    "elixir-good-service",
    "c-bad-service",
    "c-good-service",
    "cpp-bad-service",
    "cpp-good-service",
];

fn backend_doctor() -> Command {
    Command::new(env!("CARGO_BIN_EXE_backend-doctor"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> String {
    workspace_root()
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn temp_project_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "backend-doctor-schema-gate-{}-{name}-{nanos}",
        std::process::id()
    ))
}

fn write_project_file(root: &Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create {}: {error}", parent.display()));
    }
    fs::write(&path, contents).unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

fn read_json(path: PathBuf) -> Value {
    let content = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|error| panic!("parse {} as json: {error}", path.display()))
}

fn report_schema_with_local_refs() -> Value {
    let root = workspace_root();
    let mut report_schema = read_json(root.join("schemas/backend-doctor-report.schema.json"));
    let mut config_schema = read_json(root.join("schemas/backend-doctor-config.schema.json"));

    let config_object = config_schema
        .as_object_mut()
        .expect("config schema is an object");
    config_object.remove("$schema");
    config_object.remove("$id");

    report_schema["properties"]["config"] = serde_json::json!({ "$ref": "#/$defs/config" });
    report_schema["$defs"]["config"] = config_schema;
    report_schema
}

#[test]
fn config_schema_accepts_pathless_explicit_broad_suppression_flag() {
    let schema = read_json(workspace_root().join("schemas/backend-doctor-config.schema.json"));
    let validator = jsonschema::validator_for(&schema).expect("compile config schema");
    let config = serde_json::json!({
        "includeGitignored": false,
        "network": false,
        "externalTools": {
            "deep": false,
            "runTests": false,
            "scanHistory": false,
            "installMissingTools": false,
            "network": false,
            "defaultTimeoutMs": 30000
        },
        "cache": {
            "enabled": true,
            "location": "repo-local",
            "directory": null
        },
        "outputMode": "summary",
        "thresholds": {
            "minScore": 75,
            "maxCritical": null,
            "maxErrors": null
        },
        "disabledRules": [],
        "rules": {},
        "suppressions": [
            {
                "rule": "agent/production-placeholder",
                "allowBroad": true,
                "reason": "legacy generated baseline",
                "expires": null
            }
        ]
    });

    assert_schema_valid(&validator, "config-allowBroad-suppression", &config);
}

fn sarif_schema() -> Value {
    read_json(workspace_root().join("schemas/sarif-schema-2.1.0.json"))
}

fn run_fixture_json_report(fixture: &str) -> (String, Value) {
    let report_path =
        temp_project_path(&format!("json-{}", fixture.replace('/', "-"))).with_extension("json");
    let _ = fs::remove_file(&report_path);

    let output = backend_doctor()
        .args([
            fixture_path(fixture),
            "--json-out".to_string(),
            report_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "{fixture} stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fs::read_to_string(&report_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", report_path.display()));
    let value = serde_json::from_str(&report).unwrap_or_else(|error| {
        panic!("{fixture} --json-out report is valid json: {error}\nreport:\n{report}")
    });
    let _ = fs::remove_file(report_path);
    (report, value)
}

fn run_project_json_report(project: &Path, label: &str) -> (String, Value) {
    let report_path = std::env::temp_dir().join(format!(
        "backend-doctor-schema-gate-{}-{}.json",
        std::process::id(),
        label.replace('/', "-")
    ));
    let _ = fs::remove_file(&report_path);

    let output = backend_doctor()
        .args([
            project.to_string_lossy().into_owned(),
            "--no-fail".to_string(),
            "--json-out".to_string(),
            report_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "{} stderr: {}",
        label,
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fs::read_to_string(&report_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", report_path.display()));
    let value = serde_json::from_str(&report).unwrap_or_else(|error| {
        panic!("{label} --json-out report is valid json: {error}\nreport:\n{report}")
    });
    let _ = fs::remove_file(report_path);
    (report, value)
}

fn run_fixture_sarif(fixture: &str) -> (String, Value) {
    let report_path =
        temp_project_path(&format!("sarif-{}", fixture.replace('/', "-"))).with_extension("sarif");
    let _ = fs::remove_file(&report_path);

    let output = backend_doctor()
        .args([
            fixture_path(fixture),
            "--no-fail".to_string(),
            "--sarif".to_string(),
            report_path.to_string_lossy().into_owned(),
        ])
        .output()
        .expect("backend-doctor runs");

    assert!(
        output.status.success(),
        "{fixture} stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = fs::read_to_string(&report_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", report_path.display()));
    let value = serde_json::from_str(&report).unwrap_or_else(|error| {
        panic!("{fixture} --sarif report is valid json: {error}\nreport:\n{report}")
    });
    let _ = fs::remove_file(report_path);
    (report, value)
}

fn normalize_workspace_path_string(fixture: &str, value: &str) -> String {
    let workspace = workspace_root().to_string_lossy().replace('\\', "/");
    let fixture_root = workspace_root()
        .join("fixtures")
        .join(fixture)
        .to_string_lossy()
        .replace('\\', "/");
    let slash_value = value.replace('\\', "/");
    if !slash_value.contains(&workspace) && !slash_value.contains(&fixture_root) {
        return value.to_string();
    }

    slash_value
        .replace(&fixture_root, &format!("<workspace>/fixtures/{fixture}"))
        .replace(&workspace, "<workspace>")
}

fn normalize_report_value(fixture: &str, value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, child) in object.iter_mut() {
                match key.as_str() {
                    "toolVersion" => *child = Value::String("<tool-version>".to_string()),
                    "startedAt" => *child = Value::String("<started-at>".to_string()),
                    "durationMs" => *child = Value::Number(0.into()),
                    _ => normalize_report_value(fixture, child),
                }
            }
        }
        Value::Array(values) => {
            for child in values {
                normalize_report_value(fixture, child);
            }
        }
        Value::String(string) => {
            *string = normalize_workspace_path_string(fixture, string);
        }
        _ => {}
    }
}

fn normalize_report_snapshot(fixture: &str, mut report: Value) -> Value {
    normalize_report_value(fixture, &mut report);
    report
}

fn normalize_sarif_snapshot(mut report: Value) -> Value {
    if let Some(runs) = report["runs"].as_array_mut() {
        for run in runs {
            if let Some(driver) = run["tool"]["driver"].as_object_mut() {
                if driver.contains_key("version") {
                    driver.insert(
                        "version".to_string(),
                        Value::String("<tool-version>".to_string()),
                    );
                }
                if driver.contains_key("semanticVersion") {
                    driver.insert(
                        "semanticVersion".to_string(),
                        Value::String("<tool-version>".to_string()),
                    );
                }
            }
        }
    }
    report
}

fn pretty_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("snapshot value serializes")
}

fn assert_snapshot_matches(label: &str, expected: Value, actual: Value) {
    assert_eq!(
        expected,
        actual,
        "{label} golden snapshot mismatch\nexpected:\n{}\nactual:\n{}",
        pretty_json(&expected),
        pretty_json(&actual)
    );
}

fn assert_json_snapshot(fixture: &str, report: Value) {
    let expected_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("reports")
        .join(format!("{fixture}.json"));
    let expected = read_json(expected_path);
    let actual = normalize_report_snapshot(fixture, report);
    assert_snapshot_matches(&format!("{fixture} JSON report"), expected, actual);
}

fn assert_sarif_snapshot(fixture: &str, report: Value) {
    let expected_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("sarif")
        .join(format!("{fixture}.sarif.json"));
    let expected = read_json(expected_path);
    let actual = normalize_sarif_snapshot(report);
    assert_snapshot_matches(&format!("{fixture} SARIF report"), expected, actual);
}

fn assert_schema_valid(
    validator: &jsonschema::Validator,
    fixture: &str,
    report: &serde_json::Value,
) {
    let evaluation = validator.evaluate(report);
    if evaluation.flag().valid {
        return;
    }

    let errors = evaluation
        .iter_errors()
        .take(20)
        .map(|error| {
            format!(
                "{} at instance {} schema {}",
                error.error, error.instance_location, error.schema_location
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    panic!("{fixture} report failed backend-doctor JSON schema validation:\n{errors}");
}

fn assert_sarif_schema_valid(
    validator: &jsonschema::Validator,
    fixture: &str,
    report: &serde_json::Value,
) {
    let evaluation = validator.evaluate(report);
    if evaluation.flag().valid {
        return;
    }

    let errors = evaluation
        .iter_errors()
        .take(20)
        .map(|error| {
            format!(
                "{} at instance {} schema {}",
                error.error, error.instance_location, error.schema_location
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    panic!("{fixture} SARIF failed OASIS SARIF 2.1.0 schema validation:\n{errors}");
}

fn assert_slop_and_coverage_shape(report: &Value) {
    for field in [
        "index",
        "findings",
        "placeholderTests",
        "productionPlaceholders",
        "semanticCopyPaste",
        "spaghettiControlFlow",
        "swallowedErrors",
    ] {
        assert!(report["slop"][field].is_u64(), "slop.{field} is numeric");
    }
    assert!(
        report["coverage"]["languages"].is_array(),
        "coverage.languages is an array"
    );
}

fn assert_report_size_under(fixture: &str, format: &str, report: &str, ceiling_bytes: usize) {
    let size = report.len();
    assert!(
        size <= ceiling_bytes,
        "{fixture} {format} report is {size} bytes, above {ceiling_bytes} byte ceiling"
    );
}

fn assert_runtime_and_summary_consistency(fixture: &str, report: &Value) {
    assert!(
        report["durationMs"].as_u64().is_some(),
        "{fixture} durationMs must be a nonnegative integer: {:?}",
        report["durationMs"]
    );

    let findings = report["findings"]
        .as_array()
        .unwrap_or_else(|| panic!("{fixture} findings is an array"));
    let suppressed_findings = report["suppressedFindings"]
        .as_array()
        .unwrap_or_else(|| panic!("{fixture} suppressedFindings is an array"));
    let summary = &report["summary"];

    let critical_findings = findings
        .iter()
        .filter(|finding| finding["severity"] == "critical")
        .count();
    let error_findings = findings
        .iter()
        .filter(|finding| finding["severity"] == "error")
        .count();

    assert_eq!(
        summary["totalFindings"].as_u64(),
        Some(findings.len() as u64),
        "{fixture} summary.totalFindings must match findings length"
    );
    assert_eq!(
        summary["suppressedFindings"].as_u64(),
        Some(suppressed_findings.len() as u64),
        "{fixture} summary.suppressedFindings must match suppressedFindings length"
    );
    assert_eq!(
        summary["criticalFindings"].as_u64(),
        Some(critical_findings as u64),
        "{fixture} summary.criticalFindings must match active critical findings"
    );
    assert_eq!(
        summary["errorFindings"].as_u64(),
        Some(error_findings as u64),
        "{fixture} summary.errorFindings must match active error findings"
    );
}

fn assert_github_sarif_shape(fixture: &str, report: &Value) {
    assert_eq!(report["version"], "2.1.0", "{fixture} SARIF version");
    assert!(
        report["$schema"].as_str().is_some_and(|schema| {
            schema == "https://json.schemastore.org/sarif-2.1.0.json"
                || schema
                    == "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
        }),
        "{fixture} SARIF $schema is pinned to a SARIF 2.1.0 schema URI"
    );

    let runs = report["runs"].as_array().expect("SARIF runs array");
    assert!(!runs.is_empty(), "{fixture} SARIF has at least one run");
    for (run_index, run) in runs.iter().enumerate() {
        assert!(
            run["automationDetails"]["id"]
                .as_str()
                .is_some_and(|id| !id.trim().is_empty()),
            "{fixture} run {run_index} has automationDetails.id"
        );
        let rules = run["tool"]["driver"]["rules"]
            .as_array()
            .expect("SARIF rules array");
        let results = run["results"].as_array().expect("SARIF results array");
        for result in results {
            let rule_id = result["ruleId"].as_str().expect("result ruleId");
            assert!(
                rules.iter().any(|rule| rule["id"] == rule_id),
                "{fixture} result ruleId {rule_id} has matching tool.driver.rules entry"
            );
            assert!(
                result["message"]["text"]
                    .as_str()
                    .is_some_and(|message| !message.is_empty()),
                "{fixture} result has message.text"
            );
            assert!(
                result["partialFingerprints"]["backendDoctorFingerprint"]
                    .as_str()
                    .is_some_and(|fingerprint| !fingerprint.is_empty()),
                "{fixture} result has backendDoctorFingerprint"
            );
            if let Some(locations) = result["locations"].as_array() {
                for location in locations {
                    assert!(
                        location["physicalLocation"]["artifactLocation"]["uri"]
                            .as_str()
                            .is_some_and(|uri| !uri.trim().is_empty()),
                        "{fixture} result location has artifactLocation.uri"
                    );
                }
            }
        }
    }
}

fn assert_language_tier(report: &Value, language: &str, tier: &str) {
    let languages = report["coverage"]["languages"]
        .as_array()
        .expect("coverage.languages array");
    assert!(
        languages.iter().any(|entry| {
            entry["language"] == language
                && entry["tier"] == tier
                && entry["detectedFiles"]
                    .as_u64()
                    .is_some_and(|files| files > 0)
                && entry["ruleFamilies"]
                    .as_array()
                    .is_some_and(|families| !families.is_empty())
                && entry["notes"]
                    .as_str()
                    .is_some_and(|notes| !notes.is_empty())
        }),
        "missing coverage entry {language}/{tier}: {languages:?}"
    );
}

fn sorted_expected_rule_ids(case: &Tier2FixtureExpectation) -> Vec<String> {
    let mut ids = case
        .expected_rule_ids
        .iter()
        .map(|id| (*id).to_string())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn sorted_json_rule_ids(report: &Value) -> Vec<String> {
    let mut ids = report["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|finding| {
            finding["ruleId"]
                .as_str()
                .expect("finding ruleId")
                .to_string()
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn sorted_sarif_result_rule_ids(report: &Value) -> Vec<String> {
    let mut ids = report["runs"]
        .as_array()
        .expect("SARIF runs array")
        .iter()
        .flat_map(|run| {
            run["results"]
                .as_array()
                .expect("SARIF results array")
                .iter()
                .map(|result| {
                    result["ruleId"]
                        .as_str()
                        .expect("SARIF result ruleId")
                        .to_string()
                })
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn sorted_sarif_driver_rule_ids(report: &Value) -> Vec<String> {
    let mut ids = report["runs"]
        .as_array()
        .expect("SARIF runs array")
        .iter()
        .flat_map(|run| {
            run["tool"]["driver"]["rules"]
                .as_array()
                .expect("SARIF driver rules array")
                .iter()
                .map(|rule| {
                    rule["id"]
                        .as_str()
                        .expect("SARIF driver rule id")
                        .to_string()
                })
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn assert_relative_report_path(context: &str, path: &str) {
    assert!(
        !Path::new(path).is_absolute(),
        "{context} path should be relative, got {path}"
    );
    assert!(
        !path.split('/').any(|part| part == ".."),
        "{context} path should not traverse parents, got {path}"
    );
}

fn assert_tier2_json_evidence(case: &Tier2FixtureExpectation, report: &Value) {
    assert_eq!(report["schemaVersion"], "1.0.0", "{} schema", case.fixture);
    assert_eq!(report["mode"], "full", "{} mode", case.fixture);
    assert!(
        report["root"]
            .as_str()
            .is_some_and(|root| root.ends_with(&format!("fixtures/{}", case.fixture))),
        "{} root should point at its fixture without pinning an absolute workspace: {:?}",
        case.fixture,
        report["root"]
    );
    assert_eq!(
        sorted_json_rule_ids(report),
        sorted_expected_rule_ids(case),
        "{} JSON rule ids",
        case.fixture
    );
    assert_eq!(
        report["summary"]["totalFindings"].as_u64(),
        Some(case.expected_rule_ids.len() as u64),
        "{} summary total findings",
        case.fixture
    );
    assert_eq!(
        report["summary"]["suppressedFindings"].as_u64(),
        Some(0),
        "{} suppressed findings",
        case.fixture
    );
    assert_eq!(
        report["externalToolVersions"].as_array().map(Vec::len),
        Some(0),
        "{} should not execute gated external tools by default",
        case.fixture
    );
    assert_eq!(
        report["externalToolExecutions"].as_array().map(Vec::len),
        Some(0),
        "{} should not record external executions by default",
        case.fixture
    );

    let services = report["services"].as_array().expect("services array");
    assert_eq!(services.len(), 1, "{} service count", case.fixture);
    let service_languages = services[0]["languages"]
        .as_array()
        .expect("service languages array");
    assert_eq!(
        service_languages.len(),
        1,
        "{} service language count",
        case.fixture
    );
    assert_eq!(
        service_languages[0].as_str(),
        Some(case.language),
        "{} service language",
        case.fixture
    );

    let coverage_languages = report["coverage"]["languages"]
        .as_array()
        .expect("coverage.languages array");
    let coverage = coverage_languages
        .iter()
        .find(|entry| entry["language"] == case.language)
        .unwrap_or_else(|| panic!("{} missing coverage entry", case.fixture));
    assert_eq!(coverage["tier"], "tier2", "{} coverage tier", case.fixture);
    assert_eq!(
        coverage["maturity"], "language-specific",
        "{} coverage maturity",
        case.fixture
    );
    assert!(
        coverage["ruleFamilies"]
            .as_array()
            .expect("coverage ruleFamilies array")
            .iter()
            .any(|family| family == "language-heuristics"),
        "{} coverage should include language heuristics",
        case.fixture
    );
    assert!(
        coverage["notes"]
            .as_str()
            .is_some_and(|notes| notes.contains("Tier 2 language-specific heuristic rules")),
        "{} coverage notes should preserve bounded Tier 2 wording",
        case.fixture
    );

    for finding in report["findings"].as_array().expect("findings array") {
        let rule_id = finding["ruleId"].as_str().expect("finding ruleId");
        assert!(
            case.expected_rule_ids.contains(&rule_id),
            "{} unexpected finding rule id {rule_id}",
            case.fixture
        );
        assert_eq!(
            finding["language"].as_str(),
            Some(case.language),
            "{} finding language for {rule_id}",
            case.fixture
        );
        assert_eq!(
            finding["sourceTool"].as_str(),
            Some(case.source_tool),
            "{} source tool for {rule_id}",
            case.fixture
        );
        assert_eq!(
            finding["metadata"]["coverageTier"].as_str(),
            Some("tier2"),
            "{} coverage tier metadata for {rule_id}",
            case.fixture
        );
        assert_eq!(
            finding["metadata"]["maturity"].as_str(),
            Some("language-specific"),
            "{} maturity metadata for {rule_id}",
            case.fixture
        );
        assert!(
            finding["metadata"]["syntaxFingerprint"]
                .as_str()
                .is_some_and(|fingerprint| fingerprint.starts_with("fnv64:")),
            "{} syntax fingerprint for {rule_id}",
            case.fixture
        );
        let location_path = finding["location"]["path"]
            .as_str()
            .expect("finding location path");
        assert_relative_report_path(
            &format!("{} JSON finding {rule_id}", case.fixture),
            location_path,
        );
    }
}

fn assert_tier2_sarif_evidence(case: &Tier2FixtureExpectation, report: &Value) {
    assert_eq!(report["version"], "2.1.0", "{} SARIF version", case.fixture);
    assert_eq!(
        sorted_sarif_result_rule_ids(report),
        sorted_expected_rule_ids(case),
        "{} SARIF result rule ids",
        case.fixture
    );
    assert_eq!(
        sorted_sarif_driver_rule_ids(report),
        sorted_expected_rule_ids(case),
        "{} SARIF driver rule ids",
        case.fixture
    );

    let runs = report["runs"].as_array().expect("SARIF runs array");
    assert_eq!(runs.len(), 1, "{} SARIF run count", case.fixture);
    let run = &runs[0];
    let expected_automation_id = format!("backend-doctor/fixtures/{}", case.fixture);
    assert_eq!(
        run["automationDetails"]["id"].as_str(),
        Some(expected_automation_id.as_str()),
        "{} SARIF automation id",
        case.fixture
    );

    for result in run["results"].as_array().expect("SARIF results array") {
        let rule_id = result["ruleId"].as_str().expect("SARIF result ruleId");
        assert!(
            result["message"]["text"]
                .as_str()
                .is_some_and(|message| !message.trim().is_empty()),
            "{} SARIF message for {rule_id}",
            case.fixture
        );
        assert!(
            result["partialFingerprints"]["backendDoctorFingerprint"]
                .as_str()
                .is_some_and(|fingerprint| fingerprint.starts_with("fnv64:")),
            "{} SARIF fingerprint for {rule_id}",
            case.fixture
        );
        for location in result["locations"]
            .as_array()
            .expect("SARIF result locations array")
        {
            let uri = location["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .expect("SARIF artifact URI");
            assert_relative_report_path(&format!("{} SARIF {rule_id}", case.fixture), uri);
        }
    }

    for rule in run["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF driver rules array")
    {
        let rule_id = rule["id"].as_str().expect("SARIF rule id");
        assert!(
            rule["properties"]["category"]
                .as_str()
                .is_some_and(|category| !category.trim().is_empty()),
            "{} SARIF category for {rule_id}",
            case.fixture
        );
        assert_eq!(
            rule["properties"]["sourceTool"].as_str(),
            Some(case.source_tool),
            "{} SARIF source tool for {rule_id}",
            case.fixture
        );
    }
}

fn assert_tier2_clean_json_evidence(case: &CleanTier2FixtureExpectation, report: &Value) {
    assert_eq!(report["schemaVersion"], "1.0.0", "{} schema", case.fixture);
    assert_eq!(report["mode"], "full", "{} mode", case.fixture);
    assert_eq!(
        report["summary"]["totalFindings"].as_u64(),
        Some(0),
        "{} summary total findings",
        case.fixture
    );
    assert_eq!(
        report["summary"]["suppressedFindings"].as_u64(),
        Some(0),
        "{} suppressed findings",
        case.fixture
    );
    assert_eq!(
        report["externalToolVersions"].as_array().map(Vec::len),
        Some(0),
        "{} should not execute gated external tools by default",
        case.fixture
    );
    assert_eq!(
        report["externalToolExecutions"].as_array().map(Vec::len),
        Some(0),
        "{} should not record external executions by default",
        case.fixture
    );
    assert_language_tier(report, case.language, "tier2");

    let services = report["services"].as_array().expect("services array");
    assert_eq!(services.len(), 1, "{} service count", case.fixture);
    let service_languages = services[0]["languages"]
        .as_array()
        .expect("service languages array");
    assert!(
        service_languages
            .iter()
            .any(|language| language == case.language),
        "{} service languages should include {}; languages={service_languages:?}",
        case.fixture,
        case.language
    );

    let rule_ids = sorted_json_rule_ids(report);
    for rule_id in case.rule_ids {
        assert!(
            !rule_ids.iter().any(|id| id == rule_id),
            "{} JSON unexpectedly emitted {rule_id}; ids={rule_ids:?}",
            case.fixture
        );
    }
    assert!(
        !rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} JSON unexpectedly emitted same-language Tier 2 findings; ids={rule_ids:?}",
        case.fixture
    );
    assert!(
        !rule_ids
            .iter()
            .any(|id| id == "core/unsupported-language-coverage"),
        "{} JSON should not emit unsupported-language coverage",
        case.fixture
    );
}

fn assert_tier2_clean_sarif_evidence(case: &CleanTier2FixtureExpectation, report: &Value) {
    assert_eq!(report["version"], "2.1.0", "{} SARIF version", case.fixture);
    let result_rule_ids = sorted_sarif_result_rule_ids(report);
    let driver_rule_ids = sorted_sarif_driver_rule_ids(report);
    for rule_id in case.rule_ids {
        assert!(
            !result_rule_ids.iter().any(|id| id == rule_id),
            "{} SARIF unexpectedly emitted result {rule_id}; ids={result_rule_ids:?}",
            case.fixture
        );
        assert!(
            !driver_rule_ids.iter().any(|id| id == rule_id),
            "{} SARIF unexpectedly emitted driver rule {rule_id}; ids={driver_rule_ids:?}",
            case.fixture
        );
    }
    assert!(
        !result_rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} SARIF unexpectedly emitted same-language Tier 2 results; ids={result_rule_ids:?}",
        case.fixture
    );
    assert!(
        !driver_rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} SARIF unexpectedly emitted same-language Tier 2 driver rules; ids={driver_rule_ids:?}",
        case.fixture
    );
    assert!(
        !result_rule_ids
            .iter()
            .any(|id| id == "core/unsupported-language-coverage"),
        "{} SARIF should not emit unsupported-language coverage results",
        case.fixture
    );
    assert!(
        !driver_rule_ids
            .iter()
            .any(|id| id == "core/unsupported-language-coverage"),
        "{} SARIF should not emit unsupported-language coverage driver rules",
        case.fixture
    );
}

fn assert_tier3_clean_json_evidence(case: &CleanTier3FixtureExpectation, report: &Value) {
    assert_eq!(report["schemaVersion"], "1.0.0", "{} schema", case.fixture);
    assert_eq!(
        report["externalToolVersions"].as_array().map(Vec::len),
        Some(0),
        "{} should not execute gated external tools by default",
        case.fixture
    );
    assert_eq!(
        report["externalToolExecutions"].as_array().map(Vec::len),
        Some(0),
        "{} should not record external executions by default",
        case.fixture
    );
    assert_language_tier(report, case.language, "tier3");

    let rule_ids = sorted_json_rule_ids(report);
    for rule_id in case.rule_ids {
        assert!(
            !rule_ids.iter().any(|id| id == rule_id),
            "{} JSON unexpectedly emitted {rule_id}; ids={rule_ids:?}",
            case.fixture
        );
    }
    assert!(
        !rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} JSON unexpectedly emitted same-language Tier 3 findings; ids={rule_ids:?}",
        case.fixture
    );
    assert!(
        !rule_ids
            .iter()
            .any(|id| id == "core/unsupported-language-coverage"),
        "{} JSON should not emit unsupported-language coverage",
        case.fixture
    );
}

fn assert_tier3_clean_sarif_evidence(case: &CleanTier3FixtureExpectation, report: &Value) {
    assert_eq!(report["version"], "2.1.0", "{} SARIF version", case.fixture);
    let result_rule_ids = sorted_sarif_result_rule_ids(report);
    let driver_rule_ids = sorted_sarif_driver_rule_ids(report);
    for rule_id in case.rule_ids {
        assert!(
            !result_rule_ids.iter().any(|id| id == rule_id),
            "{} SARIF unexpectedly emitted result {rule_id}; ids={result_rule_ids:?}",
            case.fixture
        );
        assert!(
            !driver_rule_ids.iter().any(|id| id == rule_id),
            "{} SARIF unexpectedly emitted driver rule {rule_id}; ids={driver_rule_ids:?}",
            case.fixture
        );
    }
    assert!(
        !result_rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} SARIF unexpectedly emitted same-language Tier 3 results; ids={result_rule_ids:?}",
        case.fixture
    );
    assert!(
        !driver_rule_ids.iter().any(|id| id.starts_with(case.prefix)),
        "{} SARIF unexpectedly emitted same-language Tier 3 driver rules; ids={driver_rule_ids:?}",
        case.fixture
    );
}

fn assert_tier3_bad_json_evidence(case: &BadTier3FixtureExpectation, report: &Value) {
    assert_eq!(report["schemaVersion"], "1.0.0", "{} schema", case.fixture);
    assert_eq!(report["mode"], "full", "{} mode", case.fixture);
    assert_eq!(
        report["externalToolVersions"].as_array().map(Vec::len),
        Some(0),
        "{} should not execute gated external tools by default",
        case.fixture
    );
    assert_eq!(
        report["externalToolExecutions"].as_array().map(Vec::len),
        Some(0),
        "{} should not record external executions by default",
        case.fixture
    );

    let expected_rule_ids = vec![case.rule_id.to_string()];
    assert_eq!(
        sorted_json_rule_ids(report),
        expected_rule_ids,
        "{} JSON rule ids",
        case.fixture
    );
    assert_eq!(
        report["summary"]["totalFindings"].as_u64(),
        Some(1),
        "{} summary total findings",
        case.fixture
    );
    assert_eq!(
        report["summary"]["suppressedFindings"].as_u64(),
        Some(0),
        "{} suppressed findings",
        case.fixture
    );

    let services = report["services"].as_array().expect("services array");
    assert_eq!(services.len(), 1, "{} service count", case.fixture);
    let service_languages = services[0]["languages"]
        .as_array()
        .expect("service languages array");
    assert!(
        service_languages
            .iter()
            .any(|language| language == case.language),
        "{} service languages should include {}; languages={service_languages:?}",
        case.fixture,
        case.language
    );

    let coverage_languages = report["coverage"]["languages"]
        .as_array()
        .expect("coverage.languages array");
    let coverage = coverage_languages
        .iter()
        .find(|entry| entry["language"] == case.language)
        .unwrap_or_else(|| panic!("{} missing coverage entry", case.fixture));
    assert_eq!(coverage["tier"], "tier3", "{} coverage tier", case.fixture);
    assert_eq!(
        coverage["maturity"], "language-specific",
        "{} coverage maturity",
        case.fixture
    );
    assert!(
        coverage["ruleFamilies"]
            .as_array()
            .expect("coverage ruleFamilies array")
            .iter()
            .any(|family| family == "language-heuristics"),
        "{} coverage should include language heuristics",
        case.fixture
    );

    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "{} finding count", case.fixture);
    let finding = &findings[0];
    assert_eq!(
        finding["ruleId"].as_str(),
        Some(case.rule_id),
        "{} finding rule id",
        case.fixture
    );
    assert_eq!(
        finding["severity"].as_str(),
        Some(case.json_severity),
        "{} finding severity",
        case.fixture
    );
    assert_eq!(
        finding["language"].as_str(),
        Some(case.language),
        "{} finding language",
        case.fixture
    );
    assert_eq!(
        finding["sourceTool"].as_str(),
        Some(case.source_tool),
        "{} source tool",
        case.fixture
    );
    assert_eq!(
        finding["metadata"]["coverageTier"].as_str(),
        Some("tier3"),
        "{} coverage tier metadata",
        case.fixture
    );
    assert_eq!(
        finding["metadata"]["maturity"].as_str(),
        Some("language-specific"),
        "{} maturity metadata",
        case.fixture
    );
    assert!(
        finding["metadata"]["syntaxFingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("fnv64:")),
        "{} syntax fingerprint",
        case.fixture
    );
    assert!(
        finding["message"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{} finding message",
        case.fixture
    );
    assert!(
        finding["impact"]
            .as_str()
            .is_some_and(|impact| !impact.trim().is_empty()),
        "{} finding impact",
        case.fixture
    );
    assert!(
        finding["remediation"]
            .as_str()
            .is_some_and(|remediation| !remediation.trim().is_empty()),
        "{} finding remediation",
        case.fixture
    );

    let location_path = finding["location"]["path"]
        .as_str()
        .expect("finding location path");
    assert_eq!(location_path, case.path, "{} finding path", case.fixture);
    assert_relative_report_path(&format!("{} JSON", case.fixture), location_path);
    assert_eq!(
        finding["location"]["line"].as_u64(),
        Some(case.line),
        "{} finding line",
        case.fixture
    );
    assert_eq!(
        finding["location"]["column"].as_u64(),
        Some(case.column),
        "{} finding column",
        case.fixture
    );

    let snippet = finding["evidence"]["snippet"]
        .as_str()
        .unwrap_or_else(|| panic!("{} evidence snippet", case.fixture));
    assert!(
        !snippet.trim().is_empty(),
        "{} evidence snippet is nonempty",
        case.fixture
    );
    if let Some(expected_snippet) = case.evidence_snippet {
        assert!(
            snippet.contains(expected_snippet),
            "{} evidence snippet should contain {expected_snippet:?}: {snippet:?}",
            case.fixture
        );
    }
}

fn assert_tier3_bad_sarif_evidence(case: &BadTier3FixtureExpectation, report: &Value) {
    assert_eq!(report["version"], "2.1.0", "{} SARIF version", case.fixture);
    let expected_rule_ids = vec![case.rule_id.to_string()];
    assert_eq!(
        sorted_sarif_result_rule_ids(report),
        expected_rule_ids,
        "{} SARIF result rule ids",
        case.fixture
    );
    assert_eq!(
        sorted_sarif_driver_rule_ids(report),
        vec![case.rule_id.to_string()],
        "{} SARIF driver rule ids",
        case.fixture
    );

    let runs = report["runs"].as_array().expect("SARIF runs array");
    assert_eq!(runs.len(), 1, "{} SARIF run count", case.fixture);
    let run = &runs[0];
    let expected_automation_id = format!("backend-doctor/fixtures/{}", case.fixture);
    assert_eq!(
        run["automationDetails"]["id"].as_str(),
        Some(expected_automation_id.as_str()),
        "{} SARIF automation id",
        case.fixture
    );

    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("SARIF driver rules array");
    assert_eq!(rules.len(), 1, "{} SARIF driver rule count", case.fixture);
    let rule = &rules[0];
    assert_eq!(
        rule["id"].as_str(),
        Some(case.rule_id),
        "{} SARIF driver rule id",
        case.fixture
    );
    assert_eq!(
        rule["defaultConfiguration"]["level"].as_str(),
        Some(case.sarif_level),
        "{} SARIF driver rule level",
        case.fixture
    );
    assert_eq!(
        rule["properties"]["sourceTool"].as_str(),
        Some(case.source_tool),
        "{} SARIF source tool",
        case.fixture
    );
    assert!(
        rule["shortDescription"]["text"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{} SARIF short description",
        case.fixture
    );
    assert!(
        rule["fullDescription"]["text"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{} SARIF full description",
        case.fixture
    );

    let results = run["results"].as_array().expect("SARIF results array");
    assert_eq!(results.len(), 1, "{} SARIF result count", case.fixture);
    let result = &results[0];
    assert_eq!(
        result["ruleId"].as_str(),
        Some(case.rule_id),
        "{} SARIF result rule id",
        case.fixture
    );
    assert_eq!(
        result["level"].as_str(),
        Some(case.sarif_level),
        "{} SARIF result level",
        case.fixture
    );
    assert!(
        result["message"]["text"]
            .as_str()
            .is_some_and(|message| !message.trim().is_empty()),
        "{} SARIF message",
        case.fixture
    );
    assert!(
        result["partialFingerprints"]["backendDoctorFingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("fnv64:")),
        "{} SARIF backendDoctorFingerprint",
        case.fixture
    );
    assert!(
        result["partialFingerprints"]["backendDoctorFindingId"]
            .as_str()
            .is_some_and(|finding_id| finding_id.starts_with("fnv64:")),
        "{} SARIF backendDoctorFindingId",
        case.fixture
    );

    let locations = result["locations"]
        .as_array()
        .expect("SARIF result locations array");
    assert_eq!(locations.len(), 1, "{} SARIF location count", case.fixture);
    let location = &locations[0];
    let uri = location["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .expect("SARIF artifact URI");
    assert_eq!(uri, case.path, "{} SARIF artifact URI", case.fixture);
    assert_relative_report_path(&format!("{} SARIF", case.fixture), uri);
    assert_eq!(
        location["physicalLocation"]["region"]["startLine"].as_u64(),
        Some(case.line),
        "{} SARIF start line",
        case.fixture
    );
    assert_eq!(
        location["physicalLocation"]["region"]["startColumn"].as_u64(),
        Some(case.column),
        "{} SARIF start column",
        case.fixture
    );
}

fn write_tier_a_analysis_project(root: &Path) {
    write_project_file(
        root,
        "cmd/api/main.go",
        r#"
package main

import (
    "database/sql"
    "net/http"
    "net/url"
    "github.com/gin-gonic/gin"
    "google.golang.org/grpc"
)

type server struct{}

func listUsers(c *gin.Context) {
    q := c.Query("q")
    safe := url.QueryEscape(q)
    db.Query("select * from users where name = " + safe)
    c.JSON(200, gin.H{"ok": true})
}

func health(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("ok"))
}

func main() {
    router := gin.Default()
    router.GET("/users/:id", listUsers)
    http.HandleFunc("/health", health)
    http.Get("/internal")
    pb.RegisterUserServiceServer(grpc.NewServer(), &server{})
}
"#,
    );
    write_project_file(
        root,
        "src/app.ts",
        r#"
import express from 'express';
import { Controller, Get, Param } from '@nestjs/common';
import { z } from 'zod';
const fastify = require('fastify')();
const app = express();

function listUsers(req, res) {
  const parsed = z.string().parse(req.query.name);
  db.query('select * from users where name = ' + parsed);
  res.json({ ok: true });
}

app.get('/users/:id', listUsers);
fastify.route({ method: 'POST', url: '/events', handler: async (request, reply) => {
  await db.execute(request.body.sql);
  reply.send({ ok: true });
}});

@Controller('admin')
class AdminController {
  @Get(':id')
  find(@Param('id') id: string) {
    return id;
  }
}
"#,
    );
    write_project_file(
        root,
        "src/main/java/com/acme/UserController.java",
        r#"
package com.acme;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

@RestController
@RequestMapping("/api")
class UserController {
    @GetMapping("/users/{id}")
    ResponseEntity<String> getUser(@PathVariable String id, @RequestParam String q) {
        String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml4(q);
        jdbcTemplate.query("select * from users where name = " + safe, mapper);
        return ResponseEntity.ok(id);
    }
}

@Path("/v1")
class ItemResource {
    @POST
    @Path("/items")
    public Response create(@QueryParam("name") String name) {
        Runtime.getRuntime().exec(name);
        return Response.ok(name).build();
    }
}
"#,
    );
}

fn assert_analysis_array_populated(report: &Value, field: &str) {
    let values = report["analysisFacts"][field]
        .as_array()
        .unwrap_or_else(|| panic!("analysisFacts.{field} is an array"));
    assert!(
        !values.is_empty(),
        "analysisFacts.{field} should be populated"
    );
}

#[test]
fn fixture_sarif_reports_match_oasis_schema_and_github_shape() {
    let schema = sarif_schema();
    let validator = jsonschema::validator_for(&schema).expect("compile SARIF schema");
    const SARIF_REPORT_SIZE_CEILING_BYTES: usize = 192 * 1024;

    let mut run_ids = BTreeMap::new();
    for fixture in SCHEMA_GATE_FIXTURES {
        let (sarif, report) = run_fixture_sarif(fixture);
        assert_sarif_schema_valid(&validator, fixture, &report);
        assert_github_sarif_shape(fixture, &report);
        assert_report_size_under(fixture, "SARIF", &sarif, SARIF_REPORT_SIZE_CEILING_BYTES);
        assert!(!sarif.contains("DATABASE_URL"));
        assert!(!sarif.contains("SECRET="));
        assert!(!sarif.contains("TOKEN=raw"));

        for run in report["runs"].as_array().expect("SARIF runs array") {
            let run_id = run["automationDetails"]["id"]
                .as_str()
                .expect("automationDetails.id");
            assert!(
                run_ids.insert(run_id.to_string(), fixture).is_none(),
                "duplicate SARIF automationDetails.id {run_id}"
            );
        }
    }
}

#[test]
fn default_and_disabled_json_reports_omit_analysis_facts_without_changing_findings() {
    let root = temp_project_path("analysis-disabled");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create {}: {error}", root.display()));
    write_project_file(
        &root,
        "cmd/api/main.go",
        r#"
package main

func main() {}
"#,
    );

    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    let (_raw_default, default_report) = run_project_json_report(&root, "analysis-default");
    assert_schema_valid(&validator, "analysis-default", &default_report);
    assert!(
        default_report.get("analysisFacts").is_none(),
        "analysisFacts should be omitted by default"
    );
    let default_findings = default_report["findings"]
        .as_array()
        .expect("default findings array")
        .len();

    write_project_file(
        &root,
        ".backend-doctor.toml",
        r#"
[analysis]
enabled = false
cache = true
adapters = []
"#,
    );

    let (_raw_disabled, disabled_report) = run_project_json_report(&root, "analysis-disabled");
    assert_schema_valid(&validator, "analysis-disabled", &disabled_report);
    assert!(
        disabled_report.get("analysisFacts").is_none(),
        "analysisFacts should be omitted when analysis.enabled is false"
    );
    assert_eq!(
        disabled_report["findings"]
            .as_array()
            .expect("disabled findings array")
            .len(),
        default_findings,
        "explicitly disabled analysis should not change finding count"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn enabled_json_report_populates_analysis_facts_and_matches_schema() {
    let root = temp_project_path("analysis-enabled");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create {}: {error}", root.display()));
    write_tier_a_analysis_project(&root);
    write_project_file(
        &root,
        ".backend-doctor.toml",
        r#"
[analysis]
enabled = true
cache = true
adapters = ["go", "node-typescript", "java"]
"#,
    );

    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    let (_raw_report, report) = run_project_json_report(&root, "analysis-enabled");
    assert_schema_valid(&validator, "analysis-enabled", &report);

    let facts = report["analysisFacts"]
        .as_object()
        .expect("analysisFacts object is present");
    assert_eq!(
        facts["schemaVersion"], "1.0.0",
        "analysis facts schema version is serialized"
    );
    for field in [
        "sourceFiles",
        "symbols",
        "calls",
        "imports",
        "routes",
        "dataSources",
        "sinks",
        "sanitizers",
        "taintEdges",
    ] {
        assert_analysis_array_populated(&report, field);
    }
    assert!(report["analysisFacts"]["sourceFiles"]
        .as_array()
        .expect("sourceFiles array")
        .iter()
        .any(|source| source["language"] == "Go"));
    assert!(report["analysisFacts"]["sourceFiles"]
        .as_array()
        .expect("sourceFiles array")
        .iter()
        .any(|source| source["language"] == "Node/TypeScript"));
    assert!(report["analysisFacts"]["sourceFiles"]
        .as_array()
        .expect("sourceFiles array")
        .iter()
        .any(|source| source["language"] == "Java"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn enabled_analysis_facts_are_available_to_rules_scan_before_report_attachment() {
    let root = temp_project_path("analysis-rules-route-facts");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create {}: {error}", root.display()));
    write_project_file(
        &root,
        "src/app.ts",
        r#"
const fastify = require('fastify')();
fastify.route({ method: 'DELETE', url: '/events', handler: async (request, reply) => {
  reply.send({ ok: true });
}});
"#,
    );
    write_project_file(
        &root,
        "openapi.yaml",
        r#"
openapi: 3.0.0
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
security:
  - bearerAuth: []
paths:
  /events:
    post:
      responses:
        '400':
          description: bad request
"#,
    );
    write_project_file(
        &root,
        ".backend-doctor.toml",
        r#"
[analysis]
enabled = true
cache = true
adapters = ["node-typescript"]
"#,
    );

    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    let (_raw_report, report) = run_project_json_report(&root, "analysis-rules-route-facts");
    assert_schema_valid(&validator, "analysis-rules-route-facts", &report);
    assert!(
        report["analysisFacts"]["routes"]
            .as_array()
            .expect("analysisFacts.routes array")
            .iter()
            .any(|route| route["method"] == "DELETE" && route["path"] == "/events"),
        "analysisFacts should include the Fastify route: {:?}",
        report["analysisFacts"]["routes"]
    );
    assert!(
        report["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .any(|finding| finding["ruleId"] == "api/route-spec-drift"
                && finding["evidence"]["snippet"] == "DELETE /events"),
        "rules scan should consume analysis facts before report attachment: {:?}",
        report["findings"]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn csharp_analysis_config_aliases_emit_csharp_facts() {
    let root = temp_project_path("analysis-csharp-aliases");
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("create {}: {error}", root.display()));
    write_project_file(
        &root,
        "Program.cs",
        r#"
using Microsoft.AspNetCore.Builder;
using Microsoft.Data.SqlClient;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/admin/users/{id}", (string id) =>
{
    var client = new HttpClient();
    using var command = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}");
    return "ok";
});

app.Run();
"#,
    );
    write_project_file(
        &root,
        "App.csproj",
        r#"
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>
"#,
    );

    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    for alias in ["csharp", "c-sharp", "dotnet"] {
        write_project_file(
            &root,
            ".backend-doctor.toml",
            &format!(
                r#"
[analysis]
enabled = true
cache = true
adapters = ["{alias}"]
"#
            ),
        );

        let (_raw_report, report) =
            run_project_json_report(&root, &format!("analysis-csharp-alias-{alias}"));
        assert_schema_valid(&validator, alias, &report);
        let facts = report["analysisFacts"]
            .as_object()
            .unwrap_or_else(|| panic!("{alias} analysisFacts object is present"));
        assert!(
            facts["sourceFiles"]
                .as_array()
                .expect("sourceFiles array")
                .iter()
                .any(|source| source["language"] == "C#"),
            "{alias} should include the C# source file"
        );
        for field in ["calls", "imports"] {
            assert!(
                !facts[field]
                    .as_array()
                    .unwrap_or_else(|| panic!("{alias} analysisFacts.{field} array"))
                    .is_empty(),
                "{alias} should emit C# {field}"
            );
        }
        for field in ["routes", "dataSources", "sinks"] {
            assert!(
                facts[field]
                    .as_array()
                    .unwrap_or_else(|| panic!("{alias} analysisFacts.{field} array"))
                    .iter()
                    .any(|fact| fact["metadata"]["adapter"] == "csharp"),
                "{alias} should emit C# {field}"
            );
        }
    }

    let _ = fs::remove_dir_all(root);
}

#[test]
fn fixture_json_reports_match_backend_doctor_schema() {
    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    const JSON_REPORT_SIZE_CEILING_BYTES: usize = 256 * 1024;

    let mut reports = BTreeMap::new();
    for fixture in SCHEMA_GATE_FIXTURES {
        let (raw_report, report) = run_fixture_json_report(fixture);
        assert_schema_valid(&validator, fixture, &report);
        assert_slop_and_coverage_shape(&report);
        assert_runtime_and_summary_consistency(fixture, &report);
        assert_report_size_under(fixture, "JSON", &raw_report, JSON_REPORT_SIZE_CEILING_BYTES);
        reports.insert(*fixture, report);
    }

    let empty = reports.get("empty").expect("empty report");
    assert_eq!(
        empty["coverage"]["languages"]
            .as_array()
            .expect("coverage.languages array")
            .len(),
        0
    );

    for case in RELEASE_SCOPE_LANGUAGE_FIXTURES {
        let report = reports
            .get(case.fixture)
            .unwrap_or_else(|| panic!("{} report is schema-gated", case.fixture));
        assert_language_tier(report, case.language, case.tier);
    }

    let polyglot = reports
        .get("polyglot-monorepo")
        .expect("polyglot-monorepo report");
    for language in ["Go", "Node/TypeScript", "Java"] {
        assert_language_tier(polyglot, language, "mvp");
    }

    let unsupported = reports
        .get("unsupported-language-bad-service")
        .expect("unsupported-language-bad-service report");
    assert!(unsupported["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["ruleId"] == "core/unsupported-language-coverage"));
}

#[test]
fn report_schema_version_1_accepts_legacy_slop_without_new_agent_counters() {
    let schema = report_schema_with_local_refs();
    let validator = jsonschema::validator_for(&schema).expect("compile report schema");
    let (_raw_report, mut report) = run_fixture_json_report("empty");

    assert_eq!(report["schemaVersion"], "1.0.0");
    assert_schema_valid(&validator, "empty-current", &report);
    assert!(
        report["slop"]["semanticCopyPaste"].is_u64(),
        "current reports should emit slop.semanticCopyPaste"
    );
    assert!(
        report["slop"]["spaghettiControlFlow"].is_u64(),
        "current reports should emit slop.spaghettiControlFlow"
    );

    let slop = report["slop"].as_object_mut().expect("slop object");
    slop.remove("semanticCopyPaste");
    slop.remove("spaghettiControlFlow");

    assert_schema_valid(&validator, "empty-legacy-1.0-slop", &report);
}

#[test]
fn tier2_fixture_reports_have_normalized_json_and_sarif_evidence() {
    for case in TIER2_FIXTURE_EXPECTATIONS {
        let (_raw_json, json_report) = run_fixture_json_report(case.fixture);
        assert_tier2_json_evidence(case, &json_report);

        let (_raw_sarif, sarif_report) = run_fixture_sarif(case.fixture);
        assert_tier2_sarif_evidence(case, &sarif_report);
    }
}

#[test]
fn tier2_clean_fixture_reports_do_not_emit_language_specific_findings() {
    let report_schema = report_schema_with_local_refs();
    let report_validator =
        jsonschema::validator_for(&report_schema).expect("compile report schema");
    let sarif_schema = sarif_schema();
    let sarif_validator = jsonschema::validator_for(&sarif_schema).expect("compile SARIF schema");

    for case in CLEAN_TIER2_FIXTURE_EXPECTATIONS {
        let (_raw_json, json_report) = run_fixture_json_report(case.fixture);
        assert_schema_valid(&report_validator, case.fixture, &json_report);
        assert_tier2_clean_json_evidence(case, &json_report);

        let (_raw_sarif, sarif_report) = run_fixture_sarif(case.fixture);
        assert_sarif_schema_valid(&sarif_validator, case.fixture, &sarif_report);
        assert_tier2_clean_sarif_evidence(case, &sarif_report);
    }
}

#[test]
fn tier2_and_tier3_json_reports_match_persisted_golden_snapshots() {
    for fixture in TIER2_AND_TIER3_GOLDEN_FIXTURES {
        let (_raw_json, json_report) = run_fixture_json_report(fixture);
        assert_json_snapshot(fixture, json_report);
    }
}

#[test]
fn tier2_and_tier3_sarif_reports_match_persisted_golden_snapshots() {
    for fixture in TIER2_AND_TIER3_GOLDEN_FIXTURES {
        let (_raw_sarif, sarif_report) = run_fixture_sarif(fixture);
        assert_sarif_snapshot(fixture, sarif_report);
    }
}

#[test]
fn tier3_clean_fixture_reports_do_not_emit_language_specific_findings() {
    for case in CLEAN_TIER3_FIXTURE_EXPECTATIONS {
        let (_raw_json, json_report) = run_fixture_json_report(case.fixture);
        assert_tier3_clean_json_evidence(case, &json_report);

        let (_raw_sarif, sarif_report) = run_fixture_sarif(case.fixture);
        assert_tier3_clean_sarif_evidence(case, &sarif_report);
    }
}

#[test]
fn tier3_bad_fixture_reports_have_normalized_json_and_sarif_evidence() {
    for case in BAD_TIER3_FIXTURE_EXPECTATIONS {
        let (_raw_json, json_report) = run_fixture_json_report(case.fixture);
        assert_tier3_bad_json_evidence(case, &json_report);

        let (_raw_sarif, sarif_report) = run_fixture_sarif(case.fixture);
        assert_tier3_bad_sarif_evidence(case, &sarif_report);
    }
}

#[test]
fn schema_gate_inventory_covers_release_scope_language_fixtures() {
    for case in RELEASE_SCOPE_LANGUAGE_FIXTURES {
        assert!(
            SCHEMA_GATE_FIXTURES.contains(&case.fixture),
            "{} must be included in JSON and SARIF schema gates",
            case.fixture
        );
    }
}
