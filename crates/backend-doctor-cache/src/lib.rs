use backend_doctor_core::{
    stable_digest, Config, ExternalCommandExecution, ExternalCommandSpec, ExternalCommandStatus,
};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const CACHE_SCHEMA_VERSION: &str = "1.0.0";
pub const CACHE_RULE_VERSION: &str = "builtin-rules:0.1.0";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheLocationPolicy {
    #[default]
    RepoLocal,
    Os,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheSettings {
    pub enabled: bool,
    pub location: CacheLocationPolicy,
    pub override_dir: Option<PathBuf>,
}

impl CacheSettings {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            enabled: config.cache.enabled,
            location: match config.cache.location.as_str() {
                "os" => CacheLocationPolicy::Os,
                _ => CacheLocationPolicy::RepoLocal,
            },
            override_dir: config.cache.directory.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheKeyInput {
    pub schema_version: String,
    pub content_hash: String,
    pub rule_version: String,
    pub tool_name: String,
    pub tool_version: String,
    pub config_version: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd_fingerprint: String,
    pub timeout_ms: Option<u128>,
}

impl CacheKeyInput {
    #[must_use]
    pub fn external_command(
        root: &Path,
        spec: &ExternalCommandSpec,
        config: &Config,
        tool_version: impl Into<String>,
    ) -> Self {
        let cwd = spec.cwd.as_deref().unwrap_or(root);
        Self {
            schema_version: CACHE_SCHEMA_VERSION.to_string(),
            content_hash: content_hash(root, cwd),
            rule_version: CACHE_RULE_VERSION.to_string(),
            tool_name: spec.command.clone(),
            tool_version: tool_version.into(),
            config_version: config_version(config),
            command: spec.command.clone(),
            args: spec.args.clone(),
            env: spec.env.clone(),
            cwd_fingerprint: path_fingerprint(root, cwd),
            timeout_ms: spec.timeout.map(|timeout| timeout.as_millis()),
        }
    }

    #[must_use]
    pub fn digest(&self) -> String {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        stable_digest(&bytes).replace("fnv64:", "bdc1-")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheOutcome {
    Hit,
    Miss,
    Disabled,
    Error(String),
}

#[derive(Clone, Debug)]
pub struct CacheStore {
    root: PathBuf,
    settings: CacheSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedExternalCommandExecution {
    execution: ExternalCommandExecution,
    #[serde(default)]
    redacted_stdout: String,
    #[serde(default)]
    redacted_stderr: String,
}

impl From<&ExternalCommandExecution> for CachedExternalCommandExecution {
    fn from(execution: &ExternalCommandExecution) -> Self {
        Self {
            execution: execution.clone(),
            redacted_stdout: backend_doctor_core::redact_text(&execution.stdout),
            redacted_stderr: backend_doctor_core::redact_text(&execution.stderr),
        }
    }
}

impl CachedExternalCommandExecution {
    fn into_execution(mut self) -> ExternalCommandExecution {
        self.execution.stdout = self.redacted_stdout;
        self.execution.stderr = self.redacted_stderr;
        self.execution
    }
}

impl CacheStore {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>, settings: CacheSettings) -> Self {
        Self {
            root: repo_root.into(),
            settings,
        }
    }

    #[must_use]
    pub fn disabled(repo_root: impl Into<PathBuf>) -> Self {
        Self::new(
            repo_root,
            CacheSettings {
                enabled: false,
                location: CacheLocationPolicy::RepoLocal,
                override_dir: None,
            },
        )
    }

    #[must_use]
    pub fn cache_dir(&self) -> Option<PathBuf> {
        if let Some(dir) = &self.settings.override_dir {
            return Some(dir.clone());
        }
        match self.settings.location {
            CacheLocationPolicy::RepoLocal => Some(self.root.join(".backend-doctor").join("cache")),
            CacheLocationPolicy::Os => ProjectDirs::from("dev", "BackendDoctor", "Backend Doctor")
                .map(|dirs| dirs.cache_dir().join("results")),
        }
    }

    pub fn get_or_run(
        &self,
        key: &CacheKeyInput,
        run: impl FnOnce() -> ExternalCommandExecution,
    ) -> (ExternalCommandExecution, CacheOutcome) {
        if !self.settings.enabled {
            let mut execution = run();
            execution.cache = Some(backend_doctor_core::CacheDebug {
                status: "disabled".to_string(),
                key: None,
                reason: Some("cache disabled".to_string()),
            });
            return (execution, CacheOutcome::Disabled);
        }
        let Some(dir) = self.cache_dir() else {
            let mut execution = run();
            execution.cache = Some(backend_doctor_core::CacheDebug {
                status: "error".to_string(),
                key: None,
                reason: Some("cache directory unavailable".to_string()),
            });
            return (
                execution,
                CacheOutcome::Error("cache directory unavailable".to_string()),
            );
        };
        let digest = key.digest();
        let path = dir.join(format!("{digest}.json"));
        if let Ok(raw) = fs::read_to_string(&path) {
            let cached_execution = serde_json::from_str::<CachedExternalCommandExecution>(&raw)
                .map(CachedExternalCommandExecution::into_execution)
                .or_else(|_| serde_json::from_str::<ExternalCommandExecution>(&raw));
            if let Ok(mut execution) = cached_execution {
                execution.cache = Some(backend_doctor_core::CacheDebug {
                    status: "hit".to_string(),
                    key: Some(digest),
                    reason: None,
                });
                return (execution, CacheOutcome::Hit);
            }
        }

        let mut execution = run();
        execution.cache = Some(backend_doctor_core::CacheDebug {
            status: "miss".to_string(),
            key: Some(digest.clone()),
            reason: None,
        });
        if is_cacheable(&execution) {
            if let Err(error) = fs::create_dir_all(&dir)
                .and_then(|()| {
                    serde_json::to_vec_pretty(&CachedExternalCommandExecution::from(&execution))
                        .map_err(std::io::Error::other)
                })
                .and_then(|bytes| fs::write(&path, bytes))
            {
                execution.cache = Some(backend_doctor_core::CacheDebug {
                    status: "error".to_string(),
                    key: Some(digest),
                    reason: Some(backend_doctor_core::redact_text(&error.to_string())),
                });
                return (execution, CacheOutcome::Error(error.to_string()));
            }
        }
        (execution, CacheOutcome::Miss)
    }
}

#[must_use]
pub fn is_cacheable(execution: &ExternalCommandExecution) -> bool {
    matches!(
        execution.status,
        ExternalCommandStatus::Success
            | ExternalCommandStatus::Failure
            | ExternalCommandStatus::MissingTool
    )
}

#[must_use]
pub fn config_version(config: &Config) -> String {
    stable_digest(&serde_json::to_vec(config).unwrap_or_default())
}

#[must_use]
pub fn content_hash(root: &Path, base: &Path) -> String {
    let mut entries = Vec::new();
    collect_files(root, base, &mut entries);
    entries.sort();
    let mut bytes = Vec::new();
    for path in entries {
        if should_skip(root, &path) {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(&path);
        bytes.extend(rel.to_string_lossy().as_bytes());
        bytes.push(0);
        if let Ok(data) = fs::read(&path) {
            bytes.extend(stable_digest(&data).as_bytes());
        }
        bytes.push(0);
    }
    stable_digest(&bytes)
}

fn collect_files(root: &Path, path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if should_skip(root, &path) {
            continue;
        }
        collect_files(root, &path, files);
    }
}

fn should_skip(root: &Path, path: &Path) -> bool {
    let ignored = [".git", "target", "node_modules"];
    if path.components().any(|component| {
        component
            .as_os_str()
            .to_str()
            .is_some_and(|name| ignored.contains(&name))
    }) {
        return true;
    }
    is_repo_local_backend_doctor_generated_artifact(root, path)
}

fn is_repo_local_backend_doctor_generated_artifact(root: &Path, path: &Path) -> bool {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let mut components = relative.components();
    matches!(
        (
            components
                .next()
                .and_then(|component| component.as_os_str().to_str()),
            components
                .next()
                .and_then(|component| component.as_os_str().to_str()),
        ),
        (Some(".backend-doctor"), Some("cache"))
            | (Some(".backend-doctor"), Some("report.json"))
            | (Some(".backend-doctor"), Some("report.sarif"))
            | (Some(".backend-doctor"), Some("reports"))
    )
}

#[cfg(test)]
fn is_repo_local_backend_doctor_generated_artifact_path(root: &Path, path: &Path) -> bool {
    is_repo_local_backend_doctor_generated_artifact(root, path)
}

fn path_fingerprint(root: &Path, path: &Path) -> String {
    let relative = path.strip_prefix(root).unwrap_or(path);
    stable_digest(relative.to_string_lossy().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{
        ExternalCommandExecution, ExternalCommandRunner, ExternalCommandSpec,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn key_changes_for_content_config_tool_and_command_inputs() {
        let root = temp_root("key-changes");
        fs::write(root.join("a.txt"), "one").expect("write fixture");
        let config = Config::default();
        let spec = ExternalCommandSpec::new("tool").args(["scan"]);
        let first = CacheKeyInput::external_command(&root, &spec, &config, "1.0").digest();

        fs::write(root.join("a.txt"), "two").expect("rewrite fixture");
        let content_changed =
            CacheKeyInput::external_command(&root, &spec, &config, "1.0").digest();
        assert_ne!(first, content_changed);

        let tool_changed = CacheKeyInput::external_command(&root, &spec, &config, "2.0").digest();
        assert_ne!(content_changed, tool_changed);

        let command_changed =
            CacheKeyInput::external_command(&root, &spec.clone().args(["other"]), &config, "2.0")
                .digest();
        assert_ne!(tool_changed, command_changed);

        let mut config_changed = config;
        config_changed.external_tools.default_timeout_ms = 1;
        let config_digest =
            CacheKeyInput::external_command(&root, &spec, &config_changed, "2.0").digest();
        assert_ne!(tool_changed, config_digest);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn content_hash_includes_nested_backend_doctor_directories_but_skips_root_generated_artifacts()
    {
        let root = temp_root("backend-doctor-scope");
        let nested = root.join("packages").join("api").join(".backend-doctor");
        let root_backend_doctor = root.join(".backend-doctor");
        let root_cache = root_backend_doctor.join("cache");
        let root_reports = root_backend_doctor.join("reports");
        fs::create_dir_all(&nested).expect("create nested backend-doctor dir");
        fs::create_dir_all(&root_cache).expect("create root cache dir");
        fs::create_dir_all(&root_reports).expect("create root reports dir");
        fs::write(nested.join("legitimate.json"), "one").expect("write nested file");
        fs::write(root_cache.join("generated.json"), "one").expect("write cache file");
        fs::write(root_backend_doctor.join("report.json"), "{}").expect("write json report");
        fs::write(root_backend_doctor.join("report.sarif"), "{}").expect("write sarif report");
        fs::write(root_reports.join("scan.json"), "{}").expect("write nested report");

        let first = content_hash(&root, &root);
        fs::write(nested.join("legitimate.json"), "two").expect("rewrite nested file");
        let nested_changed = content_hash(&root, &root);
        assert_ne!(first, nested_changed);

        fs::write(root_cache.join("generated.json"), "two").expect("rewrite cache file");
        fs::write(
            root_backend_doctor.join("report.json"),
            "{\"changed\":true}",
        )
        .expect("rewrite json report");
        fs::write(
            root_backend_doctor.join("report.sarif"),
            "{\"changed\":true}",
        )
        .expect("rewrite sarif report");
        fs::write(root_reports.join("scan.json"), "{\"changed\":true}")
            .expect("rewrite nested report");
        let generated_changed = content_hash(&root, &root);
        assert_eq!(nested_changed, generated_changed);
        assert!(is_repo_local_backend_doctor_generated_artifact_path(
            &root,
            &root_cache.join("generated.json")
        ));
        assert!(is_repo_local_backend_doctor_generated_artifact_path(
            &root,
            &root_backend_doctor.join("report.json")
        ));
        assert!(is_repo_local_backend_doctor_generated_artifact_path(
            &root,
            &root_backend_doctor.join("report.sarif")
        ));
        assert!(is_repo_local_backend_doctor_generated_artifact_path(
            &root,
            &root_reports.join("scan.json")
        ));
        assert!(!is_repo_local_backend_doctor_generated_artifact_path(
            &root,
            &nested.join("legitimate.json")
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn store_reports_miss_then_hit_and_disabled_without_paths() {
        let root = temp_root("store");
        fs::write(root.join("a.txt"), "one").expect("write fixture");
        let cache_dir = root.join("cache");
        let store = CacheStore::new(
            &root,
            CacheSettings {
                enabled: true,
                location: CacheLocationPolicy::RepoLocal,
                override_dir: Some(cache_dir),
            },
        );
        let config = Config::default();
        let spec = ExternalCommandSpec::new("tool").args(["secret-token-value-123456"]);
        let key = CacheKeyInput::external_command(&root, &spec, &config, "1.0");
        let (miss, miss_status) = store.get_or_run(&key, || {
            ExternalCommandExecution::missing_tool(&spec, "missing token=secret-token-value-123456")
        });
        assert_eq!(miss_status, CacheOutcome::Miss);
        assert_eq!(
            miss.cache.as_ref().map(|cache| cache.status.as_str()),
            Some("miss")
        );

        let (hit, hit_status) = store.get_or_run(&key, || {
            panic!("cached execution should not re-run");
        });
        assert_eq!(hit_status, CacheOutcome::Hit);
        let cache = hit.cache.as_ref().expect("cache debug");
        assert_eq!(cache.status, "hit");
        assert!(!serde_json::to_string(&cache)
            .unwrap()
            .contains(root.to_str().unwrap()));
        assert!(!serde_json::to_string(&hit)
            .unwrap()
            .contains("secret-token-value-123456"));

        let disabled = CacheStore::disabled(&root);
        let (execution, status) = disabled.get_or_run(&key, || {
            ExternalCommandExecution::missing_tool(&spec, "disabled")
        });
        assert_eq!(status, CacheOutcome::Disabled);
        assert_eq!(
            execution.cache.as_ref().map(|cache| cache.status.as_str()),
            Some("disabled")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn store_replays_redacted_stdout_and_stderr_without_public_stream_fields() {
        let root = temp_root("streams");
        fs::write(root.join("a.txt"), "one").expect("write fixture");
        let cache_dir = root.join("cache");
        let store = CacheStore::new(
            &root,
            CacheSettings {
                enabled: true,
                location: CacheLocationPolicy::RepoLocal,
                override_dir: Some(cache_dir.clone()),
            },
        );
        let config = Config::default();
        let spec = ExternalCommandSpec::new("sh").args([
            "-c",
            "printf 'stdout DATABASE_URL=postgres://secret123456789@db/app'; printf 'stderr TOKEN=shhh123456789' >&2",
        ]);
        let key = CacheKeyInput::external_command(&root, &spec, &config, "tool 1.0");

        let (miss, miss_status) = store.get_or_run(&key, || ExternalCommandRunner::run(&spec));
        assert_eq!(miss_status, CacheOutcome::Miss);
        assert!(miss.stdout.contains("DATABASE_URL=[REDACTED]"));
        assert!(miss.stderr.contains("TOKEN=[REDACTED]"));

        let public_json = serde_json::to_value(&miss).expect("execution serializes");
        assert!(public_json.get("stdout").is_none());
        assert!(public_json.get("stderr").is_none());

        let cache_path = cache_dir.join(format!("{}.json", key.digest()));
        let cache_json = fs::read_to_string(cache_path).expect("cache file");
        assert!(cache_json.contains("redactedStdout"));
        assert!(cache_json.contains("redactedStderr"));
        assert!(!cache_json.contains("secret123456789"));
        assert!(!cache_json.contains("shhh123456789"));

        let (hit, hit_status) = store.get_or_run(&key, || {
            panic!("cached execution should not re-run");
        });
        assert_eq!(hit_status, CacheOutcome::Hit);
        assert_eq!(hit.stdout, miss.stdout);
        assert_eq!(hit.stderr, miss.stderr);
        assert_eq!(hit.stdout_digest, miss.stdout_digest);
        assert_eq!(hit.stderr_digest, miss.stderr_digest);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cached_external_stdout_is_bounded_and_marked_when_truncated() {
        let root = temp_root("bounded-streams");
        fs::write(root.join("a.txt"), "one").expect("write fixture");
        let cache_dir = root.join("cache");
        let store = CacheStore::new(
            &root,
            CacheSettings {
                enabled: true,
                location: CacheLocationPolicy::RepoLocal,
                override_dir: Some(cache_dir.clone()),
            },
        );
        let config = Config::default();
        let spec =
            ExternalCommandSpec::new("sh").args(["-c", "head -c 1052672 /dev/zero | tr '\\0' A"]);
        let key = CacheKeyInput::external_command(&root, &spec, &config, "tool 1.0");

        let (miss, miss_status) = store.get_or_run(&key, || ExternalCommandRunner::run(&spec));
        assert_eq!(miss_status, CacheOutcome::Miss);
        assert!(miss.stdout.contains("BACKEND_DOCTOR_OUTPUT_TRUNCATED"));
        assert!(miss.stdout.len() < 1_060_000);

        let cache_path = cache_dir.join(format!("{}.json", key.digest()));
        let cache_json = fs::read_to_string(cache_path).expect("cache file");
        assert!(cache_json.contains("BACKEND_DOCTOR_OUTPUT_TRUNCATED"));
        assert!(cache_json.len() < 1_070_000);

        let (hit, hit_status) = store.get_or_run(&key, || {
            panic!("cached execution should not re-run");
        });
        assert_eq!(hit_status, CacheOutcome::Hit);
        assert_eq!(hit.stdout, miss.stdout);
        assert!(hit.stdout.contains("BACKEND_DOCTOR_OUTPUT_TRUNCATED"));

        let _ = fs::remove_dir_all(root);
    }

    fn temp_root(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_nanos();
        let root = std::env::temp_dir().join(format!("backend-doctor-cache-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("temp dir");
        root
    }
}
