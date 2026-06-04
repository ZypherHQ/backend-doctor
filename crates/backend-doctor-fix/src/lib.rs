use backend_doctor_core::{redact_text, Finding, FixSafety, Fixability, CONFIG_FILE_NAME};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixOptions {
    pub safety: FixSelection,
    pub dry_run: bool,
    pub apply: bool,
    pub rule_filter: Option<String>,
    pub finding_filter: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixSelection {
    All,
    Safe,
    Guided,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixApplyMode {
    Safe,
    Guided,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixPlan {
    pub dry_run: bool,
    pub entries: Vec<FixPlanEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixPlanEntry {
    pub finding_id: String,
    pub rule_id: String,
    pub safety: Fixability,
    pub path: Option<PathBuf>,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub patches: Vec<Patch>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Patch {
    pub path: PathBuf,
    pub edits: Vec<FileEdit>,
    pub creates_file: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEdit {
    pub original: String,
    pub replacement: String,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixApplicationResult {
    pub applied: usize,
    pub skipped: usize,
    pub remaining: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_paths: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formatter_warnings: Vec<String>,
    pub errors: Vec<FixApplicationError>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixApplicationError {
    pub path: Option<PathBuf>,
    pub kind: FixErrorKind,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixErrorKind {
    Conflict,
    InvalidPath,
    BinaryFile,
    Io,
    Unsupported,
}

impl fmt::Display for FixApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(path) => write!(f, "{}: {}", path.display(), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl FixPlan {
    #[must_use]
    pub fn empty(dry_run: bool) -> Self {
        Self {
            dry_run,
            entries: Vec::new(),
        }
    }

    #[must_use]
    pub fn from_findings(findings: &[Finding], safety: FixSafety, dry_run: bool) -> Self {
        Self::build(Path::new("."), findings, &legacy_options(safety, dry_run))
    }

    #[must_use]
    pub fn build(root: &Path, findings: &[Finding], options: &FixOptions) -> Self {
        let mut entries = Vec::new();
        if matches!(options.safety, FixSelection::All | FixSelection::Safe)
            && options.rule_filter.is_none()
            && options.finding_filter.is_none()
            && !root.join(CONFIG_FILE_NAME).exists()
        {
            entries.push(config_init_entry());
        }

        for finding in findings {
            if !matches_filters(finding, options) || !matches_selection(finding, &options.safety) {
                continue;
            }
            if let Some(entry) = entry_for_finding(root, finding) {
                entries.push(entry);
            }
        }
        entries.sort_by(sort_entries);
        Self {
            dry_run: options.dry_run,
            entries,
        }
    }

    #[must_use]
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        if self.dry_run {
            out.push_str("Fix plan (dry run)\n");
            let safe = self
                .entries
                .iter()
                .filter(|entry| entry.safety == FixSafety::Safe)
                .count();
            let guided = self
                .entries
                .iter()
                .filter(|entry| entry.safety == FixSafety::Guided)
                .count();
            let patch = self
                .entries
                .iter()
                .map(|entry| entry.patches.len())
                .sum::<usize>();
            out.push_str(&format!("safe={safe} guided={guided} patch={patch}\n"));
        } else {
            out.push_str("Fix plan\n");
        }
        if self.entries.is_empty() {
            out.push_str("No matching fixes were planned.\n");
            return out;
        }
        for entry in &self.entries {
            let path = entry
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<no file>".to_string());
            out.push_str(&format!(
                "- {} {} {}: {}\n",
                entry.safety, entry.rule_id, path, entry.description
            ));
            for patch in &entry.patches {
                out.push_str(&format!("  patch {}\n", patch.path.display()));
                for edit in &patch.edits {
                    out.push_str(&format!("    {}\n", edit.description));
                    out.push_str(&format!("    - {}\n", preview_line(&edit.original)));
                    out.push_str(&format!("    + {}\n", preview_line(&edit.replacement)));
                }
            }
        }
        out
    }

    pub fn apply(&self, root: &Path) -> FixApplicationResult {
        self.apply_with_mode(root, FixApplyMode::Safe)
    }

    pub fn apply_guided(&self, root: &Path) -> FixApplicationResult {
        self.apply_with_mode(root, FixApplyMode::Guided)
    }

    fn apply_with_mode(&self, root: &Path, mode: FixApplyMode) -> FixApplicationResult {
        let mut grouped: BTreeMap<PathBuf, Vec<&Patch>> = BTreeMap::new();
        let mut skipped = 0;
        let mut errors = Vec::new();
        for entry in &self.entries {
            if !entry_matches_apply_mode(entry, &mode) {
                skipped += 1;
                continue;
            }
            for patch in &entry.patches {
                grouped.entry(patch.path.clone()).or_default().push(patch);
            }
        }

        let total_files = grouped.len();
        let mut applied = 0;
        let mut applied_paths = Vec::new();
        for (relative, patches) in grouped {
            match apply_file_patches(root, &relative, &patches) {
                Ok(()) => {
                    applied += 1;
                    applied_paths.push(relative);
                }
                Err(error) => errors.push(error),
            }
        }
        let formatter_warnings = if matches!(mode, FixApplyMode::Guided) && errors.is_empty() {
            run_post_formatters(root, &applied_paths, &mut errors)
        } else {
            Vec::new()
        };
        FixApplicationResult {
            applied,
            skipped,
            remaining: total_files.saturating_sub(applied) + skipped,
            applied_paths,
            formatter_warnings,
            errors,
        }
    }
}

fn entry_matches_apply_mode(entry: &FixPlanEntry, mode: &FixApplyMode) -> bool {
    match mode {
        FixApplyMode::Safe => entry.safety == FixSafety::Safe,
        FixApplyMode::Guided => entry.safety == FixSafety::Guided,
    }
}

fn legacy_options(safety: FixSafety, dry_run: bool) -> FixOptions {
    FixOptions {
        safety: match safety {
            FixSafety::Safe => FixSelection::Safe,
            FixSafety::Guided => FixSelection::Guided,
            FixSafety::None | FixSafety::Risky => FixSelection::All,
        },
        dry_run,
        apply: false,
        rule_filter: None,
        finding_filter: None,
    }
}

fn config_init_entry() -> FixPlanEntry {
    FixPlanEntry {
        finding_id: "synthetic/config-init".to_string(),
        rule_id: "config/init".to_string(),
        safety: FixSafety::Safe,
        path: Some(PathBuf::from(CONFIG_FILE_NAME)),
        description: "Create a minimal Backend Doctor config file.".to_string(),
        patches: vec![Patch {
            path: PathBuf::from(CONFIG_FILE_NAME),
            creates_file: true,
            edits: vec![FileEdit {
                original: String::new(),
                replacement: "[thresholds]\nmin-score = 80\n".to_string(),
                description: "Create config with explicit default score threshold.".to_string(),
            }],
        }],
    }
}

fn entry_for_finding(root: &Path, finding: &Finding) -> Option<FixPlanEntry> {
    let path = finding
        .location
        .as_ref()
        .map(|location| location.path.clone());
    let patches = match finding.rule_id.as_str() {
        "go/gofmt-required" => gofmt_patch(root, path.as_ref()?)?,
        "node/console-log-production" => remove_console_log_patch(root, finding, path.as_ref()?)?,
        "infra/docker-copies-entire-context" => dockerignore_patch(path.as_ref()?)?,
        "go/http-client-no-timeout" => guided_go_timeout_patch(root, finding, path.as_ref()?)?,
        "node/unbounded-json-body" => guided_node_body_limit_patch(root, finding, path.as_ref()?)?,
        "java/missing-request-validation" => {
            guided_java_validation_patch(root, finding, path.as_ref()?)?
        }
        _ => Vec::new(),
    };
    if patches.is_empty() && !finding.fix.available {
        return None;
    }
    Some(FixPlanEntry {
        finding_id: finding.id.clone(),
        rule_id: finding.rule_id.clone(),
        safety: patch_safety(finding),
        path,
        description: finding
            .fix
            .description
            .clone()
            .unwrap_or_else(|| finding.remediation.clone()),
        patches,
    })
}

fn patch_safety(finding: &Finding) -> FixSafety {
    if is_safe_patch_rule(&finding.rule_id) {
        FixSafety::Safe
    } else {
        finding.fix.safety.clone()
    }
}

fn is_safe_patch_rule(rule_id: &str) -> bool {
    matches!(rule_id, "infra/docker-copies-entire-context")
}

fn gofmt_patch(root: &Path, path: &Path) -> Option<Vec<Patch>> {
    let text = read_relative_text(root, path).ok()?;
    let formatted = format_go_lite(&text);
    if formatted == text {
        return None;
    }
    Some(vec![Patch {
        path: path.to_path_buf(),
        creates_file: false,
        edits: vec![FileEdit {
            original: text,
            replacement: formatted,
            description: "Apply deterministic gofmt-compatible whitespace cleanup.".to_string(),
        }],
    }])
}

fn remove_console_log_patch(root: &Path, finding: &Finding, path: &Path) -> Option<Vec<Patch>> {
    let text = read_relative_text(root, path).ok()?;
    let line = finding.location.as_ref()?.line?;
    let original = line_at(&text, line)?.to_string();
    if !original.contains("console.log(") {
        return None;
    }
    Some(vec![Patch {
        path: path.to_path_buf(),
        creates_file: false,
        edits: vec![FileEdit {
            original,
            replacement: String::new(),
            description: "Remove deterministic console.log debug statement.".to_string(),
        }],
    }])
}

fn dockerignore_patch(dockerfile: &Path) -> Option<Vec<Patch>> {
    let parent = dockerfile.parent().unwrap_or(Path::new(""));
    let path = parent.join(".dockerignore");
    Some(vec![Patch {
        path,
        creates_file: true,
        edits: vec![FileEdit {
            original: String::new(),
            replacement: ".git\nnode_modules\nnpm-debug.log*\n.env\n.env.*\n".to_string(),
            description: "Create adjacent .dockerignore for broad Docker COPY context.".to_string(),
        }],
    }])
}

fn guided_go_timeout_patch(root: &Path, finding: &Finding, path: &Path) -> Option<Vec<Patch>> {
    let text = read_relative_text(root, path).ok()?;
    let line = finding.location.as_ref()?.line?;
    let original = line_at(&text, line)?.to_string();
    if !original.contains("http.Client{}") {
        return None;
    }
    let replacement = original.replace("http.Client{}", "http.Client{Timeout: 10 * time.Second}");
    let mut edits = vec![FileEdit {
        original,
        replacement,
        description: "Guided suggestion: add Timeout after confirming latency budget.".to_string(),
    }];
    if !text.contains("\"time\"") {
        if text.contains("import (\n") {
            edits.push(FileEdit {
                original: "import (\n".to_string(),
                replacement: "import (\n\t\"time\"\n".to_string(),
                description: "Guided suggestion: add time import for Timeout.".to_string(),
            });
        } else if text.contains("import \"net/http\"\n") {
            edits.push(FileEdit {
                original: "import \"net/http\"\n".to_string(),
                replacement: "import (\n\t\"net/http\"\n\t\"time\"\n)\n".to_string(),
                description: "Guided suggestion: add time import for Timeout.".to_string(),
            });
        } else {
            return None;
        }
    }
    Some(vec![Patch {
        path: path.to_path_buf(),
        creates_file: false,
        edits,
    }])
}

fn guided_node_body_limit_patch(root: &Path, finding: &Finding, path: &Path) -> Option<Vec<Patch>> {
    let text = read_relative_text(root, path).ok()?;
    let line = finding.location.as_ref()?.line?;
    let original = line_at(&text, line)?.to_string();
    let replacement = original
        .replace("express.json()", "express.json({ limit: \"1mb\" })")
        .replace("bodyParser.json()", "bodyParser.json({ limit: \"1mb\" })");
    if replacement == original {
        return None;
    }
    Some(vec![Patch {
        path: path.to_path_buf(),
        creates_file: false,
        edits: vec![FileEdit {
            original,
            replacement,
            description: "Guided suggestion: set JSON body limit after confirming API needs."
                .to_string(),
        }],
    }])
}

fn guided_java_validation_patch(root: &Path, finding: &Finding, path: &Path) -> Option<Vec<Patch>> {
    let text = read_relative_text(root, path).ok()?;
    let line = finding.location.as_ref()?.line?;
    let original = line_at(&text, line)?.to_string();
    if !original.contains("@RequestBody") || original.contains("@Valid") {
        return None;
    }
    let replacement = original.replace("@RequestBody", "@Valid @RequestBody");
    let mut edits = vec![FileEdit {
        original,
        replacement,
        description: "Guided suggestion: validate request body parameter.".to_string(),
    }];
    if !text.contains("import jakarta.validation.Valid;") {
        edits.push(FileEdit {
            original: "import java.util.List;\n".to_string(),
            replacement: "import java.util.List;\nimport jakarta.validation.Valid;\n".to_string(),
            description: "Guided suggestion: add @Valid import.".to_string(),
        });
    }
    Some(vec![Patch {
        path: path.to_path_buf(),
        creates_file: false,
        edits,
    }])
}

fn matches_filters(finding: &Finding, options: &FixOptions) -> bool {
    if let Some(rule) = &options.rule_filter {
        if &finding.rule_id != rule {
            return false;
        }
    }
    if let Some(id) = &options.finding_filter {
        if &finding.id != id && &finding.fingerprint != id {
            return false;
        }
    }
    true
}

fn matches_selection(finding: &Finding, selection: &FixSelection) -> bool {
    finding.fix.available
        && match selection {
            FixSelection::All => finding.fix.safety != FixSafety::None,
            FixSelection::Safe => {
                finding.fix.safety == FixSafety::Safe || is_safe_patch_rule(&finding.rule_id)
            }
            FixSelection::Guided => {
                finding.fix.safety == FixSafety::Guided && !is_safe_patch_rule(&finding.rule_id)
            }
        }
}

fn sort_entries(left: &FixPlanEntry, right: &FixPlanEntry) -> std::cmp::Ordering {
    safety_rank(&left.safety)
        .cmp(&safety_rank(&right.safety))
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.finding_id.cmp(&right.finding_id))
}

fn safety_rank(safety: &FixSafety) -> u8 {
    match safety {
        FixSafety::Safe => 0,
        FixSafety::Guided => 1,
        FixSafety::Risky => 2,
        FixSafety::None => 3,
    }
}

fn apply_file_patches(
    root: &Path,
    relative: &Path,
    patches: &[&Patch],
) -> Result<(), FixApplicationError> {
    let full_path = checked_path(root, relative)?;
    let creates_file = patches.iter().any(|patch| patch.creates_file);
    let existing = match fs::read(&full_path) {
        Ok(bytes) => {
            if bytes.contains(&0) {
                return Err(error(
                    Some(relative),
                    FixErrorKind::BinaryFile,
                    "refusing to patch a binary file",
                ));
            }
            String::from_utf8(bytes).map_err(|_| {
                error(
                    Some(relative),
                    FixErrorKind::BinaryFile,
                    "refusing to patch a non-UTF-8 file",
                )
            })?
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound && creates_file => String::new(),
        Err(err) => {
            return Err(error(
                Some(relative),
                FixErrorKind::Io,
                &format!("failed to read file: {err}"),
            ))
        }
    };
    let mut seen = BTreeSet::new();
    let mut next = existing.clone();
    for patch in patches {
        for edit in &patch.edits {
            if !seen.insert(edit.original.clone()) && !edit.original.is_empty() {
                return Err(error(
                    Some(relative),
                    FixErrorKind::Conflict,
                    "multiple edits target the same original text",
                ));
            }
            if edit.original.is_empty() {
                if !next.is_empty() {
                    return Err(error(
                        Some(relative),
                        FixErrorKind::Conflict,
                        "create-file patch found existing content",
                    ));
                }
                next = edit.replacement.clone();
            } else {
                let count = next.matches(&edit.original).count();
                if count != 1 {
                    return Err(error(
                        Some(relative),
                        FixErrorKind::Conflict,
                        &format!("expected original text once, found {count} matches"),
                    ));
                }
                next = next.replacen(&edit.original, &edit.replacement, 1);
            }
        }
    }
    if next == existing {
        return Ok(());
    }
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            error(
                Some(relative),
                FixErrorKind::Io,
                &format!("failed to create parent directory: {err}"),
            )
        })?;
    }
    let backup = full_path.with_extension("bd-fix-backup");
    if full_path.exists() {
        fs::write(&backup, &existing).map_err(|err| {
            error(
                Some(relative),
                FixErrorKind::Io,
                &format!("failed to create rollback backup: {err}"),
            )
        })?;
    }
    let tmp = full_path.with_extension("bd-fix-tmp");
    if let Err(err) = maybe_inject_atomic_write_failure()
        .and_then(|()| fs::write(&tmp, next.as_bytes()))
        .and_then(|()| fs::rename(&tmp, &full_path))
        .and_then(|()| {
            if backup.exists() {
                fs::remove_file(&backup)?;
            }
            Ok(())
        })
    {
        let _ = fs::remove_file(&tmp);
        if backup.exists() {
            let _ = fs::rename(&backup, &full_path);
        }
        return Err(error(
            Some(relative),
            FixErrorKind::Io,
            &format!("failed to write atomically; rollback attempted: {err}"),
        ));
    }
    Ok(())
}

fn run_post_formatters(
    root: &Path,
    applied_paths: &[PathBuf],
    errors: &mut Vec<FixApplicationError>,
) -> Vec<String> {
    let go_paths = applied_paths
        .iter()
        .filter(|path| path.extension().is_some_and(|ext| ext == "go"))
        .cloned()
        .collect::<Vec<_>>();
    if go_paths.is_empty() {
        return Vec::new();
    }
    match Command::new("goimports").arg("-help").output() {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return vec![
                "goimports not found; Go guided fixes were applied without import formatting. Install golang.org/x/tools/cmd/goimports and rerun formatting.".to_string(),
            ];
        }
        Err(err) => {
            return vec![format!(
                "goimports availability check failed; Go guided fixes were applied without import formatting: {err}"
            )];
        }
        Ok(_) => {}
    }

    for relative in go_paths {
        if let Err(err) = run_goimports(root, &relative) {
            errors.push(err);
        }
    }
    Vec::new()
}

fn run_goimports(root: &Path, relative: &Path) -> Result<(), FixApplicationError> {
    let full_path = checked_path(root, relative)?;
    let before = fs::read(&full_path).map_err(|err| {
        error(
            Some(relative),
            FixErrorKind::Io,
            &format!("failed to read file before goimports: {err}"),
        )
    })?;
    let backup = full_path.with_extension("bd-fix-format-backup");
    fs::write(&backup, &before).map_err(|err| {
        error(
            Some(relative),
            FixErrorKind::Io,
            &format!("failed to create formatter rollback backup: {err}"),
        )
    })?;
    let output = Command::new("goimports").arg("-w").arg(&full_path).output();
    match output {
        Ok(output) if output.status.success() => {
            let _ = fs::remove_file(&backup);
            Ok(())
        }
        Ok(output) => {
            let _ = fs::write(&full_path, &before);
            let _ = fs::remove_file(&backup);
            Err(error(
                Some(relative),
                FixErrorKind::Io,
                &format!(
                    "goimports failed; rollback attempted: {}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            ))
        }
        Err(err) => {
            let _ = fs::write(&full_path, &before);
            let _ = fs::remove_file(&backup);
            Err(error(
                Some(relative),
                FixErrorKind::Io,
                &format!("goimports failed; rollback attempted: {err}"),
            ))
        }
    }
}

#[cfg(not(test))]
fn maybe_inject_atomic_write_failure() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_ATOMIC_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn maybe_inject_atomic_write_failure() -> io::Result<()> {
    if FAIL_NEXT_ATOMIC_WRITE.replace(false) {
        return Err(io::Error::other("injected atomic write failure"));
    }
    Ok(())
}

fn checked_path(root: &Path, relative: &Path) -> Result<PathBuf, FixApplicationError> {
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(error(
            Some(relative),
            FixErrorKind::InvalidPath,
            "patch path must stay inside the repository",
        ));
    }
    Ok(root.join(relative))
}

fn read_relative_text(root: &Path, relative: &Path) -> io::Result<String> {
    if checked_path(root, relative).is_err() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path"));
    }
    fs::read_to_string(root.join(relative))
}

fn line_at(text: &str, line: u32) -> Option<&str> {
    let index = usize::try_from(line.checked_sub(1)?).ok()?;
    text.lines().nth(index)
}

fn format_go_lite(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut next = line.to_string();
        if next.starts_with("func ") {
            next = next.replace("(){", "() {");
        }
        out.push_str(&next);
        out.push('\n');
    }
    if !text.ends_with('\n') {
        out.pop();
    }
    out
}

fn preview_line(value: &str) -> String {
    let redacted = redact_text(value);
    let one_line = redacted.replace('\n', "\\n");
    one_line.chars().take(220).collect()
}

fn error(path: Option<&Path>, kind: FixErrorKind, message: &str) -> FixApplicationError {
    FixApplicationError {
        path: path.map(Path::to_path_buf),
        kind,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{sample_finding, Category, Location, Severity};

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("backend-doctor-fix-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temp root");
        root
    }

    fn safe_finding(id: &str, rule: &str, path: &str, line: u32) -> Finding {
        let mut finding = sample_finding(id, Severity::Warning, Category::Maintainability, path);
        finding.rule_id = rule.to_string();
        finding.fix.available = true;
        finding.fix.safety = FixSafety::Safe;
        finding.location = Some(Location {
            path: PathBuf::from(path),
            line: Some(line),
            column: Some(1),
            end_line: None,
            end_column: None,
        });
        finding
    }

    fn guided_finding(id: &str, rule: &str, path: &str, line: u32) -> Finding {
        let mut finding = safe_finding(id, rule, path, line);
        finding.fix.safety = FixSafety::Guided;
        finding
    }

    #[test]
    fn render_empty_dry_run_plan() {
        let plan = FixPlan::empty(true);
        assert!(plan.render_text().contains("dry run"));
    }

    #[test]
    fn dry_run_plan_does_not_mutate() {
        let root = temp_root("dry-run");
        fs::write(
            root.join("main.go"),
            "package main\nfunc BadSpacing(){ return }\n",
        )
        .expect("write fixture");
        let finding = safe_finding("f1", "go/gofmt-required", "main.go", 1);
        let plan = FixPlan::build(
            &root,
            &[finding],
            &FixOptions {
                safety: FixSelection::Safe,
                dry_run: true,
                apply: false,
                rule_filter: None,
                finding_filter: None,
            },
        );
        assert!(plan.render_text().contains("func BadSpacing()"));
        assert!(fs::read_to_string(root.join("main.go"))
            .expect("read")
            .contains("BadSpacing(){"));
    }

    #[test]
    fn apply_modifies_expected_file_only() {
        let root = temp_root("apply");
        fs::write(
            root.join("main.go"),
            "package main\nfunc BadSpacing(){ return }\n",
        )
        .expect("write fixture");
        fs::write(root.join("other.go"), "package main\n").expect("write fixture");
        let finding = safe_finding("f1", "go/gofmt-required", "main.go", 1);
        let plan = FixPlan::build(
            &root,
            &[finding],
            &FixOptions {
                safety: FixSelection::Safe,
                dry_run: false,
                apply: true,
                rule_filter: None,
                finding_filter: None,
            },
        );
        let result = plan.apply(&root);
        assert!(result.errors.is_empty(), "{:?}", result.errors);
        assert!(fs::read_to_string(root.join("main.go"))
            .expect("read")
            .contains("BadSpacing() {"));
        assert_eq!(
            fs::read_to_string(root.join("other.go")).expect("read"),
            "package main\n"
        );
    }

    #[test]
    fn conflict_detection_rejects_changed_original() {
        let root = temp_root("conflict");
        fs::write(root.join("app.ts"), "console.info(\"changed\");\n").expect("write fixture");
        let finding = safe_finding("f1", "node/console-log-production", "app.ts", 1);
        let plan = FixPlan {
            dry_run: false,
            entries: vec![FixPlanEntry {
                finding_id: finding.id,
                rule_id: finding.rule_id,
                safety: FixSafety::Safe,
                path: Some(PathBuf::from("app.ts")),
                description: "remove".to_string(),
                patches: vec![Patch {
                    path: PathBuf::from("app.ts"),
                    creates_file: false,
                    edits: vec![FileEdit {
                        original: "console.log(\"secret\");".to_string(),
                        replacement: String::new(),
                        description: "remove".to_string(),
                    }],
                }],
            }],
        };
        let result = plan.apply(&root);
        assert_eq!(result.errors[0].kind, FixErrorKind::Conflict);
        assert_eq!(
            fs::read_to_string(root.join("app.ts")).expect("read"),
            "console.info(\"changed\");\n"
        );
    }

    #[test]
    fn atomic_write_failure_restores_original_and_cleans_sidecars() {
        let root = temp_root("rollback");
        let target = root.join("app.ts");
        let backup = target.with_extension("bd-fix-backup");
        let tmp = target.with_extension("bd-fix-tmp");
        fs::write(&target, "console.log(\"secret\");\n").expect("write fixture");
        let patch = Patch {
            path: PathBuf::from("app.ts"),
            creates_file: false,
            edits: vec![FileEdit {
                original: "console.log(\"secret\");".to_string(),
                replacement: String::new(),
                description: "remove".to_string(),
            }],
        };

        FAIL_NEXT_ATOMIC_WRITE.with(|fail| fail.set(true));
        let result = apply_file_patches(&root, Path::new("app.ts"), &[&patch]);

        let error = result.expect_err("injected write failure should fail");
        assert_eq!(error.kind, FixErrorKind::Io);
        assert!(error.message.contains("rollback attempted"));
        assert_eq!(
            fs::read_to_string(&target).expect("read restored file"),
            "console.log(\"secret\");\n"
        );
        assert!(!backup.exists(), "rollback backup should not linger");
        assert!(!tmp.exists(), "atomic write temp file should not linger");

        let remaining_paths = fs::read_dir(&root)
            .expect("read temp root")
            .map(|entry| entry.expect("dir entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining_paths, vec![std::ffi::OsString::from("app.ts")]);
    }

    #[test]
    fn path_traversal_is_rejected() {
        let root = temp_root("path");
        let plan = FixPlan {
            dry_run: false,
            entries: vec![FixPlanEntry {
                finding_id: "f".to_string(),
                rule_id: "config/init".to_string(),
                safety: FixSafety::Safe,
                path: Some(PathBuf::from("../outside")),
                description: "bad".to_string(),
                patches: vec![Patch {
                    path: PathBuf::from("../outside"),
                    creates_file: true,
                    edits: vec![FileEdit {
                        original: String::new(),
                        replacement: "bad".to_string(),
                        description: "bad".to_string(),
                    }],
                }],
            }],
        };
        let result = plan.apply(&root);
        assert_eq!(result.errors[0].kind, FixErrorKind::InvalidPath);
    }

    #[test]
    fn preview_redacts_secret_like_values() {
        let plan = FixPlan {
            dry_run: true,
            entries: vec![FixPlanEntry {
                finding_id: "f".to_string(),
                rule_id: "test".to_string(),
                safety: FixSafety::Safe,
                path: Some(PathBuf::from("x")),
                description: "x".to_string(),
                patches: vec![Patch {
                    path: PathBuf::from("x"),
                    creates_file: false,
                    edits: vec![FileEdit {
                        original: "TOKEN=super-secret-value".to_string(),
                        replacement: "TOKEN=new-secret-value".to_string(),
                        description: "x".to_string(),
                    }],
                }],
            }],
        };
        let rendered = plan.render_text();
        assert!(rendered.contains("TOKEN=[REDACTED]"));
        assert!(!rendered.contains("super-secret-value"));
    }

    #[test]
    fn rule_and_finding_filters_limit_plan() {
        let root = temp_root("filters");
        fs::write(
            root.join("main.go"),
            "package main\nfunc BadSpacing(){ return }\n",
        )
        .expect("write fixture");
        fs::write(root.join("app.ts"), "console.log(\"x\");\n").expect("write fixture");
        let go = safe_finding("go-id", "go/gofmt-required", "main.go", 1);
        let node = safe_finding("node-id", "node/console-log-production", "app.ts", 1);
        let plan = FixPlan::build(
            &root,
            &[go, node],
            &FixOptions {
                safety: FixSelection::Safe,
                dry_run: true,
                apply: false,
                rule_filter: Some("node/console-log-production".to_string()),
                finding_filter: None,
            },
        );
        assert_eq!(plan.entries.len(), 1);
        assert_eq!(plan.entries[0].rule_id, "node/console-log-production");
    }

    #[test]
    fn guided_plan_renders_timeout_body_limit_and_java_validation_suggestions() {
        let root = temp_root("guided");
        fs::create_dir_all(root.join("src/main/java")).expect("mkdirs");
        fs::write(
            root.join("client.go"),
            "package client\n\nimport (\n\t\"net/http\"\n)\n\nfunc f() { client := &http.Client{} }\n",
        )
        .expect("go fixture");
        fs::write(root.join("app.ts"), "app.use(express.json());\n").expect("node fixture");
        fs::write(
            root.join("src/main/java/UserController.java"),
            "import java.util.List;\nclass C { void create(@RequestBody User request) {} }\n",
        )
        .expect("java fixture");
        let findings = vec![
            guided_finding("go", "go/http-client-no-timeout", "client.go", 7),
            guided_finding("node", "node/unbounded-json-body", "app.ts", 1),
            guided_finding(
                "java",
                "java/missing-request-validation",
                "src/main/java/UserController.java",
                2,
            ),
        ];
        let plan = FixPlan::build(
            &root,
            &findings,
            &FixOptions {
                safety: FixSelection::Guided,
                dry_run: true,
                apply: false,
                rule_filter: None,
                finding_filter: None,
            },
        );
        let rendered = plan.render_text();
        assert!(rendered.contains("Timeout: 10 * time.Second"));
        assert!(rendered.contains("express.json({ limit: \"1mb\" })"));
        assert!(rendered.contains("@Valid @RequestBody"));
        assert!(rendered.contains("import jakarta.validation.Valid;"));
    }

    #[test]
    fn safe_apply_skips_guided_entries_and_guided_apply_skips_safe_entries() {
        let root = temp_root("apply-mode");
        fs::write(
            root.join("client.go"),
            "package client\n\nimport (\n\t\"net/http\"\n)\n\nfunc f() { client := &http.Client{} }\n",
        )
        .expect("go fixture");
        fs::write(
            root.join("main.go"),
            "package main\nfunc BadSpacing(){ return }\n",
        )
        .expect("safe fixture");
        let guided = guided_finding("go", "go/http-client-no-timeout", "client.go", 7);
        let safe = safe_finding("safe", "go/gofmt-required", "main.go", 2);
        let plan = FixPlan::build(
            &root,
            &[guided, safe],
            &FixOptions {
                safety: FixSelection::All,
                dry_run: false,
                apply: true,
                rule_filter: None,
                finding_filter: None,
            },
        );

        let safe_result = plan.apply(&root);
        assert!(safe_result.errors.is_empty(), "{:?}", safe_result.errors);
        assert!(fs::read_to_string(root.join("main.go"))
            .expect("read safe")
            .contains("BadSpacing() {"));
        assert!(fs::read_to_string(root.join("client.go"))
            .expect("read guided")
            .contains("http.Client{}"));

        let guided_result = plan.apply_guided(&root);
        assert!(
            guided_result.errors.is_empty(),
            "{:?}",
            guided_result.errors
        );
        assert!(fs::read_to_string(root.join("client.go"))
            .expect("read guided")
            .contains("Timeout: 10 * time.Second"));
    }
}
