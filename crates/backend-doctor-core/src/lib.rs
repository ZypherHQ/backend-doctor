use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
unsafe extern "C" {
    fn setsid() -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(unix)]
const SIGKILL: i32 = 9;

pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
pub const CONFIG_FILE_NAME: &str = ".backend-doctor.toml";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Architecture,
    Correctness,
    Dependencies,
    Infrastructure,
    Reliability,
    Security,
    Testing,
    Maintainability,
}

impl Category {
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Architecture,
            Self::Correctness,
            Self::Dependencies,
            Self::Infrastructure,
            Self::Reliability,
            Self::Security,
            Self::Testing,
            Self::Maintainability,
        ]
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Architecture => "architecture",
            Self::Correctness => "correctness",
            Self::Dependencies => "dependencies",
            Self::Infrastructure => "infrastructure",
            Self::Reliability => "reliability",
            Self::Security => "security",
            Self::Testing => "testing",
            Self::Maintainability => "maintainability",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Critical,
    Error,
    Warning,
    Info,
    Note,
}

impl Severity {
    #[must_use]
    pub fn rank(&self) -> u8 {
        match self {
            Self::Critical => 0,
            Self::Error => 1,
            Self::Warning => 2,
            Self::Info => 3,
            Self::Note => 4,
        }
    }

    #[must_use]
    pub fn penalty(&self) -> f64 {
        match self {
            Self::Critical => 12.0,
            Self::Error => 5.0,
            Self::Warning => 2.0,
            Self::Info => 0.5,
            Self::Note => 0.0,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Note => "note",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    #[must_use]
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::High => 1.0,
            Self::Medium => 0.75,
            Self::Low => 0.35,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixSafety {
    None,
    Safe,
    Guided,
    Risky,
}

pub type Fixability = FixSafety;

impl FixSafety {
    #[must_use]
    pub fn penalty_multiplier(&self) -> f64 {
        match self {
            Self::Safe => 0.9,
            Self::None | Self::Guided | Self::Risky => 1.0,
        }
    }
}

impl fmt::Display for FixSafety {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::None => "none",
            Self::Safe => "safe",
            Self::Guided => "guided",
            Self::Risky => "risky",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleMetadata {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub default_severity: Severity,
    pub default_confidence: Confidence,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub tags: Vec<String>,
    pub cwe: Vec<String>,
    pub owasp: Vec<String>,
    pub fixability: FixSafety,
    pub enabled_by_default: bool,
    pub supports_diff_mode: bool,
    pub docs: Option<String>,
    pub explanation: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    pub path: PathBuf,
    pub line: Option<u32>,
    pub column: Option<u32>,
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,
}

impl Location {
    #[must_use]
    pub fn display(&self) -> String {
        let mut value = self.path.display().to_string();
        if let Some(line) = self.line {
            value.push(':');
            value.push_str(&line.to_string());
            if let Some(column) = self.column {
                value.push(':');
                value.push_str(&column.to_string());
            }
        }
        value
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub snippet: String,
    pub redacted: bool,
    pub secret_fingerprint: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixInfo {
    pub available: bool,
    pub safety: FixSafety,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub tool: String,
    pub source_tool: String,
    pub title: String,
    pub message: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    pub service: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub location: Option<Location>,
    pub evidence: Option<Evidence>,
    pub impact: Option<String>,
    pub remediation: String,
    pub fix: FixInfo,
    pub links: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub suppressed: bool,
}

impl Finding {
    #[must_use]
    pub fn redacted(mut self) -> Self {
        self.title = redact_text(&self.title);
        self.message = redact_text(&self.message);
        self.impact = self.impact.map(|value| redact_text(&value));
        self.remediation = redact_text(&self.remediation);
        if let Some(evidence) = &mut self.evidence {
            let redacted = redact_text(&evidence.snippet);
            evidence.redacted = evidence.redacted || redacted != evidence.snippet;
            evidence.snippet = redacted;
        }
        self
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryScore {
    pub category: Category,
    pub score: u8,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScoreCap {
    pub cap: u8,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Score {
    pub value: u8,
    pub label: String,
    pub category_scores: Vec<CategoryScore>,
    pub caps: Vec<ScoreCap>,
}

impl Score {
    #[must_use]
    pub fn from_value(value: u8) -> Self {
        Self {
            value,
            label: score_label(value).to_string(),
            category_scores: Vec::new(),
            caps: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub path: PathBuf,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DetectionConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedLanguage {
    pub name: String,
    pub confidence: DetectionConfidence,
    pub evidence: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileInventory {
    pub total_files: usize,
    pub source_files: usize,
    pub manifest_files: usize,
    pub infra_files: usize,
    pub test_files: usize,
    pub skipped_binary_files: usize,
    pub skipped_large_files: usize,
    pub files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfraInventory {
    pub dockerfiles: Vec<PathBuf>,
    pub compose_files: Vec<PathBuf>,
    pub kubernetes_files: Vec<PathBuf>,
    pub helm_charts: Vec<PathBuf>,
    pub terraform_files: Vec<PathBuf>,
    pub github_actions: Vec<PathBuf>,
    pub gitlab_ci: Vec<PathBuf>,
    pub open_api_specs: Vec<PathBuf>,
    pub migration_files: Vec<PathBuf>,
}

impl InfraInventory {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.dockerfiles.is_empty()
            && self.compose_files.is_empty()
            && self.kubernetes_files.is_empty()
            && self.helm_charts.is_empty()
            && self.terraform_files.is_empty()
            && self.github_actions.is_empty()
            && self.gitlab_ci.is_empty()
            && self.open_api_specs.is_empty()
            && self.migration_files.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffInventory {
    pub enabled: bool,
    pub base: Option<String>,
    pub fallback_full_scan: bool,
    pub changed_files: Vec<PathBuf>,
    pub impacted_files: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectionDebug {
    pub root: PathBuf,
    pub git_root: Option<PathBuf>,
    pub workspace_root: PathBuf,
    pub ignored_patterns: Vec<String>,
    pub warnings: Vec<String>,
    pub decisions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectGraph {
    pub root: PathBuf,
    pub git_root: Option<PathBuf>,
    pub workspace_root: PathBuf,
    pub monorepo: bool,
    pub services: Vec<Service>,
    pub languages: Vec<DetectedLanguage>,
    pub inventory: FileInventory,
    pub infra: InfraInventory,
    pub diff: DiffInventory,
    pub debug: DetectionDebug,
}

impl ProjectGraph {
    #[must_use]
    pub fn empty(root: PathBuf) -> Self {
        Self {
            root: root.clone(),
            git_root: None,
            workspace_root: root.clone(),
            monorepo: false,
            services: Vec::new(),
            languages: Vec::new(),
            inventory: FileInventory {
                total_files: 0,
                source_files: 0,
                manifest_files: 0,
                infra_files: 0,
                test_files: 0,
                skipped_binary_files: 0,
                skipped_large_files: 0,
                files: Vec::new(),
            },
            infra: InfraInventory::default(),
            diff: DiffInventory {
                enabled: false,
                base: None,
                fallback_full_scan: false,
                changed_files: Vec::new(),
                impacted_files: Vec::new(),
            },
            debug: DetectionDebug {
                root: root.clone(),
                git_root: None,
                workspace_root: root,
                ignored_patterns: Vec::new(),
                warnings: Vec::new(),
                decisions: Vec::new(),
            },
        }
    }
}

pub const ANALYSIS_FACTS_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourcePosition {
    pub line: u32,
    pub column: u32,
    pub byte_offset: Option<u32>,
}

impl SourcePosition {
    #[must_use]
    pub fn new(line: u32, column: u32) -> Self {
        Self {
            line,
            column,
            byte_offset: None,
        }
    }

    #[must_use]
    pub fn with_byte_offset(mut self, byte_offset: u32) -> Self {
        self.byte_offset = Some(byte_offset);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceRange {
    pub start: SourcePosition,
    pub end: SourcePosition,
}

impl SourceRange {
    #[must_use]
    pub fn new(start: SourcePosition, end: SourcePosition) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub fn single_line(line: u32, start_column: u32, end_column: u32) -> Option<Self> {
        Some(Self {
            start: SourcePosition::new(line, start_column),
            end: SourcePosition::new(line, end_column),
        })
    }

    #[must_use]
    pub fn from_location(location: &Location) -> Option<Self> {
        let line = location.line?;
        let column = location.column.unwrap_or(1);
        Some(Self {
            start: SourcePosition::new(line, column),
            end: SourcePosition::new(
                location.end_line.unwrap_or(line),
                location.end_column.unwrap_or(column),
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceFileFact {
    pub id: String,
    pub path: PathBuf,
    pub language: String,
    pub service_id: Option<String>,
    pub content_hash: Option<String>,
    pub line_count: Option<u32>,
    pub metadata: BTreeMap<String, String>,
}

impl SourceFileFact {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, language: impl Into<String>) -> Self {
        let path = path.into();
        let language = language.into();
        let path_text = path.to_string_lossy().into_owned();
        let id = stable_fact_id("source-file", [&path_text, &language]);
        Self {
            id,
            path,
            language,
            service_id: None,
            content_hash: None,
            line_count: None,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_content(mut self, contents: &[u8]) -> Self {
        self.content_hash = Some(stable_digest(contents));
        self.line_count = Some(count_lines(contents));
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SymbolKind {
    Function,
    Method,
    Class,
    Struct,
    Enum,
    Interface,
    Module,
    Variable,
    Constant,
    Type,
    Field,
    Parameter,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SymbolFact {
    pub id: String,
    pub file_id: String,
    pub name: String,
    pub kind: SymbolKind,
    pub range: Option<SourceRange>,
    pub signature: Option<String>,
    pub visibility: Option<String>,
    pub parent_symbol_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallFact {
    pub id: String,
    pub file_id: Option<String>,
    pub caller_symbol_id: Option<String>,
    pub callee_symbol_id: Option<String>,
    pub callee_name: String,
    pub range: Option<SourceRange>,
    pub arguments: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportKind {
    Module,
    Package,
    File,
    Namespace,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFact {
    pub id: String,
    pub file_id: Option<String>,
    pub module: String,
    pub alias: Option<String>,
    pub imported_symbols: Vec<String>,
    pub kind: ImportKind,
    pub range: Option<SourceRange>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteFact {
    pub id: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub service_id: Option<String>,
    pub method: String,
    pub path: String,
    pub framework: Option<String>,
    pub range: Option<SourceRange>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataSourceKind {
    Request,
    Database,
    Cache,
    Queue,
    File,
    Network,
    Environment,
    SecretStore,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSourceFact {
    pub id: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub kind: DataSourceKind,
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub range: Option<SourceRange>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SinkKind {
    SqlQuery,
    Command,
    HttpResponse,
    Log,
    Template,
    FileWrite,
    NetworkRequest,
    Redirect,
    Deserialization,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SinkFact {
    pub id: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub kind: SinkKind,
    pub name: Option<String>,
    pub range: Option<SourceRange>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SanitizerKind {
    Validation,
    Encoding,
    Escaping,
    Parameterization,
    Authentication,
    Authorization,
    TypeCheck,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SanitizerFact {
    pub id: String,
    pub file_id: Option<String>,
    pub symbol_id: Option<String>,
    pub kind: SanitizerKind,
    pub name: Option<String>,
    pub range: Option<SourceRange>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApiSpecFormat {
    OpenApi,
    AsyncApi,
    Graphql,
    Grpc,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiSpecFact {
    pub id: String,
    pub path: PathBuf,
    pub format: ApiSpecFormat,
    pub title: Option<String>,
    pub version: Option<String>,
    pub route_ids: Vec<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentExposureKind {
    PublicHttp,
    PrivateHttp,
    MessageConsumer,
    ScheduledJob,
    Cli,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentExposureFact {
    pub id: String,
    pub service_id: Option<String>,
    pub kind: DeploymentExposureKind,
    pub path: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub public: bool,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaintEdgeKind {
    SourceToCall,
    CallToCall,
    CallToSink,
    SourceToSink,
    Sanitized,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub sanitizer_id: Option<String>,
    pub kind: TaintEdgeKind,
    pub confidence: Confidence,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisFacts {
    pub schema_version: String,
    pub source_files: Vec<SourceFileFact>,
    pub symbols: Vec<SymbolFact>,
    pub calls: Vec<CallFact>,
    pub imports: Vec<ImportFact>,
    pub routes: Vec<RouteFact>,
    pub data_sources: Vec<DataSourceFact>,
    pub sinks: Vec<SinkFact>,
    pub sanitizers: Vec<SanitizerFact>,
    pub api_specs: Vec<ApiSpecFact>,
    pub deployment_exposures: Vec<DeploymentExposureFact>,
    pub taint_edges: Vec<TaintEdge>,
    pub metadata: BTreeMap<String, String>,
}

impl Default for AnalysisFacts {
    fn default() -> Self {
        Self::empty()
    }
}

impl AnalysisFacts {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: ANALYSIS_FACTS_SCHEMA_VERSION.to_string(),
            source_files: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            imports: Vec::new(),
            routes: Vec::new(),
            data_sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            api_specs: Vec::new(),
            deployment_exposures: Vec::new(),
            taint_edges: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.source_files.is_empty()
            && self.symbols.is_empty()
            && self.calls.is_empty()
            && self.imports.is_empty()
            && self.routes.is_empty()
            && self.data_sources.is_empty()
            && self.sinks.is_empty()
            && self.sanitizers.is_empty()
            && self.api_specs.is_empty()
            && self.deployment_exposures.is_empty()
            && self.taint_edges.is_empty()
            && self.metadata.is_empty()
    }
}

#[must_use]
pub fn stable_fact_id<I, S>(kind: &str, parts: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut bytes = Vec::new();
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(0);
    for part in parts {
        bytes.extend_from_slice(part.as_ref().as_bytes());
        bytes.push(0);
    }
    let digest = stable_digest(&bytes);
    format!("{kind}:{}", digest.trim_start_matches("fnv64:"))
}

fn count_lines(contents: &[u8]) -> u32 {
    if contents.is_empty() {
        return 0;
    }
    let newline_count = contents.iter().filter(|byte| **byte == b'\n').count();
    u32::try_from(newline_count + usize::from(!contents.ends_with(b"\n"))).unwrap_or(u32::MAX)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSummary {
    pub name: String,
    pub version: Option<String>,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalToolVersion {
    pub tool: String,
    pub version: Option<String>,
    pub status: ExternalCommandStatus,
    pub diagnostic: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalCommandStatus {
    Success,
    Failure,
    MissingTool,
    Timeout,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalCommandSpec {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub timeout: Option<Duration>,
}

impl ExternalCommandSpec {
    #[must_use]
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            timeout: None,
        }
    }

    #[must_use]
    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalCommandInvocation {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<PathBuf>,
    pub timeout_ms: Option<u128>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalCommandExecution {
    pub invocation: ExternalCommandInvocation,
    pub status: ExternalCommandStatus,
    pub exit_code: Option<i32>,
    #[serde(skip, default)]
    pub stdout: String,
    #[serde(skip, default)]
    pub stderr: String,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub stdout_digest: String,
    pub stderr_digest: String,
    pub duration_ms: u128,
    pub diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheDebug>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheDebug {
    pub status: String,
    pub key: Option<String>,
    pub reason: Option<String>,
}

impl ExternalCommandExecution {
    #[must_use]
    pub fn tool_version(tool: impl Into<String>, version: Option<String>) -> ExternalToolVersion {
        ExternalToolVersion {
            tool: tool.into(),
            version: version.map(|value| redact_text(&value)),
            status: ExternalCommandStatus::Success,
            diagnostic: None,
        }
    }

    #[must_use]
    pub fn missing_tool(spec: &ExternalCommandSpec, diagnostic: impl Into<String>) -> Self {
        Self::from_parts(
            spec,
            ExternalCommandStatus::MissingTool,
            None,
            Vec::new(),
            Vec::new(),
            0,
            Some(diagnostic.into()),
        )
    }

    #[must_use]
    fn from_parts(
        spec: &ExternalCommandSpec,
        status: ExternalCommandStatus,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration_ms: u128,
        diagnostic: Option<String>,
    ) -> Self {
        let stdout_text = redact_text(&String::from_utf8_lossy(&stdout));
        let stderr_text = redact_text(&String::from_utf8_lossy(&stderr));
        Self {
            invocation: redacted_invocation(spec),
            status,
            exit_code,
            stdout_excerpt: output_excerpt(&stdout_text),
            stderr_excerpt: output_excerpt(&stderr_text),
            stdout_bytes: stdout.len(),
            stderr_bytes: stderr.len(),
            stdout_digest: stable_digest(&stdout),
            stderr_digest: stable_digest(&stderr),
            stdout: stdout_text,
            stderr: stderr_text,
            duration_ms,
            diagnostic: diagnostic.map(|value| redact_text(&value)),
            cache: None,
        }
    }
}

pub struct ExternalCommandRunner;

impl ExternalCommandRunner {
    #[must_use]
    pub fn run(spec: &ExternalCommandSpec) -> ExternalCommandExecution {
        let started = Instant::now();
        let mut command = Command::new(&spec.command);
        command
            .args(&spec.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_process_group(&mut command);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &spec.env {
            command.env(key, value);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ExternalCommandExecution::from_parts(
                    spec,
                    ExternalCommandStatus::MissingTool,
                    None,
                    Vec::new(),
                    Vec::new(),
                    started.elapsed().as_millis(),
                    Some(format!(
                        "missing external tool '{}'; install it or disable the plugin that requires it",
                        spec.command
                    )),
                );
            }
            Err(error) => {
                return ExternalCommandExecution::from_parts(
                    spec,
                    ExternalCommandStatus::Failure,
                    None,
                    Vec::new(),
                    Vec::new(),
                    started.elapsed().as_millis(),
                    Some(error.to_string()),
                );
            }
        };

        let stdout_reader = child.stdout.take().map(spawn_pipe_reader);
        let stderr_reader = child.stderr.take().map(spawn_pipe_reader);

        let (timed_out, wait_status) = loop {
            match child.try_wait() {
                Ok(Some(status)) => break (false, Some(status)),
                Ok(None) => {
                    if spec
                        .timeout
                        .is_some_and(|timeout| started.elapsed() >= timeout)
                    {
                        terminate_external_child(&mut child);
                        break (true, None);
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break (false, None),
            }
        };

        match wait_status.map_or_else(|| child.wait(), Ok) {
            Ok(status_code) => {
                let (stdout, stdout_error) = read_external_pipe(stdout_reader, timed_out);
                let (stderr, stderr_error) = read_external_pipe(stderr_reader, timed_out);
                let status = if timed_out {
                    ExternalCommandStatus::Timeout
                } else if status_code.success() {
                    ExternalCommandStatus::Success
                } else {
                    ExternalCommandStatus::Failure
                };
                let diagnostic = if timed_out {
                    Some(format!(
                        "external command timed out after {} ms",
                        spec.timeout.map_or(0, |timeout| timeout.as_millis())
                    ))
                } else {
                    stdout_error.or(stderr_error)
                };
                ExternalCommandExecution::from_parts(
                    spec,
                    status,
                    status_code.code(),
                    stdout,
                    stderr,
                    started.elapsed().as_millis(),
                    diagnostic,
                )
            }
            Err(error) => ExternalCommandExecution::from_parts(
                spec,
                ExternalCommandStatus::Failure,
                None,
                Vec::new(),
                Vec::new(),
                started.elapsed().as_millis(),
                Some(error.to_string()),
            ),
        }
    }
}

fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn terminate_external_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(child.id()) {
            unsafe {
                let _ = kill(-pid, SIGKILL);
            }
        }
    }
    let _ = child.kill();
}

struct PipeReader {
    receiver: Receiver<CapturedPipe>,
}

fn spawn_pipe_reader(reader: impl Read + Send + 'static) -> PipeReader {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(capture_external_pipe(reader, EXTERNAL_OUTPUT_CAPTURE_BYTES));
    });
    PipeReader { receiver }
}

fn read_external_pipe(reader: Option<PipeReader>, timed_out: bool) -> (Vec<u8>, Option<String>) {
    let Some(reader) = reader else {
        return (Vec::new(), None);
    };
    let captured = if timed_out {
        reader.receiver.recv_timeout(Duration::from_millis(100))
    } else {
        reader
            .receiver
            .recv()
            .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
    };
    match captured {
        Ok(captured) => {
            let mut buffer = captured.buffer;
            let mut diagnostic = captured.error;
            if captured.truncated {
                buffer.extend_from_slice(
                    format!(
                        "\n[BACKEND_DOCTOR_OUTPUT_TRUNCATED: captured {} of {} bytes]\n",
                        captured.captured_bytes, captured.total_bytes
                    )
                    .as_bytes(),
                );
                if diagnostic.is_none() {
                    diagnostic = Some(format!(
                        "external output exceeded capture limit of {} bytes",
                        EXTERNAL_OUTPUT_CAPTURE_BYTES
                    ));
                }
            }
            (buffer, diagnostic)
        }
        Err(mpsc::RecvTimeoutError::Timeout) => (
            Vec::new(),
            Some("external output pipe remained open after timeout".to_string()),
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => (
            Vec::new(),
            Some("external output reader stopped before sending output".to_string()),
        ),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedPipe {
    buffer: Vec<u8>,
    captured_bytes: usize,
    total_bytes: usize,
    truncated: bool,
    error: Option<String>,
}

fn capture_external_pipe(mut reader: impl Read, limit: usize) -> CapturedPipe {
    let mut buffer = Vec::with_capacity(limit.min(8192));
    let mut total_bytes = 0usize;
    let mut scratch = [0u8; 8192];
    let mut error = None;

    loop {
        match reader.read(&mut scratch) {
            Ok(0) => break,
            Ok(read) => {
                total_bytes = total_bytes.saturating_add(read);
                let remaining = limit.saturating_sub(buffer.len());
                if remaining > 0 {
                    buffer.extend_from_slice(&scratch[..read.min(remaining)]);
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        }
    }

    CapturedPipe {
        captured_bytes: buffer.len(),
        truncated: total_bytes > buffer.len(),
        total_bytes,
        buffer,
        error,
    }
}

const EXTERNAL_OUTPUT_CAPTURE_BYTES: usize = 1024 * 1024;
const EXTERNAL_OUTPUT_EXCERPT_CHARS: usize = 4096;

fn output_excerpt(value: &str) -> String {
    value.chars().take(EXTERNAL_OUTPUT_EXCERPT_CHARS).collect()
}

pub fn stable_digest(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv64:{hash:016x}")
}

fn redacted_invocation(spec: &ExternalCommandSpec) -> ExternalCommandInvocation {
    ExternalCommandInvocation {
        command: redact_text(&spec.command),
        args: spec.args.iter().map(|arg| redact_text(arg)).collect(),
        env: spec
            .env
            .iter()
            .map(|(key, value)| {
                let joined = format!("{key}={value}");
                let redacted = redact_text(&joined);
                let value = redacted
                    .split_once('=')
                    .map_or_else(|| "[REDACTED]".to_string(), |(_, value)| value.to_string());
                (key.clone(), value)
            })
            .collect(),
        cwd: spec.cwd.clone(),
        timeout_ms: spec.timeout.map(|timeout| timeout.as_millis()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub total_findings: usize,
    pub suppressed_findings: usize,
    pub fixable_findings: usize,
    pub safe_fixes: usize,
    pub critical_findings: usize,
    pub error_findings: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlopSummary {
    pub index: u8,
    pub findings: usize,
    pub placeholder_tests: usize,
    pub production_placeholders: usize,
    pub semantic_copy_paste: usize,
    pub spaghetti_control_flow: usize,
    pub swallowed_errors: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageTier {
    Mvp,
    Tier2,
    Tier3,
    Generic,
}

impl fmt::Display for CoverageTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Mvp => "mvp",
            Self::Tier2 => "tier2",
            Self::Tier3 => "tier3",
            Self::Generic => "generic",
        };
        f.write_str(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LanguageCoverage {
    pub language: String,
    pub tier: CoverageTier,
    pub maturity: String,
    pub rule_families: Vec<String>,
    pub detected_files: usize,
    pub notes: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageSummary {
    pub languages: Vec<LanguageCoverage>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: String,
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub duration_ms: u128,
    pub root: PathBuf,
    pub mode: ScanMode,
    pub score: Score,
    pub label: String,
    pub category_scores: Vec<CategoryScore>,
    pub services: Vec<Service>,
    pub project_graph: ProjectGraph,
    pub findings: Vec<Finding>,
    pub suppressed_findings: Vec<Finding>,
    pub tools: Vec<ToolSummary>,
    pub external_tool_versions: Vec<ExternalToolVersion>,
    pub external_tool_executions: Vec<ExternalCommandExecution>,
    pub config: Config,
    pub summary: Summary,
    pub slop: SlopSummary,
    pub coverage: CoverageSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_facts: Option<AnalysisFacts>,
}

#[derive(Clone, Debug)]
pub struct ReportInput {
    pub tool_version: String,
    pub started_at: DateTime<Utc>,
    pub duration: Duration,
    pub root: PathBuf,
    pub mode: ScanMode,
    pub services: Vec<Service>,
    pub project_graph: ProjectGraph,
    pub findings: Vec<Finding>,
    pub config: Config,
    pub external_tool_versions: Vec<ExternalToolVersion>,
    pub external_tool_executions: Vec<ExternalCommandExecution>,
}

impl Report {
    #[must_use]
    pub fn new(input: ReportInput) -> Self {
        let (findings, suppressed_findings): (Vec<_>, Vec<_>) = input
            .findings
            .into_iter()
            .map(Finding::redacted)
            .partition(|finding| !finding.suppressed);
        let findings = sort_findings(findings);
        let suppressed_findings = sort_findings(suppressed_findings);
        let score = score_findings(&findings);
        let category_scores = score.category_scores.clone();
        let summary = Summary::from_findings(&findings, &suppressed_findings);
        let slop = SlopSummary::from_findings(&findings);
        let coverage = CoverageSummary::from_graph(&input.project_graph);

        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            tool_version: input.tool_version,
            started_at: input.started_at,
            duration_ms: input.duration.as_millis(),
            root: input.root,
            mode: input.mode,
            label: score.label.clone(),
            score,
            category_scores,
            services: input.services,
            project_graph: input.project_graph,
            findings,
            suppressed_findings,
            tools: vec![ToolSummary {
                name: "backend-doctor-core".to_string(),
                version: None,
                status: "ok".to_string(),
            }],
            external_tool_versions: input.external_tool_versions,
            external_tool_executions: input.external_tool_executions,
            config: input.config,
            summary,
            slop,
            coverage,
            analysis_facts: None,
        }
    }

    #[must_use]
    pub fn with_analysis_facts(mut self, analysis_facts: AnalysisFacts) -> Self {
        self.analysis_facts = Some(analysis_facts);
        self
    }
}

impl Summary {
    #[must_use]
    pub fn from_findings(findings: &[Finding], suppressed_findings: &[Finding]) -> Self {
        Self {
            total_findings: findings.len(),
            suppressed_findings: suppressed_findings.len(),
            fixable_findings: findings
                .iter()
                .filter(|finding| finding.fix.available)
                .count(),
            safe_fixes: findings
                .iter()
                .filter(|finding| finding.fix.safety == FixSafety::Safe)
                .count(),
            critical_findings: findings
                .iter()
                .filter(|finding| finding.severity == Severity::Critical)
                .count(),
            error_findings: findings
                .iter()
                .filter(|finding| finding.severity == Severity::Error)
                .count(),
        }
    }
}

impl SlopSummary {
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        let placeholder_tests = findings
            .iter()
            .filter(|finding| finding.rule_id == "agent/placeholder-test")
            .count();
        let production_placeholders = findings
            .iter()
            .filter(|finding| finding.rule_id == "agent/production-placeholder")
            .count();
        let semantic_copy_paste = findings
            .iter()
            .filter(|finding| finding.rule_id == "agent/semantic-copy-paste")
            .count();
        let spaghetti_control_flow = findings
            .iter()
            .filter(|finding| finding.rule_id == "agent/spaghetti-control-flow")
            .count();
        let swallowed_errors = findings
            .iter()
            .filter(|finding| finding.rule_id == "agent/swallowed-error")
            .count();
        let total = findings
            .iter()
            .filter(|finding| finding.rule_id.starts_with("agent/"))
            .count();
        let weighted = findings
            .iter()
            .filter_map(|finding| agent_slop_weight(&finding.rule_id))
            .sum::<usize>();
        Self {
            index: u8::try_from(weighted.min(100)).unwrap_or(100),
            findings: total,
            placeholder_tests,
            production_placeholders,
            semantic_copy_paste,
            spaghetti_control_flow,
            swallowed_errors,
        }
    }
}

fn agent_slop_weight(rule_id: &str) -> Option<usize> {
    match rule_id {
        "agent/placeholder-test" => Some(20),
        "agent/production-placeholder" => Some(25),
        "agent/semantic-copy-paste" => Some(15),
        "agent/spaghetti-control-flow" => Some(25),
        "agent/swallowed-error" => Some(30),
        _ if rule_id.starts_with("agent/") => Some(10),
        _ => None,
    }
}

impl CoverageSummary {
    #[must_use]
    pub fn from_graph(graph: &ProjectGraph) -> Self {
        let languages = graph
            .languages
            .iter()
            .map(|language| {
                let detected_files = language.evidence.len();
                match language.name.as_str() {
                    "Go" => mvp_coverage("Go", detected_files),
                    "Java" => mvp_coverage("Java", detected_files),
                    "Node/TypeScript" => mvp_coverage("Node/TypeScript", detected_files),
                    "Python" | "C#" | "PHP" | "Rust" => {
                        tier2_coverage(&language.name, detected_files)
                    }
                    "Ruby" | "Kotlin" | "Scala" | "Elixir" | "C" | "C++" => {
                        tier3_coverage(&language.name, detected_files)
                    }
                    other => generic_coverage(other, detected_files),
                }
            })
            .collect();
        Self { languages }
    }
}

fn mvp_coverage(language: &str, detected_files: usize) -> LanguageCoverage {
    LanguageCoverage {
        language: language.to_string(),
        tier: CoverageTier::Mvp,
        maturity: "mvp".to_string(),
        rule_families: vec![
            "language-heuristics".to_string(),
            "agent-patterns".to_string(),
            "security-generic".to_string(),
            "dependency-generic".to_string(),
            "infra-generic".to_string(),
        ],
        detected_files,
        notes: "MVP heuristic rule coverage is enabled for this language.".to_string(),
    }
}

fn tier2_coverage(language: &str, detected_files: usize) -> LanguageCoverage {
    LanguageCoverage {
        language: language.to_string(),
        tier: CoverageTier::Tier2,
        maturity: "language-specific".to_string(),
        rule_families: vec![
            "language-heuristics".to_string(),
            "backend-security".to_string(),
            "external-tool-hooks".to_string(),
            "security-generic".to_string(),
            "dependency-generic".to_string(),
            "infra-generic".to_string(),
        ],
        detected_files,
        notes: "Tier 2 language-specific heuristic rules and gated external-tool hooks are enabled for this language.".to_string(),
    }
}

fn tier3_coverage(language: &str, detected_files: usize) -> LanguageCoverage {
    LanguageCoverage {
        language: language.to_string(),
        tier: CoverageTier::Tier3,
        maturity: "language-specific".to_string(),
        rule_families: vec![
            "language-heuristics".to_string(),
            "external-tool-hooks".to_string(),
            "security-generic".to_string(),
            "dependency-generic".to_string(),
            "infra-generic".to_string(),
        ],
        detected_files,
        notes: "Tier 3 language-specific heuristic rules and gated external-tool hooks are enabled for this language.".to_string(),
    }
}

fn generic_coverage(language: &str, detected_files: usize) -> LanguageCoverage {
    LanguageCoverage {
        language: language.to_string(),
        tier: CoverageTier::Generic,
        maturity: "detection-only".to_string(),
        rule_families: vec![
            "language-detection".to_string(),
            "security-generic".to_string(),
            "dependency-generic".to_string(),
            "infra-generic".to_string(),
        ],
        detected_files,
        notes: "Language-specific rules are not enabled; generic security, dependency, and infra checks still apply.".to_string(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanMode {
    Full,
    Diff,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputMode {
    Summary,
    Verbose,
    Json,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thresholds {
    pub min_score: u8,
    pub max_critical: Option<u32>,
    pub max_errors: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleConfig {
    pub enabled: Option<bool>,
    pub severity: Option<Severity>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Suppression {
    pub rule: String,
    pub path: Option<String>,
    #[serde(
        default,
        alias = "allow-broad",
        alias = "allow_broad",
        skip_serializing_if = "is_false"
    )]
    pub allow_broad: bool,
    pub reason: String,
    pub expires: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalToolConfig {
    pub deep: bool,
    pub run_tests: bool,
    pub scan_history: bool,
    pub install_missing_tools: bool,
    pub network: bool,
    pub default_timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheConfig {
    pub enabled: bool,
    pub location: String,
    pub directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisConfig {
    pub enabled: bool,
    pub cache: bool,
    pub adapters: Vec<String>,
}

impl AnalysisConfig {
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self == &Self::default()
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            location: "repo-local".to_string(),
            directory: None,
        }
    }
}

impl Default for ExternalToolConfig {
    fn default() -> Self {
        Self {
            deep: false,
            run_tests: false,
            scan_history: false,
            install_missing_tools: false,
            network: false,
            default_timeout_ms: 30_000,
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache: true,
            adapters: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub include_gitignored: bool,
    pub network: bool,
    pub external_tools: ExternalToolConfig,
    pub cache: CacheConfig,
    #[serde(default, skip_serializing_if = "AnalysisConfig::is_disabled")]
    pub analysis: AnalysisConfig,
    pub output_mode: OutputMode,
    pub thresholds: Thresholds,
    pub disabled_rules: Vec<String>,
    pub rules: BTreeMap<String, RuleConfig>,
    pub suppressions: Vec<Suppression>,
}

pub type DoctorConfig = Config;

impl Default for Config {
    fn default() -> Self {
        Self {
            include_gitignored: false,
            network: false,
            external_tools: ExternalToolConfig::default(),
            cache: CacheConfig::default(),
            analysis: AnalysisConfig::default(),
            output_mode: OutputMode::Summary,
            thresholds: Thresholds {
                min_score: 75,
                max_critical: None,
                max_errors: None,
            },
            disabled_rules: Vec::new(),
            rules: BTreeMap::new(),
            suppressions: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigFile {
    include_gitignored: Option<bool>,
    network: Option<bool>,
    external_tools: Option<ExternalToolFile>,
    cache: Option<CacheFile>,
    analysis: Option<AnalysisFile>,
    output_mode: Option<OutputMode>,
    thresholds: Option<ThresholdFile>,
    disabled_rules: Option<Vec<String>>,
    rules: Option<BTreeMap<String, RuleConfig>>,
    suppressions: Option<Vec<Suppression>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct CacheFile {
    enabled: Option<bool>,
    location: Option<String>,
    directory: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ExternalToolFile {
    deep: Option<bool>,
    run_tests: Option<bool>,
    scan_history: Option<bool>,
    install_missing_tools: Option<bool>,
    network: Option<bool>,
    default_timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct AnalysisFile {
    enabled: Option<bool>,
    cache: Option<bool>,
    adapters: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ThresholdFile {
    min_score: Option<u8>,
    max_critical: Option<u32>,
    max_errors: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigOverrides {
    pub include_gitignored: bool,
    pub network: bool,
    pub deep: bool,
    pub run_tests: bool,
    pub scan_history: bool,
    pub install_missing_tools: bool,
    pub output_mode: Option<OutputMode>,
    pub min_score: Option<u8>,
    pub max_critical: Option<u32>,
    pub max_errors: Option<u32>,
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "failed to read config {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "invalid TOML in {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn resolve_config(
    root: impl AsRef<Path>,
    overrides: ConfigOverrides,
) -> Result<Config, ConfigError> {
    let mut config = Config::default();
    let path = root.as_ref().join(CONFIG_FILE_NAME);
    if path.exists() {
        let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let file: ConfigFile = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        apply_config_file(&mut config, file);
    }
    apply_overrides(&mut config, overrides);
    Ok(config)
}

fn apply_config_file(config: &mut Config, file: ConfigFile) {
    if let Some(value) = file.include_gitignored {
        config.include_gitignored = value;
    }
    if let Some(value) = file.network {
        config.network = value;
        config.external_tools.network = value;
    }
    if let Some(value) = file.external_tools {
        apply_external_tool_file(&mut config.external_tools, value);
    }
    if let Some(value) = file.cache {
        apply_cache_file(&mut config.cache, value);
    }
    if let Some(value) = file.analysis {
        apply_analysis_file(&mut config.analysis, value);
    }
    if let Some(value) = file.output_mode {
        config.output_mode = value;
    }
    if let Some(thresholds) = file.thresholds {
        if let Some(value) = thresholds.min_score {
            config.thresholds.min_score = value;
        }
        if let Some(value) = thresholds.max_critical {
            config.thresholds.max_critical = Some(value);
        }
        if let Some(value) = thresholds.max_errors {
            config.thresholds.max_errors = Some(value);
        }
    }
    if let Some(value) = file.disabled_rules {
        config.disabled_rules = value;
    }
    if let Some(value) = file.rules {
        config.rules = value;
    }
    if let Some(value) = file.suppressions {
        config.suppressions = value;
    }
}

fn apply_cache_file(config: &mut CacheConfig, file: CacheFile) {
    if let Some(value) = file.enabled {
        config.enabled = value;
    }
    if let Some(value) = file.location {
        config.location = value;
    }
    if let Some(value) = file.directory {
        config.directory = Some(value);
    }
}

fn apply_analysis_file(config: &mut AnalysisConfig, file: AnalysisFile) {
    if let Some(value) = file.enabled {
        config.enabled = value;
    }
    if let Some(value) = file.cache {
        config.cache = value;
    }
    if let Some(value) = file.adapters {
        config.adapters = value;
    }
}

fn apply_external_tool_file(config: &mut ExternalToolConfig, file: ExternalToolFile) {
    if let Some(value) = file.deep {
        config.deep = value;
    }
    if let Some(value) = file.run_tests {
        config.run_tests = value;
    }
    if let Some(value) = file.scan_history {
        config.scan_history = value;
    }
    if let Some(value) = file.install_missing_tools {
        config.install_missing_tools = value;
    }
    if let Some(value) = file.network {
        config.network = value;
    }
    if let Some(value) = file.default_timeout_ms {
        config.default_timeout_ms = value;
    }
}

fn apply_overrides(config: &mut Config, overrides: ConfigOverrides) {
    if overrides.include_gitignored {
        config.include_gitignored = true;
    }
    if overrides.network {
        config.network = true;
        config.external_tools.network = true;
    }
    if overrides.deep {
        config.external_tools.deep = true;
    }
    if overrides.run_tests {
        config.external_tools.run_tests = true;
    }
    if overrides.scan_history {
        config.external_tools.scan_history = true;
    }
    if overrides.install_missing_tools {
        config.external_tools.install_missing_tools = true;
    }
    if let Some(value) = overrides.output_mode {
        config.output_mode = value;
    }
    if let Some(value) = overrides.min_score {
        config.thresholds.min_score = value;
    }
    if let Some(value) = overrides.max_critical {
        config.thresholds.max_critical = Some(value);
    }
    if let Some(value) = overrides.max_errors {
        config.thresholds.max_errors = Some(value);
    }
}

#[must_use]
pub fn score_label(value: u8) -> &'static str {
    match value {
        90..=100 => "Excellent",
        75..=89 => "Great",
        50..=74 => "Needs Work",
        _ => "Critical",
    }
}

#[must_use]
pub fn score_findings(findings: &[Finding]) -> Score {
    let caps = score_caps(findings);
    let mut value = score_for_category(findings.iter());
    for cap in &caps {
        value = value.min(cap.cap);
    }
    let category_scores = Category::all()
        .iter()
        .cloned()
        .map(|category| {
            let score = score_for_category(
                findings
                    .iter()
                    .filter(|finding| finding.category == category),
            );
            CategoryScore { category, score }
        })
        .collect();

    Score {
        value,
        label: score_label(value).to_string(),
        category_scores,
        caps,
    }
}

fn score_for_category<'a>(findings: impl Iterator<Item = &'a Finding>) -> u8 {
    let penalty: f64 = findings.map(finding_penalty).sum();
    (100.0 - penalty).round().clamp(0.0, 100.0) as u8
}

fn finding_penalty(finding: &Finding) -> f64 {
    if finding.suppressed {
        return 0.0;
    }

    let mut penalty = finding.severity.penalty();
    penalty *= finding.confidence.multiplier();
    penalty *= finding.fix.safety.penalty_multiplier();
    if finding.location.as_ref().is_some_and(|location| {
        location
            .path
            .components()
            .any(|component| component.as_os_str() == "testdata")
    }) {
        penalty *= 0.25;
    }
    penalty
}

fn score_caps(findings: &[Finding]) -> Vec<ScoreCap> {
    let mut caps = Vec::new();
    for finding in findings {
        if finding.rule_id == "security/hardcoded-secret"
            && finding.severity == Severity::Critical
            && finding
                .evidence
                .as_ref()
                .is_some_and(|evidence| evidence.redacted && evidence.secret_fingerprint.is_some())
        {
            caps.push(ScoreCap {
                cap: 39,
                reason: "raw secret detected in committed project files".to_string(),
            });
        }
        if finding.category == Category::Dependencies
            && finding.severity == Severity::Critical
            && finding
                .metadata
                .get("reachability")
                .is_some_and(|value| value == "reachable")
        {
            caps.push(ScoreCap {
                cap: 49,
                reason: "critical reachable dependency vulnerability detected".to_string(),
            });
        }
        if finding.category == Category::Security
            && finding.severity == Severity::Critical
            && finding
                .evidence
                .as_ref()
                .is_some_and(|evidence| !evidence.redacted)
        {
            caps.push(ScoreCap {
                cap: 49,
                reason: "critical security evidence is not redacted".to_string(),
            });
        }
    }
    caps.sort_by_key(|cap| cap.cap);
    caps.dedup_by(|left, right| left.cap == right.cap && left.reason == right.reason);
    caps
}

#[must_use]
pub fn sort_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(compare_findings);
    findings
}

fn compare_findings(left: &Finding, right: &Finding) -> Ordering {
    left.severity
        .rank()
        .cmp(&right.severity.rank())
        .then_with(|| left.category.cmp(&right.category))
        .then_with(|| {
            left.location
                .as_ref()
                .map(Location::display)
                .cmp(&right.location.as_ref().map(Location::display))
        })
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        .then_with(|| left.id.cmp(&right.id))
}

#[must_use]
pub fn redact_text(input: &str) -> String {
    let input = redact_authorization_headers(input);
    let mut output = String::with_capacity(input.len());
    let mut token = String::new();
    let mut redact_next = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !token.is_empty() {
                let (redacted, next) = redact_token_with_context(&token, redact_next);
                output.push_str(&redacted);
                redact_next = next;
                token.clear();
            }
            output.push(ch);
        } else {
            token.push(ch);
        }
    }
    if !token.is_empty() {
        let (redacted, _) = redact_token_with_context(&token, redact_next);
        output.push_str(&redacted);
    }
    output
}

fn redact_authorization_headers(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(index) = find_authorization_header(rest) {
        output.push_str(&rest[..index]);
        let header = &rest[index..];
        let Some((redacted, consumed)) = redact_authorization_header_at_start(header) else {
            output.push_str(&rest[index..index + "authorization:".len()]);
            rest = &rest[index + "authorization:".len()..];
            continue;
        };
        output.push_str(&redacted);
        rest = &header[consumed..];
    }
    output.push_str(rest);
    output
}

fn find_authorization_header(input: &str) -> Option<usize> {
    input
        .as_bytes()
        .windows("authorization:".len())
        .position(|window| window.eq_ignore_ascii_case(b"authorization:"))
}

fn redact_authorization_header_at_start(input: &str) -> Option<(String, usize)> {
    let colon = input.find(':')?;
    let mut cursor = colon + 1;
    let mut output = input[..cursor].to_string();
    while let Some(ch) = input[cursor..].chars().next() {
        if !ch.is_ascii_whitespace() || ch == '\n' || ch == '\r' {
            break;
        }
        output.push(ch);
        cursor += ch.len_utf8();
    }

    let scheme_start = cursor;
    while let Some(ch) = input[cursor..].chars().next() {
        if !ch.is_ascii_alphabetic() {
            break;
        }
        cursor += ch.len_utf8();
    }
    let scheme = &input[scheme_start..cursor];
    if !is_authorization_scheme_name(scheme) {
        return None;
    }
    output.push_str(scheme);

    let spacing_start = cursor;
    while let Some(ch) = input[cursor..].chars().next() {
        if !ch.is_ascii_whitespace() || ch == '\n' || ch == '\r' {
            break;
        }
        cursor += ch.len_utf8();
    }
    output.push_str(&input[spacing_start..cursor]);

    let credential_start = cursor;
    let credential_end = if scheme.eq_ignore_ascii_case("digest") {
        input[cursor..]
            .find(['\n', '\r'])
            .map_or(input.len(), |offset| cursor + offset)
    } else {
        while let Some(ch) = input[cursor..].chars().next() {
            if ch.is_ascii_whitespace() {
                break;
            }
            cursor += ch.len_utf8();
        }
        cursor
    };

    if credential_start >= credential_end {
        return None;
    }
    output.push_str(&redact_secret_value_token(
        &input[credential_start..credential_end],
    ));
    Some((output, credential_end))
}

fn is_authorization_scheme_name(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "bearer" | "basic" | "digest" | "token"
    )
}

fn redact_token_with_context(token: &str, force_redact: bool) -> (String, bool) {
    if force_redact {
        if token_is_authorization_scheme(token) {
            return (token.to_string(), true);
        }
        return (redact_secret_value_token(token), false);
    }
    if token_is_authorization_scheme(token) {
        return (token.to_string(), true);
    }
    let redacted = redact_token(token);
    let redact_next = redacted == token && token_is_secret_key_with_separator(token);
    (redacted, redact_next)
}

fn redact_token(token: &str) -> String {
    if token_contains_tool_log_path(token) {
        return "[REDACTED_PATH]".to_string();
    }
    if token_is_authorization_header_scheme_prefix(token) {
        return token.to_string();
    }
    let upper = token.to_ascii_uppercase();
    let looks_secret_key = secret_key_needles()
        .iter()
        .any(|needle| upper.contains(&needle.to_ascii_uppercase()));
    let has_assignment = token.contains('=') || token.contains(':');
    let long_opaque = token.len() >= 24
        && token.chars().any(|ch| ch.is_ascii_digit())
        && token.chars().any(|ch| ch.is_ascii_lowercase())
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'));

    if (looks_secret_key && has_assignment) || long_opaque {
        if let Some((prefix, _)) = token.split_once('=') {
            return format!("{prefix}=[REDACTED]");
        }
        if let Some((prefix, value)) = token.split_once(':') {
            if value.is_empty() {
                return token.to_string();
            }
            return format!("{prefix}:[REDACTED]");
        }
        return "[REDACTED]".to_string();
    }
    if token_contains_url_secret(token) {
        return redact_url_token(token);
    }
    token.to_string()
}

fn secret_key_needles() -> &'static [&'static str] {
    &[
        "SECRET",
        "TOKEN",
        "API_KEY",
        "PASSWORD",
        "DATABASE_URL",
        "PRIVATE_KEY",
        "CLIENT_SECRET",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "WEBHOOK_SECRET",
        "CREDENTIAL",
        "AUTHORIZATION",
        "BEARER",
        "SESSION",
    ]
}

fn token_is_secret_key_with_separator(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';'));
    let Some(prefix) = trimmed
        .strip_suffix(':')
        .or_else(|| trimmed.strip_suffix('='))
    else {
        return false;
    };
    let upper = prefix.to_ascii_uppercase();
    secret_key_needles()
        .iter()
        .any(|needle| upper.contains(&needle.to_ascii_uppercase()))
}

fn token_is_authorization_scheme(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';'));
    is_authorization_scheme_name(trimmed)
}

fn token_is_authorization_header_scheme_prefix(token: &str) -> bool {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';'));
    let Some((header, scheme)) = trimmed.split_once(':') else {
        return false;
    };
    header.eq_ignore_ascii_case("authorization") && is_authorization_scheme_name(scheme)
}

fn redact_secret_value_token(token: &str) -> String {
    let leading = token
        .chars()
        .take_while(|ch| matches!(ch, '"' | '\''))
        .collect::<String>();
    let trailing = token
        .chars()
        .rev()
        .take_while(|ch| matches!(ch, '"' | '\'' | ',' | ';'))
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{leading}[REDACTED]{trailing}")
}

fn token_contains_url_secret(token: &str) -> bool {
    let Some(scheme_index) = token.find("://") else {
        return false;
    };
    let after_scheme = &token[scheme_index + 3..];
    after_scheme.contains('@') || after_scheme.contains('?')
}

fn redact_url_token(token: &str) -> String {
    let Some(scheme_index) = token.find("://") else {
        return token.to_string();
    };
    let prefix = &token[..scheme_index + 3];
    let mut rest = token[scheme_index + 3..].to_string();
    if let Some(at) = rest.find('@') {
        rest = format!("[REDACTED]@{}", &rest[at + 1..]);
    }
    if let Some(query) = rest.find('?') {
        let path = &rest[..query];
        let query_tail = &rest[query + 1..];
        let fragment = query_tail
            .find('#')
            .map(|index| &query_tail[index..])
            .unwrap_or("");
        rest = format!("{path}?[REDACTED]{fragment}");
    }
    format!("{prefix}{rest}")
}

fn token_contains_tool_log_path(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    [
        "/.npm/_logs/",
        "\\.npm\\_logs\\",
        "/.cache/",
        "/node_modules/.bin/",
        "\\node_modules\\.bin\\",
        "/go/pkg/mod/cache/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[must_use]
pub fn sample_finding(
    id: &str,
    severity: Severity,
    category: Category,
    location_path: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        fingerprint: format!("sha256:{id}"),
        rule_id: "test/rule".to_string(),
        tool: "backend-doctor-test".to_string(),
        source_tool: "custom".to_string(),
        title: "Test finding".to_string(),
        message: "Test message".to_string(),
        category,
        severity,
        confidence: Confidence::High,
        service: None,
        language: None,
        framework: None,
        location: Some(Location {
            path: PathBuf::from(location_path),
            line: Some(1),
            column: Some(1),
            end_line: None,
            end_column: None,
        }),
        evidence: None,
        impact: None,
        remediation: "Fix it".to_string(),
        fix: FixInfo {
            available: true,
            safety: FixSafety::Guided,
            description: None,
        },
        links: Vec::new(),
        metadata: BTreeMap::new(),
        suppressed: false,
    }
}

#[must_use]
pub fn disabled_rule_set(config: &Config) -> BTreeSet<String> {
    config.disabled_rules.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_labels_match_thresholds() {
        assert_eq!(Score::from_value(95).label, "Excellent");
        assert_eq!(Score::from_value(80).label, "Great");
        assert_eq!(Score::from_value(60).label, "Needs Work");
        assert_eq!(Score::from_value(20).label, "Critical");
    }

    #[test]
    fn default_config_is_local_first_and_offline() {
        let config = Config::default();
        assert!(!config.include_gitignored);
        assert!(!config.network);
        assert!(!config.external_tools.network);
        assert!(!config.external_tools.deep);
        assert!(!config.external_tools.run_tests);
        assert!(!config.external_tools.scan_history);
        assert!(!config.external_tools.install_missing_tools);
        assert!(!config.analysis.enabled);
        assert!(config.analysis.cache);
        assert_eq!(config.thresholds.min_score, 75);
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn scoring_applies_severity_confidence_and_safe_fix_multiplier() {
        let mut error = sample_finding("a", Severity::Error, Category::Reliability, "src/a.rs");
        error.confidence = Confidence::Medium;
        error.fix.safety = FixSafety::Safe;

        let score = score_findings(&[error]);

        assert_eq!(score.value, 97);
        assert_eq!(score.label, "Excellent");
        assert_eq!(
            score
                .category_scores
                .iter()
                .find(|category| category.category == Category::Reliability)
                .map(|category| category.score),
            Some(97)
        );
    }

    #[test]
    fn scoring_caps_raw_secret_findings() {
        let mut secret = sample_finding(
            "secret",
            Severity::Critical,
            Category::Security,
            "src/config.yml",
        );
        secret.rule_id = "security/hardcoded-secret".to_string();
        secret.evidence = Some(Evidence {
            snippet: "[REDACTED]".to_string(),
            redacted: true,
            secret_fingerprint: Some("fnv64:test".to_string()),
        });

        let score = score_findings(&[secret]);

        assert_eq!(score.value, 39);
        assert!(score.caps.iter().any(|cap| {
            cap.cap == 39 && cap.reason == "raw secret detected in committed project files"
        }));
    }

    #[test]
    fn scoring_ignores_suppressed_findings_and_discounts_testdata() {
        let mut suppressed = sample_finding(
            "suppressed",
            Severity::Error,
            Category::Reliability,
            "src/a.rs",
        );
        suppressed.suppressed = true;
        let testdata = sample_finding(
            "testdata",
            Severity::Error,
            Category::Reliability,
            "testdata/a.rs",
        );

        let score = score_findings(&[suppressed, testdata]);

        assert_eq!(score.value, 99);
        assert_eq!(
            score
                .category_scores
                .iter()
                .find(|category| category.category == Category::Reliability)
                .map(|category| category.score),
            Some(99)
        );
        assert!(score.caps.is_empty());
    }

    #[test]
    fn slop_summary_counts_semantic_copy_paste_as_agent_slop() {
        let mut finding = sample_finding(
            "semantic",
            Severity::Info,
            Category::Architecture,
            "src/dto.ts",
        );
        finding.rule_id = "agent/semantic-copy-paste".to_string();

        let slop = SlopSummary::from_findings(&[finding]);

        assert_eq!(slop.findings, 1);
        assert_eq!(slop.semantic_copy_paste, 1);
        assert_eq!(slop.index, 15);
    }

    #[test]
    fn report_slop_summary_excludes_suppressed_agent_findings() {
        let mut suppressed = sample_finding(
            "semantic",
            Severity::Info,
            Category::Architecture,
            "src/dto.ts",
        );
        suppressed.rule_id = "agent/semantic-copy-paste".to_string();
        suppressed.suppressed = true;
        let mut active = sample_finding(
            "placeholder",
            Severity::Warning,
            Category::Maintainability,
            "src/app.ts",
        );
        active.rule_id = "agent/production-placeholder".to_string();

        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("fixtures/slop"),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from("fixtures/slop")),
            findings: vec![suppressed, active],
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.suppressed_findings.len(), 1);
        assert_eq!(report.slop.findings, 1);
        assert_eq!(report.slop.production_placeholders, 1);
        assert_eq!(report.slop.semantic_copy_paste, 0);
    }

    #[test]
    fn deterministic_sort_orders_by_severity_category_location_rule() {
        let warning = sample_finding("b", Severity::Warning, Category::Testing, "b.rs");
        let critical_b = sample_finding("c", Severity::Critical, Category::Security, "b.rs");
        let critical_a = sample_finding("a", Severity::Critical, Category::Security, "a.rs");

        let sorted = sort_findings(vec![warning, critical_b, critical_a]);

        assert_eq!(
            sorted
                .iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "c", "b"]
        );
    }

    #[test]
    fn redaction_removes_secret_like_values() {
        let raw = "DATABASE_URL=postgres://user:superSecret123456@db/app token AbCdEfGhIjKlMnOpQrSt123456 password: lowercase-secret-value-123456 url=https://user:pass@example.com/path?token=abc npm_log=/home/me/.npm/_logs/2026-debug.log";
        let redacted = redact_text(raw);

        assert!(!redacted.contains("superSecret"));
        assert!(!redacted.contains("AbCdEf"));
        assert!(!redacted.contains("lowercase-secret-value"));
        assert!(!redacted.contains("user:pass"));
        assert!(!redacted.contains("token=abc"));
        assert!(!redacted.contains(".npm/_logs"));
        assert!(redacted.contains("DATABASE_URL=[REDACTED]"));
        assert!(redacted.contains("password: [REDACTED]"));
    }

    #[test]
    fn redaction_removes_authorization_scheme_credentials() {
        let raw = "Authorization: Bearer abc Basic xyz curl -H 'Authorization: Bearer short'";
        let redacted = redact_text(raw);

        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("xyz"));
        assert!(!redacted.contains("short"));
        assert!(redacted.contains("Authorization: Bearer [REDACTED]"));
        assert!(redacted.contains("Basic [REDACTED]"));
    }

    #[test]
    fn redaction_removes_common_authorization_header_shapes() {
        let raw = concat!(
            "Authorization:Bearer abc\n",
            "Authorization: Basic xy\n",
            "Authorization: token z\n",
            "Authorization: Digest username=\"alice\", realm=\"api\", nonce=\"n\", response=\"r\"\n",
            "authorization:bearer short"
        );
        let redacted = redact_text(raw);

        assert!(!redacted.contains("abc"));
        assert!(!redacted.contains("xy"));
        assert!(!redacted.contains(" z"));
        assert!(!redacted.contains("alice"));
        assert!(!redacted.contains("nonce"));
        assert!(!redacted.contains("short"));
        assert!(redacted.contains("Authorization:Bearer [REDACTED]"));
        assert!(redacted.contains("Authorization: Basic [REDACTED]"));
        assert!(redacted.contains("Authorization: token [REDACTED]"));
        assert!(redacted.contains("Authorization: Digest [REDACTED]"));
        assert!(redacted.contains("authorization:bearer [REDACTED]"));
    }

    #[test]
    fn external_pipe_capture_is_bounded_and_marks_truncation() {
        let data = vec![b'a'; EXTERNAL_OUTPUT_CAPTURE_BYTES + 32];
        let captured =
            capture_external_pipe(std::io::Cursor::new(data), EXTERNAL_OUTPUT_CAPTURE_BYTES);

        assert_eq!(captured.buffer.len(), EXTERNAL_OUTPUT_CAPTURE_BYTES);
        assert_eq!(captured.total_bytes, EXTERNAL_OUTPUT_CAPTURE_BYTES + 32);
        assert!(captured.truncated);
    }

    #[test]
    fn report_serializes_with_camel_case_contract() {
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(3),
            root: PathBuf::from("fixtures/empty"),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from("fixtures/empty")),
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });

        let json = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(json["schemaVersion"], REPORT_SCHEMA_VERSION);
        assert_eq!(json["score"]["value"], 100);
        assert_eq!(json["slop"]["index"], 0);
        assert!(json.get("analysisFacts").is_none());
        assert_eq!(
            json["coverage"]["languages"].as_array().map(Vec::len),
            Some(0)
        );
        assert_eq!(json["findings"].as_array().map(Vec::len), Some(0));
        assert!(json.get("schema_version").is_none());
    }

    #[test]
    fn analysis_facts_use_stable_ids_and_camel_case_contract() {
        let source = SourceFileFact::new("src/main.rs", "Rust").with_content(b"fn main() {}\n");
        assert_eq!(source.line_count, Some(1));
        assert_eq!(
            source.id,
            SourceFileFact::new("src/main.rs", "Rust").id,
            "source fact IDs are deterministic"
        );

        let mut facts = AnalysisFacts::empty();
        facts.source_files.push(source);
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(3),
            root: PathBuf::from("fixtures/empty"),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from("fixtures/empty")),
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        })
        .with_analysis_facts(facts);

        let json = serde_json::to_value(&report).expect("report serializes");
        assert_eq!(
            json["analysisFacts"]["schemaVersion"],
            ANALYSIS_FACTS_SCHEMA_VERSION
        );
        assert!(json["analysisFacts"]["sourceFiles"].is_array());
        assert!(json["analysisFacts"].get("source_files").is_none());
    }

    #[test]
    fn coverage_summary_classifies_mvp_tier2_tier3_and_generic_languages() {
        let mut graph = ProjectGraph::empty(PathBuf::from("fixtures/mixed"));
        graph.languages = [
            ("Go", "main.go"),
            ("Python", "app.py"),
            ("Ruby", "app.rb"),
            ("Kotlin", "src/main/kotlin/App.kt"),
            ("Scala", "src/main/scala/App.scala"),
            ("Elixir", "lib/app.ex"),
            ("C", "main.c"),
            ("C++", "main.cpp"),
            ("Clojure", "src/app.clj"),
        ]
        .into_iter()
        .map(|(name, evidence)| DetectedLanguage {
            name: name.to_string(),
            confidence: DetectionConfidence::High,
            evidence: vec![PathBuf::from(evidence)],
        })
        .collect();

        let coverage = CoverageSummary::from_graph(&graph);
        let tier_for = |language: &str| {
            coverage
                .languages
                .iter()
                .find(|entry| entry.language == language)
                .map(|entry| &entry.tier)
        };

        assert_eq!(tier_for("Go"), Some(&CoverageTier::Mvp));
        assert_eq!(tier_for("Python"), Some(&CoverageTier::Tier2));
        for language in ["Ruby", "Kotlin", "Scala", "Elixir", "C", "C++"] {
            assert_eq!(tier_for(language), Some(&CoverageTier::Tier3));
        }
        assert_eq!(tier_for("Clojure"), Some(&CoverageTier::Generic));
    }

    #[test]
    fn config_file_parses_and_overrides_defaults() {
        let raw = r#"
include-gitignored = true
network = true
disabled-rules = ["a/b"]

[external-tools]
deep = true
run-tests = true
scan-history = true
install-missing-tools = true
network = false
default-timeout-ms = 1234

[analysis]
enabled = true
cache = false
adapters = ["rust", "go"]

[thresholds]
min-score = 88
max-critical = 0

[rules."node/example"]
severity = "critical"

[[suppressions]]
rule = "agent/production-placeholder"
reason = "legacy baseline for generated fixtures"
allowBroad = true
"#;
        let file: ConfigFile = toml::from_str(raw).expect("config parses");
        let mut config = Config::default();
        apply_config_file(&mut config, file);

        assert!(config.include_gitignored);
        assert!(config.network);
        assert!(config.external_tools.deep);
        assert!(config.external_tools.run_tests);
        assert!(config.external_tools.scan_history);
        assert!(config.external_tools.install_missing_tools);
        assert!(!config.external_tools.network);
        assert_eq!(config.external_tools.default_timeout_ms, 1234);
        assert!(config.analysis.enabled);
        assert!(!config.analysis.cache);
        assert_eq!(config.analysis.adapters, ["rust", "go"]);
        assert_eq!(config.thresholds.min_score, 88);
        assert_eq!(config.thresholds.max_critical, Some(0));
        assert_eq!(config.disabled_rules, ["a/b"]);
        assert_eq!(
            config
                .rules
                .get("node/example")
                .and_then(|rule| rule.severity.clone()),
            Some(Severity::Critical)
        );
        assert_eq!(config.suppressions.len(), 1);
        assert_eq!(config.suppressions[0].rule, "agent/production-placeholder");
        assert!(config.suppressions[0].allow_broad);
        assert_eq!(config.suppressions[0].path, None);
    }

    #[test]
    fn pathless_config_suppression_defaults_to_not_broad() {
        let raw = r#"
[[suppressions]]
rule = "agent/production-placeholder"
reason = "legacy pathless suppression remains parse-compatible"
"#;
        let file: ConfigFile = toml::from_str(raw).expect("config parses");
        let mut config = Config::default();
        apply_config_file(&mut config, file);

        assert_eq!(config.suppressions.len(), 1);
        assert_eq!(config.suppressions[0].path, None);
        assert!(
            !config.suppressions[0].allow_broad,
            "pathless suppressions must require explicit broad opt-in"
        );
    }

    #[test]
    fn cli_overrides_win_over_config_values() {
        let mut config = Config::default();
        config.thresholds.min_score = 60;

        apply_overrides(
            &mut config,
            ConfigOverrides {
                min_score: Some(90),
                output_mode: Some(OutputMode::Json),
                include_gitignored: true,
                network: true,
                deep: true,
                run_tests: true,
                scan_history: true,
                install_missing_tools: true,
                max_critical: Some(1),
                max_errors: Some(2),
            },
        );

        assert_eq!(config.thresholds.min_score, 90);
        assert_eq!(config.output_mode, OutputMode::Json);
        assert!(config.include_gitignored);
        assert!(config.network);
        assert!(config.external_tools.network);
        assert!(config.external_tools.deep);
        assert!(config.external_tools.run_tests);
        assert!(config.external_tools.scan_history);
        assert!(config.external_tools.install_missing_tools);
        assert_eq!(config.thresholds.max_critical, Some(1));
        assert_eq!(config.thresholds.max_errors, Some(2));
    }

    #[test]
    fn external_runner_captures_success_failure_and_redacts() {
        let success = ExternalCommandRunner::run(
            &ExternalCommandSpec::new("sh")
                .args([
                    "-c",
                    "printf 'DATABASE_URL=postgres://secret123456789@db/app'; printf ' TOKEN=shhh123456789' >&2",
                ])
                .env("API_KEY", "AbCdEfGhIjKlMnOpQrSt123456"),
        );
        assert_eq!(success.status, ExternalCommandStatus::Success);
        assert_eq!(success.exit_code, Some(0));
        assert!(success.stdout.contains("DATABASE_URL=[REDACTED]"));
        assert!(success.stderr.contains("TOKEN=[REDACTED]"));
        assert!(success.stdout_excerpt.contains("DATABASE_URL=[REDACTED]"));
        assert_eq!(success.stdout_bytes, 46);
        assert!(success.stdout_digest.starts_with("fnv64:"));
        assert_eq!(success.invocation.env["API_KEY"], "[REDACTED]");

        let failure =
            ExternalCommandRunner::run(&ExternalCommandSpec::new("sh").args(["-c", "exit 7"]));
        assert_eq!(failure.status, ExternalCommandStatus::Failure);
        assert_eq!(failure.exit_code, Some(7));
    }

    #[test]
    fn external_runner_reports_missing_tool_and_timeout() {
        let missing = ExternalCommandRunner::run(&ExternalCommandSpec::new(
            "backend-doctor-definitely-missing-tool",
        ));
        assert_eq!(missing.status, ExternalCommandStatus::MissingTool);
        assert!(missing
            .diagnostic
            .as_deref()
            .is_some_and(|diagnostic| diagnostic.contains("missing external tool")));

        let timeout = ExternalCommandRunner::run(
            &ExternalCommandSpec::new("sh")
                .args(["-c", "sleep 2"])
                .timeout(Duration::from_millis(50)),
        );
        assert_eq!(timeout.status, ExternalCommandStatus::Timeout);
        assert!(timeout
            .diagnostic
            .as_deref()
            .is_some_and(|diagnostic| diagnostic.contains("timed out")));
    }

    #[test]
    fn external_runner_timeout_is_bounded_when_descendant_keeps_pipes_open() {
        let started = Instant::now();
        let timeout = ExternalCommandRunner::run(
            &ExternalCommandSpec::new("sh")
                .args(["-c", "sleep 2 & wait"])
                .timeout(Duration::from_millis(50)),
        );

        assert_eq!(timeout.status, ExternalCommandStatus::Timeout);
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "timeout cleanup took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn external_runner_supports_cwd_and_version_records() {
        let temp = std::env::temp_dir().join(format!(
            "backend-doctor-external-runner-{}",
            std::process::id()
        ));
        fs::create_dir_all(&temp).expect("temp dir");
        fs::write(temp.join("version.txt"), "fake-tool 1.2.3").expect("version fixture");
        fs::write(temp.join("fake-tool.sh"), "cat version.txt").expect("fake tool script");

        let execution = ExternalCommandRunner::run(
            &ExternalCommandSpec::new("sh")
                .args(["fake-tool.sh"])
                .cwd(&temp),
        );
        assert_eq!(execution.status, ExternalCommandStatus::Success);
        assert_eq!(execution.stdout, "fake-tool 1.2.3");
        let json = serde_json::to_value(&execution).expect("execution serializes");
        assert!(json.get("stdout").is_none());
        assert_eq!(json["stdoutExcerpt"], "fake-tool 1.2.3");

        let version =
            ExternalCommandExecution::tool_version("fake-tool", Some(execution.stdout.clone()));
        assert_eq!(version.tool, "fake-tool");
        assert_eq!(version.version.as_deref(), Some("fake-tool 1.2.3"));
        assert_eq!(version.status, ExternalCommandStatus::Success);

        let _ = fs::remove_file(temp.join("version.txt"));
        let _ = fs::remove_file(temp.join("fake-tool.sh"));
        let _ = fs::remove_dir(temp);
    }
}
