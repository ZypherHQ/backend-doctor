use backend_doctor_core::{
    stable_digest, AnalysisFacts, CallFact, ImportFact, ProjectGraph, RouteFact, SinkFact,
    SourceFileFact, TaintEdge,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

pub mod adapters;

pub const ANALYSIS_CACHE_KEY_VERSION: &str = "bda1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterInput<'a> {
    pub project: &'a ProjectGraph,
    pub source_file: &'a SourceFileFact,
    pub contents: &'a str,
}

pub trait SourceAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn language(&self) -> &'static str;

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError>;

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        source_file.language == self.language()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnalysisError {
    UnsupportedLanguage { adapter: String, language: String },
    Parse { path: PathBuf, message: String },
    Io { path: PathBuf, message: String },
    Internal { message: String },
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedLanguage { adapter, language } => {
                write!(f, "adapter {adapter} does not support {language}")
            }
            Self::Parse { path, message } => {
                write!(f, "failed to parse {}: {message}", path.display())
            }
            Self::Io { path, message } => write!(f, "failed to read {}: {message}", path.display()),
            Self::Internal { message } => f.write_str(message),
        }
    }
}

impl Error for AnalysisError {}

#[derive(Default)]
pub struct ParserRegistry {
    adapters: BTreeMap<&'static str, Box<dyn SourceAdapter>>,
}

impl ParserRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<A>(&mut self, adapter: A)
    where
        A: SourceAdapter + 'static,
    {
        let language = adapter.language();
        assert!(
            !self.adapters.contains_key(language),
            "adapter already registered for language {language}"
        );
        assert!(
            !self
                .adapters
                .values()
                .any(|existing| existing.id() == adapter.id()),
            "adapter already registered with id {}",
            adapter.id()
        );
        self.adapters.insert(language, Box::new(adapter));
    }

    #[must_use]
    pub fn adapter_for(&self, source_file: &SourceFileFact) -> Option<&dyn SourceAdapter> {
        self.adapters
            .values()
            .map(|adapter| adapter.as_ref())
            .find(|adapter| adapter.supports(source_file))
    }

    pub fn analyze_file(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<Option<AnalysisFacts>, AnalysisError> {
        let Some(adapter) = self.adapter_for(input.source_file) else {
            return Ok(None);
        };
        adapter.analyze(input).map(Some)
    }

    #[must_use]
    pub fn languages(&self) -> Vec<&'static str> {
        self.adapters.keys().copied().collect()
    }
}

#[must_use]
pub fn default_parser_registry() -> ParserRegistry {
    let mut registry = ParserRegistry::new();
    adapters::register_default_adapters(&mut registry);
    registry
}

#[must_use]
pub fn tier_a_parser_registry() -> ParserRegistry {
    default_parser_registry()
}

pub fn analyze_sources<'a, I>(
    project: &'a ProjectGraph,
    sources: I,
) -> Result<AnalysisFacts, AnalysisError>
where
    I: IntoIterator<Item = (&'a SourceFileFact, &'a str)>,
{
    let registry = default_parser_registry();
    analyze_sources_with_registry(&registry, project, sources)
}

pub fn analyze_sources_with_registry<'a, I>(
    registry: &ParserRegistry,
    project: &'a ProjectGraph,
    sources: I,
) -> Result<AnalysisFacts, AnalysisError>
where
    I: IntoIterator<Item = (&'a SourceFileFact, &'a str)>,
{
    let mut parts = Vec::new();
    for (source_file, contents) in sources {
        if let Some(facts) = registry.analyze_file(AdapterInput {
            project,
            source_file,
            contents,
        })? {
            parts.push(facts);
        }
    }
    Ok(merge_analysis_facts(parts))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisCacheKey {
    pub version: String,
    pub language: String,
    pub path: PathBuf,
    pub content_digest: String,
}

impl AnalysisCacheKey {
    #[must_use]
    pub fn for_content(
        path: impl Into<PathBuf>,
        language: impl Into<String>,
        contents: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            version: ANALYSIS_CACHE_KEY_VERSION.to_string(),
            language: language.into(),
            path: path.into(),
            content_digest: stable_digest(contents.as_ref()),
        }
    }

    #[must_use]
    pub fn key(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.version.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.language.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.path.to_string_lossy().as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(self.content_digest.as_bytes());
        let digest = stable_digest(&bytes);
        format!("{}-{}", self.version, digest.trim_start_matches("fnv64:"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteGraph {
    pub routes: Vec<RouteFact>,
    pub routes_by_symbol: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Default)]
pub struct RouteGraphBuilder;

impl RouteGraphBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn build(&self, facts: &AnalysisFacts) -> RouteGraph {
        let mut routes_by_symbol: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for route in &facts.routes {
            if let Some(symbol_id) = &route.symbol_id {
                routes_by_symbol
                    .entry(symbol_id.clone())
                    .or_default()
                    .push(route.id.clone());
            }
        }
        RouteGraph {
            routes: facts.routes.clone(),
            routes_by_symbol,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaintAnalysis {
    pub edges: Vec<TaintEdge>,
    pub sink_ids: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TaintEngine;

impl TaintEngine {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn analyze(&self, facts: &AnalysisFacts) -> TaintAnalysis {
        TaintAnalysis {
            edges: facts.taint_edges.clone(),
            sink_ids: facts.sinks.iter().map(|sink| sink.id.clone()).collect(),
        }
    }
}

#[must_use]
pub fn empty_facts_for_project(project: &ProjectGraph) -> AnalysisFacts {
    let mut facts = AnalysisFacts::empty();
    facts.source_files = project
        .inventory
        .files
        .iter()
        .filter_map(|path| source_file_fact_for_path(project, path))
        .collect();
    facts
}

fn source_file_fact_for_path(project: &ProjectGraph, path: &Path) -> Option<SourceFileFact> {
    let language = language_for_path(path)?;
    let mut fact = SourceFileFact::new(path.to_path_buf(), language);
    fact.service_id = service_id_for_path(project, path);
    Some(fact)
}

fn service_id_for_path(project: &ProjectGraph, path: &Path) -> Option<String> {
    project
        .services
        .iter()
        .filter(|service| path.starts_with(&service.path) || service.path == Path::new("."))
        .max_by_key(|service| service.path.components().count())
        .map(|service| service.id.clone())
}

fn language_for_path(path: &Path) -> Option<String> {
    let extension = path.extension().and_then(|value| value.to_str())?;
    let language = match extension {
        "go" => "Go",
        "java" => "Java",
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => "Node/TypeScript",
        "py" => "Python",
        "cs" => "C#",
        "php" => "PHP",
        "rs" => "Rust",
        "rb" => "Ruby",
        "kt" | "kts" => "Kotlin",
        "scala" => "Scala",
        "ex" | "exs" => "Elixir",
        "c" | "h" => "C",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => "C++",
        _ => return None,
    };
    Some(language.to_string())
}

#[derive(Default)]
pub struct EmptySourceAdapter {
    id: &'static str,
    language: &'static str,
}

impl EmptySourceAdapter {
    #[must_use]
    pub fn new(id: &'static str, language: &'static str) -> Self {
        Self { id, language }
    }
}

impl SourceAdapter for EmptySourceAdapter {
    fn id(&self) -> &'static str {
        self.id
    }

    fn language(&self) -> &'static str {
        self.language
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let mut facts = AnalysisFacts::empty();
        facts.source_files.push(input.source_file.clone());
        Ok(facts)
    }
}

#[must_use]
pub fn merge_analysis_facts(parts: impl IntoIterator<Item = AnalysisFacts>) -> AnalysisFacts {
    let mut merged = AnalysisFacts::empty();
    for mut part in parts {
        merged.source_files.append(&mut part.source_files);
        merged.symbols.append(&mut part.symbols);
        merged.calls.append(&mut part.calls);
        merged.imports.append(&mut part.imports);
        merged.routes.append(&mut part.routes);
        merged.data_sources.append(&mut part.data_sources);
        merged.sinks.append(&mut part.sinks);
        merged.sanitizers.append(&mut part.sanitizers);
        merged.api_specs.append(&mut part.api_specs);
        merged
            .deployment_exposures
            .append(&mut part.deployment_exposures);
        merged.taint_edges.append(&mut part.taint_edges);
        merged.metadata.append(&mut part.metadata);
    }
    merged
}

#[allow(dead_code)]
fn _assert_fact_exports(_: CallFact, _: ImportFact, _: SinkFact) {}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{
        DataSourceFact, DetectionDebug, DiffInventory, FileInventory, InfraInventory, RouteFact,
        Service, SourceRange, SymbolFact, SymbolKind, TaintEdgeKind,
    };
    use std::collections::BTreeMap;

    fn project_with_files(files: Vec<&str>) -> ProjectGraph {
        ProjectGraph {
            root: PathBuf::from("."),
            git_root: None,
            workspace_root: PathBuf::from("."),
            monorepo: false,
            services: vec![Service {
                id: "api".to_string(),
                path: PathBuf::from("."),
                languages: vec!["Rust".to_string()],
                frameworks: Vec::new(),
                metadata: BTreeMap::new(),
            }],
            languages: Vec::new(),
            inventory: FileInventory {
                total_files: files.len(),
                source_files: files.len(),
                manifest_files: 0,
                infra_files: 0,
                test_files: 0,
                skipped_binary_files: 0,
                skipped_large_files: 0,
                files: files.into_iter().map(PathBuf::from).collect(),
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
                root: PathBuf::from("."),
                git_root: None,
                workspace_root: PathBuf::from("."),
                ignored_patterns: Vec::new(),
                warnings: Vec::new(),
                decisions: Vec::new(),
            },
        }
    }

    #[test]
    fn empty_generation_keeps_only_source_file_facts() {
        let project = project_with_files(vec!["src/main.rs", "README.md"]);
        let facts = empty_facts_for_project(&project);

        assert_eq!(facts.source_files.len(), 1);
        assert_eq!(facts.source_files[0].language, "Rust");
        assert_eq!(facts.source_files[0].service_id.as_deref(), Some("api"));
        assert!(facts.symbols.is_empty());
        assert!(facts.routes.is_empty());
    }

    #[test]
    fn cache_key_is_content_sensitive_and_stable() {
        let left = AnalysisCacheKey::for_content("src/main.rs", "Rust", "fn main() {}");
        let same = AnalysisCacheKey::for_content("src/main.rs", "Rust", "fn main() {}");
        let right = AnalysisCacheKey::for_content("src/main.rs", "Rust", "fn other() {}");

        assert_eq!(left.key(), same.key());
        assert_ne!(left.key(), right.key());
        assert!(left.key().starts_with("bda1-"));
    }

    #[test]
    fn parser_registry_uses_matching_adapter_only() {
        let project = project_with_files(vec!["src/main.rs"]);
        let facts = empty_facts_for_project(&project);
        let source_file = facts.source_files.first().expect("source file");
        let mut registry = ParserRegistry::new();
        registry.register(EmptySourceAdapter::new("rust-empty", "Rust"));

        let result = registry
            .analyze_file(AdapterInput {
                project: &project,
                source_file,
                contents: "",
            })
            .expect("adapter runs");

        assert_eq!(
            registry.languages(),
            vec!["Rust"],
            "registered language is exposed"
        );
        assert_eq!(
            result.expect("facts returned").source_files,
            vec![source_file.clone()]
        );
    }

    #[test]
    #[should_panic(expected = "adapter already registered for language Rust")]
    fn parser_registry_rejects_duplicate_language_registration() {
        let mut registry = ParserRegistry::new();
        registry.register(EmptySourceAdapter::new("rust-empty", "Rust"));
        registry.register(EmptySourceAdapter::new("rust-empty-two", "Rust"));
    }

    struct FlexibleNodeAdapter;

    impl SourceAdapter for FlexibleNodeAdapter {
        fn id(&self) -> &'static str {
            "flexible-node"
        }

        fn language(&self) -> &'static str {
            "Node/TypeScript"
        }

        fn supports(&self, source_file: &SourceFileFact) -> bool {
            matches!(
                source_file.language.as_str(),
                "JavaScript" | "Node/TypeScript"
            )
        }

        fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
            let mut facts = AnalysisFacts::empty();
            facts.source_files.push(input.source_file.clone());
            Ok(facts)
        }
    }

    #[test]
    fn parser_registry_uses_supports_beyond_exact_language_lookup() {
        let project = project_with_files(vec!["src/app.js"]);
        let source_file = SourceFileFact::new("src/app.js", "JavaScript");
        let mut registry = ParserRegistry::new();
        registry.register(FlexibleNodeAdapter);

        let result = registry
            .analyze_file(AdapterInput {
                project: &project,
                source_file: &source_file,
                contents: "",
            })
            .expect("adapter runs");

        assert_eq!(
            result.expect("facts returned").source_files,
            vec![source_file]
        );
    }

    #[test]
    fn default_registry_exposes_production_adapters() {
        let registry = default_parser_registry();

        assert_eq!(
            registry.languages(),
            vec![
                "C",
                "C#",
                "C++",
                "Elixir",
                "Go",
                "Java",
                "Kotlin",
                "Node/TypeScript",
                "PHP",
                "Python",
                "Ruby",
                "Rust",
                "Scala"
            ],
            "analysis registry is deterministic"
        );
    }

    #[test]
    fn tier_a_registry_name_remains_compatible_alias() {
        assert_eq!(
            tier_a_parser_registry().languages(),
            default_parser_registry().languages()
        );
    }

    #[test]
    fn analyze_sources_runs_registered_adapters_and_merges_facts() {
        let project = project_with_files(vec![
            "cmd/api/main.go",
            "src/app.ts",
            "src/App.java",
            "app/main.py",
            "src/Program.cs",
            "routes/web.php",
            "src/main.rs",
        ]);
        let mut go_file = SourceFileFact::new("cmd/api/main.go", "Go");
        go_file.service_id = Some("api".to_string());
        let mut node_file = SourceFileFact::new("src/app.ts", "Node/TypeScript");
        node_file.service_id = Some("api".to_string());
        let mut java_file = SourceFileFact::new("src/App.java", "Java");
        java_file.service_id = Some("api".to_string());
        let mut python_file = SourceFileFact::new("app/main.py", "Python");
        python_file.service_id = Some("api".to_string());
        let mut csharp_file = SourceFileFact::new("src/Program.cs", "C#");
        csharp_file.service_id = Some("api".to_string());
        let mut php_file = SourceFileFact::new("routes/web.php", "PHP");
        php_file.service_id = Some("api".to_string());
        let mut rust_file = SourceFileFact::new("src/main.rs", "Rust");
        rust_file.service_id = Some("api".to_string());

        let go_source = r#"package main
import "net/http"
func health(w http.ResponseWriter, r *http.Request) {}
func main() { http.HandleFunc("/health", health) }
"#;
        let node_source = r#"import express from 'express';
const app = express();
function health(req, res) { res.send('ok'); }
app.get('/health', health);
"#;
        let java_source = r#"import org.springframework.web.bind.annotation.*;
@RestController
class App {
  @GetMapping("/health")
  String health() { return "ok"; }
}
"#;
        let python_source = r#"from fastapi import FastAPI
app = FastAPI()
@app.get("/health")
def health(): return {"ok": True}
"#;
        let csharp_source = r#"var app = builder.Build();
app.MapGet("/health", () => "ok");
"#;
        let php_source = r#"<?php
use Illuminate\Support\Facades\Route;
Route::get('/health', function () { return 'ok'; });
"#;
        let rust_source = r#"use axum::{routing::get, Router};
async fn health() -> &'static str { "ok" }
fn app() -> Router { Router::new().route("/health", get(health)) }
"#;

        let facts = analyze_sources(
            &project,
            [
                (&go_file, go_source),
                (&node_file, node_source),
                (&java_file, java_source),
                (&python_file, python_source),
                (&csharp_file, csharp_source),
                (&php_file, php_source),
                (&rust_file, rust_source),
            ],
        )
        .expect("analysis succeeds");

        assert_eq!(facts.source_files.len(), 7);
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("net/http")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Express")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Spring")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("FastAPI")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("ASP.NET Core")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Laravel")));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Axum")));
        assert!(
            facts.routes.len() >= 7,
            "all registered adapters contribute route facts"
        );
    }

    #[test]
    fn route_graph_indexes_routes_by_symbol() {
        let mut facts = AnalysisFacts::empty();
        facts.routes.push(RouteFact {
            id: "route:1".to_string(),
            file_id: Some("file:1".to_string()),
            symbol_id: Some("symbol:handler".to_string()),
            service_id: Some("api".to_string()),
            method: "GET".to_string(),
            path: "/health".to_string(),
            framework: Some("axum".to_string()),
            range: SourceRange::single_line(1, 1, 20),
            metadata: BTreeMap::new(),
        });

        let graph = RouteGraphBuilder::new().build(&facts);

        assert_eq!(graph.routes.len(), 1);
        assert_eq!(
            graph.routes_by_symbol.get("symbol:handler"),
            Some(&vec!["route:1".to_string()])
        );
    }

    #[test]
    fn taint_engine_exposes_existing_edges_and_sinks_without_inference() {
        let mut facts = AnalysisFacts::empty();
        facts.symbols.push(SymbolFact {
            id: "symbol:handler".to_string(),
            file_id: "file:1".to_string(),
            name: "handler".to_string(),
            kind: SymbolKind::Function,
            range: None,
            signature: None,
            visibility: None,
            parent_symbol_id: None,
            metadata: BTreeMap::new(),
        });
        facts.data_sources.push(DataSourceFact {
            id: "source:req".to_string(),
            file_id: Some("file:1".to_string()),
            symbol_id: Some("symbol:handler".to_string()),
            kind: backend_doctor_core::DataSourceKind::Request,
            name: Some("request".to_string()),
            endpoint: None,
            range: None,
            metadata: BTreeMap::new(),
        });
        facts.sinks.push(SinkFact {
            id: "sink:sql".to_string(),
            file_id: Some("file:1".to_string()),
            symbol_id: Some("symbol:handler".to_string()),
            kind: backend_doctor_core::SinkKind::SqlQuery,
            name: Some("query".to_string()),
            range: None,
            metadata: BTreeMap::new(),
        });
        facts.taint_edges.push(TaintEdge {
            id: "edge:1".to_string(),
            source_id: "source:req".to_string(),
            target_id: "sink:sql".to_string(),
            sanitizer_id: None,
            kind: TaintEdgeKind::SourceToSink,
            confidence: backend_doctor_core::Confidence::Low,
            metadata: BTreeMap::new(),
        });

        let analysis = TaintEngine::new().analyze(&facts);

        assert_eq!(analysis.edges, facts.taint_edges);
        assert_eq!(analysis.sink_ids, vec!["sink:sql"]);
    }

    #[test]
    fn cache_key_serializes_with_camel_case_contract() {
        let key = AnalysisCacheKey::for_content("src/main.rs", "Rust", "fn main() {}");
        let json = serde_json::to_value(key).expect("cache key serializes");

        assert_eq!(json["version"], ANALYSIS_CACHE_KEY_VERSION);
        assert!(json.get("contentDigest").is_some());
        assert!(json.get("content_digest").is_none());
    }
}
