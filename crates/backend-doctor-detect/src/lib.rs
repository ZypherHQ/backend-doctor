pub use backend_doctor_core::ProjectGraph;
use backend_doctor_core::{
    DetectedLanguage, DetectionConfidence, DetectionDebug, DiffInventory, FileInventory,
    InfraInventory, Service,
};
use ignore::{DirEntry, WalkBuilder};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAX_TEXT_FILE_BYTES: u64 = 1024 * 1024;
const DEFAULT_IGNORES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    "build",
    "dist",
    ".next",
    "coverage",
    "vendor",
    ".terraform",
];

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DetectionOptions {
    pub diff_base: Option<String>,
    pub include_gitignored: bool,
}

#[must_use]
pub fn detect_project(root: impl AsRef<Path>) -> ProjectGraph {
    detect_project_with_options(root, DetectionOptions::default())
}

#[must_use]
pub fn detect_project_with_options(
    root: impl AsRef<Path>,
    options: DetectionOptions,
) -> ProjectGraph {
    let scan_root = normalize_root(root.as_ref());
    let git_root = git_root_for(&scan_root);
    let workspace_root = workspace_root_for(&scan_root, git_root.as_deref());
    let mut debug = DetectionDebug {
        root: scan_root.clone(),
        git_root: git_root.clone(),
        workspace_root: workspace_root.clone(),
        ignored_patterns: DEFAULT_IGNORES
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        warnings: Vec::new(),
        decisions: Vec::new(),
    };
    debug
        .decisions
        .push(format!("scan root {}", scan_root.display()));
    if options.include_gitignored {
        debug
            .decisions
            .push("gitignore filters disabled by include_gitignored".to_string());
    }

    let inventory = build_inventory(&scan_root, options.include_gitignored, &mut debug);
    let infra = detect_infra(&scan_root, &inventory.files);
    let languages = detect_languages(&scan_root, &inventory.files);
    let mut services = discover_services(&scan_root, &inventory.files);
    if services.is_empty() && !languages.is_empty() {
        services.push(build_service(&scan_root, &scan_root, &inventory.files));
    }
    services.sort_by(|left, right| left.id.cmp(&right.id));
    services.dedup_by(|left, right| left.path == right.path);
    let monorepo = services.len() > 1 || has_monorepo_marker(&inventory.files);
    let diff = build_diff(&scan_root, options.diff_base, &services, &mut debug);

    debug.decisions.push(format!(
        "inventory files={} source={} manifests={} infra={}",
        inventory.total_files,
        inventory.source_files,
        inventory.manifest_files,
        inventory.infra_files
    ));
    debug
        .decisions
        .push(format!("services detected={}", services.len()));
    debug
        .decisions
        .push(format!("languages detected={}", languages.len()));
    debug
        .decisions
        .push(format!("infra detected={}", !infra.is_empty()));

    ProjectGraph {
        root: scan_root,
        git_root,
        workspace_root,
        monorepo,
        services,
        languages,
        inventory,
        infra,
        diff,
        debug,
    }
}

fn normalize_root(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn git_root_for(root: &Path) -> Option<PathBuf> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn workspace_root_for(scan_root: &Path, git_root: Option<&Path>) -> PathBuf {
    if has_workspace_marker(scan_root) {
        return scan_root.to_path_buf();
    }
    for ancestor in scan_root.ancestors().skip(1) {
        if Some(ancestor) == git_root || has_workspace_marker(ancestor) {
            return ancestor.to_path_buf();
        }
    }
    git_root.unwrap_or(scan_root).to_path_buf()
}

fn has_workspace_marker(path: &Path) -> bool {
    [
        "go.work",
        "pnpm-workspace.yaml",
        "package.json",
        "pom.xml",
        "settings.gradle",
        "settings.gradle.kts",
        "Gemfile",
        "build.sbt",
        "mix.exs",
        "CMakeLists.txt",
    ]
    .iter()
    .any(|name| path.join(name).is_file())
}

fn build_inventory(
    root: &Path,
    include_gitignored: bool,
    debug: &mut DetectionDebug,
) -> FileInventory {
    let mut files = Vec::new();
    let mut skipped_binary_files = 0;
    let mut skipped_large_files = 0;
    let mut walker = WalkBuilder::new(root);
    walker
        .hidden(false)
        .git_ignore(!include_gitignored)
        .git_global(!include_gitignored)
        .git_exclude(!include_gitignored)
        .filter_entry(|entry| !is_default_ignored(entry));

    for result in walker.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                debug
                    .warnings
                    .push(format!("inventory walk warning: {error}"));
                continue;
            }
        };
        if !entry
            .file_type()
            .map(|file_type| file_type.is_file())
            .unwrap_or(false)
        {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_TEXT_FILE_BYTES {
            skipped_large_files += 1;
            continue;
        }
        let path = entry.path().to_path_buf();
        if looks_binary(&path) {
            skipped_binary_files += 1;
            continue;
        }
        files.push(relative_to(root, &path));
    }
    files.sort();

    FileInventory {
        total_files: files.len(),
        source_files: files.iter().filter(|path| is_source_file(path)).count(),
        manifest_files: files.iter().filter(|path| is_manifest(path)).count(),
        infra_files: files.iter().filter(|path| is_infra_file(path)).count(),
        test_files: files.iter().filter(|path| is_test_file(path)).count(),
        skipped_binary_files,
        skipped_large_files,
        files,
    }
}

fn is_default_ignored(entry: &DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    DEFAULT_IGNORES.iter().any(|ignored| name == *ignored)
}

fn looks_binary(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

fn relative_to(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root).unwrap_or(path).to_path_buf()
}

fn detect_languages(root: &Path, files: &[PathBuf]) -> Vec<DetectedLanguage> {
    let mut evidence: BTreeMap<&'static str, BTreeSet<PathBuf>> = BTreeMap::new();
    for file in files {
        let name = file_name(file);
        let ext = extension(file);
        match name.as_str() {
            "go.mod" | "go.work" => add_evidence(&mut evidence, "Go", file),
            "pom.xml" | "build.gradle" | "build.gradle.kts" | "settings.gradle" => {
                add_evidence(&mut evidence, "Java", file);
            }
            "package.json" | "pnpm-lock.yaml" | "yarn.lock" | "package-lock.json" | "bun.lockb"
            | "bun.lock" => add_evidence(&mut evidence, "Node/TypeScript", file),
            "pyproject.toml" | "requirements.txt" | "Pipfile" => {
                add_evidence(&mut evidence, "Python", file);
            }
            "Gemfile" | "gemspec" => add_evidence(&mut evidence, "Ruby", file),
            "composer.json" | "composer.lock" => add_evidence(&mut evidence, "PHP", file),
            "Cargo.toml" | "Cargo.lock" => add_evidence(&mut evidence, "Rust", file),
            "global.json" => add_evidence(&mut evidence, "C#", file),
            "deps.edn" => add_evidence(&mut evidence, "Clojure", file),
            "mix.exs" | "mix.lock" => add_evidence(&mut evidence, "Elixir", file),
            "build.sbt" => add_evidence(&mut evidence, "Scala", file),
            "Makefile" | "CMakeLists.txt" => {
                add_evidence(&mut evidence, "C", file);
                add_evidence(&mut evidence, "C++", file);
            }
            _ => {}
        }
        match ext.as_str() {
            "go" => add_evidence(&mut evidence, "Go", file),
            "java" => add_evidence(&mut evidence, "Java", file),
            "kt" | "kts" => add_evidence(&mut evidence, "Kotlin", file),
            "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => {
                add_evidence(&mut evidence, "Node/TypeScript", file);
            }
            "py" => add_evidence(&mut evidence, "Python", file),
            "rb" => add_evidence(&mut evidence, "Ruby", file),
            "php" => add_evidence(&mut evidence, "PHP", file),
            "cs" | "csproj" | "sln" => add_evidence(&mut evidence, "C#", file),
            "rs" => add_evidence(&mut evidence, "Rust", file),
            "clj" | "cljs" | "cljc" => add_evidence(&mut evidence, "Clojure", file),
            "scala" | "sc" => add_evidence(&mut evidence, "Scala", file),
            "ex" | "exs" => add_evidence(&mut evidence, "Elixir", file),
            "c" => add_evidence(&mut evidence, "C", file),
            "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => {
                add_evidence(&mut evidence, "C++", file);
            }
            _ => {}
        }
        if let Some(text) = read_small(root, file) {
            if text.contains("github.com/gin-gonic/gin") {
                add_evidence(&mut evidence, "Go", file);
            }
            if text.contains("org.springframework.boot") || text.contains("@SpringBootApplication")
            {
                add_evidence(&mut evidence, "Java", file);
            }
        }
    }
    evidence
        .into_iter()
        .map(|(name, paths)| {
            let confidence = if paths.iter().any(|path| is_manifest(path)) {
                DetectionConfidence::High
            } else if paths.len() > 1 {
                DetectionConfidence::Medium
            } else {
                DetectionConfidence::Low
            };
            DetectedLanguage {
                name: name.to_string(),
                confidence,
                evidence: paths.into_iter().collect(),
            }
        })
        .collect()
}

fn add_evidence(
    evidence: &mut BTreeMap<&'static str, BTreeSet<PathBuf>>,
    language: &'static str,
    file: &Path,
) {
    evidence
        .entry(language)
        .or_default()
        .insert(file.to_path_buf());
}

fn discover_services(root: &Path, files: &[PathBuf]) -> Vec<Service> {
    let mut roots = BTreeSet::new();
    for file in files {
        if is_service_manifest(file) {
            roots.insert(file.parent().unwrap_or(Path::new("")).to_path_buf());
        }
        if let Some(first) = file.components().next() {
            let first = first.as_os_str().to_string_lossy();
            if matches!(first.as_ref(), "services" | "apps" | "packages") {
                let mut components = file.components();
                let base = components.next();
                let name = components.next();
                if let (Some(base), Some(name)) = (base, name) {
                    roots.insert(PathBuf::from(base.as_os_str()).join(name.as_os_str()));
                }
            }
        }
    }
    roots
        .into_iter()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|relative| build_service(root, &root.join(&relative), files))
        .collect()
}

fn build_service(root: &Path, absolute_path: &Path, all_files: &[PathBuf]) -> Service {
    let relative = relative_to(root, absolute_path);
    let service_files: Vec<PathBuf> = all_files
        .iter()
        .filter(|file| relative.as_os_str().is_empty() || file.starts_with(&relative))
        .cloned()
        .collect();
    let languages = detect_languages(root, &service_files)
        .into_iter()
        .map(|language| language.name)
        .collect();
    let frameworks = detect_frameworks(root, &service_files);
    let mut metadata = BTreeMap::new();
    let layers = detect_layers(&service_files);
    if !layers.is_empty() {
        metadata.insert("layers".to_string(), layers.join(","));
    }
    if service_files.iter().any(|file| is_test_file(file)) {
        metadata.insert("testCoverage".to_string(), "present".to_string());
    }
    if let Some(package_manager) = detect_package_manager(root, &relative, &service_files) {
        metadata.insert("packageManager".to_string(), package_manager);
    }
    let id = if relative.as_os_str().is_empty() {
        ".".to_string()
    } else {
        relative.to_string_lossy().replace('\\', "/")
    };
    Service {
        id,
        path: absolute_path.to_path_buf(),
        languages,
        frameworks,
        metadata,
    }
}

fn detect_frameworks(root: &Path, files: &[PathBuf]) -> Vec<String> {
    let mut frameworks = BTreeSet::new();
    for file in files {
        let name = file_name(file);
        let text = read_small(root, file).unwrap_or_default();
        if file.extension() == Some(OsStr::new("go")) || name == "go.mod" {
            detect_by_needles(
                &text,
                &mut frameworks,
                &[
                    ("github.com/gin-gonic/gin", "Gin"),
                    ("github.com/labstack/echo", "Echo"),
                    ("github.com/gofiber/fiber", "Fiber"),
                    ("github.com/gofiber/fiber/v2", "Fiber"),
                    ("github.com/go-chi/chi", "Chi"),
                    ("google.golang.org/grpc", "gRPC"),
                ],
            );
        }
        if matches!(
            name.as_str(),
            "pom.xml" | "build.gradle" | "build.gradle.kts"
        ) || file.extension() == Some(OsStr::new("java"))
        {
            detect_by_needles(
                &text,
                &mut frameworks,
                &[
                    ("spring-boot", "Spring Boot"),
                    ("@SpringBootApplication", "Spring Boot"),
                    ("quarkus", "Quarkus"),
                    ("micronaut", "Micronaut"),
                ],
            );
        }
        if name == "package.json" || matches!(extension(file).as_str(), "js" | "ts" | "tsx") {
            detect_by_needles(
                &text,
                &mut frameworks,
                &[
                    ("express", "Express"),
                    ("fastify", "Fastify"),
                    ("@nestjs/core", "NestJS"),
                    ("@nestjs/common", "NestJS"),
                    ("@nestjs/platform-express", "NestJS"),
                    ("@nestjs/platform-fastify", "NestJS"),
                    ("@Controller(", "NestJS"),
                    ("@Module(", "NestJS"),
                    ("NestFactory", "NestJS"),
                ],
            );
        }
    }
    frameworks.into_iter().map(str::to_string).collect()
}

fn detect_by_needles(
    text: &str,
    frameworks: &mut BTreeSet<&'static str>,
    needles: &[(&str, &'static str)],
) {
    for (needle, framework) in needles {
        if text.contains(needle) {
            frameworks.insert(*framework);
        }
    }
}

fn detect_package_manager(root: &Path, service_root: &Path, files: &[PathBuf]) -> Option<String> {
    let mut managers = BTreeSet::new();
    for file in files {
        if file.parent().unwrap_or(Path::new("")) != service_root {
            continue;
        }
        match file_name(file).as_str() {
            "package-lock.json" => {
                managers.insert("npm");
            }
            "pnpm-lock.yaml" => {
                managers.insert("pnpm");
            }
            "yarn.lock" => {
                managers.insert("yarn");
            }
            "bun.lockb" | "bun.lock" => {
                managers.insert("bun");
            }
            _ => {}
        }
    }
    if let Some(package_json) = files.iter().find(|file| {
        file.parent().unwrap_or(Path::new("")) == service_root && file_name(file) == "package.json"
    }) {
        if let Some(manager) = read_small(root, package_json).and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|value| value.get("packageManager")?.as_str().map(str::to_string))
        }) {
            if let Some((name, _)) = manager.split_once('@') {
                return Some(name.to_string());
            }
            return Some(manager);
        }
    }
    if managers.len() == 1 {
        managers.first().map(|manager| (*manager).to_string())
    } else {
        None
    }
}

fn detect_layers(files: &[PathBuf]) -> Vec<String> {
    let mut layers = BTreeSet::new();
    for file in files {
        let normalized = file.to_string_lossy();
        for layer in [
            "controller",
            "handler",
            "route",
            "service",
            "repository",
            "model",
            "migration",
        ] {
            if normalized.to_ascii_lowercase().contains(layer) {
                layers.insert(layer.to_string());
            }
        }
    }
    layers.into_iter().collect()
}

fn detect_infra(_root: &Path, files: &[PathBuf]) -> InfraInventory {
    let mut infra = InfraInventory::default();
    for file in files {
        let name = file_name(file);
        let normalized = file.to_string_lossy().replace('\\', "/");
        if name == "Dockerfile" || name.ends_with(".Dockerfile") {
            infra.dockerfiles.push(file.clone());
        }
        if matches!(
            name.as_str(),
            "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
        ) {
            infra.compose_files.push(file.clone());
        }
        if matches!(extension(file).as_str(), "yaml" | "yml")
            && (normalized.starts_with("k8s/")
                || normalized.contains("/k8s/")
                || normalized.contains("/kubernetes/")
                || name.contains("deployment")
                || name.contains("service")
                || name.contains("configmap")
                || name.contains("ingress"))
        {
            infra.kubernetes_files.push(file.clone());
        }
        if name == "Chart.yaml" {
            infra.helm_charts.push(file.clone());
        }
        if matches!(extension(file).as_str(), "tf" | "tfvars") {
            infra.terraform_files.push(file.clone());
        }
        if normalized.starts_with(".github/workflows/") {
            infra.github_actions.push(file.clone());
        }
        if name == ".gitlab-ci.yml" || name == ".gitlab-ci.yaml" {
            infra.gitlab_ci.push(file.clone());
        }
        if is_open_api_spec(file) {
            infra.open_api_specs.push(file.clone());
        }
        if is_migration_file(file) {
            infra.migration_files.push(file.clone());
        }
    }
    infra
}

fn build_diff(
    root: &Path,
    base: Option<String>,
    services: &[Service],
    debug: &mut DetectionDebug,
) -> DiffInventory {
    let Some(base_ref) = base else {
        return DiffInventory {
            enabled: false,
            base: None,
            fallback_full_scan: false,
            changed_files: Vec::new(),
            impacted_files: Vec::new(),
        };
    };
    let mut diff = DiffInventory {
        enabled: true,
        base: Some(base_ref.clone()),
        fallback_full_scan: false,
        changed_files: Vec::new(),
        impacted_files: Vec::new(),
    };
    match Command::new("git")
        .args(["diff", "--name-only", &format!("{base_ref}...HEAD")])
        .current_dir(root)
        .output()
    {
        Ok(output) if output.status.success() => {
            diff.changed_files = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(PathBuf::from)
                .collect();
            diff.changed_files.sort();
            diff.impacted_files = impacted_project_files(&diff.changed_files, services);
            debug
                .decisions
                .push(format!("diff changed files={}", diff.changed_files.len()));
        }
        Ok(output) => {
            diff.fallback_full_scan = true;
            debug.warnings.push(format!(
                "git diff failed; falling back to full scan: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Err(error) => {
            diff.fallback_full_scan = true;
            debug.warnings.push(format!(
                "git diff unavailable; falling back to full scan: {error}"
            ));
        }
    }
    diff
}

fn impacted_project_files(changed_files: &[PathBuf], services: &[Service]) -> Vec<PathBuf> {
    let mut impacted = BTreeSet::new();
    for changed in changed_files {
        impacted.insert(changed.clone());
        for service in services {
            if changed.starts_with(&service.id) {
                for manifest in [
                    "go.mod",
                    "pom.xml",
                    "build.gradle",
                    "build.gradle.kts",
                    "package.json",
                ] {
                    impacted.insert(PathBuf::from(&service.id).join(manifest));
                }
            }
        }
    }
    impacted.into_iter().collect()
}

fn has_monorepo_marker(files: &[PathBuf]) -> bool {
    files.iter().any(|file| {
        matches!(
            file_name(file).as_str(),
            "go.work"
                | "pnpm-workspace.yaml"
                | "package-lock.json"
                | "yarn.lock"
                | "bun.lockb"
                | "bun.lock"
        ) || file.to_string_lossy().starts_with("services/")
            || file.to_string_lossy().starts_with("apps/")
            || file.to_string_lossy().starts_with("packages/")
    })
}

fn is_service_manifest(path: &Path) -> bool {
    matches!(
        file_name(path).as_str(),
        "go.mod"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "package.json"
            | "Gemfile"
            | "global.json"
            | "deps.edn"
            | "build.sbt"
            | "mix.exs"
            | "CMakeLists.txt"
    ) || matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("csproj" | "sln")
    )
}

fn is_manifest(path: &Path) -> bool {
    is_service_manifest(path)
        || matches!(
            file_name(path).as_str(),
            "go.work"
                | "pnpm-workspace.yaml"
                | "package-lock.json"
                | "yarn.lock"
                | "bun.lockb"
                | "bun.lock"
                | "pyproject.toml"
                | "requirements.txt"
                | "Pipfile"
                | "Gemfile"
                | "composer.json"
                | "composer.lock"
                | "global.json"
                | "deps.edn"
                | "Cargo.toml"
                | "Cargo.lock"
                | "mix.exs"
                | "mix.lock"
                | "build.sbt"
                | "CMakeLists.txt"
        )
}

fn is_source_file(path: &Path) -> bool {
    matches!(
        extension(path).as_str(),
        "go" | "java"
            | "kt"
            | "kts"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "mjs"
            | "cjs"
            | "py"
            | "rb"
            | "php"
            | "cs"
            | "csproj"
            | "sln"
            | "rs"
            | "clj"
            | "cljs"
            | "cljc"
            | "scala"
            | "sc"
            | "ex"
            | "exs"
            | "c"
            | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "hxx"
    )
}

fn is_infra_file(path: &Path) -> bool {
    let name = file_name(path);
    name == "Dockerfile"
        || name.ends_with(".Dockerfile")
        || matches!(
            name.as_str(),
            "docker-compose.yml"
                | "docker-compose.yaml"
                | "compose.yml"
                | "compose.yaml"
                | "Chart.yaml"
                | ".gitlab-ci.yml"
                | ".gitlab-ci.yaml"
        )
        || matches!(extension(path).as_str(), "tf" | "tfvars" | "yaml" | "yml")
        || is_open_api_spec(path)
        || is_migration_file(path)
}

fn is_open_api_spec(path: &Path) -> bool {
    let name = file_name(path).to_ascii_lowercase();
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "openapi.yaml"
            | "openapi.yml"
            | "openapi.json"
            | "swagger.yaml"
            | "swagger.yml"
            | "swagger.json"
    ) || matches!(
        normalized.as_str(),
        "api/openapi.yaml"
            | "api/openapi.yml"
            | "api/openapi.json"
            | "api/swagger.yaml"
            | "api/swagger.yml"
            | "api/swagger.json"
    )
}

fn is_migration_file(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let in_migration_dir =
        normalized.starts_with("db/migrations/") || normalized.starts_with("migrations/");
    in_migration_dir && path.file_name().is_some()
}

fn is_test_file(path: &Path) -> bool {
    let text = path.to_string_lossy().to_ascii_lowercase();
    text.contains("/test/")
        || text.contains("/tests/")
        || text.ends_with("_test.go")
        || text.ends_with("test.java")
}

fn read_small(root: &Path, relative: &Path) -> Option<String> {
    let absolute = root.join(relative);
    let metadata = fs::metadata(&absolute).ok()?;
    if metadata.len() > MAX_TEXT_FILE_BYTES {
        return None;
    }
    fs::read_to_string(absolute).ok()
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn extension(path: &Path) -> String {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn empty_fixture_has_empty_graph() {
        let graph = detect_project(fixture_path("empty"));
        assert_eq!(graph.services.len(), 0);
        assert!(!graph.monorepo);
    }

    #[test]
    fn polyglot_fixture_detects_services_languages_frameworks_and_infra() {
        let graph = detect_project(fixture_path("polyglot-monorepo"));

        assert!(graph.monorepo);
        assert_eq!(graph.services.len(), 3);
        assert!(graph
            .services
            .iter()
            .any(|service| { service.id == "services/go-api" && service.frameworks == ["Gin"] }));
        assert!(graph.services.iter().any(|service| {
            service.id == "services/java-api" && service.frameworks == ["Spring Boot"]
        }));
        assert!(graph
            .services
            .iter()
            .any(|service| { service.id == "apps/node-api" && service.frameworks == ["Express"] }));
        assert!(graph
            .languages
            .iter()
            .any(|language| language.name == "Go"
                && language.confidence == DetectionConfidence::High));
        assert_eq!(graph.infra.dockerfiles, [PathBuf::from("Dockerfile")]);
        assert_eq!(
            graph.infra.github_actions,
            [PathBuf::from(".github/workflows/ci.yml")]
        );
        assert_eq!(graph.infra.gitlab_ci, [PathBuf::from(".gitlab-ci.yml")]);
        assert_eq!(
            graph.infra.open_api_specs,
            [PathBuf::from("api/openapi.yaml")]
        );
        assert_eq!(
            graph.infra.migration_files,
            [PathBuf::from("db/migrations/001_init.sql")]
        );
        assert!(!graph
            .inventory
            .files
            .iter()
            .any(|path| path.starts_with("ignored-dir")));
    }

    #[test]
    fn unsupported_language_fixture_detects_python() {
        let graph = detect_project(fixture_path("unsupported-language-bad-service"));

        assert!(graph.languages.iter().any(|language| {
            language.name == "Python" && language.confidence == DetectionConfidence::High
        }));
        assert!(graph.inventory.source_files >= 1);
        assert_eq!(graph.infra.dockerfiles, [PathBuf::from("Dockerfile")]);
    }

    #[test]
    fn tier3_fixtures_detect_language_specific_services() {
        for (fixture, language) in [
            ("ruby-bad-service", "Ruby"),
            ("kotlin-bad-service", "Kotlin"),
            ("scala-bad-service", "Scala"),
            ("elixir-bad-service", "Elixir"),
            ("c-bad-service", "C"),
            ("cpp-bad-service", "C++"),
        ] {
            let graph = detect_project(fixture_path(fixture));
            assert!(
                graph
                    .languages
                    .iter()
                    .any(|candidate| candidate.name == language),
                "missing {language} in {fixture}: {:?}",
                graph.languages
            );
            assert_eq!(graph.services.len(), 1, "{fixture} should be one service");
        }
    }

    #[test]
    fn go_framework_detection_covers_common_routers_and_grpc() {
        let graph = detect_project(fixture_path("go-framework-service"));
        let frameworks = graph
            .services
            .iter()
            .find(|service| service.id == ".")
            .map(|service| service.frameworks.clone())
            .unwrap_or_default();

        for framework in ["Chi", "Echo", "Fiber", "gRPC"] {
            assert!(
                frameworks.iter().any(|candidate| candidate == framework),
                "missing {framework}; frameworks={frameworks:?}"
            );
        }
    }

    #[test]
    fn diff_failure_is_non_fatal_and_falls_back_to_full_scan() {
        let graph = detect_project_with_options(
            fixture_path("polyglot-monorepo"),
            DetectionOptions {
                diff_base: Some("definitely-missing-ref".to_string()),
                include_gitignored: false,
            },
        );

        assert!(graph.diff.enabled);
        assert!(graph.diff.fallback_full_scan);
        assert!(!graph.debug.warnings.is_empty());
    }
}
