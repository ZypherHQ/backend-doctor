use backend_doctor_analysis::{
    analyze_sources, default_parser_registry, empty_facts_for_project, AnalysisError,
    ParserRegistry,
};
use backend_doctor_core::{
    resolve_config, AnalysisFacts, Category, ConfigOverrides, Finding, OutputMode, ProjectGraph,
    Report, ReportInput, RuleMetadata, ScanMode, Severity, SourceFileFact, Suppression,
    CONFIG_FILE_NAME,
};
use backend_doctor_detect::{detect_project_with_options, DetectionOptions};
use backend_doctor_fix::{FixOptions, FixPlan, FixSelection};
use backend_doctor_report::{
    render_github_annotations, render_json, render_sarif,
    render_terminal_report_for_completed_progress_with_sidecars,
    render_terminal_report_with_color_and_sidecars,
    render_verbose_for_completed_progress_with_sidecars, render_verbose_with_sidecars,
};
use backend_doctor_rules::{builtin_rules, scan_project, scan_project_with_external_and_facts};
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Parser)]
#[command(name = "backend-doctor")]
#[command(
    version,
    about = "Polyglot backend codebase diagnostic CLI",
    long_about = "Scan a backend project, explain rules or findings, and emit human, JSON, SARIF, or CI-friendly diagnostics."
)]
#[command(subcommand_precedence_over_arg = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(
        default_value = ".",
        value_name = "PATH",
        help = "Project directory to scan"
    )]
    pub path: PathBuf,

    #[command(flatten)]
    pub scan: ScanFlags,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(about = "Explain a rule id or findings at a file:line location")]
    Explain(ExplainArgs),
    #[command(about = "List built-in rules and optional filters")]
    Rules(RulesArgs),
    #[command(about = "Create a default backend-doctor config")]
    Init(InitArgs),
    #[command(about = "Print local agent integration instructions")]
    Install(InstallArgs),
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    #[arg(help = "Rule id such as go/http-client-no-timeout, or file:line to inspect findings")]
    pub target: String,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[arg(long, help = "Show only rules for this language")]
    pub language: Option<String>,
    #[arg(long, help = "Show only rules in this category")]
    pub category: Option<String>,
    #[arg(long, help = "Print rule metadata as JSON")]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long, help = "Confirm writing the config in non-interactive mode")]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    #[arg(long, help = "Agent integration to describe")]
    pub agent: Option<String>,
    #[arg(long, help = "Confirm install guidance in non-interactive mode")]
    pub yes: bool,
}

#[derive(Clone, Debug, Default, Args)]
pub struct ScanFlags {
    #[arg(long, short = 'v', help = "Print the verbose human report")]
    pub verbose: bool,
    #[arg(long, help = "Include detection and project graph debug details")]
    pub debug: bool,
    #[arg(
        long,
        help = "Print trace diagnostics to stderr while preserving stdout format"
    )]
    pub trace: bool,
    #[arg(long, help = "Print only the numeric score")]
    pub score: bool,
    #[arg(
        long,
        value_name = "BASE",
        help = "Scan only changes relative to a git base"
    )]
    pub diff: Option<String>,
    #[arg(long, help = "Print the full report as JSON")]
    pub json: bool,
    #[arg(long, value_name = "PATH", help = "Write a JSON report sidecar")]
    pub json_out: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Write a SARIF report sidecar")]
    pub sarif: Option<PathBuf>,
    #[arg(long, help = "Use CI output behavior and configured gates")]
    pub ci: bool,
    #[arg(long, help = "Fail when the score is below this value")]
    pub min_score: Option<u8>,
    #[arg(long, help = "Fail when critical findings exceed this count")]
    pub max_critical: Option<u32>,
    #[arg(long, help = "Fail when error findings exceed this count")]
    pub max_errors: Option<u32>,
    #[arg(
        long,
        value_delimiter = ',',
        help = "Fail on severities or categories, comma-separated"
    )]
    pub fail_on: Vec<String>,
    #[arg(long, help = "Always exit zero after a completed scan")]
    pub no_fail: bool,
    #[arg(long, help = "Print a fix plan without applying changes")]
    pub plan_fixes: bool,
    #[arg(long, help = "Apply safe fixes when combined with --yes")]
    pub fix_safe: bool,
    #[arg(long, help = "Preview or apply guided fixes when combined with --yes")]
    pub fix_guided: bool,
    #[arg(long, help = "Restrict fixes to one rule id")]
    pub fix_rule: Option<String>,
    #[arg(long, help = "Restrict fixes to one finding id or fingerprint")]
    pub fix_finding: Option<String>,
    #[arg(long, help = "Preview fixes without writing files")]
    pub dry_run: bool,
    #[arg(long, help = "Confirm non-interactive fix application")]
    pub yes: bool,
    #[arg(long, help = "Emit GitHub workflow annotations for findings")]
    pub github_annotations: bool,
    #[arg(long, help = "Enable configured deep external checks")]
    pub deep: bool,
    #[arg(long, help = "Allow configured test-running external checks")]
    pub run_tests: bool,
    #[arg(long, help = "Allow configured git history scans")]
    pub scan_history: bool,
    #[arg(long, help = "Allow configured missing-tool installation")]
    pub install_missing_tools: bool,
    #[arg(long, help = "Allow network-capable checks")]
    pub network: bool,
    #[arg(long, help = "Include files normally ignored by gitignore")]
    pub include_gitignored: bool,
}

pub fn run(cli: Cli) -> i32 {
    if cli.command.is_some() {
        if let Some(error) = unsupported_advanced_flags_error(&cli.scan) {
            eprintln!("{error}");
            return 2;
        }
    }

    match cli.command {
        Some(Command::Explain(args)) => run_explain(cli.path, args, cli.scan),
        Some(Command::Rules(args)) => {
            let rules = match filter_rules(builtin_rules(), &args) {
                Ok(rules) => rules,
                Err(error) => {
                    eprintln!("{error}");
                    return 2;
                }
            };
            if args.json {
                match serde_json::to_string_pretty(&rules) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        eprintln!("failed to serialize rules: {error}");
                        return 4;
                    }
                }
            } else {
                for rule in rules {
                    println!("{} {}", rule.id, rule.title);
                }
            }
            0
        }
        Some(Command::Init(args)) => run_init(args),
        Some(Command::Install(args)) => run_install(args),
        None => run_scan(cli.path, cli.scan),
    }
}

fn run_scan(path: PathBuf, flags: ScanFlags) -> i32 {
    let path = match validate_scan_root(&path) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let started_at = Utc::now();
    let timer = Instant::now();
    let output_mode = if flags.json {
        Some(OutputMode::Json)
    } else if flags.verbose || flags.debug {
        Some(OutputMode::Verbose)
    } else {
        None
    };
    let config = match resolve_config(
        &path,
        ConfigOverrides {
            include_gitignored: flags.include_gitignored,
            network: flags.network,
            deep: flags.deep,
            run_tests: flags.run_tests,
            scan_history: flags.scan_history,
            install_missing_tools: flags.install_missing_tools,
            output_mode,
            min_score: flags.min_score,
            max_critical: flags.max_critical,
            max_errors: flags.max_errors,
        },
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };

    let mut progress = ProgressReporter::new(
        &flags,
        config.output_mode.clone(),
        io::stdout().is_terminal(),
    );
    progress.step(format!(
        "Select projects to scan › {}",
        scan_project_label(&path)
    ));
    progress.step(format!("Scanning {}", path.display()));
    progress.step("Detecting backend stack");

    let graph = detect_project_with_options(
        &path,
        DetectionOptions {
            diff_base: flags.diff.clone(),
            include_gitignored: config.include_gitignored,
        },
    );
    let mode = if flags.diff.is_some() {
        ScanMode::Diff
    } else {
        ScanMode::Full
    };

    let fail_on = match parse_fail_on_specs(&flags.fail_on) {
        Ok(specs) => specs,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };

    progress.active("Running Backend Doctor analysis...");
    let analysis_facts = if config.analysis.enabled {
        match analyze_project_sources(&graph, &config.analysis.adapters) {
            Ok(facts) => Some(facts),
            Err(error) => {
                eprintln!("failed to collect analysis facts: {error}");
                return 3;
            }
        }
    } else {
        None
    };
    let scan_output =
        scan_project_with_external_and_facts(&graph, &config, analysis_facts.as_ref());
    progress.step("Calculating Backend Doctor score");
    let mut report = Report::new(ReportInput {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        duration: timer.elapsed(),
        root: graph.root.clone(),
        mode,
        services: graph.services.clone(),
        project_graph: graph,
        findings: scan_output.findings,
        config,
        external_tool_versions: scan_output.external_tool_versions,
        external_tool_executions: scan_output.external_tool_executions,
    });
    if let Some(facts) = analysis_facts {
        report = report.with_analysis_facts(facts);
    }

    if flags.trace {
        eprintln!("{}", render_trace(&report));
    }

    if flags.plan_fixes || flags.fix_safe || flags.fix_guided {
        let apply = !flags.plan_fixes
            && (flags.fix_safe || flags.fix_guided)
            && flags.yes
            && !flags.dry_run;
        if flags.fix_guided && flags.ci && !flags.yes {
            eprintln!("--fix-guided in CI requires --yes for an explicit guided preview");
            return 2;
        }
        let safety = if flags.plan_fixes {
            FixSelection::All
        } else if flags.fix_guided {
            FixSelection::Guided
        } else {
            FixSelection::Safe
        };
        let plan = FixPlan::build(
            &report.root,
            &report.findings,
            &FixOptions {
                safety,
                dry_run: flags.dry_run || !apply,
                apply,
                rule_filter: flags.fix_rule.clone(),
                finding_filter: flags.fix_finding.clone(),
            },
        );
        println!("{}", plan.render_text());
        if apply {
            let result = if flags.fix_guided {
                plan.apply_guided(&report.root)
            } else {
                plan.apply(&report.root)
            };
            println!(
                "Fix application: applied={}, skipped={}, remaining={}",
                result.applied, result.skipped, result.remaining
            );
            for path in &result.applied_paths {
                println!("Applied change: {}", path.display());
            }
            for warning in &result.formatter_warnings {
                eprintln!("formatter warning: {warning}");
            }
            if !result.errors.is_empty() {
                for error in &result.errors {
                    eprintln!("fix error: {error}");
                }
                return 3;
            }
            let post_graph = detect_project_with_options(
                &path,
                DetectionOptions {
                    diff_base: flags.diff.clone(),
                    include_gitignored: flags.include_gitignored,
                },
            );
            let remaining = scan_project(&post_graph, &report.config)
                .into_iter()
                .filter(|finding| {
                    flags
                        .fix_rule
                        .as_ref()
                        .is_none_or(|rule| &finding.rule_id == rule)
                        && flags
                            .fix_finding
                            .as_ref()
                            .is_none_or(|id| &finding.id == id || &finding.fingerprint == id)
                })
                .count();
            println!("Targeted rescan: remaining matching findings={remaining}");
        }
        return threshold_exit_code(&report, &flags, &fail_on);
    }

    if flags.score {
        println!("{}", report.score.value);
        return threshold_exit_code(&report, &flags, &fail_on);
    }

    if let Some(json_out) = &flags.json_out {
        let json = match render_json(&report) {
            Ok(json) => json,
            Err(error) => {
                eprintln!("failed to serialize report JSON: {error}");
                return 4;
            }
        };
        if let Err(error) = fs::write(json_out, format!("{json}\n")) {
            eprintln!(
                "failed to write JSON report {}: {error}",
                json_out.display()
            );
            return 3;
        }
    }
    if let Some(sarif_out) = &flags.sarif {
        let sarif = match render_sarif(&report) {
            Ok(sarif) => sarif,
            Err(error) => {
                eprintln!("failed to serialize SARIF report: {error}");
                return 4;
            }
        };
        if let Err(error) = fs::write(sarif_out, format!("{sarif}\n")) {
            eprintln!(
                "failed to write SARIF report {}: {error}",
                sarif_out.display()
            );
            return 3;
        }
    }

    let human_color = !flags.ci && color_enabled(io::stdout().is_terminal());
    match report.config.output_mode {
        OutputMode::Json => match render_json(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("failed to serialize report JSON: {error}");
                return 4;
            }
        },
        OutputMode::Verbose if progress.emitted() || flags.ci => {
            println!(
                "{}",
                render_verbose_for_completed_progress_with_sidecars(
                    &report,
                    human_color,
                    flags.json_out.as_deref(),
                    flags.sarif.as_deref(),
                )
            )
        }
        OutputMode::Verbose => println!(
            "{}",
            render_verbose_with_sidecars(
                &report,
                flags.json_out.as_deref(),
                flags.sarif.as_deref()
            )
        ),
        OutputMode::Summary if progress.emitted() || flags.ci => {
            println!(
                "{}",
                render_terminal_report_for_completed_progress_with_sidecars(
                    &report,
                    human_color,
                    flags.json_out.as_deref(),
                    flags.sarif.as_deref(),
                )
            )
        }
        OutputMode::Summary => println!(
            "{}",
            render_terminal_report_with_color_and_sidecars(
                &report,
                human_color,
                flags.json_out.as_deref(),
                flags.sarif.as_deref(),
            )
        ),
    }
    if flags.github_annotations {
        let annotations = render_github_annotations(&report);
        if !annotations.is_empty() {
            if report.config.output_mode == OutputMode::Json {
                eprintln!("{annotations}");
            } else {
                println!("{annotations}");
            }
        }
    }

    threshold_exit_code(&report, &flags, &fail_on)
}

#[derive(Clone, Copy, Debug)]
struct ProgressReporter {
    enabled: bool,
    color: bool,
    emitted: bool,
}

impl ProgressReporter {
    fn new(flags: &ScanFlags, output_mode: OutputMode, stdout_is_terminal: bool) -> Self {
        let fix_mode = flags.plan_fixes || flags.fix_safe || flags.fix_guided;
        let enabled = !flags.json
            && !flags.score
            && !flags.ci
            && !fix_mode
            && matches!(output_mode, OutputMode::Summary | OutputMode::Verbose);
        let color = enabled && color_enabled(stdout_is_terminal);
        Self {
            enabled,
            color,
            emitted: false,
        }
    }

    fn step(&mut self, message: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        let check = if self.color {
            "\x1b[32m✔\x1b[0m"
        } else {
            "✔"
        };
        let message = if self.color {
            format!("\x1b[36m{}\x1b[0m", message.as_ref())
        } else {
            message.as_ref().to_string()
        };
        println!("{check} {message}");
        let _ = io::stdout().flush();
        self.emitted = true;
    }

    fn active(&mut self, message: impl AsRef<str>) {
        if !self.enabled {
            return;
        }
        let marker = if self.color {
            "\x1b[36m•\x1b[0m"
        } else {
            "•"
        };
        let message = if self.color {
            format!("\x1b[36m{}\x1b[0m", message.as_ref())
        } else {
            message.as_ref().to_string()
        };
        println!("{marker} {message}");
        let _ = io::stdout().flush();
        self.emitted = true;
    }

    fn emitted(self) -> bool {
        self.emitted
    }
}

fn color_enabled(stdout_is_terminal: bool) -> bool {
    color_enabled_from_env(
        stdout_is_terminal,
        std::env::var_os("NO_COLOR").is_some(),
        std::env::var("BACKEND_DOCTOR_COLOR").ok().as_deref(),
        std::env::var("CLICOLOR_FORCE").ok().as_deref(),
        std::env::var("CLICOLOR").ok().as_deref(),
    )
}

fn analyze_project_sources(
    graph: &ProjectGraph,
    enabled_adapters: &[String],
) -> Result<AnalysisFacts, AnalysisError> {
    let inputs = collect_analysis_sources(graph, enabled_adapters)?;
    analyze_sources(
        graph,
        inputs
            .iter()
            .map(|(source_file, contents)| (source_file, contents.as_str())),
    )
}

fn collect_analysis_sources(
    graph: &ProjectGraph,
    enabled_adapters: &[String],
) -> Result<Vec<(SourceFileFact, String)>, AnalysisError> {
    let facts = empty_facts_for_project(graph);
    let registry = default_parser_registry();
    let mut sources = Vec::new();

    for source_file in facts
        .source_files
        .into_iter()
        .filter(|source_file| analysis_adapter_enabled(&registry, enabled_adapters, source_file))
    {
        let path = if source_file.path.is_absolute() {
            source_file.path.clone()
        } else {
            graph.root.join(&source_file.path)
        };
        let contents = fs::read_to_string(&path).map_err(|source| AnalysisError::Io {
            path: source_file.path.clone(),
            message: source.to_string(),
        })?;
        sources.push((source_file, contents));
    }

    Ok(sources)
}

fn analysis_adapter_enabled(
    registry: &ParserRegistry,
    enabled_adapters: &[String],
    source_file: &SourceFileFact,
) -> bool {
    if enabled_adapters.is_empty() {
        return true;
    }

    let Some(source_adapter) = registry.adapter_for(source_file) else {
        return false;
    };

    let language = normalize_analysis_adapter_name(&source_file.language);
    let adapter_id = normalize_analysis_adapter_name(source_adapter.id());
    enabled_adapters.iter().any(|adapter| {
        let normalized_adapter = normalize_analysis_adapter_name(adapter);
        let configured_adapter = SourceFileFact::new("", adapter.as_str());
        normalized_adapter == language
            || normalized_adapter == adapter_id
            || registry
                .adapter_for(&configured_adapter)
                .is_some_and(|adapter| adapter.id() == source_adapter.id())
            || matches!(
                (source_file.language.as_str(), normalized_adapter.as_str()),
                ("Go", "go" | "gotreesittertiera")
                    | ("Java", "java" | "javatreesittertiera")
                    | (
                        "Node/TypeScript",
                        "node"
                            | "typescript"
                            | "ts"
                            | "nodetypescript"
                            | "nodetypescripttreesittertiera"
                    )
            )
    })
}

fn normalize_analysis_adapter_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn color_enabled_from_env(
    stdout_is_terminal: bool,
    no_color_present: bool,
    backend_doctor_color: Option<&str>,
    clicolor_force: Option<&str>,
    clicolor: Option<&str>,
) -> bool {
    if no_color_present {
        return false;
    }
    if let Some(value) = backend_doctor_color {
        match value.trim().to_ascii_lowercase().as_str() {
            "always" | "force" | "forced" | "1" | "true" | "yes" => return true,
            "never" | "none" | "0" | "false" | "no" => return false,
            "auto" | "" => {}
            _ => {}
        }
    }
    if clicolor_force.is_some_and(|value| value.trim() != "0") {
        return true;
    }
    if clicolor.is_some_and(|value| value.trim() == "0") {
        return false;
    }
    stdout_is_terminal
}

fn scan_project_label(root: &std::path::Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| root.display().to_string())
}

fn validate_scan_root(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "scan path does not exist or is not accessible: {} ({error}). Pass an existing project directory.",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "scan path is not a directory: {}. Pass the project directory, then use file:line with explain when needed.",
            path.display()
        ));
    }
    fs::canonicalize(path).map_err(|error| {
        format!(
            "failed to resolve scan path {}: {error}. Pass an existing project directory.",
            path.display()
        )
    })
}

#[derive(Debug)]
struct FileLineTarget {
    path: PathBuf,
    line: u32,
}

fn parse_file_line_target(value: &str) -> Option<FileLineTarget> {
    let (path, line) = value.rsplit_once(':')?;
    if path.trim().is_empty() {
        return None;
    }
    let line = line.parse::<u32>().ok()?;
    if line == 0 {
        return None;
    }
    Some(FileLineTarget {
        path: PathBuf::from(path),
        line,
    })
}

fn run_explain(path: PathBuf, args: ExplainArgs, flags: ScanFlags) -> i32 {
    if let Some(target) = parse_file_line_target(&args.target) {
        run_explain_location(path, target, flags)
    } else {
        explain_rule_id(&args.target)
    }
}

fn explain_rule_id(rule_id: &str) -> i32 {
    match builtin_rules().into_iter().find(|rule| rule.id == rule_id) {
        Some(rule) => {
            print_rule_explanation(&rule);
            0
        }
        None => {
            eprintln!(
                "unknown rule id '{rule_id}'; run 'backend-doctor rules' to list available rules"
            );
            2
        }
    }
}

fn run_explain_location(path: PathBuf, target: FileLineTarget, flags: ScanFlags) -> i32 {
    let scan_root = match validate_scan_root(&path) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let target_path = match resolve_explain_target_path(&scan_root, &target.path) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let report = match build_explain_report(&scan_root, &flags) {
        Ok(report) => report,
        Err((code, error)) => {
            eprintln!("{error}");
            return code;
        }
    };
    if flags.trace {
        eprintln!("{}", render_trace(&report));
    }

    let matches = report
        .findings
        .iter()
        .chain(report.suppressed_findings.iter())
        .filter(|finding| finding_matches_file_line(finding, &scan_root, &target_path, target.line))
        .collect::<Vec<_>>();

    if matches.is_empty() {
        eprintln!(
            "no finding found at {}:{} under scan root {}",
            target.path.display(),
            target.line,
            scan_root.display()
        );
        return 1;
    }

    let rules = builtin_rules();
    for (index, finding) in matches.iter().enumerate() {
        if index > 0 {
            println!();
        }
        let rule = rules.iter().find(|rule| rule.id == finding.rule_id);
        print_location_explanation(index + 1, matches.len(), finding, rule, &report);
    }

    0
}

fn resolve_explain_target_path(scan_root: &Path, target: &Path) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if target.is_absolute() {
        candidates.push(target.to_path_buf());
    } else {
        candidates.push(scan_root.join(target));
        candidates.push(target.to_path_buf());
    }
    for candidate in candidates {
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|error| {
                format!(
                    "failed to resolve explain target {}: {error}",
                    candidate.display()
                )
            });
        }
    }
    Err(format!(
        "explain target file does not exist: {}. Use a file:line path inside the scan root.",
        target.display()
    ))
}

fn build_explain_report(path: &Path, flags: &ScanFlags) -> Result<Report, (i32, String)> {
    let started_at = Utc::now();
    let timer = Instant::now();
    let output_mode = if flags.json {
        Some(OutputMode::Json)
    } else if flags.verbose || flags.debug {
        Some(OutputMode::Verbose)
    } else {
        None
    };
    let config = resolve_config(
        path,
        ConfigOverrides {
            include_gitignored: flags.include_gitignored,
            network: flags.network,
            deep: flags.deep,
            run_tests: flags.run_tests,
            scan_history: flags.scan_history,
            install_missing_tools: flags.install_missing_tools,
            output_mode,
            min_score: flags.min_score,
            max_critical: flags.max_critical,
            max_errors: flags.max_errors,
        },
    )
    .map_err(|error| (2, error.to_string()))?;
    let graph = detect_project_with_options(
        path,
        DetectionOptions {
            diff_base: flags.diff.clone(),
            include_gitignored: config.include_gitignored,
        },
    );
    let mode = if flags.diff.is_some() {
        ScanMode::Diff
    } else {
        ScanMode::Full
    };
    let analysis_facts = if config.analysis.enabled {
        Some(
            analyze_project_sources(&graph, &config.analysis.adapters)
                .map_err(|error| (3, format!("failed to collect analysis facts: {error}")))?,
        )
    } else {
        None
    };
    let scan_output =
        scan_project_with_external_and_facts(&graph, &config, analysis_facts.as_ref());
    let mut report = Report::new(ReportInput {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        started_at,
        duration: timer.elapsed(),
        root: graph.root.clone(),
        mode,
        services: graph.services.clone(),
        project_graph: graph,
        findings: scan_output.findings,
        config,
        external_tool_versions: scan_output.external_tool_versions,
        external_tool_executions: scan_output.external_tool_executions,
    });
    if let Some(facts) = analysis_facts {
        report = report.with_analysis_facts(facts);
    }
    Ok(report)
}

fn finding_matches_file_line(
    finding: &Finding,
    scan_root: &Path,
    target_path: &Path,
    target_line: u32,
) -> bool {
    let Some(location) = &finding.location else {
        return false;
    };
    let Some(start_line) = location.line else {
        return false;
    };
    let end_line = location.end_line.unwrap_or(start_line);
    if target_line < start_line || target_line > end_line {
        return false;
    }
    let location_path = if location.path.is_absolute() {
        location.path.clone()
    } else {
        scan_root.join(&location.path)
    };
    fs::canonicalize(&location_path)
        .map(|path| path == target_path)
        .unwrap_or_else(|_| location_path == target_path)
}

fn print_location_explanation(
    index: usize,
    total: usize,
    finding: &Finding,
    rule: Option<&RuleMetadata>,
    report: &Report,
) {
    println!("Finding {index} of {total}");
    println!("Rule: {} - {}", finding.rule_id, finding.title);
    if let Some(rule) = rule {
        println!("Rule title: {}", rule.title);
    }
    if let Some(location) = &finding.location {
        println!("Location: {}", location.display());
    }
    println!("Severity: {}", finding.severity);
    println!("Category: {}", finding.category);
    println!("Message: {}", finding.message);
    if let Some(evidence) = &finding.evidence {
        let snippet = evidence.snippet.trim();
        if !snippet.is_empty() {
            println!("Evidence: {snippet}");
        }
    }
    if let Some(impact) = finding.impact.as_deref() {
        if !impact.trim().is_empty() {
            println!("Explanation: {impact}");
        }
    } else if let Some(rule) = rule {
        if !rule.explanation.trim().is_empty() {
            println!("Explanation: {}", rule.explanation);
        }
    }
    if !finding.remediation.trim().is_empty() {
        println!("Remediation: {}", finding.remediation);
    } else if let Some(rule) = rule {
        if !rule.remediation.trim().is_empty() {
            println!("Remediation: {}", rule.remediation);
        }
    }
    let rule_status = if report
        .config
        .disabled_rules
        .iter()
        .any(|rule_id| rule_id == &finding.rule_id)
    {
        "disabled by config"
    } else {
        "enabled by config"
    };
    println!("Config status: {rule_status}");
    if finding.suppressed {
        if let Some(suppression) = matching_suppression(finding, &report.config.suppressions) {
            println!("Suppression status: suppressed ({})", suppression.reason);
        } else {
            println!("Suppression status: suppressed");
        }
    } else {
        println!("Suppression status: active");
    }
}

fn matching_suppression<'a>(
    finding: &Finding,
    suppressions: &'a [Suppression],
) -> Option<&'a Suppression> {
    suppressions
        .iter()
        .find(|suppression| suppression_matches_finding(suppression, finding))
}

fn suppression_matches_finding(suppression: &Suppression, finding: &Finding) -> bool {
    if suppression.rule != finding.rule_id {
        return false;
    }
    let Some(path_pattern) = &suppression.path else {
        return suppression.allow_broad;
    };
    let normalized_pattern = path_pattern.replace('\\', "/");
    if normalized_pattern.trim().is_empty() {
        return suppression.allow_broad;
    }
    finding.location.as_ref().is_some_and(|location| {
        location
            .path
            .to_string_lossy()
            .replace('\\', "/")
            .contains(&normalized_pattern)
    })
}

fn render_trace(report: &Report) -> String {
    let mut out = String::new();
    use std::fmt::Write as _;

    writeln!(&mut out, "Backend Doctor trace").expect("write to string");
    writeln!(&mut out, "  root: {}", report.root.display()).expect("write to string");
    if let Some(git_root) = &report.project_graph.git_root {
        writeln!(&mut out, "  gitRoot: {}", git_root.display()).expect("write to string");
    }
    writeln!(
        &mut out,
        "  workspaceRoot: {}",
        report.project_graph.workspace_root.display()
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  mode: {:?}, services={}, languages={}, findings={}, suppressed={}",
        report.mode,
        report.services.len(),
        report.project_graph.languages.len(),
        report.findings.len(),
        report.suppressed_findings.len()
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  inventory: files={} source={} manifests={} infra={} tests={}",
        report.project_graph.inventory.total_files,
        report.project_graph.inventory.source_files,
        report.project_graph.inventory.manifest_files,
        report.project_graph.inventory.infra_files,
        report.project_graph.inventory.test_files
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  config: includeGitignored={} network={} deep={} runTests={} scanHistory={} installMissingTools={}",
        report.config.include_gitignored,
        report.config.network,
        report.config.external_tools.deep,
        report.config.external_tools.run_tests,
        report.config.external_tools.scan_history,
        report.config.external_tools.install_missing_tools
    )
    .expect("write to string");
    for decision in &report.project_graph.debug.decisions {
        writeln!(&mut out, "  decision: {decision}").expect("write to string");
    }
    for warning in &report.project_graph.debug.warnings {
        writeln!(&mut out, "  warning: {warning}").expect("write to string");
    }
    if !report.external_tool_versions.is_empty() || !report.external_tool_executions.is_empty() {
        writeln!(
            &mut out,
            "  externalTools: versions={} executions={}",
            report.external_tool_versions.len(),
            report.external_tool_executions.len()
        )
        .expect("write to string");
    }
    out
}

fn print_rule_explanation(rule: &RuleMetadata) {
    println!("Rule: {}", rule.id);
    println!("Title: {}", rule.title);
    println!("Category: {}", rule.category);
    println!("Default severity: {}", rule.default_severity);
    println!("Default confidence: {}", rule.default_confidence);
    println!("Fixability: {}", rule.fixability);
    println!("Enabled by default: {}", rule.enabled_by_default);
    println!("Supports diff mode: {}", rule.supports_diff_mode);
    print_list("Languages", &rule.languages);
    print_list("Frameworks", &rule.frameworks);
    print_list("Tags", &rule.tags);
    print_list("CWE", &rule.cwe);
    print_list("OWASP", &rule.owasp);
    if let Some(docs) = &rule.docs {
        println!("Docs: {docs}");
    }
    println!();
    println!("Explanation:");
    println!("{}", rule.explanation);
    println!();
    println!("Remediation:");
    println!("{}", rule.remediation);
}

fn print_list(label: &str, values: &[String]) {
    if !values.is_empty() {
        println!("{label}: {}", values.join(", "));
    }
}

fn filter_rules(rules: Vec<RuleMetadata>, args: &RulesArgs) -> Result<Vec<RuleMetadata>, String> {
    let category = args.category.as_deref().map(parse_category).transpose()?;
    let language = args
        .language
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase());
    Ok(rules
        .into_iter()
        .filter(|rule| {
            category
                .as_ref()
                .is_none_or(|category| &rule.category == category)
                && language.as_ref().is_none_or(|language| {
                    rule.languages
                        .iter()
                        .any(|candidate| candidate.to_ascii_lowercase() == *language)
                })
        })
        .collect())
}

fn parse_category(value: &str) -> Result<Category, String> {
    let normalized = value.trim().to_ascii_lowercase();
    Category::all()
        .iter()
        .find(|category| category.to_string() == normalized)
        .cloned()
        .ok_or_else(|| {
            format!(
                "unsupported --category value '{value}'; expected architecture, correctness, dependencies, infrastructure, reliability, security, testing, or maintainability"
            )
        })
}

fn run_init(args: InitArgs) -> i32 {
    if !args.yes {
        eprintln!("init requires --yes in this non-interactive MVP");
        return 2;
    }
    let root = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("failed to resolve current directory: {error}");
            return 2;
        }
    };
    let config_path = root.join(CONFIG_FILE_NAME);
    if config_path.exists() {
        println!("Config already exists: {}", config_path.display());
        return 0;
    }
    if let Err(error) = fs::write(&config_path, default_config_toml()) {
        eprintln!(
            "failed to write default config {}: {error}",
            config_path.display()
        );
        return 3;
    }
    println!("Created {}", config_path.display());
    0
}

fn default_config_toml() -> &'static str {
    r#"# Backend Doctor configuration
include-gitignored = false
network = false
output-mode = "summary"
disabled-rules = []

[external-tools]
deep = false
run-tests = false
scan-history = false
install-missing-tools = false
network = false
default-timeout-ms = 30000

[cache]
enabled = true
location = "repo-local"

[thresholds]
min-score = 75
"#
}

fn run_install(args: InstallArgs) -> i32 {
    let agent = args.agent.as_deref().unwrap_or("codex");
    if agent != "codex" {
        eprintln!("unsupported agent '{agent}'; supported agent: codex");
        return 2;
    }
    if !args.yes {
        eprintln!("install requires --yes in this non-interactive MVP");
        return 2;
    }
    println!("Codex skill installation instructions:");
    println!("1. Locate this repository's skill file: skills/backend-doctor/SKILL.md");
    println!("2. Install it into your local Codex skills directory as backend-doctor/SKILL.md");
    println!("No files were written by this command.");
    0
}

fn unsupported_advanced_flags_error(flags: &ScanFlags) -> Option<String> {
    let unsupported = [
        (flags.deep, "--deep"),
        (flags.run_tests, "--run-tests"),
        (flags.scan_history, "--scan-history"),
        (flags.install_missing_tools, "--install-missing-tools"),
    ]
    .into_iter()
    .filter_map(|(enabled, name)| enabled.then_some(name))
    .collect::<Vec<_>>();
    if unsupported.is_empty() {
        None
    } else {
        Some(format!(
            "unsupported advanced scan option(s) before subcommand: {}; place scan gates on a scan invocation, not on rules/explain/init/install",
            unsupported.join(", ")
        ))
    }
}

fn threshold_exit_code(report: &Report, flags: &ScanFlags, fail_on: &[FailOnSpec]) -> i32 {
    if flags.no_fail {
        return 0;
    }
    if !flags.ci
        && flags.min_score.is_none()
        && flags.max_critical.is_none()
        && flags.max_errors.is_none()
        && flags.fail_on.is_empty()
    {
        return 0;
    }
    let thresholds = &report.config.thresholds;
    if report.score.value < thresholds.min_score {
        return 1;
    }
    if let Some(max_critical) = thresholds.max_critical {
        if report.summary.critical_findings as u32 > max_critical {
            return 1;
        }
    }
    if let Some(max_errors) = thresholds.max_errors {
        if report.summary.error_findings as u32 > max_errors {
            return 1;
        }
    }
    if fail_on.iter().any(|spec| fail_on_matches(report, spec)) {
        return 1;
    }
    0
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FailOnSpec {
    Severity(Severity),
    Category(Category),
}

fn parse_fail_on_specs(values: &[String]) -> Result<Vec<FailOnSpec>, String> {
    values
        .iter()
        .map(|value| parse_fail_on_spec(value))
        .collect()
}

fn parse_fail_on_spec(value: &str) -> Result<FailOnSpec, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(invalid_fail_on_value(value));
    }
    let severity = match normalized.as_str() {
        "critical" => Some(Severity::Critical),
        "high" | "error" => Some(Severity::Error),
        "medium" | "warning" => Some(Severity::Warning),
        "low" | "info" => Some(Severity::Info),
        "note" => Some(Severity::Note),
        _ => None,
    };
    if let Some(severity) = severity {
        return Ok(FailOnSpec::Severity(severity));
    }
    Category::all()
        .iter()
        .find(|category| category.to_string() == normalized)
        .cloned()
        .map(FailOnSpec::Category)
        .ok_or_else(|| invalid_fail_on_value(value))
}

fn invalid_fail_on_value(value: &str) -> String {
    format!(
        "unsupported --fail-on value '{value}'; expected severity critical, high, error, medium, warning, low, info, note or category architecture, correctness, dependencies, infrastructure, reliability, security, testing, maintainability"
    )
}

fn fail_on_matches(report: &Report, spec: &FailOnSpec) -> bool {
    report.findings.iter().any(|finding| match spec {
        FailOnSpec::Severity(severity) => &finding.severity == severity,
        FailOnSpec::Category(category) => &finding.category == category,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_renders_primary_commands_and_flags() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("backend-doctor"));
        assert!(help.contains("--score"));
        assert!(help.contains("--json"));
        assert!(help.contains("explain"));
        assert!(help.contains("rules"));
    }

    #[test]
    fn color_policy_forces_auto_and_suppresses_with_no_color() {
        assert!(color_enabled_from_env(
            false,
            false,
            Some("always"),
            None,
            None
        ));
        assert!(color_enabled_from_env(
            false,
            false,
            Some("force"),
            None,
            None
        ));
        assert!(!color_enabled_from_env(
            true,
            false,
            Some("never"),
            None,
            None
        ));
        assert!(!color_enabled_from_env(
            false,
            false,
            Some("auto"),
            None,
            None
        ));
        assert!(color_enabled_from_env(
            true,
            false,
            Some("auto"),
            None,
            None
        ));
        assert!(!color_enabled_from_env(
            true,
            true,
            Some("always"),
            Some("1"),
            None
        ));
        assert!(!color_enabled_from_env(true, true, None, Some("1"), None));
        assert!(color_enabled_from_env(false, false, None, Some("1"), None));
        assert!(!color_enabled_from_env(false, false, None, Some("0"), None));
        assert!(!color_enabled_from_env(false, false, None, None, Some("0")));
        assert!(!color_enabled_from_env(true, false, None, None, Some("0")));
        assert!(!color_enabled_from_env(
            false,
            false,
            Some("never"),
            Some("1"),
            None
        ));
    }

    #[test]
    fn parses_default_scan_path() {
        let cli = Cli::parse_from(["backend-doctor"]);
        assert_eq!(cli.path, PathBuf::from("."));
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_explain_command() {
        let cli = Cli::parse_from(["backend-doctor", "explain", "go/http-client-no-timeout"]);
        match cli.command {
            Some(Command::Explain(args)) => {
                assert_eq!(args.target, "go/http-client-no-timeout");
            }
            _ => panic!("expected explain command"),
        }
    }

    #[test]
    fn parses_path_before_explain_command() {
        let cli = Cli::parse_from([
            "backend-doctor",
            "fixtures/go-bad-service",
            "explain",
            "internal/client/client.go:8",
        ]);
        assert_eq!(cli.path, PathBuf::from("fixtures/go-bad-service"));
        match cli.command {
            Some(Command::Explain(args)) => {
                assert_eq!(args.target, "internal/client/client.go:8");
            }
            _ => panic!("expected explain command"),
        }
    }
}
