use backend_doctor_core::{Finding, Location, Report, Severity};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::{Component, Path};

const MAX_CATEGORY_SECTIONS: usize = 6;
const MAX_RULE_GROUPS_PER_CATEGORY: usize = 4;
/// Continuation indent under a finding row's title cell ("    " + marker + " " +
/// 4-wide severity tag + "   "), so wrapped remediation text lines up with the title.
const ROW_INDENT: &str = "             ";

pub fn render_summary(report: &Report) -> String {
    render_terminal_report(report)
}

pub fn render_terminal_report(report: &Report) -> String {
    render_terminal_report_with_options(report, TerminalRenderOptions::default())
}

pub fn render_terminal_report_for_completed_progress(report: &Report, color: bool) -> String {
    render_terminal_report_with_options(
        report,
        TerminalRenderOptions {
            include_verbose_hint: true,
            include_task_checks: false,
            color,
        },
    )
}

pub fn render_terminal_report_with_color(report: &Report, color: bool) -> String {
    render_terminal_report_with_options(
        report,
        TerminalRenderOptions {
            color,
            ..TerminalRenderOptions::default()
        },
    )
}

pub fn render_terminal_report_with_color_and_sidecars(
    report: &Report,
    color: bool,
    json_out: Option<&Path>,
    sarif_out: Option<&Path>,
) -> String {
    let style = TuiStyle::new(color);
    let mut out = render_terminal_report_with_color(report, color);
    render_sidecar_paths(&mut out, json_out, sarif_out, style);
    out
}

pub fn render_verbose_for_completed_progress(report: &Report, color: bool) -> String {
    render_verbose_with_options(
        report,
        TerminalRenderOptions {
            include_verbose_hint: false,
            include_task_checks: false,
            color,
        },
    )
}

pub fn render_terminal_report_for_completed_progress_with_sidecars(
    report: &Report,
    color: bool,
    json_out: Option<&Path>,
    sarif_out: Option<&Path>,
) -> String {
    let style = TuiStyle::new(color);
    let mut out = render_terminal_report_for_completed_progress(report, color);
    render_sidecar_paths(&mut out, json_out, sarif_out, style);
    out
}

pub fn render_verbose_for_completed_progress_with_sidecars(
    report: &Report,
    color: bool,
    json_out: Option<&Path>,
    sarif_out: Option<&Path>,
) -> String {
    let style = TuiStyle::new(color);
    let mut out = render_verbose_for_completed_progress(report, color);
    render_sidecar_paths(&mut out, json_out, sarif_out, style);
    out
}

#[derive(Clone, Copy, Debug)]
struct TerminalRenderOptions {
    include_verbose_hint: bool,
    include_task_checks: bool,
    color: bool,
}

impl Default for TerminalRenderOptions {
    fn default() -> Self {
        Self {
            include_verbose_hint: true,
            include_task_checks: true,
            color: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TuiStyle {
    color: bool,
}

impl TuiStyle {
    fn new(color: bool) -> Self {
        Self { color }
    }

    fn paint(self, code: &str, value: impl AsRef<str>) -> String {
        if self.color {
            format!("\x1b[{code}m{}\x1b[0m", value.as_ref())
        } else {
            value.as_ref().to_string()
        }
    }

    fn bold(self, value: impl AsRef<str>) -> String {
        self.paint("1", value)
    }

    fn dim(self, value: impl AsRef<str>) -> String {
        self.paint("2", value)
    }

    fn red(self, value: impl AsRef<str>) -> String {
        self.paint("31", value)
    }

    fn green(self, value: impl AsRef<str>) -> String {
        self.paint("32", value)
    }

    fn yellow(self, value: impl AsRef<str>) -> String {
        self.paint("33", value)
    }

    fn cyan(self, value: impl AsRef<str>) -> String {
        self.paint("36", value)
    }
}

fn render_terminal_report_with_options(report: &Report, options: TerminalRenderOptions) -> String {
    let style = TuiStyle::new(options.color);
    let mut out = String::new();
    writeln!(
        &mut out,
        "{}  {}  {}",
        style.cyan(format!("backend-doctor v{}", report.tool_version)),
        style.dim("·"),
        style.dim(project_label(report))
    )
    .expect("write to string");

    // The intro/task lines stand in for live progress. When the CLI already
    // streamed progress (completed-progress path), it suppresses them here to
    // avoid printing "Select projects"/"Scanning" twice.
    if options.include_task_checks {
        writeln!(
            &mut out,
            "{} Select projects to scan › {}",
            style.green("✔"),
            project_label(report)
        )
        .expect("write to string");
        if report.project_graph.diff.enabled {
            writeln!(
                &mut out,
                "{} Comparing diff{}.",
                style.green("✔"),
                diff_label(&report.project_graph.diff)
            )
            .expect("write to string");
        }
        writeln!(
            &mut out,
            "{}",
            style.dim(format!("Scanning {}...", report.root.display()))
        )
        .expect("write to string");
        render_task_checks(report, &mut out, style);
    }

    writeln!(&mut out).expect("write to string");
    render_score_banner(report, &mut out, style);

    if !report.score.caps.is_empty() {
        for cap in &report.score.caps {
            writeln!(
                &mut out,
                "  {}",
                style.yellow(format!(
                    "Score capped at {} because {}.",
                    cap.cap, cap.reason
                ))
            )
            .expect("write to string");
        }
    }

    writeln!(&mut out).expect("write to string");
    if report.findings.is_empty() {
        writeln!(&mut out, "  {}", style.green("No issues found!")).expect("write to string");
    } else {
        render_summary_line(report, &mut out, style);
        writeln!(&mut out).expect("write to string");
        render_grouped_findings(report, &mut out, options.include_verbose_hint, style);
    }

    writeln!(&mut out).expect("write to string");
    render_footer(report, &mut out, style);

    out
}

fn render_task_checks(report: &Report, out: &mut String, style: TuiStyle) {
    let ok = style.green("✔");
    writeln!(out).expect("write to string");
    writeln!(out, "{ok} Detecting backend stack.").expect("write to string");
    writeln!(out, "{ok} Running dependency and security checks.").expect("write to string");
    if report.project_graph.infra.is_empty() {
        writeln!(
            out,
            "{ok} Checking infrastructure. No infrastructure files found."
        )
        .expect("write to string");
    } else {
        writeln!(out, "{ok} Checking infrastructure files.").expect("write to string");
    }
    if report.project_graph.infra.open_api_specs.is_empty() {
        writeln!(out, "{ok} Checking API and configuration surfaces.").expect("write to string");
    } else {
        writeln!(
            out,
            "{ok} Checking API contracts and configuration surfaces."
        )
        .expect("write to string");
    }
    if report.config.external_tools.deep || !report.external_tool_executions.is_empty() {
        writeln!(out, "{ok} Running configured deep and external checks.")
            .expect("write to string");
    }
    writeln!(out, "{ok} Calculating Backend Doctor score.").expect("write to string");
}

fn render_grouped_findings(
    report: &Report,
    out: &mut String,
    include_verbose_hint: bool,
    style: TuiStyle,
) {
    let groups_by_category = finding_groups_by_category(&report.findings);
    let mut categories_by_impact = groups_by_category
        .iter()
        .filter(|(_, groups)| !groups.is_empty())
        .map(|(category, groups)| (category, groups.as_slice()))
        .collect::<Vec<_>>();
    categories_by_impact.sort_by(compare_category_impact);
    let displayed_categories = categories_by_impact
        .iter()
        .take(MAX_CATEGORY_SECTIONS)
        .copied()
        .collect::<Vec<_>>();
    let hidden_category_findings = categories_by_impact
        .iter()
        .skip(MAX_CATEGORY_SECTIONS)
        .flat_map(|(_, groups)| groups.iter())
        .map(|group| group.count)
        .sum::<usize>();

    for (category, groups) in displayed_categories {
        let category_count = groups.iter().map(|group| group.count).sum::<usize>();
        writeln!(
            out,
            "  {}  {}",
            style.bold(title_case(&category.to_string())),
            style.dim(category_count.to_string())
        )
        .expect("write to string");

        let shown = groups
            .iter()
            .take(MAX_RULE_GROUPS_PER_CATEGORY)
            .collect::<Vec<_>>();
        let label_width = shown
            .iter()
            .map(|group| group_label(group).chars().count())
            .max()
            .unwrap_or(0)
            .min(52);
        for group in &shown {
            let plain_label = group_label(group);
            let pad = " ".repeat(label_width.saturating_sub(plain_label.chars().count()));
            let count_suffix = if group.count > 1 {
                style.dim(format!(" ×{}", group.count))
            } else {
                String::new()
            };
            let location = group
                .location
                .as_ref()
                .map(|location| format!("  {}", style.cyan(location.display())))
                .unwrap_or_default();
            writeln!(
                out,
                "    {} {}   {}{}{}{}",
                severity_marker(&group.severity, style),
                severity_tag(&group.severity, style),
                group.title,
                count_suffix,
                pad,
                location
            )
            .expect("write to string");
            let remediation = group.remediation.trim();
            if !remediation.is_empty() {
                writeln!(out, "{ROW_INDENT}{}", style.dim(remediation)).expect("write to string");
            }
        }

        let hidden_in_category = groups
            .iter()
            .skip(MAX_RULE_GROUPS_PER_CATEGORY)
            .map(|group| group.count)
            .sum::<usize>();
        if hidden_in_category > 0 {
            writeln!(
                out,
                "    {}",
                style.dim(format!(
                    "... {} in {}",
                    count_label(hidden_in_category, "finding", "findings"),
                    category
                ))
            )
            .expect("write to string");
        }
        writeln!(out).expect("write to string");
    }

    if hidden_category_findings > 0 {
        writeln!(
            out,
            "  {}",
            style.dim(format!(
                "... {} in additional categories",
                count_label(hidden_category_findings, "finding", "findings")
            ))
        )
        .expect("write to string");
    }

    if include_verbose_hint
        && report.findings.len() > displayed_finding_count(&categories_by_impact)
    {
        writeln!(
            out,
            "  {}",
            style.dim(
                "Run with --verbose to see every finding, or --json for machine-readable output."
            )
        )
        .expect("write to string");
    }
    if report.summary.safe_fixes > 0 {
        writeln!(
            out,
            "  {}",
            style.cyan(format!(
                "Preview {} with --fix-safe --dry-run or --fix-safe; apply with --fix-safe --yes.",
                count_label(report.summary.safe_fixes, "safe fix", "safe fixes")
            ))
        )
        .expect("write to string");
    }
}

fn render_score_banner(report: &Report, out: &mut String, style: TuiStyle) {
    writeln!(
        out,
        "  {}   {} / 100 {}",
        style.bold("Backend Doctor"),
        score_value(report.score.value, style),
        score_label(report.score.value, &report.label, style)
    )
    .expect("write to string");
    writeln!(
        out,
        "  {}  {}",
        score_bar(report.score.value, style),
        score_color(report.score.value, style, grade_letter(report.score.value))
    )
    .expect("write to string");
}

fn render_summary_line(report: &Report, out: &mut String, style: TuiStyle) {
    let mut parts = Vec::new();
    let languages = detected_languages(report);
    if !languages.is_empty() {
        parts.push(style.bold(display_list(&languages)));
    }
    parts.push(count_label(report.services.len(), "service", "services"));
    parts.push(count_label(
        report.project_graph.inventory.total_files,
        "file",
        "files",
    ));
    let counts = severity_counts(&report.findings);
    if counts.critical > 0 {
        parts.push(style.red(format!("{} crit", counts.critical)));
    }
    if counts.high > 0 {
        parts.push(style.red(format!("{} high", counts.high)));
    }
    if counts.medium > 0 {
        parts.push(style.yellow(format!("{} med", counts.medium)));
    }
    if counts.low > 0 {
        parts.push(style.cyan(format!("{} low", counts.low)));
    }
    writeln!(out, "  {}", parts.join(&style.dim(" · "))).expect("write to string");
    writeln!(out, "  {}", style.dim("─".repeat(44))).expect("write to string");
}

fn render_footer(report: &Report, out: &mut String, style: TuiStyle) {
    writeln!(
        out,
        "{}",
        style.dim(format!(
            "{} across {} in {}",
            count_label(report.findings.len(), "issue", "issues"),
            count_label(finding_file_count(&report.findings), "file", "files"),
            format_duration(report.duration_ms)
        ))
    )
    .expect("write to string");
    writeln!(
        out,
        "{}",
        style.dim(
            "Run with --verbose for full diagnostics, --json/--json-out for reports, or --score for numeric-only output."
        )
    )
    .expect("write to string");
}

fn score_value(score: u8, style: TuiStyle) -> String {
    score_color(score, style, score.to_string())
}

fn score_label(score: u8, label: &str, style: TuiStyle) -> String {
    score_color(score, style, label)
}

fn score_color(score: u8, style: TuiStyle, value: impl AsRef<str>) -> String {
    match score {
        80..=100 => style.green(value),
        50..=79 => style.yellow(value),
        _ => style.red(value),
    }
}

fn score_bar(score: u8, style: TuiStyle) -> String {
    let width = 48usize;
    let filled = (usize::from(score) * width + 50) / 100;
    let empty = width.saturating_sub(filled);
    score_color(
        score,
        style,
        format!("{}{}", "█".repeat(filled), "░".repeat(empty)),
    )
}

fn severity_marker(severity: &Severity, style: TuiStyle) -> String {
    match severity {
        Severity::Critical | Severity::Error => style.red("⚠"),
        Severity::Warning => style.yellow("⚠"),
        Severity::Info | Severity::Note => style.cyan("ⓘ"),
    }
}

#[derive(Clone, Debug)]
struct FindingGroup {
    title: String,
    remediation: String,
    severity: Severity,
    location: Option<Location>,
    count: usize,
}

fn finding_groups_by_category(
    findings: &[Finding],
) -> BTreeMap<backend_doctor_core::Category, Vec<FindingGroup>> {
    let mut categories: BTreeMap<_, BTreeMap<(String, String), FindingGroup>> = BTreeMap::new();
    for finding in findings {
        let groups = categories.entry(finding.category.clone()).or_default();
        let key = (finding.rule_id.clone(), finding.title.clone());
        groups
            .entry(key)
            .and_modify(|group| {
                group.count += 1;
                if finding.severity.rank() < group.severity.rank() {
                    group.severity = finding.severity.clone();
                }
            })
            .or_insert_with(|| FindingGroup {
                title: finding.title.clone(),
                remediation: finding.remediation.clone(),
                severity: finding.severity.clone(),
                location: finding.location.clone(),
                count: 1,
            });
    }

    categories
        .into_iter()
        .map(|(category, groups)| {
            let mut groups = groups.into_values().collect::<Vec<_>>();
            groups.sort_by(|left, right| {
                left.severity
                    .rank()
                    .cmp(&right.severity.rank())
                    .then_with(|| right.count.cmp(&left.count))
                    .then_with(|| left.title.cmp(&right.title))
            });
            (category, groups)
        })
        .collect()
}

fn compare_category_impact(
    left: &(&backend_doctor_core::Category, &[FindingGroup]),
    right: &(&backend_doctor_core::Category, &[FindingGroup]),
) -> std::cmp::Ordering {
    category_worst_severity(left.1)
        .cmp(&category_worst_severity(right.1))
        .then_with(|| category_finding_count(right.1).cmp(&category_finding_count(left.1)))
        .then_with(|| left.0.to_string().cmp(&right.0.to_string()))
}

fn category_worst_severity(groups: &[FindingGroup]) -> u8 {
    groups
        .iter()
        .map(|group| group.severity.rank())
        .min()
        .unwrap_or(u8::MAX)
}

fn category_finding_count(groups: &[FindingGroup]) -> usize {
    groups.iter().map(|group| group.count).sum()
}

fn displayed_finding_count(
    categories_by_impact: &[(&backend_doctor_core::Category, &[FindingGroup])],
) -> usize {
    categories_by_impact
        .iter()
        .take(MAX_CATEGORY_SECTIONS)
        .flat_map(|(_, groups)| groups.iter().take(MAX_RULE_GROUPS_PER_CATEGORY))
        .map(|group| group.count)
        .sum()
}

fn finding_file_count(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter_map(|finding| finding.location.as_ref())
        .map(|location| location.path.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

fn grade_letter(score: u8) -> &'static str {
    match score {
        90..=100 => "A",
        80..=89 => "B",
        70..=79 => "C",
        60..=69 => "D",
        _ => "F",
    }
}

fn severity_word(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "crit",
        Severity::Error => "high",
        Severity::Warning => "med",
        Severity::Info => "info",
        Severity::Note => "note",
    }
}

fn severity_tag(severity: &Severity, style: TuiStyle) -> String {
    let label = format!("{:<4}", severity_word(severity));
    match severity {
        Severity::Critical | Severity::Error => style.red(label),
        Severity::Warning => style.yellow(label),
        Severity::Info | Severity::Note => style.cyan(label),
    }
}

#[derive(Clone, Copy, Default)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
}

fn severity_counts(findings: &[Finding]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for finding in findings {
        match finding.severity {
            Severity::Critical => counts.critical += 1,
            Severity::Error => counts.high += 1,
            Severity::Warning => counts.medium += 1,
            Severity::Info | Severity::Note => counts.low += 1,
        }
    }
    counts
}

/// Plain (uncolored) text of a finding row's title cell, used to compute the
/// alignment padding before the trailing location column.
fn group_label(group: &FindingGroup) -> String {
    if group.count > 1 {
        format!("{} ×{}", group.title, group.count)
    } else {
        group.title.clone()
    }
}

fn title_case(value: &str) -> String {
    let mut characters = value.chars();
    match characters.next() {
        Some(first) => format!("{}{}", first.to_ascii_uppercase(), characters.as_str()),
        None => String::new(),
    }
}

fn count_label(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

fn detected_languages(report: &Report) -> Vec<String> {
    if !report.project_graph.languages.is_empty() {
        report
            .project_graph
            .languages
            .iter()
            .map(|language| language.name.clone())
            .collect()
    } else {
        report
            .coverage
            .languages
            .iter()
            .map(|language| language.language.clone())
            .collect()
    }
}

fn project_label(report: &Report) -> String {
    report
        .root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| report.root.display().to_string())
}

fn diff_label(diff: &backend_doctor_core::DiffInventory) -> String {
    match &diff.base {
        Some(base) if diff.fallback_full_scan => {
            format!(" against {base}; full scan fallback")
        }
        Some(base) => format!(" against {base}"),
        None if diff.fallback_full_scan => "; full scan fallback".to_string(),
        None => String::new(),
    }
}

fn format_duration(duration_ms: u128) -> String {
    if duration_ms < 1_000 {
        format!("{duration_ms}ms")
    } else {
        let seconds = duration_ms as f64 / 1_000.0;
        format!("{seconds:.1}s")
    }
}

pub fn render_verbose(report: &Report) -> String {
    render_verbose_with_options(
        report,
        TerminalRenderOptions {
            include_verbose_hint: false,
            ..TerminalRenderOptions::default()
        },
    )
}

pub fn render_verbose_with_sidecars(
    report: &Report,
    json_out: Option<&Path>,
    sarif_out: Option<&Path>,
) -> String {
    let style = TuiStyle::new(false);
    let mut out = render_verbose(report);
    render_sidecar_paths(&mut out, json_out, sarif_out, style);
    out
}

fn render_verbose_with_options(report: &Report, options: TerminalRenderOptions) -> String {
    let mut out = render_terminal_report_with_options(report, options);
    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "Services").expect("write to string");
    if report.services.is_empty() {
        writeln!(&mut out, "  none detected").expect("write to string");
    } else {
        for service in &report.services {
            let languages = display_list(&service.languages);
            let frameworks = display_list(&service.frameworks);
            writeln!(
                &mut out,
                "  {}  {}  languages: {}  frameworks: {}",
                service.id,
                service.path.display(),
                languages,
                frameworks
            )
            .expect("write to string");
        }
    }

    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "Coverage").expect("write to string");
    if report.coverage.languages.is_empty() {
        writeln!(&mut out, "  no languages detected").expect("write to string");
    } else {
        for language in &report.coverage.languages {
            writeln!(
                &mut out,
                "  {}  tier: {}  maturity: {}  files: {}",
                language.language, language.tier, language.maturity, language.detected_files
            )
            .expect("write to string");
            writeln!(&mut out, "    {}", language.notes).expect("write to string");
        }
    }

    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "Agent Slop Index").expect("write to string");
    writeln!(
        &mut out,
        "  {} / 100  {} observable slop-pattern findings",
        report.slop.index, report.slop.findings
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  placeholderTests={} productionPlaceholders={} semanticCopyPaste={} spaghettiControlFlow={} swallowedErrors={}",
        report.slop.placeholder_tests,
        report.slop.production_placeholders,
        report.slop.semantic_copy_paste,
        report.slop.spaghetti_control_flow,
        report.slop.swallowed_errors
    )
    .expect("write to string");

    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "Project graph").expect("write to string");
    writeln!(&mut out, "  root: {}", report.project_graph.root.display()).expect("write to string");
    writeln!(
        &mut out,
        "  workspace root: {}",
        report.project_graph.workspace_root.display()
    )
    .expect("write to string");
    if let Some(git_root) = &report.project_graph.git_root {
        writeln!(&mut out, "  git root: {}", git_root.display()).expect("write to string");
    }
    writeln!(&mut out, "  monorepo: {}", report.project_graph.monorepo).expect("write to string");
    writeln!(
        &mut out,
        "  inventory: {} files, {} source, {} manifests, {} infra",
        report.project_graph.inventory.total_files,
        report.project_graph.inventory.source_files,
        report.project_graph.inventory.manifest_files,
        report.project_graph.inventory.infra_files
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  languages: {}",
        display_list(
            &report
                .project_graph
                .languages
                .iter()
                .map(|language| language.name.clone())
                .collect::<Vec<_>>()
        )
    )
    .expect("write to string");
    writeln!(
        &mut out,
        "  infra: docker={} compose={} kubernetes={} helm={} terraform={} githubActions={} gitlabCi={} openApiSpecs={} migrationFiles={}",
        report.project_graph.infra.dockerfiles.len(),
        report.project_graph.infra.compose_files.len(),
        report.project_graph.infra.kubernetes_files.len(),
        report.project_graph.infra.helm_charts.len(),
        report.project_graph.infra.terraform_files.len(),
        report.project_graph.infra.github_actions.len(),
        report.project_graph.infra.gitlab_ci.len(),
        report.project_graph.infra.open_api_specs.len(),
        report.project_graph.infra.migration_files.len()
    )
    .expect("write to string");
    if report.project_graph.diff.enabled {
        writeln!(
            &mut out,
            "  diff: base={} changed={} impacted={} fallbackFullScan={}",
            report.project_graph.diff.base.as_deref().unwrap_or(""),
            report.project_graph.diff.changed_files.len(),
            report.project_graph.diff.impacted_files.len(),
            report.project_graph.diff.fallback_full_scan
        )
        .expect("write to string");
    }
    writeln!(
        &mut out,
        "  ignores: {}",
        display_list(&report.project_graph.debug.ignored_patterns)
    )
    .expect("write to string");
    for decision in &report.project_graph.debug.decisions {
        writeln!(&mut out, "  decision: {decision}").expect("write to string");
    }
    for warning in &report.project_graph.debug.warnings {
        writeln!(&mut out, "  warning: {warning}").expect("write to string");
    }

    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "External tools").expect("write to string");
    if report.external_tool_versions.is_empty() && report.external_tool_executions.is_empty() {
        writeln!(&mut out, "  none executed").expect("write to string");
    } else {
        for version in &report.external_tool_versions {
            writeln!(
                &mut out,
                "  version: {} status={:?} value={}",
                version.tool,
                version.status,
                version.version.as_deref().unwrap_or("")
            )
            .expect("write to string");
        }
        for execution in &report.external_tool_executions {
            let cache_status = execution
                .cache
                .as_ref()
                .map_or("none", |cache| cache.status.as_str());
            writeln!(
                &mut out,
                "  execution: {} status={:?} exit={:?} durationMs={} cache={}",
                execution.invocation.command,
                execution.status,
                execution.exit_code,
                execution.duration_ms,
                cache_status
            )
            .expect("write to string");
        }
    }

    writeln!(&mut out).expect("write to string");
    writeln!(&mut out, "Findings").expect("write to string");
    if report.findings.is_empty() {
        writeln!(&mut out, "  none").expect("write to string");
        return out;
    }

    for finding in &report.findings {
        writeln!(
            &mut out,
            "\n[{}] {}",
            finding.severity.to_string().to_ascii_uppercase(),
            finding.rule_id
        )
        .expect("write to string");
        writeln!(&mut out, "Category: {}", finding.category).expect("write to string");
        writeln!(&mut out, "Confidence: {}", finding.confidence).expect("write to string");
        writeln!(&mut out, "Fix: {}", finding.fix.safety).expect("write to string");
        if let Some(location) = &finding.location {
            writeln!(&mut out, "File: {}", location.display()).expect("write to string");
        }
        writeln!(&mut out).expect("write to string");
        writeln!(&mut out, "Problem").expect("write to string");
        writeln!(&mut out, "  {}", finding.message).expect("write to string");
        if let Some(evidence) = &finding.evidence {
            writeln!(&mut out).expect("write to string");
            writeln!(&mut out, "Evidence").expect("write to string");
            writeln!(&mut out, "  {}", evidence.snippet).expect("write to string");
        }
        writeln!(&mut out).expect("write to string");
        writeln!(&mut out, "Recommended fix").expect("write to string");
        writeln!(&mut out, "  {}", finding.remediation).expect("write to string");
        if let Some(impact) = &finding.impact {
            writeln!(&mut out).expect("write to string");
            writeln!(&mut out, "Why this matters").expect("write to string");
            writeln!(&mut out, "  {impact}").expect("write to string");
        }
    }

    out
}

fn render_sidecar_paths(
    out: &mut String,
    json_out: Option<&Path>,
    sarif_out: Option<&Path>,
    style: TuiStyle,
) {
    if json_out.is_none() && sarif_out.is_none() {
        return;
    }

    writeln!(out).expect("write to string");
    writeln!(out, "{}", style.bold("Reports")).expect("write to string");
    if let Some(path) = json_out {
        writeln!(
            out,
            "  {} JSON report written to {}",
            style.green("✔"),
            style.cyan(path.display().to_string())
        )
        .expect("write to string");
    }
    if let Some(path) = sarif_out {
        writeln!(
            out,
            "  {} SARIF report written to {}",
            style.green("✔"),
            style.cyan(path.display().to_string())
        )
        .expect("write to string");
    }
}

pub fn render_json(report: &Report) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn render_sarif(report: &Report) -> Result<String, serde_json::Error> {
    let document = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Backend Doctor",
                        "version": report.tool_version,
                        "semanticVersion": report.tool_version,
                        "rules": sarif_rules(report),
                    }
                },
                "automationDetails": {
                    "id": sarif_run_automation_id(report),
                },
                "results": report.findings.iter().map(sarif_result).collect::<Vec<_>>(),
            }
        ],
    });

    serde_json::to_string_pretty(&document)
}

pub fn render_github_annotations(report: &Report) -> String {
    report
        .findings
        .iter()
        .map(github_annotation)
        .collect::<Vec<_>>()
        .join("\n")
}

fn sarif_rules(report: &Report) -> Vec<Value> {
    let mut rules = BTreeMap::new();
    for finding in &report.findings {
        rules.entry(finding.rule_id.clone()).or_insert_with(|| {
            json!({
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {
                    "text": finding.title,
                },
                "fullDescription": {
                    "text": finding.message,
                },
                "defaultConfiguration": {
                    "level": sarif_level(&finding.severity),
                },
                "properties": {
                    "category": finding.category.to_string(),
                    "confidence": finding.confidence.to_string(),
                    "sourceTool": finding.source_tool,
                },
            })
        });
    }
    rules.into_values().collect()
}

fn sarif_result(finding: &Finding) -> Value {
    let mut result = Map::new();
    result.insert("ruleId".to_string(), json!(finding.rule_id));
    result.insert("level".to_string(), json!(sarif_level(&finding.severity)));
    result.insert(
        "message".to_string(),
        json!({
            "text": finding.message,
        }),
    );
    result.insert(
        "partialFingerprints".to_string(),
        json!({
            "backendDoctorFingerprint": finding.fingerprint,
            "backendDoctorFindingId": finding.id,
        }),
    );
    if let Some(location) = &finding.location {
        result.insert("locations".to_string(), json!([sarif_location(location)]));
    }
    Value::Object(result)
}

fn sarif_location(location: &Location) -> Value {
    let mut physical_location = Map::new();
    physical_location.insert(
        "artifactLocation".to_string(),
        json!({
            "uri": path_uri(location),
        }),
    );

    let mut region = Map::new();
    if let Some(line) = location.line.filter(|line| *line > 0) {
        region.insert("startLine".to_string(), json!(line));
    }
    if let Some(column) = location.column.filter(|column| *column > 0) {
        region.insert("startColumn".to_string(), json!(column));
    }
    if let Some(line) = location.end_line.filter(|line| *line > 0) {
        region.insert("endLine".to_string(), json!(line));
    }
    if let Some(column) = location.end_column.filter(|column| *column > 0) {
        region.insert("endColumn".to_string(), json!(column));
    }
    if !region.is_empty() {
        physical_location.insert("region".to_string(), Value::Object(region));
    }

    json!({
        "physicalLocation": Value::Object(physical_location),
    })
}

fn sarif_run_automation_id(report: &Report) -> String {
    let current_dir = std::env::current_dir().ok();
    let analysis_path = current_dir
        .as_deref()
        .and_then(|cwd| {
            cwd.ancestors()
                .filter(|ancestor| ancestor.parent().is_some())
                .find_map(|ancestor| report.root.strip_prefix(ancestor).ok())
        })
        .or_else(|| {
            report
                .project_graph
                .git_root
                .as_deref()
                .and_then(|git_root| report.root.strip_prefix(git_root).ok())
        })
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| {
            report
                .root
                .file_name()
                .map(Path::new)
                .unwrap_or_else(|| Path::new("repository"))
        });
    format!(
        "backend-doctor/{}",
        slug_path(analysis_path).unwrap_or_else(|| "repository".to_string())
    )
}

fn slug_path(path: &Path) -> Option<String> {
    let parts = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(slug_part(&value.to_string_lossy())),
            _ => None,
        })
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

fn slug_part(value: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    slug.trim_matches('-').to_string()
}

fn github_annotation(finding: &Finding) -> String {
    let command = match finding.severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning | Severity::Info | Severity::Note => "warning",
    };
    let mut properties = Vec::new();
    if let Some(location) = &finding.location {
        properties.push(format!(
            "file={}",
            escape_command_property(&path_uri(location))
        ));
        if let Some(line) = location.line {
            properties.push(format!("line={line}"));
        }
        if let Some(column) = location.column {
            properties.push(format!("col={column}"));
        }
    }
    properties.push(format!(
        "title={}",
        escape_command_property(&format!("{}: {}", finding.rule_id, finding.title))
    ));
    let property_text = if properties.is_empty() {
        String::new()
    } else {
        format!(" {}", properties.join(","))
    };
    format!(
        "::{command}{property_text}::{}",
        escape_command_data(&finding.message)
    )
}

fn sarif_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info | Severity::Note => "note",
    }
}

fn path_uri(location: &Location) -> String {
    location.path.to_string_lossy().replace('\\', "/")
}

fn escape_command_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_command_property(value: &str) -> String {
    escape_command_data(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{
        sample_finding, Category, Config, FixSafety, ProjectGraph, Report, ReportInput, ScanMode,
        Severity,
    };
    use chrono::Utc;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn summary_includes_score_and_empty_state() {
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("."),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from(".")),
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });

        let summary = render_summary(&report);
        assert!(summary.contains("backend-doctor v0.1.0"));
        assert!(summary.contains("✔ Select projects to scan › ."));
        assert!(summary.contains("Scanning ...."));
        let score_task = summary
            .lines()
            .find(|line| line.contains("Calculating Backend Doctor score"))
            .expect("score calculation task line");
        assert_eq!(score_task, "✔ Calculating Backend Doctor score.");
        assert!(!score_task.contains("Slop Index"));
        assert!(!score_task.contains("findings"));
        assert!(summary.contains("100 / 100 Excellent"));
        assert!(summary.contains("No issues found!"));
        assert!(summary.contains("Backend Doctor"));
        assert!(summary.contains("0 issues across 0 files in 1ms"));
    }

    #[test]
    fn colored_terminal_report_wraps_and_resets_ansi_styles() {
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("."),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from(".")),
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });

        let summary = render_terminal_report_with_color(&report, true);

        assert!(summary.contains("\u{1b}[36mbackend-doctor v0.1.0\u{1b}[0m"));
        assert!(summary.contains("\u{1b}[32m✔\u{1b}[0m Select projects to scan"));
        assert!(summary.contains("\u{1b}[32m100\u{1b}[0m / 100"));
        assert!(summary.contains("\u{1b}[32mNo issues found!\u{1b}[0m"));
    }

    #[test]
    fn terminal_report_groups_findings_by_category_and_rule() {
        let mut first = sample_finding(
            "finding-1",
            Severity::Error,
            Category::Security,
            "src/app.rs",
        );
        first.rule_id = "security/test-rule".to_string();
        first.title = "Unsafe value".to_string();
        first.message = "Avoid unsafe values.".to_string();
        first.remediation = "Validate and constrain inputs.".to_string();
        let mut second = first.clone();
        second.id = "finding-2".to_string();
        second.fingerprint = "sha256:finding-2".to_string();
        second.location.as_mut().expect("location").path = PathBuf::from("src/other.rs");
        let report = report_with_findings(vec![first, second]);

        let summary = render_terminal_report(&report);

        assert!(summary.contains("Security  2"));
        assert!(summary.contains("high"));
        assert!(summary.contains("Unsafe value ×2"));
        assert!(summary.contains("Validate and constrain inputs."));
        assert!(summary.contains("src/app.rs:1:1"));
        assert!(summary.contains("2 issues across 2 files in"));
    }

    #[test]
    fn terminal_report_safe_fix_hint_distinguishes_preview_from_apply() {
        let mut finding = sample_finding(
            "safe-fix",
            Severity::Warning,
            Category::Maintainability,
            "src/app.rs",
        );
        finding.fix.safety = FixSafety::Safe;
        let report = report_with_findings(vec![finding]);

        let summary = render_terminal_report(&report);

        assert!(summary.contains(
            "Preview 1 safe fix with --fix-safe --dry-run or --fix-safe; apply with --fix-safe --yes."
        ));
        assert!(!summary.contains("Run with --fix-safe to apply"));
    }

    #[test]
    fn terminal_report_truncates_large_rule_groups_with_hint() {
        let findings = (0..6)
            .map(|index| {
                let mut finding = sample_finding(
                    &format!("finding-{index}"),
                    Severity::Warning,
                    Category::Reliability,
                    &format!("src/file-{index}.rs"),
                );
                finding.rule_id = format!("reliability/rule-{index}");
                finding.title = format!("Reliability rule {index}");
                finding
            })
            .collect::<Vec<_>>();
        let report = report_with_findings(findings);

        let summary = render_terminal_report(&report);

        assert!(summary.contains("Reliability  6"));
        assert!(summary.contains("Reliability rule 0"));
        assert!(summary.contains("Reliability rule 3"));
        assert!(!summary.contains("Reliability rule 4"));
        assert!(summary.contains("... 2 findings in reliability"));
        assert!(summary.contains("Run with --verbose to see every finding"));
    }

    #[test]
    fn terminal_report_sorts_category_sections_by_impact_before_truncating() {
        let mut findings = [
            Category::Architecture,
            Category::Correctness,
            Category::Dependencies,
            Category::Infrastructure,
            Category::Reliability,
            Category::Security,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, category)| {
            let mut finding = sample_finding(
                &format!("finding-{index}"),
                Severity::Warning,
                category,
                &format!("src/category-{index}.rs"),
            );
            finding.rule_id = format!("category/rule-{index}");
            finding.title = format!("Category rule {index}");
            finding
        })
        .collect::<Vec<_>>();
        let mut critical = sample_finding(
            "finding-critical-late-category",
            Severity::Critical,
            Category::Maintainability,
            "src/late-critical.rs",
        );
        critical.rule_id = "maintainability/critical-late-rule".to_string();
        critical.title = "Late critical rule".to_string();
        findings.push(critical);
        let report = report_with_findings(findings);

        let summary = render_terminal_report(&report);

        assert!(summary.contains("Maintainability  1"));
        assert!(summary.contains("crit"));
        assert!(summary.contains("Late critical rule"));
        assert!(!summary.contains("Security"));
        assert!(summary.contains("... 1 finding in additional categories"));
    }

    #[test]
    fn verbose_omits_truncated_summary_verbose_hint() {
        let findings = (0..6)
            .map(|index| {
                let mut finding = sample_finding(
                    &format!("finding-{index}"),
                    Severity::Warning,
                    Category::Reliability,
                    &format!("src/file-{index}.rs"),
                );
                finding.rule_id = format!("reliability/rule-{index}");
                finding.title = format!("Reliability rule {index}");
                finding
            })
            .collect::<Vec<_>>();
        let report = report_with_findings(findings);

        let verbose = render_verbose(&report);

        assert!(!verbose.contains("Run with --verbose to see every finding"));
        assert!(verbose.contains("[WARNING] reliability/rule-5"));
    }

    #[test]
    fn verbose_includes_services_and_findings_sections() {
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("."),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from(".")),
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });

        let verbose = render_verbose(&report);
        assert!(verbose.contains("Services"));
        assert!(verbose.contains("Coverage"));
        assert!(verbose.contains("Agent Slop Index"));
        assert!(verbose.contains("0 / 100  0 observable slop-pattern findings"));
        assert!(verbose.contains("Findings"));
        assert!(verbose.contains("  none"));
    }

    #[test]
    fn verbose_includes_complete_agent_slop_breakdown() {
        let mut semantic = sample_finding(
            "semantic-copy-paste",
            Severity::Info,
            Category::Architecture,
            "src/dto.rs",
        );
        semantic.rule_id = "agent/semantic-copy-paste".to_string();
        let mut spaghetti = sample_finding(
            "spaghetti-control-flow",
            Severity::Warning,
            Category::Architecture,
            "src/controller.rs",
        );
        spaghetti.rule_id = "agent/spaghetti-control-flow".to_string();
        let report = report_with_findings(vec![semantic, spaghetti]);

        let verbose = render_verbose(&report);

        assert!(verbose.contains("40 / 100  2 observable slop-pattern findings"));
        assert!(verbose.contains(
            "placeholderTests=0 productionPlaceholders=0 semanticCopyPaste=1 spaghettiControlFlow=1 swallowedErrors=0"
        ));
    }

    #[test]
    fn sidecar_aware_human_renderers_show_report_paths_without_changing_machine_output() {
        let report = report_with_findings(Vec::new());
        let json_path = PathBuf::from("target/backend-doctor/report.json");
        let sarif_path = PathBuf::from("target/backend-doctor/report.sarif");

        let summary = render_terminal_report_with_color_and_sidecars(
            &report,
            false,
            Some(&json_path),
            Some(&sarif_path),
        );
        assert!(summary.contains("Reports"));
        assert!(summary.contains("JSON report written to target/backend-doctor/report.json"));
        assert!(summary.contains("SARIF report written to target/backend-doctor/report.sarif"));

        let verbose = render_verbose_with_sidecars(&report, Some(&json_path), Some(&sarif_path));
        assert!(verbose.contains("Findings"));
        assert!(verbose.contains("JSON report written to target/backend-doctor/report.json"));

        let json = render_json(&report).expect("json renders");
        let sarif = render_sarif(&report).expect("sarif renders");
        assert!(!json.contains("report.json"));
        assert!(!sarif.contains("report.sarif"));
        assert_sarif_schema_valid("sidecar unaffected", &sarif);
    }

    #[test]
    fn sarif_maps_findings_to_rules_results_locations_and_fingerprints() {
        let mut finding = sample_finding(
            "finding-1",
            Severity::Error,
            Category::Security,
            "src/app.rs",
        );
        finding.rule_id = "security/test-rule".to_string();
        finding.title = "Unsafe value".to_string();
        finding.message = "Avoid TOKEN=[REDACTED] in source".to_string();
        finding.location.as_mut().expect("location").line = Some(7);
        finding.location.as_mut().expect("location").column = Some(3);
        let report = report_with_findings(vec![finding]);

        let sarif = render_sarif(&report).expect("sarif renders");
        let value: serde_json::Value = serde_json::from_str(&sarif).expect("sarif json");

        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "Backend Doctor");
        assert_eq!(
            value["runs"][0]["automationDetails"]["id"],
            "backend-doctor/repository"
        );
        assert_eq!(
            value["runs"][0]["tool"]["driver"]["rules"][0]["id"],
            "security/test-rule"
        );
        let result = &value["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "security/test-rule");
        assert_eq!(result["level"], "error");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/app.rs"
        );
        assert_eq!(
            result["partialFingerprints"]["backendDoctorFingerprint"],
            "sha256:finding-1"
        );
        assert!(!sarif.contains("TOKEN=raw"));
    }

    #[test]
    fn sarif_output_matches_oasis_2_1_0_schema() {
        let mut finding = sample_finding(
            "finding-1",
            Severity::Warning,
            Category::Security,
            "src/app.rs",
        );
        finding.rule_id = "security/test-rule".to_string();
        finding.title = "Unsafe value".to_string();
        finding.message = "Avoid TOKEN=[REDACTED] in source".to_string();
        finding.location.as_mut().expect("location").line = Some(7);
        finding.location.as_mut().expect("location").column = Some(3);
        let report = report_with_findings(vec![finding]);

        let sarif = render_sarif(&report).expect("sarif renders");
        assert!(!sarif.contains("TOKEN=raw"));
        assert_sarif_schema_valid("representative report", &sarif);
    }

    #[test]
    fn sarif_run_automation_id_is_repo_relative_and_unique_by_scan_root() {
        let first = report_with_root(PathBuf::from("/repo/fixtures/go-bad-service"));
        let second = report_with_root(PathBuf::from("/repo/fixtures/node-express-bad-service"));

        let first_sarif = render_sarif(&first).expect("first sarif renders");
        let second_sarif = render_sarif(&second).expect("second sarif renders");
        let first_value: serde_json::Value =
            serde_json::from_str(&first_sarif).expect("first sarif json");
        let second_value: serde_json::Value =
            serde_json::from_str(&second_sarif).expect("second sarif json");

        let first_id = &first_value["runs"][0]["automationDetails"]["id"];
        let second_id = &second_value["runs"][0]["automationDetails"]["id"];
        assert_eq!(first_id, "backend-doctor/fixtures/go-bad-service");
        assert_eq!(
            second_id,
            "backend-doctor/fixtures/node-express-bad-service"
        );
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn github_annotations_escape_properties_and_message_data() {
        let mut finding = sample_finding(
            "finding-1",
            Severity::Warning,
            Category::Security,
            "src/app:1,2.rs",
        );
        finding.rule_id = "security/test-rule".to_string();
        finding.title = "Bad, title: unsafe".to_string();
        finding.message = "Line 1 % TOKEN=RawSecret12345".to_string();
        let mut report = report_with_findings(vec![finding]);
        report.findings[0].message.push_str("\nNext\rLine");

        let annotations = render_github_annotations(&report);

        assert!(annotations.starts_with("::warning "));
        assert!(annotations.contains("file=src/app%3A1%2C2.rs"));
        assert!(annotations.contains("title=security/test-rule%3A Bad%2C title%3A unsafe"));
        assert!(annotations.contains("Line 1 %25 TOKEN=[REDACTED]%0ANext%0DLine"));
        assert!(!annotations.contains("Line 1 % TOKEN=[REDACTED]\nNext\rLine"));
        assert!(!annotations.contains("RawSecret12345"));
    }

    #[test]
    fn report_generation_and_rendering_perf_smoke_10000_findings() {
        const FINDING_COUNT: usize = 10_000;
        const MAX_ELAPSED: Duration = Duration::from_secs(20);

        let findings = (0..FINDING_COUNT)
            .map(|index| {
                let severity = match index % 4 {
                    0 => Severity::Critical,
                    1 => Severity::Error,
                    2 => Severity::Warning,
                    _ => Severity::Info,
                };
                let category = match index % 5 {
                    0 => Category::Security,
                    1 => Category::Reliability,
                    2 => Category::Correctness,
                    3 => Category::Testing,
                    _ => Category::Maintainability,
                };
                let id = format!("perf-finding-{index:05}");
                let path = format!("src/module-{}/file-{}.rs", index % 100, index % 1_000);
                let mut finding = sample_finding(&id, severity, category, &path);
                finding.rule_id = format!("perf/rule-{}", index % 50);
                finding.title = format!("Synthetic finding {}", index % 50);
                finding.message =
                    "Synthetic performance smoke finding with deterministic text.".to_string();
                finding.remediation =
                    "Keep report generation and rendering linear for large reports.".to_string();
                finding
            })
            .collect::<Vec<_>>();

        let started = Instant::now();
        let report = Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("."),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from(".")),
            findings,
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        });
        let json = render_json(&report).expect("json renders");
        let verbose = render_verbose(&report);
        let elapsed = started.elapsed();

        assert_eq!(report.findings.len(), FINDING_COUNT);
        assert!(json.contains("\"findings\""));
        assert!(verbose.contains("Findings"));
        assert!(
            elapsed <= MAX_ELAPSED,
            "rendering {FINDING_COUNT} synthetic findings took {elapsed:?}, expected <= {MAX_ELAPSED:?}"
        );
    }

    fn assert_sarif_schema_valid(name: &str, sarif: &str) {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/sarif-schema-2.1.0.json"))
                .expect("parse vendored OASIS SARIF schema");
        let sarif: Value = serde_json::from_str(sarif).expect("parse generated SARIF json");
        let validator = jsonschema::validator_for(&schema).expect("compile SARIF schema");
        let evaluation = validator.evaluate(&sarif);
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
        panic!("{name} failed OASIS SARIF 2.1.0 schema validation:\n{errors}");
    }

    fn report_with_findings(findings: Vec<backend_doctor_core::Finding>) -> Report {
        Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root: PathBuf::from("."),
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: ProjectGraph::empty(PathBuf::from(".")),
            findings,
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        })
    }

    fn report_with_root(root: PathBuf) -> Report {
        let mut graph = ProjectGraph::empty(root.clone());
        graph.git_root = Some(PathBuf::from("/repo"));
        graph.workspace_root = PathBuf::from("/repo");
        Report::new(ReportInput {
            tool_version: "0.1.0".to_string(),
            started_at: Utc::now(),
            duration: Duration::from_millis(1),
            root,
            mode: ScanMode::Full,
            services: Vec::new(),
            project_graph: graph,
            findings: Vec::new(),
            config: Config::default(),
            external_tool_versions: Vec::new(),
            external_tool_executions: Vec::new(),
        })
    }
}
