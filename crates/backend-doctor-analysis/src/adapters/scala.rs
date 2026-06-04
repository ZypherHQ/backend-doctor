use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, DataSourceFact, DataSourceKind, ImportFact,
    ImportKind, RouteFact, SanitizerFact, SanitizerKind, SinkFact, SinkKind, SourceFileFact,
    SourcePosition, SourceRange, SymbolFact, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::common::{add_local_taint_edges, facts_with_source, join_paths};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct ScalaAdapter;

impl SourceAdapter for ScalaAdapter {
    fn id(&self) -> &'static str {
        "scala-text-tier-c"
    }

    fn language(&self) -> &'static str {
        "Scala"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        let language = source_file.language.to_ascii_lowercase();
        matches!(language.as_str(), "scala" | "play" | "http4s" | "akka-http")
            || source_file
                .path
                .extension()
                .is_some_and(|extension| extension == "scala")
            || source_file.path.ends_with("conf/routes")
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let lines = source_lines(input.contents);
        let mut facts = facts_with_source(&input);
        let imports = collect_imports(&mut facts, input.source_file, &lines);
        let symbols = collect_symbols(&mut facts, input.source_file, &lines);
        if is_play_routes_file(input.source_file) {
            collect_play_routes_file(&mut facts, input.source_file, &lines);
        }
        collect_play_controller_facts(&mut facts, input.source_file, &lines, &symbols);
        collect_http4s_routes(&mut facts, input.source_file, &lines, &symbols);
        collect_akka_http_routes(&mut facts, input.source_file, &lines, &symbols);
        collect_calls_sources_and_flows(&mut facts, input.source_file, &lines, &symbols, &imports);
        add_local_taint_edges(&mut facts);
        Ok(facts)
    }
}

#[derive(Clone, Debug)]
struct SourceLine<'a> {
    number: u32,
    start_byte: usize,
    text: &'a str,
}

#[derive(Clone, Debug)]
struct LineSymbol {
    id: String,
    start_line: u32,
    end_line: u32,
}

#[derive(Clone, Debug)]
struct AkkaScope {
    depth: i32,
    path: Option<String>,
}

#[derive(Clone, Debug)]
struct PendingHttp4sRoute {
    line_number: u32,
    method: String,
    path: String,
    range: Option<SourceRange>,
    symbol_id: Option<String>,
}

fn source_lines(source: &str) -> Vec<SourceLine<'_>> {
    let mut lines = Vec::new();
    let mut start_byte = 0;
    for (index, line) in source.split('\n').enumerate() {
        lines.push(SourceLine {
            number: u32::try_from(index + 1).unwrap_or(u32::MAX),
            start_byte,
            text: line,
        });
        start_byte += line.len() + 1;
    }
    lines
}

fn collect_imports(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
) -> BTreeSet<String> {
    let mut imports = BTreeSet::new();
    for line in lines {
        let trimmed = line.text.trim();
        let Some(module) = trimmed.strip_prefix("import ") else {
            continue;
        };
        let module = module.trim().to_string();
        if module.is_empty() {
            continue;
        }
        imports.insert(module.clone());
        facts.imports.push(ImportFact {
            id: stable_fact_id(
                "import",
                [file.id.as_str(), module.as_str(), &line.number.to_string()],
            ),
            file_id: Some(file.id.clone()),
            module,
            alias: None,
            imported_symbols: Vec::new(),
            kind: ImportKind::Package,
            range: range_for_line(line),
            metadata: metadata("adapter", "scala"),
        });
    }
    imports
}

fn collect_symbols(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
) -> Vec<LineSymbol> {
    let mut symbols = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.text.trim_start();
        let parsed = if let Some(name) = declaration_name(trimmed, "class ") {
            Some((name, SymbolKind::Class))
        } else if let Some(name) = declaration_name(trimmed, "object ") {
            Some((name, SymbolKind::Module))
        } else if let Some(name) = declaration_name(trimmed, "trait ") {
            Some((name, SymbolKind::Interface))
        } else if let Some(name) = scala_def_name(trimmed) {
            Some((name, SymbolKind::Function))
        } else {
            val_name(trimmed).map(|name| (name, SymbolKind::Variable))
        };

        let Some((name, kind)) = parsed else {
            continue;
        };
        let end_line = block_end_line(lines, index);
        let id = stable_fact_id(
            "symbol",
            [
                file.id.as_str(),
                name.as_str(),
                &line.number.to_string(),
                &end_line.to_string(),
            ],
        );
        facts.symbols.push(SymbolFact {
            id: id.clone(),
            file_id: file.id.clone(),
            name: name.clone(),
            kind,
            range: range_for_line(line),
            signature: Some(trimmed.to_string()),
            visibility: visibility(trimmed),
            parent_symbol_id: containing_symbol_id(&symbols, line.number),
            metadata: metadata("adapter", "scala"),
        });
        symbols.push(LineSymbol {
            id,
            start_line: line.number,
            end_line,
        });
    }
    symbols
}

fn collect_play_routes_file(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
) {
    for line in lines {
        let trimmed = line.text.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = trimmed.split_whitespace().collect();
        if columns.len() < 3 || !is_http_method(columns[0]) {
            continue;
        }
        let method = columns[0];
        let path = normalize_play_path(columns[1]);
        let action = columns[2];
        let symbol_id = push_route_file_action_symbol(facts, file, line, action);
        let mut route_metadata = metadata("adapter", "scala");
        route_metadata.insert("source".to_string(), "conf/routes".to_string());
        facts.routes.push(RouteFact {
            id: stable_fact_id(
                "route",
                [
                    file.id.as_str(),
                    method,
                    path.as_str(),
                    "Play",
                    &line.number.to_string(),
                ],
            ),
            file_id: Some(file.id.clone()),
            symbol_id: Some(symbol_id),
            service_id: file.service_id.clone(),
            method: method.to_string(),
            path,
            framework: Some("Play".to_string()),
            range: range_for_line(line),
            metadata: route_metadata,
        });
    }
}

fn collect_play_controller_facts(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
) {
    for line in lines {
        let trimmed = line.text.trim();
        if !(trimmed.contains("Action") || trimmed.contains("Action.async")) {
            continue;
        }
        if let Some(name) = scala_def_name(trimmed) {
            push_call(facts, file, symbols, line, "Action", Vec::new());
            let mut source_metadata = metadata("adapter", "scala");
            source_metadata.insert("framework".to_string(), "Play".to_string());
            if trimmed.contains("Request") || trimmed.contains("request") {
                push_data_source(
                    facts,
                    file,
                    symbols,
                    line,
                    DataSourceKind::Request,
                    &format!("{name}.request"),
                    None,
                    source_metadata,
                );
            }
        }
    }
}

fn collect_http4s_routes(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
) {
    let prefixes = router_prefixes(lines);
    let mut routes = Vec::new();
    for line in lines {
        let trimmed = line.text.trim();
        let Some((method, path)) = parse_http4s_case(trimmed) else {
            continue;
        };
        routes.push(PendingHttp4sRoute {
            line_number: line.number,
            method,
            path,
            range: range_for_line(line),
            symbol_id: containing_symbol_id(symbols, line.number),
        });
    }

    for route in routes {
        let emitted_paths = if prefixes.len() == 1 {
            vec![join_paths(Some(&prefixes[0]), Some(&route.path))]
        } else {
            vec![route.path.clone()]
        };
        for path in emitted_paths {
            let mut route_metadata = metadata("adapter", "scala");
            route_metadata.insert("dsl".to_string(), "HttpRoutes.of".to_string());
            if prefixes.len() == 1 {
                route_metadata.insert("routerPrefix".to_string(), prefixes[0].clone());
            }
            facts.routes.push(RouteFact {
                id: stable_fact_id(
                    "route",
                    [
                        file.id.as_str(),
                        route.method.as_str(),
                        path.as_str(),
                        "http4s",
                        &route.line_number.to_string(),
                    ],
                ),
                file_id: Some(file.id.clone()),
                symbol_id: route.symbol_id.clone(),
                service_id: file.service_id.clone(),
                method: route.method.clone(),
                path,
                framework: Some("http4s".to_string()),
                range: route.range.clone(),
                metadata: route_metadata,
            });
        }
    }
}

fn collect_akka_http_routes(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
) {
    let mut scopes = Vec::<AkkaScope>::new();
    let mut depth = 0_i32;

    for line in lines {
        let trimmed = strip_line_comment(line.text);
        if starts_directive(&trimmed, "path") || starts_directive(&trimmed, "pathPrefix") {
            if let Some(path) = akka_path_argument(&trimmed) {
                if trimmed.contains('{') {
                    scopes.push(AkkaScope {
                        depth: depth + 1,
                        path: Some(path),
                    });
                }
            }
        }

        for (directive, method) in [
            ("get", "GET"),
            ("post", "POST"),
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
        ] {
            if !starts_directive(&trimmed, directive) {
                continue;
            }
            if let Some(path) = current_akka_prefix(&scopes) {
                let mut route_metadata = metadata("adapter", "scala");
                route_metadata.insert("dsl".to_string(), "Akka HTTP directives".to_string());
                facts.routes.push(RouteFact {
                    id: stable_fact_id(
                        "route",
                        [
                            file.id.as_str(),
                            method,
                            path.as_str(),
                            "Akka HTTP",
                            &line.number.to_string(),
                        ],
                    ),
                    file_id: Some(file.id.clone()),
                    symbol_id: containing_symbol_id(symbols, line.number),
                    service_id: file.service_id.clone(),
                    method: method.to_string(),
                    path,
                    framework: Some("Akka HTTP".to_string()),
                    range: range_for_line(line),
                    metadata: route_metadata,
                });
            }
        }

        depth += brace_delta(&trimmed);
        scopes.retain(|scope| scope.depth <= depth);
    }
}

fn collect_calls_sources_and_flows(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
    imports: &BTreeSet<String>,
) {
    for line in lines {
        let trimmed = strip_line_comment(line.text);
        for call in invocation_names(&trimmed) {
            push_call(
                facts,
                file,
                symbols,
                line,
                &call,
                call_arguments(&trimmed, &call),
            );
            collect_flow_fact_from_call(facts, file, symbols, line, &call, &trimmed, imports);
        }

        if is_scala_request_source(&trimmed) {
            push_data_source(
                facts,
                file,
                symbols,
                line,
                DataSourceKind::Request,
                request_source_name(&trimmed),
                None,
                metadata("adapter", "scala"),
            );
        }
        if trimmed.contains("sql\"") || trimmed.contains("fr\"") || trimmed.contains("SQL(") {
            push_sink(
                facts,
                file,
                symbols,
                line,
                SinkKind::SqlQuery,
                "sql-interpolation",
                metadata("adapter", "scala"),
            );
        }
    }
}

fn collect_flow_fact_from_call(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    call: &str,
    line_text: &str,
    imports: &BTreeSet<String>,
) {
    let lower = call.to_ascii_lowercase();
    let final_segment = lower.rsplit('.').next().unwrap_or(lower.as_str());

    if (lower.contains("database.forconfig")
        || lower.contains("transactor")
        || lower.contains("dbio")
        || imports
            .iter()
            .any(|module| module.contains("slick.jdbc") || module.contains("doobie")))
        && matches!(final_segment, "forconfig" | "transactor" | "dbio" | "xa")
    {
        push_data_source(
            facts,
            file,
            symbols,
            line,
            DataSourceKind::Database,
            call,
            None,
            metadata("adapter", "scala"),
        );
    }

    if is_scala_sql_sink(&lower, final_segment, line_text) {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::SqlQuery,
            call,
            metadata("adapter", "scala"),
        );
    } else if matches!(final_segment, "ok" | "created" | "badrequest" | "complete") {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::HttpResponse,
            call,
            metadata("adapter", "scala"),
        );
    } else if matches!(final_segment, "redirect" | "seeother" | "found") {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::Redirect,
            call,
            metadata("adapter", "scala"),
        );
    }

    if lower.contains("security.authenticated")
        || lower.contains("authenticated")
        || lower.contains("authenticate")
        || lower.contains("authorize")
    {
        let kind = if lower.contains("authorize") {
            SanitizerKind::Authorization
        } else {
            SanitizerKind::Authentication
        };
        push_sanitizer(
            facts,
            file,
            symbols,
            line,
            kind,
            call,
            metadata("adapter", "scala"),
        );
    }
}

fn is_scala_sql_sink(lower: &str, final_segment: &str, line_text: &str) -> bool {
    matches!(
        final_segment,
        "run"
            | "execute"
            | "executequery"
            | "executeupdate"
            | "preparestatement"
            | "query"
            | "update"
    ) && (lower.contains("db")
        || lower.contains("sql")
        || lower.contains("query")
        || lower.contains("statement")
        || line_text.contains("DBIO")
        || line_text.contains("SQL(")
        || line_text.contains("sql\"")
        || line_text.contains("fr\""))
}

fn is_scala_request_source(text: &str) -> bool {
    text.contains("request.body")
        || text.contains("request.headers")
        || text.contains("request.cookies")
        || text.contains("request.queryString")
        || text.contains("request.getQueryString")
        || text.contains(".asJson")
        || text.contains("req.params")
        || text.contains("req.headers")
        || text.contains("Request[")
}

fn request_source_name(text: &str) -> &str {
    for marker in [
        "request.body",
        "request.headers",
        "request.cookies",
        "request.queryString",
        "request.getQueryString",
        ".asJson",
        "req.params",
        "req.headers",
        "Request[",
    ] {
        if text.contains(marker) {
            return marker;
        }
    }
    "request"
}

fn parse_http4s_case(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("case ")?;
    let (method, after_method) = rest.split_once(" -> ")?;
    if !is_http_method(method.trim()) {
        return None;
    }
    let pattern = after_method.split("=>").next()?.trim();
    let root = pattern.strip_prefix("Root")?.trim();
    let path = http4s_path_from_root(root);
    Some((method.trim().to_string(), path))
}

fn http4s_path_from_root(pattern: &str) -> String {
    let mut segments = Vec::new();
    for part in pattern.split('/').skip(1) {
        let segment = part.trim();
        if segment.is_empty() {
            continue;
        }
        if let Some(value) = first_quoted_string(segment) {
            segments.push(value);
        } else {
            let name = segment
                .split_whitespace()
                .next()
                .unwrap_or(segment)
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
            if !name.is_empty() && name != "Root" {
                segments.push(format!("{{{name}}}"));
            }
        }
    }
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn router_prefixes(lines: &[SourceLine<'_>]) -> Vec<String> {
    let mut prefixes = BTreeSet::new();
    for line in lines {
        let text = line.text;
        if !text.contains("Router(") {
            continue;
        }
        let mut rest = text;
        while let Some(index) = rest.find('"') {
            let after = &rest[index..];
            if let Some(prefix) = first_quoted_string(after) {
                prefixes.insert(prefix);
                rest = &after[1..];
            } else {
                break;
            }
        }
    }
    prefixes.into_iter().collect()
}

fn akka_path_argument(text: &str) -> Option<String> {
    let open = text.find('(')?;
    let close = matching_paren(text, open)?;
    let args = &text[open + 1..close];
    let mut segments = Vec::new();
    for part in args.split('/') {
        let segment = part.trim();
        if let Some(value) = first_quoted_string(segment) {
            segments.push(value);
        } else if segment.contains("Segment") {
            segments.push("{segment}".to_string());
        } else if segment.contains("IntNumber") {
            segments.push("{int}".to_string());
        }
    }
    if segments.is_empty() {
        None
    } else {
        Some(format!("/{}", segments.join("/")))
    }
}

fn current_akka_prefix(scopes: &[AkkaScope]) -> Option<String> {
    let mut prefix: Option<String> = None;
    for scope in scopes {
        if let Some(path) = scope.path.as_deref() {
            prefix = Some(join_paths(prefix.as_deref(), Some(path)));
        }
    }
    prefix
}

fn normalize_play_path(path: &str) -> String {
    let normalized = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    normalized
        .split('/')
        .map(|segment| {
            if let Some(name) = segment.strip_prefix(':') {
                format!("{{{name}}}")
            } else if let Some(name) = segment.strip_prefix('*') {
                format!("{{{name}}}")
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn push_route_file_action_symbol(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    line: &SourceLine<'_>,
    action: &str,
) -> String {
    let name = action.split('(').next().unwrap_or(action).to_string();
    let id = stable_fact_id(
        "symbol",
        [file.id.as_str(), name.as_str(), &line.number.to_string()],
    );
    facts.symbols.push(SymbolFact {
        id: id.clone(),
        file_id: file.id.clone(),
        name,
        kind: SymbolKind::Method,
        range: range_for_line(line),
        signature: Some(line.text.trim().to_string()),
        visibility: None,
        parent_symbol_id: None,
        metadata: metadata("adapter", "scala"),
    });
    id
}

fn push_call(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    callee_name: &str,
    arguments: Vec<String>,
) {
    facts.calls.push(CallFact {
        id: stable_fact_id(
            "call",
            [file.id.as_str(), callee_name, &line.number.to_string()],
        ),
        file_id: Some(file.id.clone()),
        caller_symbol_id: containing_symbol_id(symbols, line.number),
        callee_symbol_id: None,
        callee_name: callee_name.to_string(),
        range: range_for_line(line),
        arguments,
        metadata: metadata("adapter", "scala"),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_data_source(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    kind: DataSourceKind,
    name: &str,
    endpoint: Option<String>,
    metadata: BTreeMap<String, String>,
) {
    facts.data_sources.push(DataSourceFact {
        id: stable_fact_id(
            "data-source",
            [file.id.as_str(), name, &line.number.to_string()],
        ),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(symbols, line.number),
        kind,
        name: Some(name.to_string()),
        endpoint,
        range: range_for_line(line),
        metadata,
    });
}

fn push_sink(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    kind: SinkKind,
    name: &str,
    metadata: BTreeMap<String, String>,
) {
    facts.sinks.push(SinkFact {
        id: stable_fact_id("sink", [file.id.as_str(), name, &line.number.to_string()]),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(symbols, line.number),
        kind,
        name: Some(name.to_string()),
        range: range_for_line(line),
        metadata,
    });
}

fn push_sanitizer(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    kind: SanitizerKind,
    name: &str,
    metadata: BTreeMap<String, String>,
) {
    facts.sanitizers.push(SanitizerFact {
        id: stable_fact_id(
            "sanitizer",
            [file.id.as_str(), name, &line.number.to_string()],
        ),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(symbols, line.number),
        kind,
        name: Some(name.to_string()),
        range: range_for_line(line),
        metadata,
    });
}

fn invocation_names(text: &str) -> Vec<String> {
    let mut names = BTreeSet::new();
    let bytes = text.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'(' {
            continue;
        }
        let mut start = index;
        while start > 0 {
            let ch = bytes[start - 1] as char;
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.') {
                start -= 1;
            } else {
                break;
            }
        }
        if start == index {
            continue;
        }
        let name = text[start..index].trim_matches('.').to_string();
        if name.is_empty() || is_scala_control_keyword(&name) {
            continue;
        }
        names.insert(name);
    }
    names.into_iter().collect()
}

fn call_arguments(text: &str, call: &str) -> Vec<String> {
    let Some(start) = text.find(&format!("{call}(")) else {
        return Vec::new();
    };
    let Some(end) = matching_paren(text, start + call.len()) else {
        return Vec::new();
    };
    text[start + call.len() + 1..end]
        .split(',')
        .map(str::trim)
        .filter(|argument| !argument.is_empty())
        .map(str::to_string)
        .collect()
}

fn first_quoted_string(text: &str) -> Option<String> {
    let mut chars = text.char_indices();
    while let Some((index, ch)) = chars.next() {
        if ch != '"' && ch != '\'' {
            continue;
        }
        let quote = ch;
        let mut escaped = false;
        for (end, candidate) in chars.by_ref() {
            if escaped {
                escaped = false;
                continue;
            }
            if candidate == '\\' {
                escaped = true;
                continue;
            }
            if candidate == quote {
                return Some(text[index + 1..end].to_string());
            }
        }
    }
    None
}

fn matching_paren(text: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0_i32;
    for (index, ch) in text
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn starts_directive(text: &str, name: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with(&format!("{name}(")) || trimmed.starts_with(&format!("{name} "))
}

fn declaration_name(text: &str, keyword: &str) -> Option<String> {
    let after = text.split_once(keyword)?.1.trim_start();
    let name: String = after
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '.')
        .collect();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn scala_def_name(text: &str) -> Option<String> {
    let marker = if text.starts_with("def ") {
        "def "
    } else if text.contains(" def ") {
        " def "
    } else {
        return None;
    };
    let after = text.split_once(marker)?.1.trim_start();
    let name = after
        .split(['(', ':', '='])
        .next()
        .unwrap_or_default()
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn val_name(text: &str) -> Option<String> {
    let marker = if text.starts_with("val ") {
        "val "
    } else if text.starts_with("lazy val ") {
        "lazy val "
    } else {
        return None;
    };
    let after = text.strip_prefix(marker)?.trim_start();
    let name = after
        .split([':', '=', ' '])
        .next()
        .unwrap_or_default()
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn block_end_line(lines: &[SourceLine<'_>], start_index: usize) -> u32 {
    let mut depth = 0_i32;
    let mut seen_open = false;
    for line in &lines[start_index..] {
        for ch in strip_line_comment(line.text).chars() {
            if ch == '{' {
                depth += 1;
                seen_open = true;
            } else if ch == '}' {
                depth -= 1;
                if seen_open && depth <= 0 {
                    return line.number;
                }
            }
        }
    }
    lines[start_index].number
}

fn brace_delta(text: &str) -> i32 {
    let mut delta = 0;
    for ch in text.chars() {
        if ch == '{' {
            delta += 1;
        } else if ch == '}' {
            delta -= 1;
        }
    }
    delta
}

fn containing_symbol_id(symbols: &[LineSymbol], line: u32) -> Option<String> {
    symbols
        .iter()
        .filter(|symbol| symbol.start_line <= line && symbol.end_line >= line)
        .max_by_key(|symbol| symbol.start_line)
        .map(|symbol| symbol.id.clone())
}

fn range_for_line(line: &SourceLine<'_>) -> Option<SourceRange> {
    let end_column = u32::try_from(line.text.len() + 1).ok()?;
    Some(SourceRange::new(
        SourcePosition::new(line.number, 1).with_byte_offset(u32::try_from(line.start_byte).ok()?),
        SourcePosition::new(line.number, end_column)
            .with_byte_offset(u32::try_from(line.start_byte + line.text.len()).ok()?),
    ))
}

fn strip_line_comment(text: &str) -> String {
    text.split_once("//")
        .map_or(text, |(code, _)| code)
        .to_string()
}

fn is_play_routes_file(file: &SourceFileFact) -> bool {
    file.path.ends_with("conf/routes")
}

fn is_http_method(value: &str) -> bool {
    matches!(
        value,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    )
}

fn visibility(text: &str) -> Option<String> {
    let first = text.split_whitespace().next()?;
    match first {
        "private" | "protected" | "override" | "final" => Some(first.to_string()),
        _ => None,
    }
}

fn is_scala_control_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "for" | "while" | "match" | "catch" | "Some" | "None" | "Left" | "Right"
    )
}

fn metadata(key: &str, value: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(key.to_string(), value.to_string());
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{ProjectGraph, SourceFileFact};
    use std::path::PathBuf;

    fn analyze_scala(path: &str, source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new(path, "Scala");
        file.service_id = Some("api".to_string());
        ScalaAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("scala analysis succeeds")
    }

    #[test]
    fn extracts_play_routes_file_entries() {
        let source = r#"
# comment
GET     /hello/:name       controllers.Application.hello(name)
POST    /users             controllers.UserController.create
"#;

        let facts = analyze_scala("conf/routes", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/hello/{name}"
                && route.framework.as_deref() == Some("Play")
        }));
        assert!(facts
            .symbols
            .iter()
            .any(|symbol| symbol.name == "controllers.Application.hello"));
    }

    #[test]
    fn extracts_play_controller_sources_and_database_sinks() {
        let source = r#"
import play.api.mvc._
import slick.jdbc.PostgresProfile.api._

class UserController(cc: ControllerComponents) extends AbstractController(cc) {
  def create = Action.async { request =>
    val name = request.body.asJson.get.toString
    db.run(sql"select * from users where name = $name".as[String])
    Ok(name)
  }
}
"#;

        let facts = analyze_scala("app/controllers/UserController.scala", source);

        assert!(facts.symbols.iter().any(|symbol| symbol.name == "create"));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("Ok")));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_http4s_router_prefixed_routes() {
        let source = r#"
import org.http4s._
import org.http4s.dsl.io._
import org.http4s.server.Router

object Routes {
  val users = HttpRoutes.of[IO] {
    case GET -> Root / "users" / id => Ok(id)
    case POST -> Root / "users" => Created()
  }
  val app = Router("/api" -> users).orNotFound
}
"#;

        let facts = analyze_scala("src/main/scala/Routes.scala", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/{id}"
                && route.framework.as_deref() == Some("http4s")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/api/users"
                && route.framework.as_deref() == Some("http4s")
        }));
    }

    #[test]
    fn extracts_akka_http_directive_routes_and_auth_sanitizers() {
        let source = r#"
import akka.http.scaladsl.server.Directives._

object Api {
  val route =
    pathPrefix("api") {
      authenticateOAuth2("realm", authenticator) { user =>
        path("users" / Segment) { id =>
          get {
            complete(id)
          }
        }
      }
    }
}
"#;

        let facts = analyze_scala("src/main/scala/Api.scala", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/{segment}"
                && route.framework.as_deref() == Some("Akka HTTP")
        }));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Authentication));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("complete")));
    }
}
