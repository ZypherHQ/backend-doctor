use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, DataSourceFact, DataSourceKind, ImportFact,
    ImportKind, RouteFact, SanitizerFact, SanitizerKind, SinkFact, SinkKind, SourceFileFact,
    SourcePosition, SourceRange, SymbolFact, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::common::{add_local_taint_edges, facts_with_source, join_paths};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct KotlinAdapter;

impl SourceAdapter for KotlinAdapter {
    fn id(&self) -> &'static str {
        "kotlin-text-tier-c"
    }

    fn language(&self) -> &'static str {
        "Kotlin"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        let language = source_file.language.to_ascii_lowercase();
        matches!(language.as_str(), "kotlin" | "ktor" | "spring-kotlin")
            || source_file
                .path
                .extension()
                .is_some_and(|extension| extension == "kt" || extension == "kts")
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let lines = source_lines(input.contents);
        let mut facts = facts_with_source(&input);
        let imports = collect_imports(&mut facts, input.source_file, &lines);
        let symbols = collect_symbols(&mut facts, input.source_file, &lines);
        collect_ktor_routes_and_auth(&mut facts, input.source_file, &lines, &symbols, &imports);
        collect_spring_kotlin_routes(&mut facts, input.source_file, &lines, &symbols);
        collect_calls_sources_and_flows(&mut facts, input.source_file, &lines, &symbols);
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
struct KtorScope {
    depth: i32,
    path: Option<String>,
    authenticated: bool,
    route_context: bool,
}

#[derive(Clone, Debug)]
struct KotlinFunctionRange {
    name: String,
    signature: String,
    start_line: u32,
    end_line: u32,
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
            metadata: metadata("adapter", "kotlin"),
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
        } else if let Some(name) = declaration_name(trimmed, "interface ") {
            Some((name, SymbolKind::Interface))
        } else if let Some(name) = declaration_name(trimmed, "object ") {
            Some((name, SymbolKind::Module))
        } else {
            kotlin_function_name(trimmed).map(|name| (name, SymbolKind::Function))
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
            metadata: metadata("adapter", "kotlin"),
        });
        symbols.push(LineSymbol {
            id,
            start_line: line.number,
            end_line,
        });
    }
    symbols
}

fn collect_ktor_routes_and_auth(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
    imports: &BTreeSet<String>,
) {
    let mut scopes = Vec::<KtorScope>::new();
    let mut depth = 0_i32;
    let has_ktor_routing_import = has_ktor_server_routing_import(imports);
    let shadowed_ktor_symbols = local_ktor_route_symbol_names(lines);
    let function_ranges = collect_kotlin_function_ranges(lines);

    for line in lines {
        let trimmed = strip_line_comment(line.text);
        let function_declaration = kotlin_function_name(trimmed.trim_start()).is_some();

        if trimmed.contains("install(Authentication)")
            || trimmed.contains("install(io.ktor.server.auth.Authentication)")
        {
            push_sanitizer(
                facts,
                file,
                symbols,
                line,
                SanitizerKind::Authentication,
                "install(Authentication)",
                metadata("adapter", "kotlin"),
            );
        }

        if starts_call(&trimmed, "authenticate") {
            let mut auth_metadata = metadata("adapter", "kotlin");
            auth_metadata.insert("framework".to_string(), "Ktor".to_string());
            push_sanitizer(
                facts,
                file,
                symbols,
                line,
                SanitizerKind::Authentication,
                "authenticate",
                auth_metadata,
            );
            if trimmed.contains('{') {
                scopes.push(KtorScope {
                    depth: depth + 1,
                    path: None,
                    authenticated: true,
                    route_context: false,
                });
            }
        }

        if has_ktor_routing_import
            && !function_declaration
            && !shadowed_ktor_call_is_local(
                "routing",
                line.number,
                &shadowed_ktor_symbols,
                &function_ranges,
            )
            && (starts_call(&trimmed, "routing") || starts_block_call(&trimmed, "routing"))
            && trimmed.contains('{')
        {
            scopes.push(KtorScope {
                depth: depth + 1,
                path: None,
                authenticated: false,
                route_context: true,
            });
        }

        if has_ktor_routing_import
            && !function_declaration
            && !shadowed_ktor_call_is_local(
                "route",
                line.number,
                &shadowed_ktor_symbols,
                &function_ranges,
            )
            && starts_call(&trimmed, "route")
        {
            if let Some(path) = first_string_argument(&trimmed, "route") {
                if trimmed.contains('{') {
                    scopes.push(KtorScope {
                        depth: depth + 1,
                        path: Some(path),
                        authenticated: false,
                        route_context: true,
                    });
                }
            }
        }

        for (function, method) in [
            ("get", "GET"),
            ("post", "POST"),
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
        ] {
            if function_declaration {
                continue;
            }
            if !starts_call(&trimmed, function) {
                continue;
            }
            if !has_ktor_routing_import {
                continue;
            }
            if !current_ktor_route_context(&scopes)
                && !line_is_in_ktor_route_function(line.number, &function_ranges)
            {
                continue;
            }
            if shadowed_ktor_call_is_local(
                function,
                line.number,
                &shadowed_ktor_symbols,
                &function_ranges,
            ) {
                continue;
            }
            let route_path =
                first_string_argument(&trimmed, function).unwrap_or_else(|| "/".to_string());
            let full_path = join_paths(current_ktor_prefix(&scopes).as_deref(), Some(&route_path));
            let mut route_metadata = metadata("adapter", "kotlin");
            route_metadata.insert("dsl".to_string(), function.to_string());
            if current_ktor_auth(&scopes) {
                route_metadata.insert("authenticated".to_string(), "true".to_string());
            }
            push_route(
                facts,
                file,
                symbols,
                line,
                method,
                full_path,
                "Ktor",
                route_metadata,
            );
        }

        depth += brace_delta(&trimmed);
        scopes.retain(|scope| scope.depth <= depth);
    }
}

fn has_ktor_server_routing_import(imports: &BTreeSet<String>) -> bool {
    imports
        .iter()
        .any(|module| module.starts_with("io.ktor.server.routing."))
}

fn local_ktor_route_symbol_names(lines: &[SourceLine<'_>]) -> BTreeSet<&'static str> {
    let mut names = BTreeSet::new();
    for line in lines {
        let trimmed = strip_line_comment(line.text);
        let Some(name) = kotlin_function_name(trimmed.trim_start()) else {
            continue;
        };
        let simple_name = name.rsplit('.').next().unwrap_or(name.as_str());
        match simple_name {
            "routing" => {
                names.insert("routing");
            }
            "route" => {
                names.insert("route");
            }
            "get" => {
                names.insert("get");
            }
            "post" => {
                names.insert("post");
            }
            "put" => {
                names.insert("put");
            }
            "patch" => {
                names.insert("patch");
            }
            "delete" => {
                names.insert("delete");
            }
            "head" => {
                names.insert("head");
            }
            "options" => {
                names.insert("options");
            }
            _ => {}
        }
    }
    names
}

fn collect_kotlin_function_ranges(lines: &[SourceLine<'_>]) -> Vec<KotlinFunctionRange> {
    let mut ranges = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let trimmed = strip_line_comment(line.text);
        let signature = trimmed.trim_start();
        let Some(name) = kotlin_function_name(signature) else {
            continue;
        };
        ranges.push(KotlinFunctionRange {
            name,
            signature: signature.to_string(),
            start_line: line.number,
            end_line: block_end_line(lines, index),
        });
    }
    ranges
}

fn shadowed_ktor_call_is_local(
    name: &str,
    line: u32,
    shadowed_ktor_symbols: &BTreeSet<&'static str>,
    function_ranges: &[KotlinFunctionRange],
) -> bool {
    shadowed_ktor_symbols.contains(name)
        && !line_is_in_valid_ktor_receiver_function(name, line, function_ranges)
}

fn line_is_in_valid_ktor_receiver_function(
    name: &str,
    line: u32,
    function_ranges: &[KotlinFunctionRange],
) -> bool {
    innermost_function_at_line(line, function_ranges).is_some_and(|function| {
        is_ktor_application_function(function)
            || (name != "routing" && is_ktor_route_function(function))
    })
}

fn line_is_in_ktor_route_function(line: u32, function_ranges: &[KotlinFunctionRange]) -> bool {
    innermost_function_at_line(line, function_ranges).is_some_and(is_ktor_route_function)
}

fn innermost_function_at_line(
    line: u32,
    function_ranges: &[KotlinFunctionRange],
) -> Option<&KotlinFunctionRange> {
    function_ranges
        .iter()
        .filter(|function| function.start_line <= line && line <= function.end_line)
        .max_by_key(|function| function.start_line)
}

fn is_ktor_application_function(function: &KotlinFunctionRange) -> bool {
    is_kotlin_extension_function_on(function, "Application")
}

fn is_ktor_route_function(function: &KotlinFunctionRange) -> bool {
    is_kotlin_extension_function_on(function, "Route")
}

fn is_kotlin_extension_function_on(function: &KotlinFunctionRange, receiver: &str) -> bool {
    let receiver_prefix = format!("{receiver}.");
    let qualified_receiver = format!(".{receiver}.");
    function.name.starts_with(&receiver_prefix)
        || function.name.contains(&qualified_receiver)
        || function
            .signature
            .starts_with(&format!("fun {receiver_prefix}"))
        || function
            .signature
            .contains(&format!(" fun {receiver_prefix}"))
}

fn collect_spring_kotlin_routes(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
) {
    let mut pending_class_prefix: Option<String> = None;
    let mut pending_rest_controller = false;
    let mut current_class_context: Option<(Option<String>, u32)> = None;
    let mut pending_routes = Vec::<(&'static str, String, String, u32)>::new();

    for (index, line) in lines.iter().enumerate() {
        let trimmed = line.text.trim();
        if trimmed.starts_with("@RestController") || trimmed.starts_with("@Controller") {
            pending_rest_controller = true;
        }
        if let Some(prefix) = spring_request_mapping_path(trimmed) {
            pending_class_prefix = Some(prefix);
        }
        if let Some((method, path, annotation)) = spring_route_annotation(trimmed) {
            pending_routes.push((method, path, annotation, line.number));
        }
        if declaration_name(trimmed, "class ").is_some() {
            let end_line = block_end_line(lines, index);
            let prefix = pending_class_prefix.take();
            current_class_context =
                (pending_rest_controller || prefix.is_some()).then_some((prefix, end_line));
            pending_rest_controller = false;
        }
        if kotlin_function_name(trimmed).is_some() {
            let Some((prefix, class_end_line)) = current_class_context.as_ref() else {
                pending_routes.clear();
                continue;
            };
            if line.number > *class_end_line {
                current_class_context = None;
                pending_routes.clear();
                continue;
            }
            for (method, path, annotation, annotation_line) in pending_routes.drain(..) {
                if annotation_line + 4 < line.number {
                    continue;
                }
                let mut route_metadata = metadata("adapter", "kotlin");
                route_metadata.insert("annotation".to_string(), annotation);
                push_route(
                    facts,
                    file,
                    symbols,
                    line,
                    method,
                    join_paths(prefix.as_deref(), Some(&path)),
                    "Spring",
                    route_metadata,
                );
            }
        }
    }
}

fn collect_calls_sources_and_flows(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    lines: &[SourceLine<'_>],
    symbols: &[LineSymbol],
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
            collect_flow_fact_from_call(facts, file, symbols, line, &call, &trimmed);
        }

        if starts_block_call(&trimmed, "transaction") {
            push_call(facts, file, symbols, line, "transaction", Vec::new());
            collect_flow_fact_from_call(facts, file, symbols, line, "transaction", &trimmed);
        }

        if trimmed.contains("TransactionManager.current().exec") {
            push_sink(
                facts,
                file,
                symbols,
                line,
                SinkKind::SqlQuery,
                "TransactionManager.current().exec",
                metadata("adapter", "kotlin"),
            );
        }

        if trimmed.contains("call.receive")
            || trimmed.contains("call.parameters")
            || trimmed.contains("queryParameters")
            || trimmed.contains("headers")
            || trimmed.contains("cookies")
            || trimmed.contains("call.request.header")
            || trimmed.contains("call.principal")
        {
            let name = request_source_name(&trimmed);
            push_data_source(
                facts,
                file,
                symbols,
                line,
                DataSourceKind::Request,
                &name,
                None,
                metadata("adapter", "kotlin"),
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
) {
    let lower = call.to_ascii_lowercase();
    let final_segment = lower.rsplit('.').next().unwrap_or(lower.as_str());

    if lower == "transaction" || lower.ends_with(".transaction") {
        push_data_source(
            facts,
            file,
            symbols,
            line,
            DataSourceKind::Database,
            call,
            None,
            metadata("adapter", "kotlin"),
        );
    }

    if is_kotlin_sql_sink(final_segment, line_text) {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::SqlQuery,
            call,
            metadata("adapter", "kotlin"),
        );
    } else if is_kotlin_persistence_sink(&lower, final_segment) {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::Unknown,
            call,
            metadata("adapter", "kotlin"),
        );
    } else if matches!(final_segment, "respond" | "respondtext" | "respondbytes") {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::HttpResponse,
            call,
            metadata("adapter", "kotlin"),
        );
    } else if matches!(final_segment, "redirect") {
        push_sink(
            facts,
            file,
            symbols,
            line,
            SinkKind::Redirect,
            call,
            metadata("adapter", "kotlin"),
        );
    }

    if final_segment.contains("validate")
        || final_segment.contains("sanitize")
        || final_segment.contains("escape")
    {
        let kind = if final_segment.contains("escape") {
            SanitizerKind::Escaping
        } else {
            SanitizerKind::Validation
        };
        push_sanitizer(
            facts,
            file,
            symbols,
            line,
            kind,
            call,
            metadata("adapter", "kotlin"),
        );
    }
}

fn is_kotlin_sql_sink(final_segment: &str, line_text: &str) -> bool {
    matches!(
        final_segment,
        "exec" | "execute" | "executequery" | "executeupdate" | "preparestatement" | "query"
    ) || line_text.contains("SqlExpressionBuilder")
        || line_text.contains("rawSql")
        || line_text.contains("TransactionManager.current().exec")
}

fn is_kotlin_persistence_sink(lower: &str, final_segment: &str) -> bool {
    matches!(
        final_segment,
        "save"
            | "saveall"
            | "insert"
            | "insertandgetid"
            | "update"
            | "delete"
            | "deletewhere"
            | "batchinsert"
    ) && (lower.contains("repository")
        || lower.contains("service")
        || lower.contains("dao")
        || lower.contains("table")
        || lower.contains("users")
        || lower.contains("repository."))
}

fn spring_request_mapping_path(text: &str) -> Option<String> {
    if text.starts_with("@RequestMapping") {
        first_annotation_string(text)
    } else {
        None
    }
}

fn spring_route_annotation(text: &str) -> Option<(&'static str, String, String)> {
    for (annotation, method) in [
        ("@GetMapping", "GET"),
        ("@PostMapping", "POST"),
        ("@PutMapping", "PUT"),
        ("@PatchMapping", "PATCH"),
        ("@DeleteMapping", "DELETE"),
    ] {
        if text.starts_with(annotation) {
            return Some((
                method,
                first_annotation_string(text).unwrap_or_else(|| "/".to_string()),
                annotation.trim_start_matches('@').to_string(),
            ));
        }
    }
    None
}

fn first_annotation_string(text: &str) -> Option<String> {
    let open = text.find('(')?;
    first_quoted_string(&text[open..])
}

fn current_ktor_prefix(scopes: &[KtorScope]) -> Option<String> {
    let mut prefix: Option<String> = None;
    for scope in scopes {
        if let Some(path) = scope.path.as_deref() {
            prefix = Some(join_paths(prefix.as_deref(), Some(path)));
        }
    }
    prefix
}

fn current_ktor_auth(scopes: &[KtorScope]) -> bool {
    scopes.iter().any(|scope| scope.authenticated)
}

fn current_ktor_route_context(scopes: &[KtorScope]) -> bool {
    scopes.iter().any(|scope| scope.route_context)
}

#[allow(clippy::too_many_arguments)]
fn push_route(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbols: &[LineSymbol],
    line: &SourceLine<'_>,
    method: &str,
    path: String,
    framework: &str,
    metadata: BTreeMap<String, String>,
) {
    facts.routes.push(RouteFact {
        id: stable_fact_id(
            "route",
            [
                file.id.as_str(),
                method,
                path.as_str(),
                framework,
                &line.number.to_string(),
            ],
        ),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(symbols, line.number),
        service_id: file.service_id.clone(),
        method: method.to_string(),
        path,
        framework: Some(framework.to_string()),
        range: range_for_line(line),
        metadata,
    });
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
        metadata: metadata("adapter", "kotlin"),
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
        if name.is_empty() || is_kotlin_control_keyword(&name) {
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

fn first_string_argument(text: &str, call: &str) -> Option<String> {
    let start = text.find(&format!("{call}("))?;
    let end = matching_paren(text, start + call.len())?;
    first_quoted_string(&text[start + call.len() + 1..end])
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

fn starts_call(text: &str, name: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with(&format!("{name}("))
        || trimmed.starts_with(&format!("{name}<"))
        || trimmed.contains(&format!(" {name}("))
}

fn starts_block_call(text: &str, name: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with(&format!("{name} {{")) || trimmed == name
}

fn request_source_name(text: &str) -> String {
    for marker in [
        "call.receive",
        "call.parameters",
        "queryParameters",
        "headers",
        "cookies",
        "call.request.header",
        "call.principal",
    ] {
        if text.contains(marker) {
            return marker.to_string();
        }
    }
    "request".to_string()
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

fn kotlin_function_name(text: &str) -> Option<String> {
    let marker = if text.starts_with("fun ") {
        "fun "
    } else if text.contains(" fun ") {
        " fun "
    } else {
        return None;
    };
    let after = text.split_once(marker)?.1.trim_start();
    let signature_name = after.split('(').next()?.trim();
    let name = signature_name
        .split_whitespace()
        .last()
        .unwrap_or(signature_name)
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

fn visibility(text: &str) -> Option<String> {
    let first = text.split_whitespace().next()?;
    match first {
        "public" | "private" | "protected" | "internal" => Some(first.to_string()),
        _ => None,
    }
}

fn is_kotlin_control_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "for" | "while" | "when" | "catch" | "return" | "throw" | "class" | "fun"
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

    fn analyze_kotlin(source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/main/kotlin/com/acme/App.kt", "Kotlin");
        file.service_id = Some("api".to_string());
        KotlinAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("kotlin analysis succeeds")
    }

    #[test]
    fn extracts_ktor_nested_routes_sources_sanitizers_and_sinks() {
        let source = r#"
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.jetbrains.exposed.sql.transactions.transaction

fun Application.configureRouting() {
    install(Authentication)
    routing {
        route("/api") {
            authenticate("jwt") {
                get("/users/{id}") {
                    val id = call.parameters["id"]
                    val body = call.receive<CreateUser>()
                    val q = call.request.queryParameters["q"]
                    transaction {
                        UserRepository.save(body)
                        TransactionManager.current().exec("select * from users where id = $id")
                    }
                    call.respondText(q ?: id)
                }
            }
        }
    }
}
"#;

        let facts = analyze_kotlin(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module == "io.ktor.server.routing.*"));
        assert!(facts
            .symbols
            .iter()
            .any(|fact| fact.name == "Application.configureRouting"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/{id}"
                && route.framework.as_deref() == Some("Ktor")
                && route
                    .metadata
                    .get("authenticated")
                    .is_some_and(|value| value == "true")
        }));
        assert!(facts
            .sanitizers
            .iter()
            .any(|fact| fact.name.as_deref() == Some("authenticate")));
        assert!(facts
            .data_sources
            .iter()
            .any(|fact| fact.kind == DataSourceKind::Request
                && fact.name.as_deref() == Some("call.receive")));
        assert!(facts
            .data_sources
            .iter()
            .any(|fact| fact.kind == DataSourceKind::Database
                && fact.name.as_deref() == Some("transaction")));
        assert!(facts
            .sinks
            .iter()
            .any(|fact| fact.name.as_deref() == Some("UserRepository.save")));
        assert!(facts
            .sinks
            .iter()
            .any(|fact| fact.kind == SinkKind::SqlQuery
                && fact.name.as_deref() == Some("TransactionManager.current().exec")));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn does_not_extract_ktor_get_outside_route_context() {
        let source = r#"
import io.ktor.server.routing.get

fun helper() {
    get("/not-a-route") {
        println("client helper")
    }
}
"#;

        let facts = analyze_kotlin(source);

        assert!(!facts.routes.iter().any(|route| {
            route.path == "/not-a-route" && route.framework.as_deref() == Some("Ktor")
        }));
    }

    #[test]
    fn does_not_extract_generic_routing_without_ktor_server_routing_imports() {
        let source = r#"
fun genericRouter() {
    routing {
        get("/not-ktor") {
            println("generic helper")
        }
    }
}
"#;

        let facts = analyze_kotlin(source);

        assert!(!facts.routes.iter().any(|route| {
            route.path == "/not-ktor" && route.framework.as_deref() == Some("Ktor")
        }));
    }

    #[test]
    fn does_not_extract_shadowed_ktor_helpers_with_ktor_imports() {
        let source = r#"
import io.ktor.server.routing.*

fun routing(block: () -> Unit) = block()

fun get(path: String, block: () -> Unit) = block()

fun helperRouter() {
    routing({
        get("/not-ktor") {
            println("generic helper")
        }
    })
}
"#;

        let facts = analyze_kotlin(source);

        assert!(!facts.routes.iter().any(|route| {
            route.path == "/not-ktor" && route.framework.as_deref() == Some("Ktor")
        }));
    }

    #[test]
    fn extracts_real_ktor_route_despite_shadowed_helpers_elsewhere() {
        let source = r#"
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun routing(block: () -> Unit) = block()

fun route(path: String, block: () -> Unit) = block()

fun get(path: String, block: () -> Unit) = block()

fun helperRouter() {
    routing({
        get("/not-ktor") {
            println("generic helper")
        }
    })
}

fun Application.module() {
    routing {
        realRoutes()
    }
}

fun Route.realRoutes() {
    get("/real") {
        call.respondText("ok")
    }
}
"#;

        let facts = analyze_kotlin(source);

        assert!(!facts.routes.iter().any(|route| {
            route.path == "/not-ktor" && route.framework.as_deref() == Some("Ktor")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/real"
                && route.framework.as_deref() == Some("Ktor")
        }));
    }

    #[test]
    fn extracts_spring_kotlin_annotation_routes() {
        let source = r#"
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api")
class UserController {
    @PostMapping("/users")
    fun create(@RequestBody body: CreateUser): String {
        userService.save(body)
        return "ok"
    }
}
"#;

        let facts = analyze_kotlin(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/api/users"
                && route.framework.as_deref() == Some("Spring")
        }));
        assert!(facts
            .sinks
            .iter()
            .any(|fact| fact.name.as_deref() == Some("userService.save")));
    }

    #[test]
    fn extracts_spring_rest_controller_method_route_without_class_prefix() {
        let source = r#"
import org.springframework.web.bind.annotation.*

@RestController
class HealthController {
    @GetMapping("/health")
    fun health(): String = "ok"
}
"#;

        let facts = analyze_kotlin(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/health"
                && route.framework.as_deref() == Some("Spring")
        }));
    }
}
