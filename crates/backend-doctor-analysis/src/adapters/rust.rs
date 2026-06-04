use backend_doctor_core::{
    stable_fact_id, ApiSpecFact, ApiSpecFormat, DataSourceKind, ImportKind, RouteFact,
    SanitizerKind, SinkKind, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

use super::common::{
    add_call, add_data_source, add_import, add_local_taint_edges, add_sanitizer, add_sink,
    add_symbol, argument_texts, child_of_kind, child_text, containing_symbol_id,
    direct_named_children, facts_with_source, final_segment, join_paths, lower_final_segment,
    metadata_entry, node_text, normalize_path, parse_tree, range_for_node, string_value,
    symbol_id_by_name, walk_tree, SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct RustAdapter;

impl SourceAdapter for RustAdapter {
    fn id(&self) -> &'static str {
        "rust-tree-sitter-tier-b"
    }

    fn language(&self) -> &'static str {
        "Rust"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_rust::LANGUAGE.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let actix_scope_prefixes = collect_actix_scope_prefixes(root, input.contents);
        let mut route_symbols = collect_attribute_routes_and_parameter_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &actix_scope_prefixes,
        );
        let call_route_symbols = collect_calls_routes_specs_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &route_symbols,
        );
        route_symbols.extend(call_route_symbols);
        add_handler_parameter_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &route_symbols,
        );
        add_handler_context_unwrap_sinks(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &route_symbols,
        );
        add_local_taint_edges(&mut facts);
        Ok(facts)
    }
}

fn collect_imports(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
) -> BTreeSet<String> {
    let mut imports = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "use_declaration" {
            return;
        }
        let module = node_text(node, source)
            .trim()
            .trim_start_matches("use")
            .trim()
            .trim_end_matches(';')
            .trim()
            .to_string();
        if module.is_empty() {
            return;
        }
        imports.insert(module.clone());
        add_import(
            facts,
            file,
            module,
            None,
            Vec::new(),
            ImportKind::Package,
            node,
        );
    });
    imports
}

fn collect_symbols(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
) -> Vec<SymbolSpan> {
    let mut spans = Vec::new();
    walk_tree(root, &mut |node| match node.kind() {
        "function_item" => {
            if let Some(name) = child_text(node, "name", source) {
                let kind = if has_ancestor_kind(node, "impl_item") {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                let parent = containing_symbol_id(&spans, node);
                add_symbol(facts, &mut spans, file, node, name, kind, parent, source);
            }
        }
        "struct_item" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Struct,
                    None,
                    source,
                );
            }
        }
        "enum_item" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Enum,
                    None,
                    source,
                );
            }
        }
        "trait_item" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Interface,
                    None,
                    source,
                );
            }
        }
        "mod_item" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Module,
                    None,
                    source,
                );
            }
        }
        _ => {}
    });
    spans
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == kind {
            return true;
        }
        parent = candidate.parent();
    }
    false
}

fn collect_attribute_routes_and_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    actix_scope_prefixes: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut route_symbol_ids = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "function_item" {
            return;
        }
        for attribute in attributes_for_node(node, source) {
            if let Some(route) = route_from_rust_attribute(&attribute, imports) {
                let symbol_id = containing_symbol_id(symbols, node);
                let path = child_text(node, "name", source)
                    .and_then(|name| actix_scope_prefixes.get(name))
                    .map_or(route.path.clone(), |prefix| {
                        join_paths(Some(prefix), Some(&route.path))
                    });
                push_route(
                    facts,
                    file,
                    node,
                    route.method,
                    path,
                    route.framework,
                    symbol_id.clone(),
                    &attribute,
                );
                if let Some(symbol_id) = symbol_id {
                    route_symbol_ids.insert(symbol_id);
                }
                collect_rust_parameter_sources(facts, file, node, source, symbols);
            }
        }
    });
    route_symbol_ids
}

#[derive(Clone, Debug)]
struct RustRoute {
    method: &'static str,
    path: String,
    framework: String,
}

fn route_from_rust_attribute(text: &str, imports: &BTreeSet<String>) -> Option<RustRoute> {
    let trimmed = text
        .trim()
        .trim_start_matches("#[")
        .trim_end_matches(']')
        .trim();
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
        .unwrap_or(trimmed.len());
    let raw_name = &trimmed[..name_end];
    let name = raw_name.rsplit("::").next().unwrap_or("");
    let method = rust_attribute_http_method(name)
        .or_else(|| rust_attribute_alias_http_method(imports, name))?;
    let path = first_quoted_fragment(trimmed)?;
    let framework = rust_attribute_framework(raw_name, name, imports)?;
    Some(RustRoute {
        method,
        path: normalize_path(&path),
        framework: framework.to_string(),
    })
}

fn rust_attribute_http_method(name: &str) -> Option<&'static str> {
    match name {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" => Some("DELETE"),
        "head" => Some("HEAD"),
        "options" => Some("OPTIONS"),
        _ => None,
    }
}

fn rust_attribute_alias_http_method(
    imports: &BTreeSet<String>,
    local_name: &str,
) -> Option<&'static str> {
    [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
    ]
    .into_iter()
    .find_map(|(canonical, method)| {
        (rust_imports_symbol_as(imports, "actix_web", canonical, local_name)
            || rust_imports_symbol_as(imports, "rocket", canonical, local_name))
        .then_some(method)
    })
}

fn rust_attribute_framework(
    raw_name: &str,
    local_name: &str,
    imports: &BTreeSet<String>,
) -> Option<&'static str> {
    if raw_name.contains("rocket") {
        return Some("Rocket");
    }
    if raw_name.contains("actix_web") {
        return Some("Actix Web");
    }
    let canonical = rust_attribute_http_method(local_name)
        .and_then(method_to_rust_macro_name)
        .unwrap_or(local_name);
    let actix = rust_imports_symbol_as(imports, "actix_web", canonical, local_name);
    let rocket = rust_imports_symbol_as(imports, "rocket", canonical, local_name);
    match (actix, rocket) {
        (true, false) => Some("Actix Web"),
        (false, true) => Some("Rocket"),
        _ => None,
    }
}

fn method_to_rust_macro_name(method: &str) -> Option<&'static str> {
    match method {
        "GET" => Some("get"),
        "POST" => Some("post"),
        "PUT" => Some("put"),
        "PATCH" => Some("patch"),
        "DELETE" => Some("delete"),
        "HEAD" => Some("head"),
        "OPTIONS" => Some("options"),
        _ => None,
    }
}

fn collect_rust_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    function_node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    let Some(parameters) = function_node.child_by_field_name("parameters") else {
        return;
    };
    for parameter in direct_named_children(parameters) {
        let text = node_text(parameter, source);
        if text.is_empty() || text == "&self" || text == "self" {
            continue;
        }
        if rust_parameter_is_request_source(text) {
            add_data_source(
                facts,
                file,
                symbols,
                parameter,
                DataSourceKind::Request,
                rust_parameter_name(text),
                None,
                metadata_entry("adapter", "rust"),
            );
        }
    }
}

fn rust_parameter_is_request_source(text: &str) -> bool {
    [
        "Path<",
        "Query<",
        "Json<",
        "Form<",
        "HeaderMap",
        "Request",
        "HttpRequest",
        "Payload",
        "web::Path",
        "web::Query",
        "web::Json",
        "State<",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn rust_parameter_name(text: &str) -> String {
    text.split(':')
        .next()
        .unwrap_or(text)
        .trim()
        .trim_start_matches("mut ")
        .to_string()
}

#[allow(clippy::too_many_arguments)]
fn collect_calls_routes_specs_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    route_symbols: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut call_route_symbols = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if !matches!(node.kind(), "call_expression" | "macro_invocation") {
            return;
        }
        let callee = rust_callee_name(node, source);
        if callee.is_empty() {
            return;
        }
        let arguments = argument_texts(node, source);
        add_call(facts, file, symbols, node, callee.clone(), arguments);
        if let Some(symbol_id) =
            collect_route_from_rust_call(facts, file, node, source, symbols, imports, &callee)
        {
            call_route_symbols.insert(symbol_id);
        }
        collect_tonic_spec_from_call(facts, file, node, imports, &callee);
        collect_flow_fact_from_rust_call(
            facts,
            file,
            node,
            source,
            symbols,
            imports,
            route_symbols,
            &callee,
        );
    });
    call_route_symbols
}

fn rust_callee_name(node: Node<'_>, source: &str) -> String {
    if node.kind() == "macro_invocation" {
        return node_text(node, source)
            .split('!')
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
    }
    node.child_by_field_name("function")
        .map(|function| node_text(function, source).to_string())
        .unwrap_or_default()
}

fn collect_route_from_rust_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    callee: &str,
) -> Option<String> {
    let final_name = final_segment(callee);
    if final_name != "route" && final_name != "service" {
        return None;
    }
    let text = node_text(node, source);
    if !(has_rust_import(imports, "axum") || has_rust_import(imports, "actix_web")) {
        return None;
    }
    if text.contains("reqwest") || text.contains("client.") {
        return None;
    }
    let arguments = call_argument_nodes(node);
    let path = arguments
        .first()
        .and_then(|argument| string_value(*argument, source))?;
    let route_argument_text = arguments
        .get(1)
        .map(|argument| node_text(*argument, source));
    let framework = rust_route_call_framework(route_argument_text, imports)?;
    let method_handlers = rust_method_handlers_from_route_call(route_argument_text);
    let mut first_handler_symbol_id = None;
    for (method, handler_name) in method_handlers {
        let handler_symbol_id = handler_name
            .and_then(|name| symbol_id_by_name(symbols, &name))
            .or_else(|| {
                arguments
                    .get(1)
                    .and_then(|argument| {
                        rust_handler_name_from_route_arg(node_text(*argument, source))
                    })
                    .and_then(|name| symbol_id_by_name(symbols, &name))
            });
        if first_handler_symbol_id.is_none() {
            first_handler_symbol_id = handler_symbol_id.clone();
        }
        push_route(
            facts,
            file,
            node,
            method,
            normalize_path(&path),
            framework.to_string(),
            handler_symbol_id.clone(),
            callee,
        );
    }
    first_handler_symbol_id
}

fn rust_method_handlers_from_route_call(
    argument: Option<&str>,
) -> Vec<(&'static str, Option<String>)> {
    let Some(argument) = argument else {
        return vec![("ANY", None)];
    };
    let methods: Vec<_> = [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
        ("any", "ANY"),
    ]
    .into_iter()
    .filter_map(|(function, method)| {
        rust_immediate_call_argument(argument, function).map(|handler| {
            let handler = if handler.trim().is_empty() {
                rust_immediate_call_argument(argument, "to").unwrap_or(handler)
            } else {
                handler
            };
            (
                method,
                rust_handler_name_from_route_arg(&handler).or_else(|| {
                    let trimmed = handler.trim();
                    (!trimmed.is_empty()).then(|| trimmed.to_string())
                }),
            )
        })
    })
    .collect();
    if methods.is_empty() {
        vec![("ANY", rust_handler_name_from_route_arg(argument))]
    } else {
        methods
    }
}

fn rust_route_call_framework(
    argument: Option<&str>,
    imports: &BTreeSet<String>,
) -> Option<&'static str> {
    let argument = argument.unwrap_or_default();
    if has_rust_import(imports, "actix_web")
        && (argument.contains("web::")
            || argument.contains("actix_web::")
            || argument.contains(".to("))
    {
        return Some("Actix Web");
    }
    if has_rust_import(imports, "axum")
        && rust_method_handlers_from_route_call(Some(argument))
            .iter()
            .any(|(method, _)| *method != "ANY")
    {
        return Some("Axum");
    }
    None
}

fn rust_immediate_call_argument(text: &str, function: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut search_start = 0usize;
    let needle = format!("{function}(");
    while let Some(relative) = text[search_start..].find(&needle) {
        let function_start = search_start + relative;
        let before = function_start
            .checked_sub(1)
            .and_then(|index| bytes.get(index));
        let before_ok = before.is_none_or(|ch| !ch.is_ascii_alphanumeric() && *ch != b'_');
        if !before_ok {
            search_start = function_start + function.len();
            continue;
        }
        let value_start = function_start + needle.len();
        let mut depth = 0usize;
        for index in value_start..bytes.len() {
            match bytes[index] {
                b'(' | b'[' | b'{' => depth += 1,
                b')' if depth == 0 => return Some(text[value_start..index].to_string()),
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        search_start = function_start + function.len();
    }
    None
}

fn rust_handler_name_from_route_arg(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let before_paren = trimmed.split('(').nth(1).unwrap_or(trimmed);
    let candidate = before_paren
        .split([',', ')', '.'])
        .find(|part| {
            let part = part.trim();
            !part.is_empty()
                && part
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })?
        .trim();
    (!candidate.is_empty()).then(|| candidate.to_string())
}

fn collect_tonic_spec_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    imports: &BTreeSet<String>,
    callee: &str,
) {
    if !has_rust_import(imports, "tonic") || final_segment(callee) != "add_service" {
        return;
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "rust".to_string());
    metadata.insert("registrationCall".to_string(), callee.to_string());
    facts.api_specs.push(ApiSpecFact {
        id: stable_fact_id(
            "api-spec",
            [
                file.id.as_str(),
                "tonic",
                callee,
                &node.start_byte().to_string(),
            ],
        ),
        path: file.path.clone(),
        format: ApiSpecFormat::Grpc,
        title: Some("Tonic service".to_string()),
        version: None,
        route_ids: Vec::new(),
        metadata,
    });
}

#[allow(clippy::too_many_arguments)]
fn collect_flow_fact_from_rust_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    route_symbols: &BTreeSet<String>,
    callee: &str,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = lower_final_segment(callee);

    if is_rust_request_source(&lower, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "rust"),
        );
    }

    if is_rust_sql_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "rust"),
        );
    } else if is_rust_command_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "rust"),
        );
    } else if is_rust_file_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "rust"),
        );
    } else if is_rust_network_sink(&lower, &final_lower, imports) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata_entry("adapter", "rust"),
        );
    } else if matches!(
        final_lower.as_str(),
        "info" | "warn" | "error" | "debug" | "trace"
    ) && (has_rust_import(imports, "tracing") || node.kind() == "macro_invocation")
    {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Log,
            callee,
            metadata_entry("adapter", "rust"),
        );
    }

    if is_rust_sanitizer(&lower, &final_lower) {
        let kind = if final_lower == "parse" || lower.contains("fromstr") {
            SanitizerKind::TypeCheck
        } else if lower.contains("escape") {
            SanitizerKind::Escaping
        } else {
            SanitizerKind::Validation
        };
        add_sanitizer(
            facts,
            file,
            symbols,
            node,
            kind,
            callee,
            metadata_entry("adapter", "rust"),
        );
    }

    let in_route_handler = containing_symbol_id(symbols, node)
        .as_ref()
        .is_some_and(|symbol_id| route_symbols.contains(symbol_id));
    if in_route_handler && (final_lower == "unwrap" || final_lower == "expect" || lower == "panic")
    {
        let mut metadata = metadata_entry("adapter", "rust");
        metadata.insert("handlerContext".to_string(), "true".to_string());
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Unknown,
            callee,
            metadata,
        );
    }

    if node.kind() == "macro_invocation" && lower.starts_with("sqlx::query") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "rust"),
        );
    }

    if node_text(node, source).contains("serde_json::from_str") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Deserialization,
            callee,
            metadata_entry("adapter", "rust"),
        );
    }
}

fn add_handler_context_unwrap_sinks(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    route_symbols: &BTreeSet<String>,
) {
    walk_tree(root, &mut |node| {
        if node.kind() != "call_expression" && node.kind() != "macro_invocation" {
            return;
        }
        let callee = rust_callee_name(node, source);
        let final_lower = lower_final_segment(&callee);
        let lower = callee.to_ascii_lowercase();
        let in_route_handler = containing_symbol_id(symbols, node)
            .as_ref()
            .is_some_and(|symbol_id| route_symbols.contains(symbol_id));
        if in_route_handler
            && (final_lower == "unwrap" || final_lower == "expect" || lower == "panic")
            && !facts.sinks.iter().any(|sink| {
                sink.range == range_for_node(node) && sink.name.as_deref() == Some(&callee)
            })
        {
            let mut metadata = metadata_entry("adapter", "rust");
            metadata.insert("handlerContext".to_string(), "true".to_string());
            add_sink(
                facts,
                file,
                symbols,
                node,
                SinkKind::Unknown,
                callee,
                metadata,
            );
        }
    });
}

fn add_handler_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    route_symbols: &BTreeSet<String>,
) {
    walk_tree(root, &mut |node| {
        if node.kind() != "function_item" {
            return;
        }
        let Some(symbol_id) = containing_symbol_id(symbols, node) else {
            return;
        };
        if !route_symbols.contains(&symbol_id) {
            return;
        }
        collect_rust_parameter_sources(facts, file, node, source, symbols);
    });
}

fn is_rust_request_source(full_lower: &str, final_lower: &str) -> bool {
    matches!(final_lower, "query" | "headers" | "uri" | "body" | "path")
        && (full_lower.contains("request")
            || full_lower.contains("req.")
            || full_lower.contains("http_request"))
}

fn is_rust_sql_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower.starts_with("sqlx::query")
        || full_lower.contains("diesel::sql_query")
        || matches!(final_lower, "execute" | "fetch_one" | "fetch_all" | "load")
            && (full_lower.contains("sqlx")
                || full_lower.contains("diesel")
                || full_lower.contains("query"))
}

fn is_rust_command_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower.contains("command::new")
        || full_lower.ends_with("std::process::command::new")
        || matches!(final_lower, "spawn" | "output" | "status") && full_lower.contains("command")
}

fn is_rust_file_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower == "fs::write"
        || full_lower == "std::fs::write"
        || full_lower.contains("file::create")
        || final_lower == "create"
            && (full_lower.contains("file") || full_lower.contains("openoptions"))
}

fn is_rust_network_sink(full_lower: &str, final_lower: &str, imports: &BTreeSet<String>) -> bool {
    full_lower.starts_with("reqwest::")
        || has_rust_import(imports, "reqwest")
            && (full_lower.starts_with("reqwest::")
                || matches!(
                    final_lower,
                    "get" | "post" | "put" | "patch" | "delete" | "send" | "request"
                ))
}

fn is_rust_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    matches!(final_lower, "validate" | "parse" | "fromstr")
        || full_lower.contains("validator")
        || full_lower.contains("sanitize")
        || full_lower.contains("escape")
}

#[allow(clippy::too_many_arguments)]
fn push_route(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    method: &'static str,
    path: String,
    framework: String,
    symbol_id: Option<String>,
    provenance_text: &str,
) {
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "rust".to_string());
    metadata.insert("provenance".to_string(), provenance_text.to_string());
    facts.routes.push(RouteFact {
        id: stable_fact_id(
            "route",
            [
                file.id.as_str(),
                method,
                &path,
                framework.as_str(),
                &node.start_byte().to_string(),
            ],
        ),
        file_id: Some(file.id.clone()),
        symbol_id,
        service_id: file.service_id.clone(),
        method: method.to_string(),
        path,
        framework: Some(framework),
        range: range_for_node(node),
        metadata,
    });
}

fn attributes_for_node(node: Node<'_>, source: &str) -> Vec<String> {
    let mut attributes = Vec::new();
    let mut sibling = node.prev_named_sibling();
    while let Some(candidate) = sibling {
        if candidate.kind() != "attribute_item" {
            break;
        }
        attributes.push(node_text(candidate, source).to_string());
        sibling = candidate.prev_named_sibling();
    }
    attributes.reverse();
    for child in direct_named_children(node) {
        if child.kind() == "attribute_item" {
            attributes.push(node_text(child, source).to_string());
        }
    }
    attributes
}

fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call
        .child_by_field_name("arguments")
        .or_else(|| child_of_kind(call, "arguments"))
    else {
        return Vec::new();
    };
    direct_named_children(arguments)
}

fn has_rust_import(imports: &BTreeSet<String>, needle: &str) -> bool {
    imports.iter().any(|module| module.contains(needle))
}

fn rust_imports_symbol_as(
    imports: &BTreeSet<String>,
    module: &str,
    canonical: &str,
    local_name: &str,
) -> bool {
    imports.iter().any(|import| {
        if !import.contains(module) {
            return false;
        }
        if import.contains(&format!("{canonical} as {local_name}")) {
            return true;
        }
        local_name == canonical
            && (import.ends_with(&format!("::{canonical}"))
                || import.contains(&format!("::{canonical};"))
                || import.contains(&format!("{{{canonical}"))
                || import.contains(&format!(", {canonical}"))
                || import.contains(&format!("{canonical},")))
            && !import.contains(&format!("{canonical} as "))
    })
}

fn collect_actix_scope_prefixes(root: Node<'_>, source: &str) -> BTreeMap<String, String> {
    let mut prefixes = BTreeMap::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let text = node_text(node, source);
        if !text.contains("scope(") || !text.contains(".service(") {
            return;
        }
        let Some(prefix) = prefix_from_rust_scope_text(text) else {
            return;
        };
        for service in service_handlers_from_scope_text(text) {
            prefixes.insert(service, prefix.clone());
        }
    });
    prefixes
}

fn prefix_from_rust_scope_text(text: &str) -> Option<String> {
    let scope_index = text.find("scope(")?;
    first_quoted_fragment(&text[scope_index..]).map(|prefix| normalize_path(&prefix))
}

fn service_handlers_from_scope_text(text: &str) -> Vec<String> {
    let mut handlers = Vec::new();
    let mut search_start = 0usize;
    while let Some(relative) = text[search_start..].find(".service(") {
        let start = search_start + relative + ".service(".len();
        let Some(argument) = balanced_call_argument(text, start) else {
            search_start = start;
            continue;
        };
        if !argument.contains("scope(") {
            let name = argument
                .trim()
                .split([',', ')'])
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches('&')
                .rsplit("::")
                .next()
                .unwrap_or("")
                .to_string();
            if !name.is_empty() {
                handlers.push(name);
            }
        }
        search_start = start + argument.len();
    }
    handlers
}

fn balanced_call_argument(text: &str, start: usize) -> Option<String> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    for index in start..bytes.len() {
        match bytes[index] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' if depth == 0 => return Some(text[start..index].to_string()),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

fn first_quoted_fragment(text: &str) -> Option<String> {
    let mut quote = None;
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if quote.is_none() && matches!(ch, '"' | '\'') {
            quote = Some(ch);
            start = index + ch.len_utf8();
        } else if Some(ch) == quote {
            return Some(text[start..index].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{ProjectGraph, SourceFileFact};
    use std::path::PathBuf;

    fn analyze_rust(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/main.rs", "Rust");
        file.service_id = Some("api".to_string());
        RustAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("rust analysis succeeds")
    }

    #[test]
    fn extracts_axum_routes_sources_sinks_and_tonic_specs() {
        let source = r#"
use axum::{extract::{Path, Query}, routing::{get, post}, Router};
use sqlx;
use tonic::transport::Server;

async fn get_user(Path(id): Path<String>, Query(q): Query<Search>) -> String {
    let row = sqlx::query("select * from users where id = $1").fetch_one(&pool).await.unwrap();
    reqwest::get("https://example.test").await.unwrap();
    id
}

async fn create_user() {}

async fn serve_grpc(svc: UserSvc) {
    Server::builder().add_service(UserServer::new(svc)).serve(addr).await.unwrap();
}

fn router() -> Router {
    Router::new().route("/users/:id", get(get_user).post(create_user))
}
"#;

        let facts = analyze_rust(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module.contains("axum")));
        assert!(facts.symbols.iter().any(|fact| fact.name == "get_user"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/users/:id"
                && route.framework.as_deref() == Some("Axum")
        }));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/users/:id"));
        assert!(
            facts
                .data_sources
                .iter()
                .any(|source| source.name.as_deref() == Some("Path(id)")),
            "{:?}",
            facts.data_sources
        );
        assert!(facts.sinks.iter().any(|sink| sink
            .name
            .as_deref()
            .is_some_and(|name| name.contains("sqlx"))
            && sink.kind == SinkKind::SqlQuery));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("reqwest::get")
                && sink.kind == SinkKind::NetworkRequest));
        assert!(facts
            .api_specs
            .iter()
            .any(|spec| spec.format == ApiSpecFormat::Grpc));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_actix_and_rocket_attributes_but_rejects_reqwest_get_route() {
        let source = r#"
use actix_web::{get, post, web, HttpRequest};
use rocket::get as rocket_get;
use reqwest;

#[get("/health")]
async fn health(req: HttpRequest) -> String {
    reqwest::get("https://example.test").await.unwrap();
    "ok".to_string()
}

#[post("/items/{id}")]
async fn create(path: web::Path<String>) -> String {
    std::process::Command::new("echo").arg(path.into_inner()).output().unwrap();
    "ok".to_string()
}

async fn client() {
    reqwest::get("/not-a-route").await.unwrap();
}
"#;

        let facts = analyze_rust(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/health"
                && route.framework.as_deref() == Some("Actix Web")
        }));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/items/{id}"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/not-a-route"));
        assert!(facts.sinks.iter().any(|sink| sink
            .name
            .as_deref()
            .is_some_and(|name| name.contains("Command"))
            && sink.kind == SinkKind::Command));
        assert!(facts.sinks.iter().any(|sink| {
            sink.name
                .as_deref()
                .is_some_and(|name| name.ends_with("unwrap"))
                && sink.metadata.get("handlerContext").map(String::as_str) == Some("true")
        }));
    }

    #[test]
    fn axum_chained_methods_attach_to_their_own_handlers() {
        let source = r#"
use axum::{routing::{get, post}, Router};

async fn list_widgets() {}
async fn create_widget() {}

fn router() -> Router {
    Router::new().route("/widgets", get(list_widgets).post(create_widget))
}
"#;

        let facts = analyze_rust(source);
        let list_id = facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "list_widgets")
            .map(|symbol| symbol.id.clone())
            .expect("list handler symbol");
        let create_id = facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "create_widget")
            .map(|symbol| symbol.id.clone())
            .expect("create handler symbol");

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/widgets"
                && route.symbol_id.as_deref() == Some(list_id.as_str())
                && route.framework.as_deref() == Some("Axum")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/widgets"
                && route.symbol_id.as_deref() == Some(create_id.as_str())
                && route.framework.as_deref() == Some("Axum")
        }));
    }

    #[test]
    fn route_attributes_require_actix_or_rocket_provenance() {
        let source = r#"
use actix_web::{get, HttpRequest};
use rocket::get as rocket_get;

#[get("/actix")]
async fn actix(req: HttpRequest) -> String {
    "ok".to_string()
}

#[rocket_get("/rocket")]
async fn rocket() -> String {
    "ok".to_string()
}

#[post("/unproven")]
async fn unproven() -> String {
    "ok".to_string()
}
"#;

        let facts = analyze_rust(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/actix"
                && route.framework.as_deref() == Some("Actix Web")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/rocket"
                && route.framework.as_deref() == Some("Rocket")
        }));
        assert!(!facts.routes.iter().any(|route| route.path == "/unproven"));
    }

    #[test]
    fn actix_scope_prefixes_attribute_service_routes() {
        let source = r#"
use actix_web::{get, web, App};

#[get("/widgets")]
async fn list_widgets() -> String {
    "ok".to_string()
}

fn app() -> App {
    App::new().service(web::scope("/api").service(list_widgets))
}
"#;

        let facts = analyze_rust(source);

        assert!(
            facts.routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/api/widgets"
                    && route.framework.as_deref() == Some("Actix Web")
            }),
            "{:?}",
            facts.routes
        );
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/widgets"));
    }

    #[test]
    fn actix_route_call_framework_uses_route_argument_provenance() {
        let source = r#"
use actix_web::{web, App};
use axum::Router;

async fn show(path: web::Path<String>) -> String {
    "ok".to_string()
}

fn app() -> App {
    App::new().route("/actix", web::get().to(show))
}
"#;

        let facts = analyze_rust(source);
        let show_id = facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "show")
            .map(|symbol| symbol.id.clone())
            .expect("show handler symbol");

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/actix"
                && route.symbol_id.as_deref() == Some(show_id.as_str())
                && route.framework.as_deref() == Some("Actix Web")
        }));
        assert!(
            facts
                .data_sources
                .iter()
                .any(|source| source.name.as_deref() == Some("path")),
            "{:?}",
            facts.data_sources
        );
        assert!(!facts
            .routes
            .iter()
            .any(|route| { route.path == "/actix" && route.framework.as_deref() == Some("Axum") }));
    }
}
