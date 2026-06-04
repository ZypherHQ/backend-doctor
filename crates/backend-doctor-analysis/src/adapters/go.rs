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
    metadata_entry, node_text, parse_tree, range_for_node, string_value, symbol_id_by_name,
    walk_tree, SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct GoAdapter;

impl SourceAdapter for GoAdapter {
    fn id(&self) -> &'static str {
        "go-tree-sitter-tier-a"
    }

    fn language(&self) -> &'static str {
        "Go"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_go::LANGUAGE.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let provenance = collect_go_provenance(root, input.contents, &imports);
        collect_calls_routes_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &provenance,
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
        if node.kind() != "import_spec" {
            return;
        }
        let Some(path_node) = node
            .child_by_field_name("path")
            .or_else(|| child_of_kind(node, "interpreted_string_literal"))
            .or_else(|| child_of_kind(node, "raw_string_literal"))
        else {
            return;
        };
        let Some(module) = string_value(path_node, source) else {
            return;
        };
        let alias = child_text(node, "name", source).map(str::to_string);
        imports.insert(module.clone());
        add_import(
            facts,
            file,
            module,
            alias,
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
        "function_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Function,
                    None,
                    source,
                );
            }
        }
        "method_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                let qualified = receiver_type_name(node, source)
                    .map(|receiver| format!("{receiver}.{name}"))
                    .unwrap_or_else(|| name.to_string());
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    qualified,
                    SymbolKind::Method,
                    None,
                    source,
                );
            }
        }
        "type_spec" => {
            if let Some(name) = child_text(node, "name", source) {
                let kind = node
                    .child_by_field_name("type")
                    .map(|type_node| match type_node.kind() {
                        "struct_type" => SymbolKind::Struct,
                        "interface_type" => SymbolKind::Interface,
                        _ => SymbolKind::Type,
                    })
                    .unwrap_or(SymbolKind::Type);
                add_symbol(facts, &mut spans, file, node, name, kind, None, source);
            }
        }
        "var_spec" | "const_spec" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                for identifier in direct_named_children(name_node) {
                    if identifier.kind() == "identifier" {
                        let kind = if node.kind() == "const_spec" {
                            SymbolKind::Constant
                        } else {
                            SymbolKind::Variable
                        };
                        add_symbol(
                            facts,
                            &mut spans,
                            file,
                            identifier,
                            node_text(identifier, source),
                            kind,
                            None,
                            source,
                        );
                    }
                }
            }
        }
        _ => {}
    });
    spans
}

fn receiver_type_name(node: Node<'_>, source: &str) -> Option<String> {
    let receiver = node.child_by_field_name("receiver")?;
    let text = node_text(receiver, source);
    let mut candidate = String::new();
    for ch in text.chars().rev() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            candidate.push(ch);
        } else if !candidate.is_empty() {
            break;
        }
    }
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.chars().rev().collect())
    }
}

#[derive(Clone, Debug, Default)]
struct GoProvenance {
    routers: BTreeMap<String, GoRouterInfo>,
    grpc_servers: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct GoRouterInfo {
    framework: String,
    prefix: Option<String>,
}

impl GoRouterInfo {
    fn new(framework: impl Into<String>) -> Self {
        Self {
            framework: framework.into(),
            prefix: None,
        }
    }

    fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }
}

fn collect_go_provenance(root: Node<'_>, source: &str, imports: &BTreeSet<String>) -> GoProvenance {
    let mut provenance = GoProvenance::default();
    walk_tree(root, &mut |node| {
        if is_gin_router_parameter(node, source, imports) {
            for name in binding_names(node, source) {
                provenance.routers.insert(name, GoRouterInfo::new("Gin"));
            }
            return;
        }
        if !matches!(
            node.kind(),
            "short_var_declaration" | "assignment_statement" | "var_spec"
        ) {
            return;
        }
        let names = binding_names(node, source);
        let values = binding_value_nodes(node);
        for (name, value) in names.iter().zip(values.iter()) {
            if let Some(router) = router_info_from_go_expr(*value, source, imports, &provenance) {
                provenance.routers.insert(name.clone(), router);
            }
            if is_grpc_new_server_expr(*value, source, imports) {
                provenance.grpc_servers.insert(name.clone());
            }
        }
    });
    provenance
}

fn is_gin_router_parameter(node: Node<'_>, source: &str, imports: &BTreeSet<String>) -> bool {
    if node.kind() != "parameter_declaration" || !has_go_import(imports, "github.com/gin-gonic/gin")
    {
        return false;
    }
    let Some(type_node) = node.child_by_field_name("type") else {
        return false;
    };
    matches!(
        node_text(type_node, source).trim().trim_start_matches('*'),
        "gin.Engine" | "gin.RouterGroup" | "gin.IRouter" | "gin.IRoutes"
    )
}

fn binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .map(|left| identifiers_in_node(left, source))
        .unwrap_or_default()
}

fn identifiers_in_node(node: Node<'_>, source: &str) -> Vec<String> {
    if node.kind() == "identifier" {
        return vec![node_text(node, source).to_string()];
    }
    direct_named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "identifier")
        .map(|identifier| node_text(identifier, source).to_string())
        .collect()
}

fn binding_value_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    let Some(value) = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))
    else {
        return Vec::new();
    };
    if matches!(value.kind(), "expression_list" | "parenthesized_expression") {
        return direct_named_children(value);
    }
    vec![value]
}

fn router_info_from_go_expr(
    value: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
) -> Option<GoRouterInfo> {
    let call = first_call_expression(value)?;
    let function_node = call.child_by_field_name("function")?;
    let callee = node_text(function_node, source);
    if has_go_import(imports, "github.com/gin-gonic/gin")
        && matches!(callee, "gin.Default" | "gin.New")
    {
        return Some(GoRouterInfo::new("Gin"));
    }
    if has_go_import(imports, "net/http") && callee == "http.NewServeMux" {
        return Some(GoRouterInfo::new("net/http"));
    }
    if has_go_import(imports, "github.com/labstack/echo") && callee == "echo.New" {
        return Some(GoRouterInfo::new("Echo"));
    }
    if has_go_import(imports, "github.com/gofiber/fiber") && callee == "fiber.New" {
        return Some(GoRouterInfo::new("Fiber"));
    }
    if has_go_import(imports, "github.com/go-chi/chi")
        && matches!(callee, "chi.NewRouter" | "chi.NewMux")
    {
        return Some(GoRouterInfo::new("Chi"));
    }
    if final_segment(callee) != "Group" {
        return None;
    }
    let receiver = receiver_name(callee)?;
    let parent = provenance.routers.get(receiver)?;
    let prefix = call_argument_nodes(call)
        .first()
        .and_then(|argument| string_value(*argument, source))?;
    Some(
        parent
            .clone()
            .with_prefix(join_paths(parent.prefix.as_deref(), Some(&prefix))),
    )
}

fn first_call_expression(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "call_expression" {
        return Some(node);
    }
    direct_named_children(node)
        .into_iter()
        .find_map(first_call_expression)
}

fn is_grpc_new_server_expr(value: Node<'_>, source: &str, imports: &BTreeSet<String>) -> bool {
    has_go_import(imports, "google.golang.org/grpc")
        && first_call_expression(value)
            .and_then(|call| call.child_by_field_name("function"))
            .is_some_and(|function| node_text(function, source) == "grpc.NewServer")
}

fn has_go_import(imports: &BTreeSet<String>, needle: &str) -> bool {
    imports.iter().any(|module| module.contains(needle))
}

struct GoCallContext<'a> {
    file: &'a backend_doctor_core::SourceFileFact,
    source: &'a str,
    symbols: &'a [SymbolSpan],
    imports: &'a BTreeSet<String>,
    provenance: &'a GoProvenance,
}

fn collect_calls_routes_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
) {
    let context = GoCallContext {
        file,
        source,
        symbols,
        imports,
        provenance,
    };
    walk_tree(root, &mut |node| {
        if node.kind() != "call_expression" {
            return;
        }
        let Some(function_node) = node.child_by_field_name("function") else {
            return;
        };
        let callee = node_text(function_node, source).to_string();
        let arguments = argument_texts(node, source);
        add_call(facts, file, symbols, node, callee.clone(), arguments);
        collect_route_from_call(facts, node, &callee, &context);
        collect_grpc_from_call(facts, file, node, source, imports, provenance, &callee);
        collect_flow_fact_from_call(facts, node, &callee, &context);
    });
}

fn collect_route_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    node: Node<'_>,
    callee: &str,
    context: &GoCallContext<'_>,
) {
    let arguments = call_argument_nodes(node);
    let Some(route) = go_route_from_call(
        &arguments,
        context.source,
        context.imports,
        context.provenance,
        callee,
    ) else {
        return;
    };
    let handler_symbol_id = arguments
        .get(1)
        .map(|argument| node_text(*argument, context.source))
        .and_then(normalize_handler_name)
        .and_then(|name| symbol_id_by_name(context.symbols, &name))
        .or_else(|| containing_symbol_id(context.symbols, node));
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "go".to_string());
    metadata.insert("callee".to_string(), callee.to_string());
    let id = stable_fact_id(
        "route",
        [
            context.file.id.as_str(),
            route.method,
            &route.path,
            route.framework.as_str(),
            &node.start_byte().to_string(),
        ],
    );
    facts.routes.push(RouteFact {
        id,
        file_id: Some(context.file.id.clone()),
        symbol_id: handler_symbol_id,
        service_id: context.file.service_id.clone(),
        method: route.method.to_string(),
        path: route.path,
        framework: Some(route.framework),
        range: range_for_node(node),
        metadata,
    });
}

struct GoRouteCall {
    method: &'static str,
    path: String,
    framework: String,
}

fn go_route_from_call(
    arguments: &[Node<'_>],
    source: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
    callee: &str,
) -> Option<GoRouteCall> {
    let final_name = final_segment(callee);
    if is_net_http_handle_call(callee, imports, provenance) {
        let pattern = arguments
            .first()
            .and_then(|argument| string_value(*argument, source))?;
        let (method, path) = parse_servemux_pattern(&pattern)?;
        return Some(GoRouteCall {
            method,
            path,
            framework: "net/http".to_string(),
        });
    }
    if matches!(
        callee,
        "http.Get" | "http.Post" | "http.Head" | "http.PostForm"
    ) {
        return None;
    }

    let lower = final_name.to_ascii_lowercase();
    let method = match lower.as_str() {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "patch" => "PATCH",
        "delete" => "DELETE",
        "options" => "OPTIONS",
        "head" => "HEAD",
        "any" | "all" => "ANY",
        "connect" => "CONNECT",
        "trace" => "TRACE",
        _ => return None,
    };
    let receiver = receiver_name(callee)?;
    let router = provenance.routers.get(receiver)?;
    if router.framework == "net/http" {
        return None;
    }
    let path = arguments
        .first()
        .and_then(|argument| string_value(*argument, source))?;
    if !path.starts_with('/') {
        return None;
    }
    Some(GoRouteCall {
        method,
        path: join_paths(router.prefix.as_deref(), Some(&path)),
        framework: router.framework.clone(),
    })
}

fn is_net_http_handle_call(
    callee: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
) -> bool {
    let final_name = final_segment(callee);
    if !matches!(final_name, "HandleFunc" | "Handle") {
        return false;
    }
    if matches!(callee, "http.HandleFunc" | "http.Handle") {
        return has_go_import(imports, "net/http");
    }
    receiver_name(callee)
        .and_then(|receiver| provenance.routers.get(receiver))
        .is_some_and(|router| router.framework == "net/http")
}

fn parse_servemux_pattern(pattern: &str) -> Option<(&'static str, String)> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((maybe_method, rest)) = split_first_token(trimmed) {
        if let Some(method) = method_from_text(maybe_method) {
            return servemux_path(rest.trim()).map(|path| (method, path));
        }
    }
    servemux_path(trimmed).map(|path| ("ANY", path))
}

fn split_first_token(text: &str) -> Option<(&str, &str)> {
    let index = text.find(char::is_whitespace)?;
    Some((&text[..index], &text[index..]))
}

fn servemux_path(pattern: &str) -> Option<String> {
    if pattern.starts_with('/') {
        return Some(pattern.to_string());
    }
    pattern.find('/').map(|index| pattern[index..].to_string())
}

fn method_from_text(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => Some("GET"),
        "POST" => Some("POST"),
        "PUT" => Some("PUT"),
        "PATCH" => Some("PATCH"),
        "DELETE" => Some("DELETE"),
        "OPTIONS" => Some("OPTIONS"),
        "HEAD" => Some("HEAD"),
        "CONNECT" => Some("CONNECT"),
        "TRACE" => Some("TRACE"),
        _ => None,
    }
}

fn collect_grpc_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
    callee: &str,
) {
    if !has_go_import(imports, "google.golang.org/grpc") {
        return;
    }
    let final_name = final_segment(callee);
    if !(final_name.starts_with("Register") && final_name.ends_with("Server")) {
        return;
    }
    if receiver_name(callee).is_none() {
        return;
    }
    let Some(server_argument) = call_argument_nodes(node).first().copied() else {
        return;
    };
    if !is_grpc_server_argument(server_argument, source, imports, provenance) {
        return;
    }
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "go".to_string());
    metadata.insert("registrationCall".to_string(), callee.to_string());
    metadata.insert("rangeStartByte".to_string(), node.start_byte().to_string());
    facts.api_specs.push(ApiSpecFact {
        id: stable_fact_id(
            "api-spec",
            [
                file.id.as_str(),
                "grpc",
                callee,
                &node.start_byte().to_string(),
            ],
        ),
        path: file.path.clone(),
        format: ApiSpecFormat::Grpc,
        title: Some(final_name.to_string()),
        version: None,
        route_ids: Vec::new(),
        metadata,
    });
}

fn is_grpc_server_argument(
    argument: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
) -> bool {
    if is_grpc_new_server_expr(argument, source, imports) {
        return true;
    }
    let text = node_text(argument, source).trim().trim_start_matches('&');
    provenance.grpc_servers.contains(text)
}

fn collect_flow_fact_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    node: Node<'_>,
    callee: &str,
    context: &GoCallContext<'_>,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = lower_final_segment(callee);
    let receiver = receiver_name(callee)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let route_like_call = is_route_like_call(
        node,
        context.source,
        context.imports,
        context.provenance,
        callee,
    );

    if is_go_request_source(&receiver, &final_lower, &lower) {
        let mut metadata = metadata_entry("callee", callee);
        metadata.insert("adapter".to_string(), "go".to_string());
        add_data_source(
            facts,
            context.file,
            context.symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata,
        );
    } else if matches!(lower.as_str(), "os.getenv" | "syscall.getenv") {
        add_data_source(
            facts,
            context.file,
            context.symbols,
            node,
            DataSourceKind::Environment,
            callee,
            None,
            metadata_entry("adapter", "go"),
        );
    }

    if is_go_http_network_sink(&lower) {
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata_entry("adapter", "go"),
        );
    } else if !route_like_call && is_go_sql_sink(&receiver, &final_lower) {
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "go"),
        );
    } else if matches!(lower.as_str(), "exec.command" | "os.startprocess") {
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "go"),
        );
    } else if is_go_response_sink(&receiver, &final_lower, &lower) {
        let sink_kind = if final_lower == "redirect" {
            SinkKind::Redirect
        } else {
            SinkKind::HttpResponse
        };
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            sink_kind,
            callee,
            metadata_entry("adapter", "go"),
        );
    } else if matches!(final_lower.as_str(), "executetemplate" | "execute")
        && lower.contains("template")
    {
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            SinkKind::Template,
            callee,
            metadata_entry("adapter", "go"),
        );
    } else if matches!(final_lower.as_str(), "writefile" | "create" | "openfile") {
        add_sink(
            facts,
            context.file,
            context.symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "go"),
        );
    }

    if is_go_sanitizer(&lower, &final_lower) {
        let kind = if final_lower.contains("escape") {
            SanitizerKind::Escaping
        } else if final_lower.starts_with("parse") || final_lower == "atoi" {
            SanitizerKind::TypeCheck
        } else {
            SanitizerKind::Validation
        };
        add_sanitizer(
            facts,
            context.file,
            context.symbols,
            node,
            kind,
            callee,
            metadata_entry("adapter", "go"),
        );
    }
}

fn is_route_like_call(
    node: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
    provenance: &GoProvenance,
    callee: &str,
) -> bool {
    let arguments = call_argument_nodes(node);
    go_route_from_call(&arguments, source, imports, provenance, callee).is_some()
}

fn is_go_request_source(receiver: &str, final_lower: &str, full_lower: &str) -> bool {
    let request_receiver = matches!(
        receiver,
        "r" | "req" | "request" | "c" | "ctx" | "context" | "ginctx" | "echoctx"
    );
    request_receiver
        && matches!(
            final_lower,
            "query"
                | "defaultquery"
                | "param"
                | "postform"
                | "formvalue"
                | "bodyparser"
                | "bind"
                | "bindjson"
                | "shouldbind"
                | "shouldbindjson"
                | "cookie"
                | "header"
                | "getheader"
                | "pathvalue"
        )
        || full_lower.ends_with(".url.query")
}

fn is_go_sql_sink(receiver: &str, final_lower: &str) -> bool {
    !matches!(
        receiver,
        "r" | "req" | "request" | "c" | "ctx" | "context" | "w" | "res" | "response"
    ) && matches!(
        final_lower,
        "query" | "queryrow" | "exec" | "prepare" | "namedexec" | "select" | "get"
    )
}

fn is_go_http_network_sink(full_lower: &str) -> bool {
    matches!(
        full_lower,
        "http.get" | "http.post" | "http.defaultclient.do"
    )
}

fn is_go_response_sink(receiver: &str, final_lower: &str, full_lower: &str) -> bool {
    matches!(full_lower, "http.redirect")
        || matches!(receiver, "w" | "res" | "response" | "c" | "ctx")
            && matches!(
                final_lower,
                "write" | "json" | "string" | "html" | "redirect" | "blob" | "stream" | "send"
            )
}

fn is_go_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    final_lower.contains("escape")
        || matches!(
            final_lower,
            "atoi" | "parseint" | "parsebool" | "parsefloat" | "matchstring" | "valid"
        )
        || full_lower.contains("validator.")
}

fn receiver_name(callee: &str) -> Option<&str> {
    callee.split_once('.').map(|(receiver, _)| receiver.trim())
}

fn normalize_handler_name(text: &str) -> Option<String> {
    let trimmed = text.trim().trim_start_matches('&');
    let final_name = final_segment(trimmed).trim();
    (!final_name.is_empty()).then(|| final_name.to_string())
}

fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call
        .child_by_field_name("arguments")
        .or_else(|| child_of_kind(call, "argument_list"))
    else {
        return Vec::new();
    };
    direct_named_children(arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{ProjectGraph, SinkFact, SourceFileFact};
    use std::path::PathBuf;

    fn analyze_go(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("cmd/api/main.go", "Go");
        file.service_id = Some("api".to_string());
        GoAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("go analysis succeeds")
    }

    #[test]
    fn extracts_go_routes_imports_symbols_flows_and_grpc_specs() {
        let source = r#"
package main

import (
    "database/sql"
    "net/http"
    "net/url"
    "github.com/gin-gonic/gin"
    "google.golang.org/grpc"
)

type server struct{}

func listUsers(c *gin.Context) {
    q := c.Query("q")
    safe := url.QueryEscape(q)
    db.Query("select * from users where name = " + safe)
    c.JSON(200, gin.H{"ok": true})
}

func health(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("ok"))
}

func main() {
    router := gin.Default()
    router.GET("/users/:id", listUsers)
    http.HandleFunc("/health", health)
    http.Get("/internal")
    pb.RegisterUserServiceServer(grpc.NewServer(), &server{})
}
"#;

        let facts = analyze_go(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module == "github.com/gin-gonic/gin"));
        assert!(facts.symbols.iter().any(|fact| fact.name == "listUsers"));
        assert!(facts
            .calls
            .iter()
            .any(|fact| fact.callee_name == "router.GET"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/users/:id"
                && route.framework.as_deref() == Some("Gin")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "ANY"
                && route.path == "/health"
                && route.framework.as_deref() == Some("net/http")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("c.Query")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("db.Query")));
        assert!(!facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("router.GET")));
        assert!(!facts.routes.iter().any(|route| route.path == "/internal"));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("http.Get")
                && sink.kind == SinkKind::NetworkRequest));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("url.QueryEscape")));
        assert!(facts
            .api_specs
            .iter()
            .any(|spec| spec.format == ApiSpecFormat::Grpc));
        assert!(!facts.taint_edges.is_empty());
    }

    fn sink_named<'a>(facts: &'a backend_doctor_core::AnalysisFacts, name: &str) -> &'a SinkFact {
        facts
            .sinks
            .iter()
            .find(|sink| sink.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("expected sink named {name}; sinks: {:?}", facts.sinks))
    }

    #[test]
    fn classifies_go_http_client_calls_as_network_requests_before_sql_sinks() {
        let source = r#"
package main

import (
    "database/sql"
    "net/http"
)

func load(db *sql.DB, tx *sql.Tx, req *http.Request) {
    _, _ = http.Get("https://example.test")
    _, _ = http.Post("https://example.test", "text/plain", nil)
    _, _ = http.DefaultClient.Do(req)
    _, _ = db.Query("select 1")
    _, _ = db.Exec("update users set active = true")
    _, _ = tx.Query("select 1")
}
"#;

        let facts = analyze_go(source);

        for name in ["http.Get", "http.Post", "http.DefaultClient.Do"] {
            let sink = sink_named(&facts, name);
            assert_eq!(sink.kind, SinkKind::NetworkRequest, "{name}");
            assert_eq!(
                sink.metadata.get("adapter").map(String::as_str),
                Some("go"),
                "{name}"
            );
        }
        assert!(!facts.sinks.iter().any(|sink| {
            sink.name.as_deref() == Some("http.Get") && sink.kind == SinkKind::SqlQuery
        }));

        for name in ["db.Query", "db.Exec", "tx.Query"] {
            assert_eq!(sink_named(&facts, name).kind, SinkKind::SqlQuery, "{name}");
        }
    }

    #[test]
    fn extracts_go_122_servemux_methods_and_pathvalue_sources() {
        let source = r#"
package main

import "net/http"

func show(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    w.Write([]byte(id))
}

func legacy(w http.ResponseWriter, r *http.Request) {}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("GET /posts/{id}", show)
    http.HandleFunc("/legacy", legacy)
}
"#;

        let facts = analyze_go(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/posts/{id}"
                && route.framework.as_deref() == Some("net/http")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "ANY"
                && route.path == "/legacy"
                && route.framework.as_deref() == Some("net/http")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("r.PathValue")));
    }

    #[test]
    fn tracks_gin_group_prefixes_and_rejects_unproven_route_receivers() {
        let source = r#"
package main

import "github.com/gin-gonic/gin"

func list(c *gin.Context) {}

func register(rg *gin.RouterGroup) {
    admin := rg.Group("/admin")
    admin.POST("/users", list)
}

func main() {
    router := gin.Default()
    api := router.Group("/api")
    v1 := api.Group("/v1")
    v1.GET("/posts/:id", list)
    cache.GET("/not-a-route", list)
}
"#;

        let facts = analyze_go(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/v1/posts/:id"
                && route.framework.as_deref() == Some("Gin")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/admin/users"
                && route.framework.as_deref() == Some("Gin")
        }));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/not-a-route"));
    }

    #[test]
    fn requires_proven_grpc_server_argument_for_grpc_specs() {
        let source = r#"
package main

import "google.golang.org/grpc"

type server struct{}

func main() {
    grpcServer := grpc.NewServer()
    pb.RegisterUserServiceServer(grpcServer, &server{})
    fake.RegisterOtherServer(nonGrpcServer, &server{})
}
"#;

        let facts = analyze_go(source);

        assert_eq!(
            facts
                .api_specs
                .iter()
                .filter(|spec| spec.format == ApiSpecFormat::Grpc)
                .count(),
            1
        );
        assert!(facts
            .api_specs
            .iter()
            .any(|spec| spec.title.as_deref() == Some("RegisterUserServiceServer")));
    }
}
