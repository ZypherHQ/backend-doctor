use backend_doctor_core::{
    stable_fact_id, DataSourceKind, ImportKind, RouteFact, SanitizerKind, SinkKind, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

use super::common::{
    add_call, add_data_source, add_import, add_local_taint_edges, add_sanitizer, add_sink,
    add_symbol, argument_texts, child_of_kind, child_text, containing_symbol_id,
    direct_named_children, facts_with_source, join_paths, metadata_entry, node_text,
    normalize_path, parse_tree, range_for_node, string_value, symbol_id_by_name, walk_tree,
    SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct PhpAdapter;

impl SourceAdapter for PhpAdapter {
    fn id(&self) -> &'static str {
        "php-tree-sitter-tier-b"
    }

    fn language(&self) -> &'static str {
        "PHP"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_php::LANGUAGE_PHP.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let route_symbols = collect_attribute_routes(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
        );
        collect_calls_routes_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &route_symbols,
        );
        collect_superglobal_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
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
        if !matches!(node.kind(), "namespace_use_declaration" | "use_declaration") {
            return;
        }
        let text = node_text(node, source);
        let body = text
            .trim()
            .trim_start_matches("use")
            .trim()
            .trim_end_matches(';')
            .trim();
        for part in body
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            let (module, alias) = split_php_alias(part);
            if module.is_empty() {
                continue;
            }
            imports.insert(module.to_string());
            add_import(
                facts,
                file,
                module,
                alias.map(str::to_string),
                Vec::new(),
                ImportKind::Namespace,
                node,
            );
        }
    });
    imports
}

fn split_php_alias(text: &str) -> (&str, Option<&str>) {
    text.split_once(" as ")
        .or_else(|| text.split_once(" AS "))
        .map_or((text.trim(), None), |(module, alias)| {
            (module.trim(), Some(alias.trim()))
        })
}

fn collect_symbols(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
) -> Vec<SymbolSpan> {
    let mut spans = Vec::new();
    walk_tree(root, &mut |node| match node.kind() {
        "class_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Class,
                    None,
                    source,
                );
            }
        }
        "function_definition" => {
            if let Some(name) = child_text(node, "name", source) {
                let parent = containing_symbol_id(&spans, node);
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Function,
                    parent,
                    source,
                );
            }
        }
        "method_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                let parent = containing_symbol_id(&spans, node);
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Method,
                    parent,
                    source,
                );
            }
        }
        "property_declaration" => {
            if let Some(property) = descendants_of_kind(node, "property_element")
                .first()
                .copied()
            {
                let name = node_text(property, source)
                    .trim()
                    .trim_start_matches('$')
                    .to_string();
                if !name.is_empty() {
                    let parent = containing_symbol_id(&spans, node);
                    add_symbol(
                        facts,
                        &mut spans,
                        file,
                        property,
                        name,
                        SymbolKind::Field,
                        parent,
                        source,
                    );
                }
            }
        }
        _ => {}
    });
    spans
}

fn collect_attribute_routes(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) -> BTreeSet<String> {
    let mut route_symbol_ids = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if !matches!(node.kind(), "method_declaration" | "function_definition") {
            return;
        }
        for attribute in attributes_for_node(node, source) {
            if let Some(route) = route_from_php_attribute(&attribute) {
                let symbol_id = containing_symbol_id(symbols, node);
                for method in route.methods {
                    push_route(
                        facts,
                        file,
                        node,
                        method,
                        route.path.clone(),
                        route.framework.clone(),
                        symbol_id.clone(),
                        &attribute.text,
                    );
                }
                if let Some(symbol_id) = symbol_id {
                    route_symbol_ids.insert(symbol_id);
                }
            }
            if is_php_auth_attribute(&attribute.name) {
                add_sanitizer(
                    facts,
                    file,
                    symbols,
                    node,
                    SanitizerKind::Authorization,
                    attribute.name,
                    metadata_entry("adapter", "php"),
                );
            }
        }
    });
    route_symbol_ids
}

#[derive(Clone, Debug)]
struct PhpAttribute {
    name: String,
    text: String,
}

#[derive(Clone, Debug)]
struct PhpRoute {
    methods: Vec<&'static str>,
    path: String,
    framework: String,
}

fn attributes_for_node(node: Node<'_>, source: &str) -> Vec<PhpAttribute> {
    let mut attributes = Vec::new();
    let mut sibling = node.prev_named_sibling();
    while let Some(candidate) = sibling {
        if candidate.kind() != "attribute_list" {
            break;
        }
        for attribute in descendants_of_kind(candidate, "attribute") {
            if let Some(parsed) = parse_php_attribute(node_text(attribute, source)) {
                attributes.push(parsed);
            }
        }
        sibling = candidate.prev_named_sibling();
    }
    attributes.reverse();
    for child in direct_named_children(node) {
        if child.kind() == "attribute_list" {
            for attribute in descendants_of_kind(child, "attribute") {
                if let Some(parsed) = parse_php_attribute(node_text(attribute, source)) {
                    attributes.push(parsed);
                }
            }
        }
    }
    attributes
}

fn parse_php_attribute(text: &str) -> Option<PhpAttribute> {
    let trimmed = text.trim();
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '\\'))
        .unwrap_or(trimmed.len());
    let name = trimmed[..name_end]
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    Some(PhpAttribute {
        name,
        text: text.to_string(),
    })
}

fn route_from_php_attribute(attribute: &PhpAttribute) -> Option<PhpRoute> {
    if attribute.name != "Route" {
        return None;
    }
    let path = symfony_route_attribute_path(&attribute.text)?;
    let methods = explicit_methods_from_php_keyword(&attribute.text, "methods");
    let methods = if methods.is_empty() {
        vec!["ANY"]
    } else {
        methods
    };
    Some(PhpRoute {
        methods,
        path: normalize_path(&path),
        framework: "Symfony".to_string(),
    })
}

fn is_php_auth_attribute(name: &str) -> bool {
    matches!(name, "IsGranted" | "Security")
}

#[allow(clippy::too_many_arguments)]
fn collect_calls_routes_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    route_symbols: &BTreeSet<String>,
) {
    walk_tree(root, &mut |node| {
        if !matches!(
            node.kind(),
            "function_call_expression"
                | "member_call_expression"
                | "scoped_call_expression"
                | "object_creation_expression"
        ) {
            return;
        }
        let callee = php_callee_name(node, source);
        if callee.is_empty() {
            return;
        }
        let arguments = argument_texts(node, source);
        add_call(facts, file, symbols, node, callee.clone(), arguments);
        collect_route_from_php_call(facts, file, node, source, symbols, imports, &callee);
        collect_flow_fact_from_php_call(facts, file, node, source, symbols, route_symbols, &callee);
    });
}

fn php_callee_name(node: Node<'_>, source: &str) -> String {
    match node.kind() {
        "member_call_expression" => {
            let object = child_text(node, "object", source).unwrap_or_default();
            let name = child_text(node, "name", source).unwrap_or_default();
            format!("{object}->{name}")
        }
        "scoped_call_expression" => {
            let scope = child_text(node, "scope", source).unwrap_or_default();
            let name = child_text(node, "name", source).unwrap_or_default();
            format!("{scope}::{name}")
        }
        "object_creation_expression" => node
            .child_by_field_name("class")
            .or_else(|| node.child_by_field_name("name"))
            .map(|class| format!("new {}", node_text(class, source)))
            .unwrap_or_else(|| node_text(node, source).to_string()),
        _ => node
            .child_by_field_name("function")
            .map(|function| node_text(function, source).to_string())
            .unwrap_or_default(),
    }
}

fn collect_route_from_php_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    callee: &str,
) {
    let arguments = call_argument_nodes(node);
    let Some(framework) = php_route_framework(callee, imports) else {
        return;
    };
    let routes = php_routes_from_call(callee, &arguments, source);
    if routes.is_empty() {
        return;
    }
    let prefix = route_prefix_for_node(node, source);
    for route in routes {
        let handler_symbol_id = route
            .handler_argument_index
            .and_then(|index| arguments.get(index))
            .map(|argument| node_text(*argument, source))
            .and_then(normalize_php_handler_name)
            .and_then(|name| symbol_id_by_name(symbols, &name));
        push_route(
            facts,
            file,
            node,
            route.method,
            join_paths(prefix.as_deref(), Some(&route.path)),
            framework.clone(),
            handler_symbol_id.or_else(|| containing_symbol_id(symbols, node)),
            callee,
        );
    }
    if php_route_call_has_auth_middleware(node_text(node, source)) {
        add_sanitizer(
            facts,
            file,
            symbols,
            node,
            SanitizerKind::Authorization,
            "route-middleware",
            metadata_entry("adapter", "php"),
        );
    }
}

#[derive(Clone, Debug)]
struct PhpCallRoute {
    method: &'static str,
    path: String,
    handler_argument_index: Option<usize>,
}

fn php_routes_from_call(callee: &str, arguments: &[Node<'_>], source: &str) -> Vec<PhpCallRoute> {
    let lower = php_final_segment(callee);
    match lower.as_str() {
        "get" | "post" | "put" | "patch" | "delete" | "options" | "any" => {
            let Some(path) = arguments
                .first()
                .and_then(|argument| string_value(*argument, source))
            else {
                return Vec::new();
            };
            let method = match lower.as_str() {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "patch" => "PATCH",
                "delete" => "DELETE",
                "options" => "OPTIONS",
                "any" => "ANY",
                _ => "ANY",
            };
            vec![PhpCallRoute {
                method,
                path: normalize_path(&path),
                handler_argument_index: Some(1),
            }]
        }
        "match" | "map" => {
            let methods = arguments
                .first()
                .map(|argument| methods_from_php_value(node_text(*argument, source)))
                .unwrap_or_default();
            let Some(path) = arguments
                .get(1)
                .and_then(|argument| string_value(*argument, source))
            else {
                return Vec::new();
            };
            let methods = if methods.is_empty() {
                vec!["ANY"]
            } else {
                methods
            };
            methods
                .into_iter()
                .map(|method| PhpCallRoute {
                    method,
                    path: normalize_path(&path),
                    handler_argument_index: Some(2),
                })
                .collect()
        }
        "resource" | "apiresource" => {
            let Some(resource) = arguments
                .first()
                .and_then(|argument| string_value(*argument, source))
            else {
                return Vec::new();
            };
            laravel_resource_routes(&resource, lower == "apiresource")
        }
        "apiresources" => arguments
            .first()
            .map(|argument| laravel_api_resources_routes(node_text(*argument, source)))
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn php_route_framework(callee: &str, imports: &BTreeSet<String>) -> Option<String> {
    if callee.starts_with("Route::") {
        return Some("Laravel".to_string());
    }
    if imports.iter().any(|module| module.contains("Slim"))
        && (callee.starts_with("$app->")
            || callee.starts_with("$group->")
            || callee.starts_with("$route->")
            || callee.starts_with("$routes->")
            || callee.starts_with("$routeCollector->"))
    {
        return Some("Slim".to_string());
    }
    None
}

fn php_final_segment(callee: &str) -> String {
    callee
        .rsplit([':', '>', '\\'])
        .next()
        .unwrap_or(callee)
        .trim()
        .to_ascii_lowercase()
}

fn collect_flow_fact_from_php_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    route_symbols: &BTreeSet<String>,
    callee: &str,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = php_final_segment(callee);
    let receiver = callee
        .split_once("->")
        .map(|(receiver, _)| receiver.to_ascii_lowercase())
        .or_else(|| {
            callee
                .split_once("::")
                .map(|(receiver, _)| receiver.to_ascii_lowercase())
        })
        .unwrap_or_default();

    if is_php_request_source(&lower, &receiver, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "php"),
        );
    }

    if is_php_sql_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "php"),
        );
    } else if is_php_command_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "php"),
        );
    } else if is_php_file_sink(&lower, &final_lower, node, source) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "php"),
        );
    } else if is_php_template_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Template,
            callee,
            metadata_entry("adapter", "php"),
        );
    } else if is_php_log_sink(&receiver, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Log,
            callee,
            metadata_entry("adapter", "php"),
        );
    } else if final_lower == "redirect" {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Redirect,
            callee,
            metadata_entry("adapter", "php"),
        );
    }

    if is_php_sanitizer(&lower, &final_lower) {
        let kind = if matches!(final_lower.as_str(), "htmlspecialchars" | "e")
            || final_lower.contains("escape")
        {
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
            metadata_entry("adapter", "php"),
        );
    }

    if final_lower == "middleware"
        && node_text(node, source)
            .to_ascii_lowercase()
            .contains("auth")
    {
        add_sanitizer(
            facts,
            file,
            symbols,
            node,
            SanitizerKind::Authorization,
            callee,
            metadata_entry("adapter", "php"),
        );
    }

    if lower.starts_with("unserialize") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Deserialization,
            callee,
            metadata_entry("adapter", "php"),
        );
    }

    let in_route_handler = containing_symbol_id(symbols, node)
        .as_ref()
        .is_some_and(|symbol_id| route_symbols.contains(symbol_id));
    if in_route_handler && final_lower == "json" {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::HttpResponse,
            callee,
            metadata_entry("adapter", "php"),
        );
    }
}

fn collect_superglobal_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    walk_tree(root, &mut |node| {
        if !matches!(node.kind(), "subscript_expression" | "variable_name") {
            return;
        }
        let text = node_text(node, source);
        if [
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_COOKIE",
            "$_FILES",
            "$_SERVER",
        ]
        .iter()
        .any(|needle| text.contains(needle))
        {
            add_data_source(
                facts,
                file,
                symbols,
                node,
                DataSourceKind::Request,
                text,
                None,
                metadata_entry("adapter", "php"),
            );
        }
    });
}

fn is_php_request_source(full_lower: &str, receiver: &str, final_lower: &str) -> bool {
    receiver.contains("request")
        && matches!(
            final_lower,
            "input" | "query" | "request" | "post" | "get" | "all" | "file" | "header"
        )
        || matches!(full_lower, "request" | "request()")
        || full_lower.starts_with("input::")
}

fn is_php_sql_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "query"
            | "exec"
            | "prepare"
            | "raw"
            | "select"
            | "statement"
            | "unprepared"
            | "selectraw"
            | "whereraw"
            | "orderbyraw"
    ) && (matches!(receiver, "$pdo" | "$db" | "$conn" | "$connection" | "db")
        || full_lower.starts_with("db::")
        || full_lower.contains("pdo"))
}

fn is_php_command_sink(full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "exec" | "shell_exec" | "system" | "passthru" | "proc_open" | "popen"
    ) || matches!(
        full_lower,
        "exec" | "shell_exec" | "system" | "passthru" | "proc_open" | "popen"
    )
}

fn is_php_file_sink(full_lower: &str, final_lower: &str, node: Node<'_>, source: &str) -> bool {
    matches!(
        final_lower,
        "file_put_contents" | "move_uploaded_file" | "unlink"
    ) || full_lower == "file_put_contents"
        || (full_lower == "fopen" && fopen_writes(node, source))
}

fn is_php_template_sink(full_lower: &str, final_lower: &str) -> bool {
    matches!(final_lower, "view" | "render" | "make")
        && (full_lower.contains("view") || full_lower.contains("twig") || full_lower == "view")
}

fn is_php_log_sink(receiver: &str, final_lower: &str) -> bool {
    matches!(receiver, "log" | "$logger")
        && matches!(
            final_lower,
            "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency"
        )
        || final_lower == "error_log"
}

fn is_php_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "validate" | "validator" | "filter_var" | "htmlspecialchars" | "e" | "csrf_token"
    ) || full_lower.contains("validator::")
        || full_lower.contains("sanitize")
        || final_lower.contains("escape")
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
    metadata.insert("adapter".to_string(), "php".to_string());
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

fn descendants_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Vec<Node<'tree>> {
    let mut found = Vec::new();
    walk_tree(node, &mut |candidate| {
        if candidate != node && candidate.kind() == kind {
            found.push(candidate);
        }
    });
    found
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

fn normalize_php_handler_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.contains("function") || trimmed.contains("=>") {
        return None;
    }
    let name = trimmed
        .trim_matches(['[', ']'])
        .split(',')
        .next_back()
        .unwrap_or(trimmed)
        .trim()
        .trim_matches(['"', '\''])
        .rsplit("::")
        .next()
        .unwrap_or(trimmed)
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn symfony_route_attribute_path(text: &str) -> Option<String> {
    if let Some(fragment) = php_keyword_value_fragment(text, "path") {
        return first_quoted_fragment(fragment);
    }
    let first_quote = text.find(['"', '\''])?;
    let name_key = text.find("name:");
    if name_key.is_some_and(|index| index < first_quote) {
        return None;
    }
    first_quoted_fragment(text)
}

fn explicit_methods_from_php_keyword(text: &str, key: &str) -> Vec<&'static str> {
    php_keyword_value_fragment(text, key)
        .map(methods_from_php_value)
        .unwrap_or_default()
}

fn methods_from_php_value(text: &str) -> Vec<&'static str> {
    quoted_fragments(text)
        .into_iter()
        .filter_map(|method| http_method_literal(&method))
        .collect()
}

fn laravel_resource_routes(resource: &str, api_only: bool) -> Vec<PhpCallRoute> {
    let collection = normalize_path(resource);
    let parameter = singular_resource_parameter(resource);
    let member = join_paths(Some(&collection), Some(&format!("{{{parameter}}}")));
    let mut routes = vec![
        PhpCallRoute {
            method: "GET",
            path: collection.clone(),
            handler_argument_index: Some(1),
        },
        PhpCallRoute {
            method: "POST",
            path: collection.clone(),
            handler_argument_index: Some(1),
        },
        PhpCallRoute {
            method: "GET",
            path: member.clone(),
            handler_argument_index: Some(1),
        },
        PhpCallRoute {
            method: "PUT",
            path: member.clone(),
            handler_argument_index: Some(1),
        },
        PhpCallRoute {
            method: "PATCH",
            path: member.clone(),
            handler_argument_index: Some(1),
        },
        PhpCallRoute {
            method: "DELETE",
            path: member.clone(),
            handler_argument_index: Some(1),
        },
    ];
    if !api_only {
        routes.insert(
            1,
            PhpCallRoute {
                method: "GET",
                path: join_paths(Some(&collection), Some("create")),
                handler_argument_index: Some(1),
            },
        );
        routes.insert(
            routes.len().saturating_sub(3),
            PhpCallRoute {
                method: "GET",
                path: join_paths(Some(&member), Some("edit")),
                handler_argument_index: Some(1),
            },
        );
    }
    routes
}

fn laravel_api_resources_routes(text: &str) -> Vec<PhpCallRoute> {
    quoted_fragments(text)
        .into_iter()
        .flat_map(|resource| laravel_resource_routes(&resource, true))
        .collect()
}

fn singular_resource_parameter(resource: &str) -> String {
    let segment = resource
        .trim_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(resource)
        .trim();
    segment
        .strip_suffix("ies")
        .map(|prefix| format!("{prefix}y"))
        .or_else(|| segment.strip_suffix('s').map(str::to_string))
        .unwrap_or_else(|| segment.to_string())
}

fn route_prefix_for_node(node: Node<'_>, source: &str) -> Option<String> {
    let mut prefixes = Vec::new();
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if matches!(
            candidate.kind(),
            "function_call_expression" | "member_call_expression" | "scoped_call_expression"
        ) {
            let text = node_text(candidate, source);
            if text.contains("->group") || text.contains("::group") {
                if let Some(prefix) = laravel_prefix_from_group_text(text)
                    .or_else(|| first_group_argument_prefix(text))
                {
                    prefixes.push(prefix);
                }
            }
        }
        parent = candidate.parent();
    }
    prefixes
        .into_iter()
        .rev()
        .fold(None, |prefix: Option<String>, next| {
            Some(join_paths(prefix.as_deref(), Some(&next)))
        })
}

fn laravel_prefix_from_group_text(text: &str) -> Option<String> {
    let prefix_index = text.find("prefix(")?;
    first_quoted_fragment(&text[prefix_index..]).map(|prefix| normalize_path(&prefix))
}

fn first_group_argument_prefix(text: &str) -> Option<String> {
    let group_index = text.find("group(")?;
    let first_argument = first_php_call_argument_text(&text[group_index + "group(".len()..])?;
    let trimmed = first_argument.trim();
    laravel_prefix_from_group_array_argument(trimmed).or_else(|| {
        trimmed
            .starts_with(['"', '\''])
            .then(|| first_quoted_fragment(trimmed).map(|prefix| normalize_path(&prefix)))
            .flatten()
    })
}

fn first_php_call_argument_text(text: &str) -> Option<&str> {
    let mut quote = None;
    let mut escaped = false;
    let mut depth = 0usize;
    for (index, ch) in text.char_indices() {
        if let Some(quote_char) = quote {
            if ch == '\\' && !escaped {
                escaped = true;
                continue;
            }
            if ch == quote_char && !escaped {
                quote = None;
            }
            escaped = false;
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' if depth > 0 => depth = depth.saturating_sub(1),
            ',' | ')' if depth == 0 => return Some(text[..index].trim()),
            _ => {}
        }
    }
    None
}

fn laravel_prefix_from_group_array_argument(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if !(trimmed.starts_with('[') || trimmed.starts_with("array(")) {
        return None;
    }
    php_quoted_key_value_fragment(trimmed, "prefix")
        .or_else(|| php_keyword_value_fragment(trimmed, "prefix"))
        .and_then(first_quoted_fragment)
        .map(|prefix| normalize_path(&prefix))
}

fn php_quoted_key_value_fragment<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut search_start = 0usize;
    while search_start < text.len() {
        let Some(relative) = text[search_start..].find(['"', '\'']) else {
            break;
        };
        let key_quote_start = search_start + relative;
        let quote = bytes[key_quote_start];
        let key_start = key_quote_start + 1;
        let Some(relative_end) = text[key_start..].find(quote as char) else {
            break;
        };
        let key_end = key_start + relative_end;
        if &text[key_start..key_end] == key {
            let mut index = key_end + 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            if bytes.get(index) == Some(&b'=') && bytes.get(index + 1) == Some(&b'>') {
                index += 2;
            } else if bytes.get(index) == Some(&b':') {
                index += 1;
            } else {
                search_start = key_end + 1;
                continue;
            }
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            return Some(value_fragment_from(text, index));
        }
        search_start = key_end + 1;
    }
    None
}

fn php_route_call_has_auth_middleware(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    (lower.contains("middleware(") || lower.contains("->middleware"))
        && (lower.contains("'auth")
            || lower.contains("\"auth")
            || lower.contains("auth:")
            || lower.contains("auth."))
}

fn php_keyword_value_fragment<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut search_start = 0usize;
    while let Some(relative) = text[search_start..].find(key) {
        let key_start = search_start + relative;
        let key_end = key_start + key.len();
        let before_ok = key_start == 0
            || !bytes[key_start - 1].is_ascii_alphanumeric() && bytes[key_start - 1] != b'_';
        let after_ok = key_end >= bytes.len()
            || !bytes[key_end].is_ascii_alphanumeric() && bytes[key_end] != b'_';
        if !before_ok || !after_ok {
            search_start = key_end;
            continue;
        }
        let mut index = key_end;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if bytes.get(index) == Some(&b'=') {
            index += 1;
            if bytes.get(index) == Some(&b'>') {
                index += 1;
            }
        } else if bytes.get(index) == Some(&b':') {
            index += 1;
        } else {
            search_start = key_end;
            continue;
        }
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        return Some(value_fragment_from(text, index));
    }
    None
}

fn value_fragment_from(text: &str, start: usize) -> &str {
    let bytes = text.as_bytes();
    if let Some(open) = bytes
        .get(start)
        .copied()
        .filter(|ch| matches!(ch, b'[' | b'(' | b'{'))
    {
        let close = match open {
            b'[' => b']',
            b'(' => b')',
            b'{' => b'}',
            _ => b',',
        };
        let mut depth = 0usize;
        for index in start..bytes.len() {
            match bytes[index] {
                ch if ch == open => depth += 1,
                ch if ch == close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return &text[start..=index];
                    }
                }
                _ => {}
            }
        }
        return &text[start..];
    }
    let end = text[start..]
        .find(',')
        .map(|relative| start + relative)
        .unwrap_or(text.len());
    &text[start..end]
}

fn quoted_fragments(text: &str) -> Vec<String> {
    let mut fragments = Vec::new();
    let mut quote = None;
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if quote.is_none() && matches!(ch, '"' | '\'') {
            quote = Some(ch);
            start = index + ch.len_utf8();
        } else if Some(ch) == quote {
            fragments.push(text[start..index].to_string());
            quote = None;
        }
    }
    fragments
}

fn http_method_literal(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => Some("GET"),
        "POST" => Some("POST"),
        "PUT" => Some("PUT"),
        "PATCH" => Some("PATCH"),
        "DELETE" => Some("DELETE"),
        "OPTIONS" => Some("OPTIONS"),
        "HEAD" => Some("HEAD"),
        _ => None,
    }
}

fn fopen_writes(node: Node<'_>, source: &str) -> bool {
    call_argument_nodes(node)
        .get(1)
        .and_then(|argument| string_value(*argument, source))
        .is_some_and(|mode| {
            mode.contains('w') || mode.contains('a') || mode.contains('x') || mode.contains('+')
        })
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

    fn analyze_php(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("app/Http/routes.php", "PHP");
        file.service_id = Some("api".to_string());
        PhpAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("php analysis succeeds")
    }

    #[test]
    fn extracts_laravel_routes_sources_sinks_and_auth_hints() {
        let source = r#"<?php
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;

class UserController {
    public function show(Request $request) {
        $name = $request->input('name');
        DB::select('select * from users where name = ' . $name);
        shell_exec($name);
        Log::info($name);
        return view('users.show', ['name' => e($name)]);
    }
}

Route::get('/users/{id}', [UserController::class, 'show'])->middleware('auth');
"#;

        let facts = analyze_php(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module == "Illuminate\\Support\\Facades\\Route"));
        assert!(facts
            .symbols
            .iter()
            .any(|fact| fact.name == "UserController"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/users/{id}"
                && route.framework.as_deref() == Some("Laravel")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("$request->input")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("DB::select")
                && sink.kind == SinkKind::SqlQuery));
        assert!(facts.sinks.iter().any(
            |sink| sink.name.as_deref() == Some("shell_exec") && sink.kind == SinkKind::Command
        ));
        assert!(
            facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_symfony_and_slim_routes_but_rejects_array_get_false_positive() {
        let source = r#"<?php
use Symfony\Component\Routing\Annotation\Route;
use Slim\App;

class HealthController {
    #[Route('/health', methods: ['GET'])]
    public function health(Request $request) {
        $q = $_GET['q'];
        return $this->json(['ok' => $q]);
    }
}

$app = new App();
$app->post('/hooks', function ($request, $response) {
    file_put_contents('/tmp/hook', $request->getBody());
});

$cache->get('/not-a-route');
"#;

        let facts = analyze_php(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/health"
                && route.framework.as_deref() == Some("Symfony")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/hooks"
                && route.framework.as_deref() == Some("Slim")
        }));
        assert!(
            !facts
                .routes
                .iter()
                .any(|route| route.path == "/not-a-route"),
            "{:?}",
            facts.routes
        );
        assert!(facts.data_sources.iter().any(|source| source
            .name
            .as_deref()
            .is_some_and(|name| name.contains("$_GET"))));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("file_put_contents")));
    }

    #[test]
    fn parses_explicit_methods_without_path_substring_false_positives() {
        let source = r#"<?php
use Symfony\Component\Routing\Annotation\Route;
use Illuminate\Support\Facades\Route as LaravelRoute;

class WidgetController {
    #[Route(name: 'widgets_store', path: '/widgets', methods: ['POST'])]
    public function store() {}
}

Route::post('/widgets', [WidgetController::class, 'store']);
"#;

        let facts = analyze_php(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/widgets"
                && route.framework.as_deref() == Some("Symfony")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/widgets"
                && route.framework.as_deref() == Some("Laravel")
        }));
        assert!(
            !facts
                .routes
                .iter()
                .any(|route| route.method == "GET" && route.path == "/widgets"),
            "{:?}",
            facts.routes
        );
    }

    #[test]
    fn expands_laravel_match_slim_map_resources_and_prefix_groups() {
        let source = r#"<?php
use Illuminate\Support\Facades\Route;
use Slim\App;

class WidgetController {}
class PhotoController {}

Route::match(['get', 'post'], '/combo', [WidgetController::class, 'combo']);
Route::prefix('api')->group(function () {
    Route::apiResource('widgets', WidgetController::class);
});
Route::group(['prefix' => 'api'], function () {
    Route::get('/users', [WidgetController::class, 'users']);
});
Route::apiResources([
    'photos' => PhotoController::class,
]);

$app = new App();
$app->map(['PUT', 'DELETE'], '/hooks', function ($request, $response) {});
"#;

        let facts = analyze_php(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/combo"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/combo"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "PUT" && route.path == "/hooks"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "DELETE" && route.path == "/hooks"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/widgets"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/users"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/prefix/users"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/api/widgets"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/widgets/{widget}"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "PATCH" && route.path == "/api/widgets/{widget}"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/photos/{photo}"));
    }

    #[test]
    fn avoids_current_user_and_broad_auth_route_false_authorization() {
        let source = r#"<?php
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Illuminate\Support\Facades\Route;

class AuthStatusController {
    #[Route('/auth/status', methods: ['GET'])]
    public function show(#[CurrentUser] $user) {}
}

Route::get('/auth/status', [AuthStatusController::class, 'show']);
"#;

        let facts = analyze_php(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/auth/status"
                && route.framework.as_deref() == Some("Symfony")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/auth/status"
                && route.framework.as_deref() == Some("Laravel")
        }));
        assert!(
            !facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
    }
}
