use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, Confidence, DataSourceFact, DataSourceKind, ImportKind,
    RouteFact, SanitizerKind, SinkFact, SinkKind, SourceRange, SymbolKind, TaintEdge,
    TaintEdgeKind,
};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

use super::common::{
    add_call, add_data_source, add_import, add_local_taint_edges, add_sanitizer, add_sink,
    add_symbol, argument_texts, child_of_kind, child_text, containing_symbol_id,
    direct_named_children, facts_with_source, final_segment, first_string_descendant, join_paths,
    lower_final_segment, metadata_entry, node_text, parse_tree, range_for_node, string_value,
    symbol_id_by_name, walk_tree, SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct NodeTypeScriptAdapter;

impl SourceAdapter for NodeTypeScriptAdapter {
    fn id(&self) -> &'static str {
        "node-typescript-tree-sitter-tier-a"
    }

    fn language(&self) -> &'static str {
        "Node/TypeScript"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let language = if uses_tsx_grammar(&input.source_file.path) {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        };
        let tree = parse_tree(&input, language)?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let provenance = collect_node_provenance(root, input.contents, &imports);
        collect_calls_routes_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &provenance,
        );
        collect_nest_decorator_routes(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
        );
        add_local_taint_edges(&mut facts);
        add_node_request_sql_local_taint_edges(&mut facts, root, input.contents);
        Ok(facts)
    }
}

fn add_node_request_sql_local_taint_edges(
    facts: &mut AnalysisFacts,
    root: Node<'_>,
    source_text: &str,
) {
    remove_broad_node_request_sql_edges(facts);

    let mut edges = Vec::new();
    for source in facts.data_sources.iter().filter(|source| {
        source.kind == DataSourceKind::Request
            && node_adapter_fact_metadata_is_node(&source.metadata)
    }) {
        for sink in facts.sinks.iter().filter(|sink| {
            sink.kind == SinkKind::SqlQuery && node_adapter_fact_metadata_is_node(&sink.metadata)
        }) {
            if source.file_id.as_deref() != sink.file_id.as_deref()
                || facts.taint_edges.iter().any(|edge| {
                    edge.kind == TaintEdgeKind::SourceToSink
                        && edge.source_id == source.id
                        && edge.target_id == sink.id
                })
                || !node_request_source_contributes_to_sql_argument(root, source_text, source, sink)
            {
                continue;
            }
            edges.push(TaintEdge {
                id: stable_fact_id("taint-edge", [source.id.as_str(), sink.id.as_str(), ""]),
                source_id: source.id.clone(),
                target_id: sink.id.clone(),
                sanitizer_id: None,
                kind: TaintEdgeKind::SourceToSink,
                confidence: Confidence::Low,
                metadata: BTreeMap::new(),
            });
        }
    }
    facts.taint_edges.extend(edges);
}

fn remove_broad_node_request_sql_edges(facts: &mut AnalysisFacts) {
    let request_source_ids = facts
        .data_sources
        .iter()
        .filter(|source| {
            source.kind == DataSourceKind::Request
                && node_adapter_fact_metadata_is_node(&source.metadata)
        })
        .map(|source| source.id.clone())
        .collect::<BTreeSet<_>>();
    let sql_sink_ids = facts
        .sinks
        .iter()
        .filter(|sink| {
            sink.kind == SinkKind::SqlQuery && node_adapter_fact_metadata_is_node(&sink.metadata)
        })
        .map(|sink| sink.id.clone())
        .collect::<BTreeSet<_>>();

    facts.taint_edges.retain(|edge| {
        !(edge.kind == TaintEdgeKind::SourceToSink
            && request_source_ids.contains(&edge.source_id)
            && sql_sink_ids.contains(&edge.target_id))
    });
}

fn node_adapter_fact_metadata_is_node(metadata: &BTreeMap<String, String>) -> bool {
    metadata
        .get("adapter")
        .is_some_and(|adapter| adapter.eq_ignore_ascii_case("node-typescript"))
}

fn node_request_source_contributes_to_sql_argument(
    root: Node<'_>,
    source_text: &str,
    source: &DataSourceFact,
    sink: &SinkFact,
) -> bool {
    let (Some(source_range), Some(sink_range)) = (source.range.as_ref(), sink.range.as_ref())
    else {
        return false;
    };
    if source_range.start > sink_range.end {
        return false;
    }
    let Some(source_node) = exact_node_for_range(root, source_range) else {
        return false;
    };
    let Some(sink_call) =
        exact_node_for_range(root, sink_range).filter(|node| node.kind() == "call_expression")
    else {
        return false;
    };
    let Some(scope) = smallest_callable_containing_both(root, source_node, sink_call) else {
        return false;
    };
    let Some(sql_argument) = sql_argument_node_for_query_call(sink_call, source_text) else {
        return false;
    };

    let tainted_identifiers =
        tainted_request_identifiers_before_sink(scope, source_text, source_node, sink_call);
    expression_references_request_taint(
        sql_argument,
        source_text,
        source_node,
        &tainted_identifiers,
    )
}

fn exact_node_for_range<'tree>(root: Node<'tree>, range: &SourceRange) -> Option<Node<'tree>> {
    let (start, end) = range_byte_bounds(range)?;
    let mut found = None;
    walk_tree(root, &mut |node| {
        if found.is_none() && node.start_byte() == start && node.end_byte() == end {
            found = Some(node);
        }
    });
    found
}

fn range_byte_bounds(range: &SourceRange) -> Option<(usize, usize)> {
    Some((
        usize::try_from(range.start.byte_offset?).ok()?,
        usize::try_from(range.end.byte_offset?).ok()?,
    ))
}

fn smallest_callable_containing_both<'tree>(
    root: Node<'tree>,
    source_node: Node<'tree>,
    sink_call: Node<'tree>,
) -> Option<Node<'tree>> {
    let mut best = None;
    walk_tree(root, &mut |node| {
        if !is_callable_scope_node(node) {
            return;
        }
        if !node_contains_node(node, source_node) || !node_contains_node(node, sink_call) {
            return;
        }
        if best.is_none_or(|current: Node<'_>| node_byte_len(node) < node_byte_len(current)) {
            best = Some(node);
        }
    });
    best
}

fn is_callable_scope_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "function_declaration"
            | "generator_function_declaration"
            | "function"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
    )
}

fn node_contains_node(outer: Node<'_>, inner: Node<'_>) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

fn node_byte_len(node: Node<'_>) -> usize {
    node.end_byte().saturating_sub(node.start_byte())
}

fn sql_argument_node_for_query_call<'tree>(call: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    let first = *call_argument_nodes(call).first()?;
    if matches!(first.kind(), "object" | "object_pattern") {
        return object_sql_text_value_node(first, source);
    }
    Some(first)
}

fn object_sql_text_value_node<'tree>(object: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    direct_named_children(object)
        .into_iter()
        .filter(|child| child.kind() == "pair")
        .find_map(|pair| {
            let key = pair
                .child_by_field_name("key")
                .map(|key| node_text(key, source).trim_matches(['"', '\'', '`']))
                .unwrap_or_default()
                .to_ascii_lowercase();
            matches!(key.as_str(), "text" | "query" | "sql")
                .then(|| pair.child_by_field_name("value"))
                .flatten()
        })
}

fn tainted_request_identifiers_before_sink(
    scope: Node<'_>,
    source: &str,
    source_node: Node<'_>,
    sink_call: Node<'_>,
) -> BTreeSet<String> {
    let mut tainted = BTreeSet::new();
    walk_node_executable_scope(scope, &mut |node| {
        if node.end_byte() < source_node.start_byte() || node.start_byte() > sink_call.start_byte()
        {
            return;
        }
        if !matches!(node.kind(), "variable_declarator" | "assignment_expression") {
            return;
        }
        let Some(value) = node_binding_value_node(node) else {
            return;
        };
        let binding_names = node_binding_names(node, source);
        if binding_value_contributes_request_to_sql_text(value, source, source_node, &tainted) {
            tainted.extend(binding_names);
        } else if node_is_simple_binding_overwrite(node, source) {
            for name in node_simple_binding_names(node, source) {
                tainted.remove(&name);
            }
        }
    });
    tainted
}

fn walk_node_executable_scope<'tree>(scope: Node<'tree>, visit: &mut impl FnMut(Node<'tree>)) {
    visit(scope);
    let mut cursor = scope.walk();
    for child in scope.children(&mut cursor) {
        if is_callable_scope_node(child) {
            continue;
        }
        walk_node_executable_scope(child, visit);
    }
}

fn binding_value_contributes_request_to_sql_text(
    value: Node<'_>,
    source: &str,
    source_node: Node<'_>,
    tainted_identifiers: &BTreeSet<String>,
) -> bool {
    if matches!(value.kind(), "object" | "object_pattern") {
        return object_sql_text_value_node(value, source).is_some_and(|sql_value| {
            expression_references_request_taint(sql_value, source, source_node, tainted_identifiers)
        });
    }
    expression_references_request_taint(value, source, source_node, tainted_identifiers)
}

fn node_binding_value_node(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))
}

fn node_is_simple_binding_overwrite(node: Node<'_>, source: &str) -> bool {
    node.kind() == "variable_declarator"
        || (node.kind() == "assignment_expression"
            && node_assignment_operator(node, source).is_some_and(|operator| operator == "="))
}

fn node_assignment_operator<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    source
        .get(left.end_byte()..right.start_byte())
        .map(str::trim)
}

fn node_simple_binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .filter(|name| name.kind() == "identifier")
        .map(|name| vec![node_text(name, source).to_string()])
        .unwrap_or_default()
}

fn expression_references_request_taint(
    expression: Node<'_>,
    source: &str,
    source_node: Node<'_>,
    tainted_identifiers: &BTreeSet<String>,
) -> bool {
    node_contains_node(expression, source_node)
        || node_identifier_view(node_text(expression, source))
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'))
            .filter(|token| !token.is_empty())
            .any(|token| tainted_identifiers.contains(token))
}

fn node_identifier_view(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' => {
                output.push(' ');
                skip_node_quoted_string(&mut chars, ch);
            }
            '`' => {
                output.push(' ');
                copy_node_template_interpolations(&mut chars, &mut output);
            }
            _ => output.push(ch),
        }
    }
    output
}

fn skip_node_quoted_string<I>(chars: &mut std::iter::Peekable<I>, quote: char)
where
    I: Iterator<Item = char>,
{
    let mut escaped = false;
    for ch in chars.by_ref() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == quote {
            break;
        }
    }
}

fn copy_node_template_interpolations<I>(chars: &mut std::iter::Peekable<I>, output: &mut String)
where
    I: Iterator<Item = char>,
{
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '`' {
            break;
        } else if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            output.push(' ');
            copy_node_template_expression(chars, output);
            output.push(' ');
        }
    }
}

fn copy_node_template_expression<I>(chars: &mut std::iter::Peekable<I>, output: &mut String)
where
    I: Iterator<Item = char>,
{
    let mut depth = 1u32;
    for ch in chars.by_ref() {
        match ch {
            '{' => {
                depth += 1;
                output.push(ch);
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    break;
                }
                output.push(ch);
            }
            _ => output.push(ch),
        }
    }
}

fn uses_tsx_grammar(path: &std::path::Path) -> bool {
    matches!(
        path.extension().and_then(|extension| extension.to_str()),
        Some("tsx" | "jsx")
    )
}

fn collect_imports(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
) -> BTreeSet<String> {
    let mut imports = BTreeSet::new();
    walk_tree(root, &mut |node| match node.kind() {
        "import_statement" => {
            let Some(module) = first_string_descendant(node, source) else {
                return;
            };
            let imported_symbols = imported_symbols_from_import(node, source);
            let alias = default_import_alias(node, source);
            imports.insert(module.clone());
            add_import(
                facts,
                file,
                module,
                alias,
                imported_symbols,
                ImportKind::Module,
                node,
            );
        }
        "export_statement" => {
            let Some(module) = export_source_module(node, source) else {
                return;
            };
            let imported_symbols = imported_symbols_from_import(node, source);
            imports.insert(module.clone());
            add_import(
                facts,
                file,
                module,
                None,
                imported_symbols,
                ImportKind::Module,
                node,
            );
        }
        "call_expression" => {
            let Some(function_node) = node.child_by_field_name("function") else {
                return;
            };
            if node_text(function_node, source) != "require" {
                return;
            }
            let Some(module) = first_string_descendant(node, source) else {
                return;
            };
            imports.insert(module.clone());
            add_import(
                facts,
                file,
                module,
                None,
                Vec::new(),
                ImportKind::Module,
                node,
            );
        }
        _ => {}
    });
    imports
}

fn export_source_module(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("source")
        .and_then(|source_node| string_value(source_node, source))
        .or_else(|| {
            let text = node_text(node, source);
            text.split_once(" from ")
                .and_then(|(_, rest)| first_quoted_fragment(rest))
        })
}

fn imported_symbols_from_import(node: Node<'_>, source: &str) -> Vec<String> {
    let mut symbols = Vec::new();
    walk_tree(node, &mut |candidate| {
        if matches!(
            candidate.kind(),
            "import_specifier" | "namespace_import" | "named_imports"
        ) {
            let text = node_text(candidate, source);
            if !text.starts_with('{') && !text.is_empty() {
                symbols.push(text.to_string());
            }
        }
    });
    symbols.sort();
    symbols.dedup();
    symbols
}

fn default_import_alias(node: Node<'_>, source: &str) -> Option<String> {
    direct_named_children(node)
        .into_iter()
        .find(|child| child.kind() == "import_clause")
        .and_then(|clause| {
            direct_named_children(clause)
                .into_iter()
                .find(|candidate| candidate.kind() == "identifier")
        })
        .map(|identifier| node_text(identifier, source).to_string())
}

fn collect_symbols(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
) -> Vec<SymbolSpan> {
    let mut spans = Vec::new();
    walk_tree(root, &mut |node| match node.kind() {
        "function_declaration" | "generator_function_declaration" => {
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
        "method_definition" | "public_field_definition" => {
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
        "variable_declarator" => {
            if let Some(name) = child_text(node, "name", source) {
                let value_kind = node
                    .child_by_field_name("value")
                    .map(|value| value.kind())
                    .unwrap_or_default();
                let kind = if matches!(
                    value_kind,
                    "arrow_function" | "function" | "function_expression"
                ) {
                    SymbolKind::Function
                } else {
                    SymbolKind::Variable
                };
                add_symbol(facts, &mut spans, file, node, name, kind, None, source);
            }
        }
        "interface_declaration" => {
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
        "type_alias_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Type,
                    None,
                    source,
                );
            }
        }
        _ => {}
    });
    spans
}

#[derive(Clone, Debug)]
struct NodeRouterInfo {
    framework: String,
}

fn collect_node_provenance(
    root: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
) -> BTreeMap<String, NodeRouterInfo> {
    let mut routers = BTreeMap::new();
    walk_tree(root, &mut |node| {
        if !matches!(node.kind(), "variable_declarator" | "assignment_expression") {
            return;
        }
        let names = node_binding_names(node, source);
        let values = node_binding_value_nodes(node);
        for (name, value) in names.iter().zip(values.iter()) {
            if let Some(router) = router_info_from_node_expr(*value, source, imports) {
                routers.insert(name.clone(), router);
            }
        }
    });
    routers
}

fn node_binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    node.child_by_field_name("left")
        .or_else(|| node.child_by_field_name("name"))
        .map(|name| node_identifiers_in_node(name, source))
        .unwrap_or_default()
}

fn node_identifiers_in_node(node: Node<'_>, source: &str) -> Vec<String> {
    if node.kind() == "identifier" {
        return vec![node_text(node, source).to_string()];
    }
    direct_named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "identifier")
        .map(|identifier| node_text(identifier, source).to_string())
        .collect()
}

fn node_binding_value_nodes(node: Node<'_>) -> Vec<Node<'_>> {
    node.child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"))
        .map(|value| vec![value])
        .unwrap_or_default()
}

fn router_info_from_node_expr(
    value: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
) -> Option<NodeRouterInfo> {
    let text = node_text(value, source);
    let callee = first_call_expression(value)
        .and_then(|call| call.child_by_field_name("function"))
        .map(|function| node_text(function, source))
        .unwrap_or_default();
    if has_node_import(imports, "express")
        && matches!(callee, "express" | "express.Router" | "Router")
    {
        return Some(NodeRouterInfo {
            framework: "Express".to_string(),
        });
    }
    if has_node_import(imports, "fastify")
        && (matches!(callee, "fastify" | "Fastify")
            || text.contains("require('fastify')")
            || text.contains("require(\"fastify\")"))
    {
        return Some(NodeRouterInfo {
            framework: "Fastify".to_string(),
        });
    }
    None
}

fn first_call_expression(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "call_expression" {
        return Some(node);
    }
    direct_named_children(node)
        .into_iter()
        .find_map(first_call_expression)
}

fn has_node_import(imports: &BTreeSet<String>, module: &str) -> bool {
    imports
        .iter()
        .any(|imported| imported == module || imported.contains(module))
}

fn collect_calls_routes_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    provenance: &BTreeMap<String, NodeRouterInfo>,
) {
    walk_tree(root, &mut |node| {
        if node.kind() == "call_expression" {
            let Some(function_node) = node.child_by_field_name("function") else {
                return;
            };
            let callee = node_text(function_node, source).to_string();
            let arguments = argument_texts(node, source);
            add_call(facts, file, symbols, node, callee.clone(), arguments);
            collect_call_route(facts, file, node, source, symbols, provenance, &callee);
            collect_flow_fact_from_call(facts, file, node, symbols, &callee);
        } else if matches!(node.kind(), "member_expression" | "subscript_expression") {
            collect_member_source(facts, file, node, source, symbols);
        }
    });
}

fn collect_call_route(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    provenance: &BTreeMap<String, NodeRouterInfo>,
    callee: &str,
) {
    if is_inside_decorator(node) {
        return;
    }
    let argument_nodes = call_argument_nodes(node);
    if lower_final_segment(callee) == "route" {
        let Some(router) =
            node_route_receiver(callee).and_then(|receiver| provenance.get(receiver))
        else {
            return;
        };
        if router.framework != "Fastify" {
            return;
        }
        if let Some((method, path)) = fastify_route_object(&argument_nodes, source) {
            push_route(
                facts,
                file,
                node,
                symbols,
                method,
                path,
                router.framework.clone(),
                None,
                callee,
            );
        }
        return;
    }

    let Some(method) = node_http_method(callee) else {
        return;
    };
    let Some(router) = node_route_receiver(callee).and_then(|receiver| provenance.get(receiver))
    else {
        return;
    };
    let Some(path) = argument_nodes
        .first()
        .and_then(|argument| string_value(*argument, source))
    else {
        return;
    };
    if !path.starts_with('/') {
        return;
    }
    let handler_symbol_id = argument_nodes
        .iter()
        .skip(1)
        .find_map(|argument| normalize_handler_name(node_text(*argument, source)))
        .and_then(|name| symbol_id_by_name(symbols, &name));
    push_route(
        facts,
        file,
        node,
        symbols,
        method,
        path,
        router.framework.clone(),
        handler_symbol_id,
        callee,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_route(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    symbols: &[SymbolSpan],
    method: &'static str,
    path: String,
    framework: String,
    explicit_symbol_id: Option<String>,
    callee: &str,
) {
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "node-typescript".to_string());
    metadata.insert("callee".to_string(), callee.to_string());
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
        symbol_id: explicit_symbol_id.or_else(|| containing_symbol_id(symbols, node)),
        service_id: file.service_id.clone(),
        method: method.to_string(),
        path,
        framework: Some(framework),
        range: range_for_node(node),
        metadata,
    });
}

fn node_http_method(callee: &str) -> Option<&'static str> {
    match lower_final_segment(callee).as_str() {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" | "del" => Some("DELETE"),
        "options" => Some("OPTIONS"),
        "head" => Some("HEAD"),
        "all" | "use" => Some("ANY"),
        _ => None,
    }
}

fn node_route_receiver(callee: &str) -> Option<&str> {
    callee.split_once('.').map(|(receiver, _)| receiver.trim())
}

fn is_inside_decorator(node: Node<'_>) -> bool {
    let mut parent = node.parent();
    while let Some(candidate) = parent {
        if candidate.kind() == "decorator" {
            return true;
        }
        parent = candidate.parent();
    }
    false
}

fn collect_member_source(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    let text = node_text(node, source);
    let lower = text.to_ascii_lowercase();
    if lower.contains("req.query")
        || lower.contains("req.params")
        || lower.contains("req.body")
        || lower.contains("req.headers")
        || lower.contains("request.query")
        || lower.contains("request.params")
        || lower.contains("request.body")
        || lower.contains("ctx.request")
    {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            text,
            None,
            metadata_entry("adapter", "node-typescript"),
        );
    }
}

fn fastify_route_object(
    argument_nodes: &[Node<'_>],
    source: &str,
) -> Option<(&'static str, String)> {
    let object = argument_nodes.first()?;
    if !matches!(object.kind(), "object" | "object_pattern") {
        return None;
    }
    let mut method = None;
    let mut path = None;
    for pair in direct_named_children(*object) {
        if !matches!(pair.kind(), "pair" | "property_identifier") {
            continue;
        }
        let key = pair
            .child_by_field_name("key")
            .map(|key| node_text(key, source).trim_matches(['"', '\'']))
            .unwrap_or_default();
        let Some(value_node) = pair.child_by_field_name("value") else {
            continue;
        };
        match key {
            "method" => {
                let raw = string_value(value_node, source)
                    .unwrap_or_else(|| node_text(value_node, source).to_string());
                method = method_from_text(&raw);
            }
            "url" | "path" => {
                path = string_value(value_node, source);
            }
            _ => {}
        }
    }
    Some((method?, path?))
}

fn method_from_text(value: &str) -> Option<&'static str> {
    match value
        .trim()
        .trim_matches(['"', '\''])
        .to_ascii_uppercase()
        .as_str()
    {
        "GET" => Some("GET"),
        "POST" => Some("POST"),
        "PUT" => Some("PUT"),
        "PATCH" => Some("PATCH"),
        "DELETE" => Some("DELETE"),
        "OPTIONS" => Some("OPTIONS"),
        "HEAD" => Some("HEAD"),
        "ALL" | "ANY" | "USE" => Some("ANY"),
        _ => None,
    }
}

fn collect_nest_decorator_routes(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    walk_tree(root, &mut |class_node| {
        if class_node.kind() != "class_declaration" {
            return;
        }
        let class_prefix = decorators_for_node(class_node, source)
            .into_iter()
            .find_map(|decorator| {
                let parsed = parse_ts_decorator(&decorator)?;
                (parsed.name == "Controller").then_some(parsed.path)
            })
            .flatten();
        for method_node in descendants_of_kind(class_node, "method_definition") {
            for decorator_text in decorators_for_node(method_node, source) {
                let Some(decorator) = parse_ts_decorator(&decorator_text) else {
                    continue;
                };
                let Some(method) = decorator_http_method(&decorator.name) else {
                    continue;
                };
                let path = join_paths(class_prefix.as_deref(), decorator.path.as_deref());
                let method_symbol_id = containing_symbol_id(symbols, method_node);
                let mut metadata = BTreeMap::new();
                metadata.insert("adapter".to_string(), "node-typescript".to_string());
                metadata.insert("decorator".to_string(), decorator_text);
                facts.routes.push(RouteFact {
                    id: stable_fact_id(
                        "route",
                        [
                            file.id.as_str(),
                            method,
                            &path,
                            "NestJS",
                            &method_node.start_byte().to_string(),
                        ],
                    ),
                    file_id: Some(file.id.clone()),
                    symbol_id: method_symbol_id,
                    service_id: file.service_id.clone(),
                    method: method.to_string(),
                    path,
                    framework: Some("NestJS".to_string()),
                    range: range_for_node(method_node),
                    metadata,
                });
            }
        }
    });
}

#[derive(Debug)]
struct Decorator {
    name: String,
    path: Option<String>,
}

fn parse_ts_decorator(text: &str) -> Option<Decorator> {
    let trimmed = text.trim().strip_prefix('@')?;
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(trimmed.len());
    let name = trimmed[..name_end]
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return None;
    }
    let path = trimmed[name_end..]
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inside, _)| inside))
        .and_then(first_quoted_fragment);
    Some(Decorator { name, path })
}

fn decorator_http_method(name: &str) -> Option<&'static str> {
    match name {
        "Get" => Some("GET"),
        "Post" => Some("POST"),
        "Put" => Some("PUT"),
        "Patch" => Some("PATCH"),
        "Delete" => Some("DELETE"),
        "Options" => Some("OPTIONS"),
        "Head" => Some("HEAD"),
        "All" => Some("ANY"),
        _ => None,
    }
}

fn first_quoted_fragment(text: &str) -> Option<String> {
    let mut quote = None;
    let mut start = 0usize;
    for (index, ch) in text.char_indices() {
        if quote.is_none() && matches!(ch, '"' | '\'' | '`') {
            quote = Some(ch);
            start = index + ch.len_utf8();
        } else if Some(ch) == quote {
            return Some(text[start..index].to_string());
        }
    }
    None
}

fn direct_decorators(node: Node<'_>, source: &str) -> Vec<String> {
    direct_named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "decorator")
        .map(|child| node_text(child, source).to_string())
        .collect()
}

fn decorators_for_node(node: Node<'_>, source: &str) -> Vec<String> {
    let mut previous = Vec::new();
    let mut sibling = node.prev_named_sibling();
    while let Some(candidate) = sibling {
        if candidate.kind() != "decorator" {
            break;
        }
        previous.push(node_text(candidate, source).to_string());
        sibling = candidate.prev_named_sibling();
    }
    previous.reverse();
    previous.extend(direct_decorators(node, source));
    previous
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

fn collect_flow_fact_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    symbols: &[SymbolSpan],
    callee: &str,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = lower_final_segment(callee);
    let receiver = callee
        .split_once('.')
        .map(|(receiver, _)| receiver.to_ascii_lowercase())
        .unwrap_or_default();

    if is_node_request_source(&lower, &receiver, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "node-typescript"),
        );
    }

    if is_node_sql_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "node-typescript"),
        );
    } else if matches!(
        final_lower.as_str(),
        "exec" | "execsync" | "execfile" | "execfilesync" | "spawn" | "spawnsync" | "fork"
    ) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "node-typescript"),
        );
    } else if is_node_response_sink(&receiver, &final_lower) {
        let kind = if final_lower == "redirect" {
            SinkKind::Redirect
        } else if final_lower == "render" {
            SinkKind::Template
        } else {
            SinkKind::HttpResponse
        };
        add_sink(
            facts,
            file,
            symbols,
            node,
            kind,
            callee,
            metadata_entry("adapter", "node-typescript"),
        );
    } else if is_node_network_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata_entry("adapter", "node-typescript"),
        );
    }

    if is_node_sanitizer(&lower, &final_lower) {
        let kind = if final_lower.contains("escape") || final_lower.contains("encode") {
            SanitizerKind::Escaping
        } else if matches!(
            final_lower.as_str(),
            "parse" | "safeparse" | "validate" | "isemail" | "isint"
        ) {
            SanitizerKind::Validation
        } else {
            SanitizerKind::Unknown
        };
        add_sanitizer(
            facts,
            file,
            symbols,
            node,
            kind,
            callee,
            metadata_entry("adapter", "node-typescript"),
        );
    }
}

fn is_node_request_source(full_lower: &str, receiver: &str, final_lower: &str) -> bool {
    matches!(
        receiver,
        "req" | "request" | "ctx" | "context" | "params" | "query"
    ) && matches!(
        final_lower,
        "param" | "get" | "body" | "query" | "params" | "header" | "headers" | "cookie"
    ) || full_lower.contains("req.query")
        || full_lower.contains("req.params")
        || full_lower.contains("req.body")
        || full_lower.contains("request.query")
        || full_lower.contains("request.params")
        || full_lower.contains("request.body")
        || full_lower.contains("ctx.request")
}

fn is_node_sql_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "query" | "execute" | "exec" | "raw" | "$queryraw" | "$executeraw"
    ) && matches!(
        receiver,
        "db" | "pool" | "client" | "connection" | "sequelize" | "prisma" | "knex"
    ) || full_lower.contains(".queryraw")
        || full_lower.contains("prisma.$")
}

fn is_node_response_sink(receiver: &str, final_lower: &str) -> bool {
    matches!(receiver, "res" | "response" | "reply" | "ctx")
        && matches!(
            final_lower,
            "send" | "json" | "jsonp" | "redirect" | "render" | "end" | "html" | "body"
        )
}

fn is_node_network_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    full_lower == "fetch"
        || receiver == "axios"
        || matches!(final_lower, "request" | "got")
        || full_lower.starts_with("http.")
        || full_lower.starts_with("https.")
}

fn is_node_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    full_lower.contains("sanitize")
        || full_lower.contains("validator.")
        || final_lower.contains("escape")
        || final_lower.contains("encode")
        || matches!(
            final_lower,
            "parse" | "safeparse" | "validate" | "isemail" | "isint"
        )
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

fn normalize_handler_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with(['(', '{', '[']) {
        return None;
    }
    let name = final_segment(trimmed)
        .trim_matches(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '$'));
    (!name.is_empty()).then(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{ProjectGraph, SourceFileFact};
    use std::path::PathBuf;

    fn analyze_node(path: &str, source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new(path, "Node/TypeScript");
        file.service_id = Some("api".to_string());
        NodeTypeScriptAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("node analysis succeeds")
    }

    #[test]
    fn extracts_node_routes_imports_symbols_flows_and_nest_decorators() {
        let source = r#"
import express from 'express';
import { Controller, Get, Param } from '@nestjs/common';
import { z } from 'zod';
const fastify = require('fastify')();
const app = express();

function listUsers(req, res) {
  const parsed = z.string().parse(req.query.name);
  db.query('select * from users where name = ' + parsed);
  res.json({ ok: true });
}

app.get('/users/:id', listUsers);
fastify.route({ method: 'POST', url: '/events', handler: async (request, reply) => {
  await db.execute(request.body.sql);
  reply.send({ ok: true });
}});

@Controller('admin')
class AdminController {
  @Get(':id')
  find(@Param('id') id: string) {
    return id;
  }
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts.imports.iter().any(|fact| fact.module == "express"));
        assert!(facts.symbols.iter().any(|fact| fact.name == "listUsers"));
        assert!(facts.calls.iter().any(|fact| fact.callee_name == "app.get"));
        assert!(
            facts.routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/users/:id"
                    && route.framework.as_deref() == Some("Fastify")
            }) || facts.routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/users/:id"
                    && route.framework.as_deref() == Some("Express")
            })
        );
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/events"
                && route.framework.as_deref() == Some("Fastify")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/:id"
                && route.framework.as_deref() == Some("NestJS")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("req.query.name")
                || source.name.as_deref() == Some("request.body.sql")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("db.query")));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("z.string().parse")));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn receiver_provenance_prevents_cache_calls_and_mixed_import_mislabels() {
        let source = r#"
import express from 'express';
import fastify from 'fastify';

const app = express();
const server = fastify();

function handler(req, res) {
  res.send('ok');
}

app.get('/users', handler);
server.delete('/events', handler);
cache.get('/cached');
client.delete('/documents');
cache.route({ method: 'GET', url: '/fake', handler });
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/users"
                && route.framework.as_deref() == Some("Express")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "DELETE"
                && route.path == "/events"
                && route.framework.as_deref() == Some("Fastify")
        }));
        assert!(!facts
            .routes
            .iter()
            .any(|route| matches!(route.path.as_str(), "/cached" | "/documents" | "/fake")));
    }

    #[test]
    fn nest_decorator_calls_are_not_extracted_as_generic_routes() {
        let source = r#"
import { Controller, Get } from '@nestjs/common';

@Controller('cats')
class CatsController {
  @Get('/profile')
  profile() {
    return 'ok';
  }
}
"#;

        let facts = analyze_node("src/cats.controller.ts", source);

        assert_eq!(
            facts
                .routes
                .iter()
                .filter(|route| route.framework.as_deref() == Some("NestJS"))
                .count(),
            1
        );
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/cats/profile"
                && route.framework.as_deref() == Some("NestJS")
        }));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/profile"));
    }

    #[test]
    fn plain_string_exports_are_not_imports() {
        let source = r#"
export const label = 'not-a-module';
export { actual } from './actual';
"#;

        let facts = analyze_node("src/index.ts", source);

        assert!(facts
            .imports
            .iter()
            .any(|import| import.module == "./actual"));
        assert!(!facts
            .imports
            .iter()
            .any(|import| import.module == "not-a-module"));
    }

    #[test]
    fn request_to_sql_edges_require_sql_argument_contribution() {
        let source = r#"
async function listUsers(req, client) {
  console.log(req.query.sort);
  const sort = defaultSort();
  const sql = `SELECT * FROM users ORDER BY ${sort}`;
  return client.query(sql);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            request_to_sql_edges(&facts).is_empty(),
            "unrelated same-name SQL interpolation should not receive request-to-SQL edges: {facts:?}"
        );
    }

    #[test]
    fn request_to_sql_edges_keep_alias_flow_into_query_argument() {
        let source = r#"
async function listUsers(req, client) {
  const sort = req.query.sort;
  const sql = `SELECT * FROM users ORDER BY ${sort}`;
  return client.query(sql);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(
            !request_to_sql_edges(&facts).is_empty(),
            "request alias interpolated into SQL argument should receive a request-to-SQL edge: {facts:?}"
        );
    }

    #[test]
    fn sync_child_process_calls_emit_command_sinks() {
        let source = r#"
import { execSync, execFileSync, spawnSync } from 'node:child_process';

function run(req) {
  const cmd = req.query.cmd;
  execSync(cmd);
  execFileSync(cmd, [], { shell: true });
  spawnSync(cmd, [], { shell: true });
}
"#;

        let facts = analyze_node("src/app.ts", source);

        for callee in ["execSync", "execFileSync", "spawnSync"] {
            assert!(
                facts.sinks.iter().any(|sink| {
                    sink.kind == SinkKind::Command
                        && sink
                            .name
                            .as_deref()
                            .is_some_and(|name| name.ends_with(callee))
                }),
                "expected command sink for {callee}; facts: {facts:?}"
            );
        }
    }

    #[test]
    fn request_to_sql_edges_remove_alias_after_safe_overwrite() {
        let source = r#"
async function listUsers(req, client) {
  let sort = req.query.sort;
  sort = defaultSort();
  const sql = `SELECT * FROM users ORDER BY ${sort}`;
  return client.query(sql);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            request_to_sql_edges(&facts).is_empty(),
            "request alias overwritten by a safe assignment should not receive request-to-SQL edges: {facts:?}"
        );
    }

    #[test]
    fn request_to_sql_edges_ignore_nested_callable_safe_overwrite() {
        let source = r#"
async function showUser(req, client) {
  let id = req.query.id;
  function reset(){ id = defaultId(); }
  const sql = `SELECT * FROM users WHERE id = ${id}`;
  return client.query(sql);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            !request_to_sql_edges(&facts).is_empty(),
            "safe assignment inside an uncalled nested function should not clear the outer request alias before SQL: {facts:?}"
        );
    }

    #[test]
    fn request_to_sql_edges_ignore_nested_callable_taint_assignment() {
        let source = r#"
async function showUser(req, client) {
  let id = defaultId();
  function load(){ id = req.query.id; }
  const sql = `SELECT * FROM users WHERE id = ${id}`;
  return client.query(sql);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            request_to_sql_edges(&facts).is_empty(),
            "request assignment inside an uncalled nested function should not taint the outer SQL alias: {facts:?}"
        );
    }

    #[test]
    fn parameterized_query_values_do_not_emit_request_to_sql_edge() {
        let source = r#"
async function showUser(req, client) {
  return client.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            request_to_sql_edges(&facts).is_empty(),
            "parameterized query values should not produce unsanitized request-to-SQL edges: {facts:?}"
        );
    }

    #[test]
    fn parameterized_query_object_alias_does_not_emit_request_to_sql_edge() {
        let source = r#"
async function showUser(req, client) {
  const id = req.query.id;
  const query = { text: 'SELECT * FROM users WHERE id = $1', values: [id] };
  return client.query(query);
}
"#;

        let facts = analyze_node("src/app.ts", source);

        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.kind == DataSourceKind::Request));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(
            request_to_sql_edges(&facts).is_empty(),
            "query option objects tainted only through values should not produce unsanitized request-to-SQL edges: {facts:?}"
        );
    }

    fn request_to_sql_edges(facts: &backend_doctor_core::AnalysisFacts) -> Vec<&TaintEdge> {
        facts
            .taint_edges
            .iter()
            .filter(|edge| {
                edge.kind == TaintEdgeKind::SourceToSink
                    && edge.sanitizer_id.is_none()
                    && facts.data_sources.iter().any(|source| {
                        source.id == edge.source_id && source.kind == DataSourceKind::Request
                    })
                    && facts
                        .sinks
                        .iter()
                        .any(|sink| sink.id == edge.target_id && sink.kind == SinkKind::SqlQuery)
            })
            .collect()
    }
}
