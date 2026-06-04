use backend_doctor_core::{
    stable_fact_id, DataSourceKind, ImportKind, RouteFact, SanitizerKind, SinkKind, SymbolKind,
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
pub struct PythonAdapter;

impl SourceAdapter for PythonAdapter {
    fn id(&self) -> &'static str {
        "python-tree-sitter-tier-b"
    }

    fn language(&self) -> &'static str {
        "Python"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_python::LANGUAGE.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let provenance = collect_python_provenance(root, input.contents, &imports);
        let route_symbols = collect_routes_and_parameter_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &provenance,
        );
        collect_calls_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
            &provenance,
            &route_symbols,
        );
        collect_pydantic_model_sanitizers(
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
    walk_tree(root, &mut |node| match node.kind() {
        "import_statement" => {
            let text = node_text(node, source).trim();
            let body = text.trim_start_matches("import").trim();
            for part in body
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                let (module, alias) = split_alias(part);
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
                    ImportKind::Module,
                    node,
                );
            }
        }
        "import_from_statement" => {
            let text = node_text(node, source).trim();
            let Some(rest) = text.strip_prefix("from") else {
                return;
            };
            let Some((module, imported)) = rest.trim().split_once(" import ") else {
                return;
            };
            let module = module.trim();
            if module.is_empty() {
                return;
            }
            let imported_symbols = imported
                .trim()
                .trim_matches(['(', ')'])
                .split(',')
                .filter_map(|symbol| {
                    let (name, alias) = split_alias(symbol.trim());
                    if name.is_empty() {
                        return None;
                    }
                    imports.insert(format!("{module}.{name}"));
                    if let Some(alias) = alias {
                        imports.insert(format!("{module}.{alias}={name}"));
                    }
                    Some(name.to_string())
                })
                .collect::<Vec<_>>();
            imports.insert(module.to_string());
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
        _ => {}
    });
    imports
}

fn split_alias(text: &str) -> (&str, Option<&str>) {
    text.split_once(" as ")
        .map_or((text.trim(), None), |(name, alias)| {
            (name.trim(), Some(alias.trim()))
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
        "class_definition" => {
            if let Some(name) = child_text(node, "name", source) {
                add_python_symbol(
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
                let kind = if has_ancestor_kind(node, "class_definition") {
                    SymbolKind::Method
                } else {
                    SymbolKind::Function
                };
                add_python_symbol(facts, &mut spans, file, node, name, kind, parent, source);
            }
        }
        "assignment" => {
            if containing_symbol_id(&spans, node).is_some() {
                return;
            }
            if let Some(left) = node.child_by_field_name("left") {
                for name in identifiers_in_node(left, source) {
                    add_python_symbol(
                        facts,
                        &mut spans,
                        file,
                        left,
                        name,
                        SymbolKind::Variable,
                        None,
                        source,
                    );
                }
            }
        }
        _ => {}
    });
    spans
}

#[allow(clippy::too_many_arguments)]
fn add_python_symbol(
    facts: &mut backend_doctor_core::AnalysisFacts,
    spans: &mut Vec<SymbolSpan>,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    name: impl Into<String>,
    kind: SymbolKind,
    parent_symbol_id: Option<String>,
    source: &str,
) -> String {
    let id = add_symbol(
        facts,
        spans,
        file,
        node,
        name,
        kind,
        parent_symbol_id,
        source,
    );
    if let Some(symbol) = facts.symbols.iter_mut().find(|symbol| symbol.id == id) {
        symbol.signature = Some(python_signature(node, source));
    }
    id
}

fn python_signature(node: Node<'_>, source: &str) -> String {
    node_text(node, source)
        .split_once(':')
        .map_or_else(|| node_text(node, source), |(signature, _)| signature)
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
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

#[derive(Clone, Debug)]
struct PythonRouterInfo {
    framework: String,
    prefix: Option<String>,
}

impl PythonRouterInfo {
    fn new(framework: impl Into<String>) -> Self {
        Self {
            framework: framework.into(),
            prefix: None,
        }
    }

    fn with_prefix(mut self, prefix: Option<String>) -> Self {
        self.prefix = prefix;
        self
    }
}

fn collect_python_provenance(
    root: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
) -> BTreeMap<String, PythonRouterInfo> {
    let mut routers = BTreeMap::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "assignment" {
            return;
        }
        let names = node
            .child_by_field_name("left")
            .map(|left| identifiers_in_node(left, source))
            .unwrap_or_default();
        let Some(right) = node.child_by_field_name("right") else {
            return;
        };
        for name in names {
            if let Some(router) = router_info_from_python_expr(right, source, imports) {
                routers.insert(name, router);
            }
        }
    });
    routers
}

fn router_info_from_python_expr(
    value: Node<'_>,
    source: &str,
    imports: &BTreeSet<String>,
) -> Option<PythonRouterInfo> {
    let call = first_call(value)?;
    let function = call.child_by_field_name("function")?;
    let callee = node_text(function, source);
    let body = node_text(call, source);
    if has_python_import(imports, "fastapi")
        && python_imported_symbol_matches(imports, "fastapi", "FastAPI", callee)
    {
        return Some(PythonRouterInfo::new("FastAPI"));
    }
    if has_python_import(imports, "fastapi")
        && python_imported_symbol_matches(imports, "fastapi", "APIRouter", callee)
    {
        return Some(
            PythonRouterInfo::new("FastAPI").with_prefix(
                keyword_string_value(body, "prefix")
                    .as_deref()
                    .map(normalize_path),
            ),
        );
    }
    if has_python_import(imports, "flask")
        && python_imported_symbol_matches(imports, "flask", "Flask", callee)
    {
        return Some(PythonRouterInfo::new("Flask"));
    }
    if has_python_import(imports, "flask")
        && python_imported_symbol_matches(imports, "flask", "Blueprint", callee)
    {
        return Some(
            PythonRouterInfo::new("Flask").with_prefix(
                keyword_string_value(body, "url_prefix")
                    .as_deref()
                    .map(normalize_path),
            ),
        );
    }
    None
}

fn first_call(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "call" {
        return Some(node);
    }
    direct_named_children(node).into_iter().find_map(first_call)
}

fn has_python_import(imports: &BTreeSet<String>, needle: &str) -> bool {
    imports.iter().any(|module| module.contains(needle))
}

fn python_imported_symbol_matches(
    imports: &BTreeSet<String>,
    module: &str,
    symbol: &str,
    callee: &str,
) -> bool {
    let local_name = final_segment(callee);
    local_name == symbol || imports.contains(&format!("{module}.{local_name}={symbol}"))
}

fn collect_routes_and_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    provenance: &BTreeMap<String, PythonRouterInfo>,
) -> BTreeSet<String> {
    let mut route_symbol_ids = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "function_definition" {
            return;
        }
        let mut emitted_for_function = false;
        for decorator_text in decorators_for_node(node, source) {
            for route in routes_from_python_decorator(&decorator_text, provenance, imports) {
                let symbol_id = containing_symbol_id(symbols, node);
                push_route(
                    facts,
                    file,
                    node,
                    route.method,
                    route.path,
                    route.framework,
                    symbol_id.clone(),
                    &decorator_text,
                );
                if let Some(symbol_id) = symbol_id {
                    route_symbol_ids.insert(symbol_id);
                }
                emitted_for_function = true;
            }
            if let Some((kind, name)) = sanitizer_from_python_decorator(&decorator_text) {
                add_sanitizer(
                    facts,
                    file,
                    symbols,
                    node,
                    kind,
                    name,
                    metadata_entry("adapter", "python"),
                );
            }
        }
        if emitted_for_function {
            collect_python_parameter_sources(facts, file, node, source, symbols);
        }
    });
    route_symbol_ids
}

struct PythonRoute {
    method: &'static str,
    path: String,
    framework: String,
}

fn routes_from_python_decorator(
    text: &str,
    provenance: &BTreeMap<String, PythonRouterInfo>,
    imports: &BTreeSet<String>,
) -> Vec<PythonRoute> {
    let Some(decorator) = parse_python_decorator(text) else {
        return Vec::new();
    };
    let final_name = final_segment(&decorator.name);
    if let Some(method) = python_http_method(final_name) {
        if final_name == "api_route" {
            return routes_from_python_route_decorator(&decorator, provenance);
        }
        let Some(receiver) = decorator.name.split_once('.').map(|(receiver, _)| receiver) else {
            return Vec::new();
        };
        let Some(router) = provenance.get(receiver) else {
            return Vec::new();
        };
        let Some(path) = decorator.path else {
            return Vec::new();
        };
        return vec![PythonRoute {
            method,
            path: join_paths(router.prefix.as_deref(), Some(&path)),
            framework: router.framework.clone(),
        }];
    }
    if final_name == "route" {
        return routes_from_python_route_decorator(&decorator, provenance);
    }
    if django_route_function_name(imports, final_name).is_some() {
        return vec![PythonRoute {
            method: "ANY",
            path: decorator.path.map_or_else(
                || "/".to_string(),
                |path| normalize_django_route_path(&path),
            ),
            framework: "Django".to_string(),
        }];
    }
    Vec::new()
}

fn routes_from_python_route_decorator(
    decorator: &PythonDecorator,
    provenance: &BTreeMap<String, PythonRouterInfo>,
) -> Vec<PythonRoute> {
    let Some(receiver) = decorator.name.split_once('.').map(|(receiver, _)| receiver) else {
        return Vec::new();
    };
    let Some(router) = provenance.get(receiver) else {
        return Vec::new();
    };
    let Some(path) = decorator.path.clone() else {
        return Vec::new();
    };
    let methods = explicit_methods_from_keyword_value(&decorator.body, "methods");
    let methods = if methods.is_empty() {
        vec!["ANY"]
    } else {
        methods
    };
    methods
        .into_iter()
        .map(|method| PythonRoute {
            method,
            path: join_paths(router.prefix.as_deref(), Some(&path)),
            framework: router.framework.clone(),
        })
        .collect()
}

#[derive(Debug)]
struct PythonDecorator {
    name: String,
    body: String,
    path: Option<String>,
}

fn parse_python_decorator(text: &str) -> Option<PythonDecorator> {
    let trimmed = text.trim().strip_prefix('@')?.trim();
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(trimmed.len());
    let name = trimmed[..name_end].to_string();
    if name.is_empty() {
        return None;
    }
    let body = trimmed[name_end..]
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inside, _)| inside))
        .unwrap_or("")
        .to_string();
    let path = first_quoted_fragment(&body);
    Some(PythonDecorator { name, body, path })
}

fn python_http_method(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" => Some("DELETE"),
        "options" => Some("OPTIONS"),
        "head" => Some("HEAD"),
        "api_route" => Some("ANY"),
        _ => None,
    }
}

fn collect_python_parameter_sources(
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
        if text == "self" || text.contains("Depends(") {
            continue;
        }
        let Some(name) = parameter_name(parameter, source) else {
            continue;
        };
        let mut metadata = metadata_entry("adapter", "python");
        metadata.insert(
            "binding".to_string(),
            parameter_source_binding(text).to_string(),
        );
        add_data_source(
            facts,
            file,
            symbols,
            parameter,
            DataSourceKind::Request,
            name,
            None,
            metadata,
        );
    }
}

fn parameter_source_binding(text: &str) -> &'static str {
    if text.contains("Request") {
        "request"
    } else if text.contains("Body(") {
        "body"
    } else if text.contains("Query(") {
        "query"
    } else if text.contains("Path(") {
        "path"
    } else if text.contains("Header(") {
        "header"
    } else {
        "parameter"
    }
}

fn parameter_name(node: Node<'_>, source: &str) -> Option<String> {
    node.child_by_field_name("name")
        .map(|name| node_text(name, source).to_string())
        .or_else(|| {
            if node.kind() == "identifier" {
                Some(node_text(node, source).to_string())
            } else {
                direct_named_children(node)
                    .into_iter()
                    .find(|child| child.kind() == "identifier")
                    .map(|identifier| node_text(identifier, source).to_string())
            }
        })
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
    metadata.insert("adapter".to_string(), "python".to_string());
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

#[allow(clippy::too_many_arguments)]
fn collect_calls_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    provenance: &BTreeMap<String, PythonRouterInfo>,
    route_symbols: &BTreeSet<String>,
) {
    walk_tree(root, &mut |node| match node.kind() {
        "call" => {
            let Some(function_node) = node.child_by_field_name("function") else {
                return;
            };
            let callee = node_text(function_node, source).to_string();
            let arguments = argument_texts(node, source);
            add_call(facts, file, symbols, node, callee.clone(), arguments);
            collect_route_from_python_call(
                facts, file, node, source, symbols, imports, provenance, &callee,
            );
            collect_flow_fact_from_python_call(
                facts,
                file,
                node,
                source,
                symbols,
                route_symbols,
                &callee,
            );
        }
        "attribute" | "subscript" => {
            collect_python_member_source(facts, file, node, source, symbols)
        }
        _ => {}
    });
}

#[allow(clippy::too_many_arguments)]
fn collect_route_from_python_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
    provenance: &BTreeMap<String, PythonRouterInfo>,
    callee: &str,
) {
    if is_inside_decorator(node) {
        return;
    }
    let arguments = call_argument_nodes(node);
    let final_name = final_segment(callee);
    if django_route_function_name(imports, final_name).is_some() {
        let Some(path) = arguments
            .first()
            .and_then(|argument| string_value(*argument, source))
        else {
            return;
        };
        let symbol_id = arguments
            .get(1)
            .map(|argument| node_text(*argument, source))
            .and_then(normalize_handler_name)
            .and_then(|name| symbol_id_by_name(symbols, &name));
        push_route(
            facts,
            file,
            node,
            "ANY",
            normalize_django_route_path(&path),
            "Django".to_string(),
            symbol_id,
            callee,
        );
        return;
    }

    if final_name != "add_api_route" && final_name != "add_url_rule" {
        return;
    }
    let Some(receiver) = callee.split_once('.').map(|(receiver, _)| receiver) else {
        return;
    };
    let Some(router) = provenance.get(receiver) else {
        return;
    };
    let Some(path) = arguments
        .first()
        .and_then(|argument| string_value(*argument, source))
    else {
        return;
    };
    let methods = explicit_methods_from_keyword_value(node_text(node, source), "methods");
    let methods = if methods.is_empty() {
        vec!["ANY"]
    } else {
        methods
    };
    let handler_symbol_id = arguments
        .get(1)
        .map(|argument| node_text(*argument, source))
        .and_then(normalize_handler_name)
        .and_then(|name| symbol_id_by_name(symbols, &name));
    for method in methods {
        push_route(
            facts,
            file,
            node,
            method,
            join_paths(router.prefix.as_deref(), Some(&path)),
            router.framework.clone(),
            handler_symbol_id.clone(),
            callee,
        );
    }
}

fn collect_flow_fact_from_python_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    route_symbols: &BTreeSet<String>,
    callee: &str,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = lower_final_segment(callee);
    let receiver = callee
        .split_once('.')
        .map(|(receiver, _)| receiver.to_ascii_lowercase())
        .unwrap_or_default();

    if is_python_request_source(&lower, &receiver, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "python"),
        );
    } else if matches!(
        lower.as_str(),
        "os.getenv" | "environ.get" | "os.environ.get"
    ) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Environment,
            callee,
            None,
            metadata_entry("adapter", "python"),
        );
    }

    if is_python_sql_sink(&lower, &receiver, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if is_python_command_sink(&lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if is_python_network_sink(&lower, &receiver, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if final_lower == "open" && open_call_writes(node, source) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if is_python_log_sink(&receiver, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Log,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if matches!(final_lower.as_str(), "render" | "render_template") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Template,
            callee,
            metadata_entry("adapter", "python"),
        );
    } else if final_lower == "redirect" {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Redirect,
            callee,
            metadata_entry("adapter", "python"),
        );
    }

    if is_python_sanitizer(&lower, &final_lower) {
        let kind = if final_lower.contains("escape") || final_lower.contains("quote") {
            SanitizerKind::Escaping
        } else if matches!(final_lower.as_str(), "int" | "float" | "bool") {
            SanitizerKind::TypeCheck
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
            metadata_entry("adapter", "python"),
        );
    }

    if matches!(final_lower.as_str(), "pickle.loads" | "loads") && lower.contains("pickle") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Deserialization,
            callee,
            metadata_entry("adapter", "python"),
        );
    }

    if matches!(
        final_lower.as_str(),
        "task" | "send_task" | "delay" | "apply_async"
    ) || lower.contains("celery")
    {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Queue,
            callee,
            None,
            metadata_entry("adapter", "python"),
        );
    }

    if route_symbols.contains(&containing_symbol_id(symbols, node).unwrap_or_default())
        && matches!(final_lower.as_str(), "raise_for_status")
    {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Unknown,
            callee,
            metadata_entry("handlerContext", "true"),
        );
    }
}

fn collect_python_member_source(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    let text = node_text(node, source);
    let lower = text.to_ascii_lowercase();
    if lower.contains("request.args")
        || lower.contains("request.form")
        || lower.contains("request.json")
        || lower.contains("request.data")
        || lower.contains("request.body")
        || lower.contains("request.get")
        || lower.contains("request.post")
        || lower.contains("query_params")
        || lower.contains("path_params")
        || lower.contains("self.request")
    {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            text,
            None,
            metadata_entry("adapter", "python"),
        );
    }
}

fn collect_pydantic_model_sanitizers(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    walk_tree(root, &mut |node| {
        if node.kind() != "class_definition" {
            return;
        }
        let text = node_text(node, source);
        if text.contains("BaseModel") || text.contains("pydantic.") {
            let name = child_text(node, "name", source).unwrap_or("PydanticModel");
            add_sanitizer(
                facts,
                file,
                symbols,
                node,
                SanitizerKind::Validation,
                name,
                metadata_entry("adapter", "python"),
            );
        }
    });
}

fn decorators_for_node(node: Node<'_>, source: &str) -> Vec<String> {
    let mut decorators = Vec::new();
    if let Some(parent) = node.parent() {
        if parent.kind() == "decorated_definition" {
            for child in direct_named_children(parent) {
                if child.kind() == "decorator" {
                    decorators.push(node_text(child, source).to_string());
                }
            }
        }
    }
    decorators
}

fn sanitizer_from_python_decorator(text: &str) -> Option<(SanitizerKind, String)> {
    let parsed = parse_python_decorator(text)?;
    let lower = parsed.name.to_ascii_lowercase();
    if lower.contains("login_required")
        || lower.contains("permission_required")
        || lower.contains("requires_auth")
    {
        return Some((SanitizerKind::Authorization, parsed.name));
    }
    if lower.contains("auth") || parsed.body.contains("get_current_user") {
        return Some((SanitizerKind::Authentication, parsed.name));
    }
    if lower.contains("validate") || lower.contains("schema") {
        return Some((SanitizerKind::Validation, parsed.name));
    }
    None
}

fn is_python_request_source(full_lower: &str, receiver: &str, final_lower: &str) -> bool {
    matches!(
        receiver,
        "request" | "flask.request" | "self.request" | "request.args" | "request.form"
    ) && matches!(
        final_lower,
        "get"
            | "getlist"
            | "get_json"
            | "json"
            | "form"
            | "args"
            | "body"
            | "data"
            | "files"
            | "headers"
            | "cookies"
    ) || full_lower.contains("request.query_params")
        || full_lower.contains("request.path_params")
        || full_lower.contains("request.args")
        || full_lower.contains("request.form")
        || full_lower.contains("request.get_json")
        || full_lower.contains("request.post")
        || full_lower.contains("request.get")
}

fn is_python_sql_sink(full_lower: &str, receiver: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "execute" | "executemany" | "raw" | "extra" | "rawsql" | "text"
    ) && (matches!(
        receiver,
        "db" | "session" | "cursor" | "connection" | "conn" | "engine" | "models" | "objects"
    ) || full_lower.contains("sqlalchemy")
        || full_lower.contains(".objects.raw")
        || full_lower.contains("rawsql"))
}

fn is_python_command_sink(full_lower: &str) -> bool {
    matches!(
        full_lower,
        "os.system"
            | "os.popen"
            | "subprocess.run"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "subprocess.popen"
    )
}

fn is_python_network_sink(full_lower: &str, receiver: &str, final_lower: &str) -> bool {
    matches!(receiver, "requests" | "httpx" | "urllib.request")
        && matches!(
            final_lower,
            "get" | "post" | "put" | "patch" | "delete" | "request" | "urlopen"
        )
        || matches!(full_lower, "requests.request" | "httpx.request")
}

fn is_python_log_sink(receiver: &str, final_lower: &str) -> bool {
    matches!(receiver, "logging" | "logger" | "log")
        && matches!(
            final_lower,
            "debug" | "info" | "warning" | "warn" | "error" | "exception" | "critical"
        )
}

fn is_python_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    final_lower.contains("escape")
        || final_lower.contains("quote")
        || final_lower.contains("validate")
        || full_lower.contains("pydantic")
        || full_lower.contains("schema.load")
        || matches!(
            final_lower,
            "int" | "float" | "bool" | "isinstance" | "model_validate" | "parse_obj"
        )
}

fn open_call_writes(node: Node<'_>, source: &str) -> bool {
    let arguments = call_argument_nodes(node);
    arguments
        .get(1)
        .and_then(|argument| string_value(*argument, source))
        .is_some_and(|mode| {
            mode.contains('w') || mode.contains('a') || mode.contains('x') || mode.contains('+')
        })
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

fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let Some(arguments) = call
        .child_by_field_name("arguments")
        .or_else(|| child_of_kind(call, "argument_list"))
    else {
        return Vec::new();
    };
    direct_named_children(arguments)
}

fn normalize_handler_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let name = trimmed
        .trim_start_matches('&')
        .rsplit('.')
        .next()
        .unwrap_or(trimmed)
        .trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn keyword_string_value(text: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let (_, rest) = text.split_once(&needle)?;
    first_quoted_fragment(rest)
}

fn explicit_methods_from_keyword_value(text: &str, key: &str) -> Vec<&'static str> {
    let Some(value) = keyword_value_fragment(text, key) else {
        return Vec::new();
    };
    quoted_fragments(value)
        .into_iter()
        .filter_map(|method| http_method_literal(&method))
        .collect()
}

fn keyword_value_fragment<'a>(text: &'a str, key: &str) -> Option<&'a str> {
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
        if bytes.get(index) != Some(&b'=') {
            search_start = key_end;
            continue;
        }
        index += 1;
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

fn django_route_function_name<'a>(
    imports: &BTreeSet<String>,
    final_name: &'a str,
) -> Option<&'a str> {
    if !has_python_import(imports, "django") {
        return None;
    }
    ["path", "re_path", "url"].into_iter().find(|canonical| {
        final_name == *canonical
            || imports.contains(&format!("django.urls.{final_name}={canonical}"))
            || imports.contains(&format!("django.conf.urls.{final_name}={canonical}"))
    })
}

fn normalize_django_route_path(path: &str) -> String {
    let path = path.trim();
    let path = if path
        .chars()
        .next()
        .is_some_and(|ch| matches!(ch, 'r' | 'R' | 'u' | 'U' | 'b' | 'B'))
    {
        first_quoted_fragment(path).unwrap_or_else(|| path.to_string())
    } else {
        path.to_string()
    };
    normalize_path(path.trim_start_matches('^').trim_end_matches('$'))
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

    fn analyze_python(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("app/main.py", "Python");
        file.service_id = Some("api".to_string());
        PythonAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("python analysis succeeds")
    }

    #[test]
    fn extracts_python_routes_symbols_flows_and_validation_hints() {
        let source = r#"
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
import subprocess
import requests

router = APIRouter(prefix="/api")

class UserIn(BaseModel):
    name: str

def current_user():
    return "u"

@router.get("/users/{id}", dependencies=[Depends(current_user)])
async def get_user(id: int, request: Request, q: str = Query("")):
    term = request.query_params.get("q")
    subprocess.run(["echo", term])
    requests.get("https://example.test/" + term)
    return {"id": id}
"#;

        let facts = analyze_python(source);

        assert!(facts.imports.iter().any(|fact| fact.module == "fastapi"));
        assert!(facts.symbols.iter().any(|fact| fact.name == "get_user"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/{id}"
                && route.framework.as_deref() == Some("FastAPI")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("request")));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("request.query_params.get")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("subprocess.run")
                && sink.kind == SinkKind::Command));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("requests.get")
                && sink.kind == SinkKind::NetworkRequest));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("UserIn")));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_flask_and_django_routes_but_rejects_unproven_client_gets() {
        let source = r#"
from flask import Blueprint, request
from django.urls import path
import requests

bp = Blueprint("admin", __name__, url_prefix="/admin")

def show():
    value = request.args.get("q")
    return value

@bp.route("/users", methods=["POST"])
def create_user():
    return show()

urlpatterns = [
    path("health/", show),
]

def not_a_route():
    requests.get("/local")
    cache.get("/not-a-route")
"#;

        let facts = analyze_python(source);

        assert!(
            facts.routes.iter().any(|route| {
                route.method == "POST"
                    && route.path == "/admin/users"
                    && route.framework.as_deref() == Some("Flask")
            }),
            "{:?}",
            facts.routes
        );
        assert!(facts.routes.iter().any(|route| {
            route.method == "ANY"
                && route.path == "/health/"
                && route.framework.as_deref() == Some("Django")
        }));
        assert!(!facts.routes.iter().any(|route| route.path == "/local"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/not-a-route"));
    }

    #[test]
    fn route_methods_only_come_from_explicit_method_fields() {
        let source = r#"
from flask import Blueprint

bp = Blueprint("widgets", __name__)

@bp.route("/forget")
def forget():
    return "ok"

@bp.route("/widgets", methods=["POST"])
def create_widget():
    return "ok"
"#;

        let facts = analyze_python(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "ANY" && route.path == "/forget"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/forget"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/widgets"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/widgets"));
    }

    #[test]
    fn preserves_router_import_aliases_and_normalizes_django_re_path_anchors() {
        let source = r#"
from fastapi import APIRouter as Router
from flask import Blueprint as BP
from django.urls import re_path as regex

api = Router(prefix="/api")
bp = BP("admin", __name__, url_prefix="/admin")

def health():
    return "ok"

@api.post("/widgets")
def create_widget():
    return {"ok": True}

@bp.route("/sessions", methods=["DELETE"])
def delete_session():
    return "ok"

urlpatterns = [
    regex(r"^health/$", health),
]
"#;

        let facts = analyze_python(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/api/widgets"
                && route.framework.as_deref() == Some("FastAPI")
        }));
        assert!(
            facts.routes.iter().any(|route| {
                route.method == "DELETE"
                    && route.path == "/admin/sessions"
                    && route.framework.as_deref() == Some("Flask")
            }),
            "{:?}",
            facts.routes
        );
        assert!(facts.routes.iter().any(|route| {
            route.method == "ANY"
                && route.path == "/health/"
                && route.framework.as_deref() == Some("Django")
        }));
        assert!(!facts.routes.iter().any(|route| route.path == "/^health/"));
    }
}
