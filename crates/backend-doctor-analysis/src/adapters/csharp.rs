use backend_doctor_core::{
    stable_fact_id, DataSourceKind, ImportKind, RouteFact, SanitizerKind, SinkKind, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

use super::common::{
    add_call, add_data_source, add_import, add_local_taint_edges, add_sanitizer, add_sink,
    add_symbol, argument_texts, child_of_kind, child_text, containing_symbol_id,
    direct_named_children, facts_with_source, join_paths, lower_final_segment, metadata_entry,
    node_text, parse_tree, range_for_node, string_value, symbol_id_by_name, walk_tree, SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct CSharpAdapter;

impl SourceAdapter for CSharpAdapter {
    fn id(&self) -> &'static str {
        "csharp-tree-sitter-tier-b"
    }

    fn language(&self) -> &'static str {
        "C#"
    }

    fn supports(&self, source_file: &backend_doctor_core::SourceFileFact) -> bool {
        source_file.language == "C#"
            || matches!(
                normalize_csharp_adapter_name(&source_file.language).as_str(),
                "csharp" | "dotnet" | "net"
            )
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_c_sharp::LANGUAGE.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let _imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        let provenance = collect_csharp_provenance(root, input.contents);
        let route_symbols = collect_controller_routes_and_parameter_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
        );
        let minimal_route_symbols = collect_calls_routes_and_flows(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &provenance,
            &route_symbols,
        );
        for symbol_id in minimal_route_symbols {
            facts
                .metadata
                .insert(format!("csharpRouteSymbol:{symbol_id}"), "true".to_string());
        }
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
        if node.kind() != "using_directive" {
            return;
        }
        let module = node_text(node, source)
            .trim()
            .trim_start_matches("using")
            .trim_start_matches("static")
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
            ImportKind::Namespace,
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
        "class_declaration" | "record_declaration" => {
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
        "local_function_statement" => {
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
        "property_declaration" => {
            if let Some(name) = child_text(node, "name", source) {
                let parent = containing_symbol_id(&spans, node);
                add_symbol(
                    facts,
                    &mut spans,
                    file,
                    node,
                    name,
                    SymbolKind::Field,
                    parent,
                    source,
                );
            }
        }
        "field_declaration" => {
            for declarator in descendants_of_kind(node, "variable_declarator") {
                if let Some(name) = child_text(declarator, "name", source) {
                    let parent = containing_symbol_id(&spans, node);
                    add_symbol(
                        facts,
                        &mut spans,
                        file,
                        declarator,
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

#[derive(Clone, Debug)]
struct CSharpEndpointInfo {
    framework: String,
    prefix: Option<String>,
    authorization_required: bool,
}

impl CSharpEndpointInfo {
    fn new(framework: impl Into<String>) -> Self {
        Self {
            framework: framework.into(),
            prefix: None,
            authorization_required: false,
        }
    }

    fn with_prefix(mut self, prefix: String) -> Self {
        self.prefix = Some(prefix);
        self
    }

    fn requiring_authorization(mut self) -> Self {
        self.authorization_required = true;
        self
    }
}

fn collect_csharp_provenance(root: Node<'_>, source: &str) -> BTreeMap<String, CSharpEndpointInfo> {
    let mut endpoints = BTreeMap::new();
    walk_tree(root, &mut |node| {
        if node.kind() != "variable_declarator" {
            return;
        }
        let Some(name) = child_text(node, "name", source) else {
            return;
        };
        let text = node_text(node, source);
        if text.contains(".Build()") || text.contains("WebApplication.CreateBuilder") {
            endpoints.insert(name.to_string(), CSharpEndpointInfo::new("ASP.NET Core"));
        } else if let Some(map_group) = csharp_map_group_invocation(node, source) {
            let Some(path) = call_argument_nodes(map_group)
                .first()
                .and_then(|argument| string_value(*argument, source))
            else {
                return;
            };
            let mut endpoint = CSharpEndpointInfo::new("ASP.NET Core").with_prefix(path);
            let chain_methods = csharp_fluent_methods_after_invocation(map_group, source);
            if csharp_method_chain_invokes(&chain_methods, "RequireAuthorization")
                && !csharp_method_chain_invokes(&chain_methods, "AllowAnonymous")
            {
                endpoint = endpoint.requiring_authorization();
            }
            endpoints.insert(name.to_string(), endpoint);
        }
    });
    walk_tree(root, &mut |node| {
        if node.kind() != "invocation_expression" || csharp_invocation_is_nested_configuration(node)
        {
            return;
        }
        let callee = csharp_callee_name(node, source);
        if !lower_final_segment(&callee).eq_ignore_ascii_case("requireauthorization") {
            return;
        }
        let Some(receiver) = callee.split_once('.').map(|(receiver, _)| receiver) else {
            return;
        };
        let chain_methods = csharp_fluent_methods_after_invocation(node, source);
        if csharp_method_chain_invokes(&chain_methods, "AllowAnonymous") {
            return;
        }
        if let Some(endpoint) = endpoints.get_mut(receiver) {
            if endpoint.prefix.is_some() {
                endpoint.authorization_required = true;
            }
        }
    });
    if !endpoints.contains_key("app") {
        endpoints.insert("app".to_string(), CSharpEndpointInfo::new("ASP.NET Core"));
    }
    endpoints
}

fn collect_controller_routes_and_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) -> BTreeSet<String> {
    let mut route_symbol_ids = BTreeSet::new();
    walk_tree(root, &mut |class_node| {
        if !matches!(
            class_node.kind(),
            "class_declaration" | "record_declaration" | "interface_declaration"
        ) {
            return;
        }
        let class_attributes = attributes_for_node(class_node, source);
        let class_path = class_attributes.iter().find_map(attribute_route_path);
        let class_auth = class_attributes
            .iter()
            .any(|attribute| is_auth_attribute(&attribute.name));
        let class_allows_anonymous = class_attributes
            .iter()
            .any(|attribute| is_allow_anonymous_attribute(&attribute.name));
        for method_node in direct_method_declarations(class_node) {
            let method_attributes = attributes_for_node(method_node, source);
            for route in csharp_routes_from_attributes(&method_attributes, class_path.as_deref()) {
                let symbol_id = containing_symbol_id(symbols, method_node);
                push_route(
                    facts,
                    file,
                    method_node,
                    route.method,
                    route.path,
                    "ASP.NET Core".to_string(),
                    symbol_id.clone(),
                    &route.attribute,
                );
                if let Some(symbol_id) = symbol_id {
                    route_symbol_ids.insert(symbol_id);
                }
            }
            let method_auth = method_attributes
                .iter()
                .any(|attribute| is_auth_attribute(&attribute.name));
            let method_allows_anonymous = method_attributes
                .iter()
                .any(|attribute| is_allow_anonymous_attribute(&attribute.name));
            if (class_auth || method_auth) && !class_allows_anonymous && !method_allows_anonymous {
                add_sanitizer(
                    facts,
                    file,
                    symbols,
                    method_node,
                    SanitizerKind::Authorization,
                    "Authorize",
                    metadata_entry("adapter", "csharp"),
                );
            }
            if method_attributes
                .iter()
                .any(|attribute| attribute.name == "ValidateAntiForgeryToken")
            {
                add_sanitizer(
                    facts,
                    file,
                    symbols,
                    method_node,
                    SanitizerKind::Validation,
                    "ValidateAntiForgeryToken",
                    metadata_entry("adapter", "csharp"),
                );
            }
            collect_csharp_parameter_sources(facts, file, method_node, source, symbols);
        }
    });
    route_symbol_ids
}

#[derive(Clone, Debug)]
struct CSharpAttribute {
    name: String,
    text: String,
    body: String,
}

#[derive(Clone, Debug)]
struct CSharpRoute {
    method: &'static str,
    path: String,
    attribute: String,
}

fn attributes_for_node(node: Node<'_>, source: &str) -> Vec<CSharpAttribute> {
    direct_named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "attribute_list")
        .flat_map(|attribute_list| descendants_of_kind(attribute_list, "attribute"))
        .filter_map(|attribute| parse_csharp_attribute(node_text(attribute, source)))
        .collect()
}

fn parse_csharp_attribute(text: &str) -> Option<CSharpAttribute> {
    let trimmed = text.trim().trim_start_matches('[').trim_end_matches(']');
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(trimmed.len());
    let mut name = trimmed[..name_end]
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_string();
    if let Some(stripped) = name.strip_suffix("Attribute") {
        name = stripped.to_string();
    }
    if name.is_empty() {
        return None;
    }
    let body = trimmed[name_end..]
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inside, _)| inside))
        .unwrap_or("")
        .to_string();
    Some(CSharpAttribute {
        name,
        text: text.to_string(),
        body,
    })
}

fn attribute_route_path(attribute: &CSharpAttribute) -> Option<String> {
    matches!(
        attribute.name.as_str(),
        "Route"
            | "HttpGet"
            | "HttpPost"
            | "HttpPut"
            | "HttpPatch"
            | "HttpDelete"
            | "HttpHead"
            | "HttpOptions"
    )
    .then(|| first_quoted_fragment(&attribute.body))
    .flatten()
}

fn csharp_routes_from_attributes(
    attributes: &[CSharpAttribute],
    class_path: Option<&str>,
) -> Vec<CSharpRoute> {
    attributes
        .iter()
        .filter_map(|attribute| {
            let method = http_method_from_csharp_attribute(&attribute.name)?;
            let path = attribute_route_path(attribute);
            Some(CSharpRoute {
                method,
                path: join_paths(class_path, path.as_deref()),
                attribute: attribute.text.clone(),
            })
        })
        .collect()
}

fn http_method_from_csharp_attribute(name: &str) -> Option<&'static str> {
    match name {
        "HttpGet" => Some("GET"),
        "HttpPost" => Some("POST"),
        "HttpPut" => Some("PUT"),
        "HttpPatch" => Some("PATCH"),
        "HttpDelete" => Some("DELETE"),
        "HttpHead" => Some("HEAD"),
        "HttpOptions" => Some("OPTIONS"),
        "Route" => Some("ANY"),
        _ => None,
    }
}

fn is_auth_attribute(name: &str) -> bool {
    name == "Authorize"
}

fn is_allow_anonymous_attribute(name: &str) -> bool {
    name == "AllowAnonymous"
}

fn collect_csharp_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    method_node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    let Some(parameters) = method_node.child_by_field_name("parameters") else {
        return;
    };
    for parameter in direct_named_children(parameters) {
        if parameter.kind() != "parameter" {
            continue;
        }
        let text = node_text(parameter, source);
        let binding = [
            "FromRoute",
            "FromQuery",
            "FromBody",
            "FromHeader",
            "FromForm",
            "FromServices",
        ]
        .into_iter()
        .find(|attribute| text.contains(attribute));
        if binding.is_some()
            || text.contains("HttpRequest")
            || text.contains("HttpContext")
            || text.contains("ClaimsPrincipal")
        {
            let mut metadata = metadata_entry("adapter", "csharp");
            if let Some(binding) = binding {
                metadata.insert("binding".to_string(), binding.to_string());
            }
            add_data_source(
                facts,
                file,
                symbols,
                parameter,
                DataSourceKind::Request,
                parameter_name(parameter, source).unwrap_or_else(|| text.to_string()),
                None,
                metadata,
            );
        }
    }
}

fn parameter_name(parameter: Node<'_>, source: &str) -> Option<String> {
    parameter
        .child_by_field_name("name")
        .map(|name| node_text(name, source).to_string())
        .or_else(|| {
            direct_named_children(parameter)
                .into_iter()
                .rev()
                .find(|child| child.kind() == "identifier")
                .map(|identifier| node_text(identifier, source).to_string())
        })
}

#[allow(clippy::too_many_arguments)]
fn collect_calls_routes_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    provenance: &BTreeMap<String, CSharpEndpointInfo>,
    route_symbols: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut minimal_route_symbols = BTreeSet::new();
    walk_tree(root, &mut |node| {
        if !matches!(
            node.kind(),
            "invocation_expression" | "object_creation_expression"
        ) {
            return;
        }
        let callee = csharp_callee_name(node, source);
        if callee.is_empty() {
            return;
        }
        let arguments = argument_texts(node, source);
        add_call(facts, file, symbols, node, callee.clone(), arguments);
        if let Some(symbol_id) =
            collect_minimal_route_from_call(facts, file, node, source, symbols, provenance, &callee)
        {
            minimal_route_symbols.insert(symbol_id);
        }
        collect_flow_fact_from_csharp_call(
            facts,
            file,
            node,
            source,
            symbols,
            route_symbols,
            &callee,
        );
    });
    minimal_route_symbols
}

fn csharp_callee_name(node: Node<'_>, source: &str) -> String {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .map(|type_node| format!("new {}", node_text(type_node, source)))
            .unwrap_or_else(|| node_text(node, source).to_string());
    }
    node.child_by_field_name("function")
        .map(|function| node_text(function, source).to_string())
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn collect_minimal_route_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    provenance: &BTreeMap<String, CSharpEndpointInfo>,
    callee: &str,
) -> Option<String> {
    let final_lower = lower_final_segment(callee);
    let arguments = call_argument_nodes(node);
    let methods = if final_lower == "mapmethods" {
        arguments
            .get(1)
            .map(|argument| csharp_methods_from_map_methods_argument(*argument, source))
            .filter(|methods| !methods.is_empty())
            .unwrap_or_else(|| vec!["ANY"])
    } else {
        vec![minimal_api_method(callee)?]
    };
    let receiver = callee.split_once('.')?.0;
    let endpoint = provenance.get(receiver)?;
    let path = arguments
        .first()
        .and_then(|argument| string_value(*argument, source))?;
    let handler_argument_index = if final_lower == "mapmethods" { 2 } else { 1 };
    let handler_symbol_id = arguments
        .iter()
        .skip(handler_argument_index)
        .map(|argument| node_text(*argument, source))
        .find_map(normalize_handler_name)
        .and_then(|name| symbol_id_by_name(symbols, &name));
    let chain_methods = csharp_fluent_methods_after_invocation(node, source);
    let route_allows_anonymous = csharp_method_chain_invokes(&chain_methods, "AllowAnonymous");
    let route_requires_authorization =
        csharp_method_chain_invokes(&chain_methods, "RequireAuthorization");
    for method in methods {
        push_route(
            facts,
            file,
            node,
            method,
            join_paths(endpoint.prefix.as_deref(), Some(&path)),
            endpoint.framework.clone(),
            handler_symbol_id.clone(),
            callee,
        );
    }
    if (route_requires_authorization || endpoint.authorization_required) && !route_allows_anonymous
    {
        add_sanitizer(
            facts,
            file,
            symbols,
            node,
            SanitizerKind::Authorization,
            "RequireAuthorization",
            metadata_entry("adapter", "csharp"),
        );
    }
    collect_minimal_api_parameter_source(facts, file, node, source, symbols);
    handler_symbol_id
}

fn csharp_map_group_invocation<'tree>(node: Node<'tree>, source: &str) -> Option<Node<'tree>> {
    descendants_of_kind(node, "invocation_expression")
        .into_iter()
        .find(|candidate| {
            lower_final_segment(&csharp_callee_name(*candidate, source)) == "mapgroup"
        })
}

fn csharp_fluent_methods_after_invocation(node: Node<'_>, source: &str) -> Vec<String> {
    let mut methods = Vec::new();
    let mut current = node;
    while let Some(member_access) = current.parent() {
        if member_access.kind() != "member_access_expression"
            || !member_access
                .child_by_field_name("expression")
                .is_some_and(|expression| expression == current)
        {
            break;
        }
        let Some(method_name) = child_text(member_access, "name", source) else {
            break;
        };
        let Some(invocation) = member_access.parent() else {
            break;
        };
        if invocation.kind() != "invocation_expression"
            || !invocation
                .child_by_field_name("function")
                .is_some_and(|function| function == member_access)
        {
            break;
        }
        methods.push(method_name.to_string());
        current = invocation;
    }
    methods
}

fn csharp_method_chain_invokes(methods: &[String], method: &str) -> bool {
    methods
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(method))
}

fn csharp_invocation_is_nested_configuration(node: Node<'_>) -> bool {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "argument" | "argument_list" | "anonymous_method_expression" | "lambda_expression"
        ) {
            return true;
        }
        current = parent;
    }
    false
}

fn minimal_api_method(callee: &str) -> Option<&'static str> {
    match lower_final_segment(callee).as_str() {
        "mapget" => Some("GET"),
        "mappost" => Some("POST"),
        "mapput" => Some("PUT"),
        "mappatch" => Some("PATCH"),
        "mapdelete" => Some("DELETE"),
        "map" => Some("ANY"),
        _ => None,
    }
}

fn csharp_methods_from_map_methods_argument(node: Node<'_>, source: &str) -> Vec<&'static str> {
    let text = node_text(node, source);
    let mut methods = Vec::new();
    for value in quoted_fragments(text) {
        if let Some(method) = http_method_literal(&value) {
            methods.push(method);
        }
    }
    let upper = text.to_ascii_uppercase();
    for (needle, method) in [
        ("HTTPMETHODS.GET", "GET"),
        ("HTTPMETHODS.POST", "POST"),
        ("HTTPMETHODS.PUT", "PUT"),
        ("HTTPMETHODS.PATCH", "PATCH"),
        ("HTTPMETHODS.DELETE", "DELETE"),
        ("HTTPMETHODS.HEAD", "HEAD"),
        ("HTTPMETHODS.OPTIONS", "OPTIONS"),
    ] {
        if upper.contains(needle) && !methods.contains(&method) {
            methods.push(method);
        }
    }
    methods
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
        "HEAD" => Some("HEAD"),
        "OPTIONS" => Some("OPTIONS"),
        _ => None,
    }
}

fn normalize_csharp_adapter_name(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn collect_minimal_api_parameter_source(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    let text = node_text(node, source);
    if !(text.contains("HttpRequest")
        || text.contains("HttpContext")
        || text.contains("FromBody")
        || text.contains("FromQuery")
        || text.contains("FromRoute")
        || text.contains("ClaimsPrincipal")
        || text.contains("=>"))
    {
        return;
    }
    add_data_source(
        facts,
        file,
        symbols,
        node,
        DataSourceKind::Request,
        "minimal-api-parameters",
        None,
        metadata_entry("adapter", "csharp"),
    );
}

fn collect_flow_fact_from_csharp_call(
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

    if is_csharp_request_source(&lower, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "csharp"),
        );
    }

    if is_csharp_sql_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    } else if is_csharp_command_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    } else if is_csharp_file_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    } else if is_csharp_log_sink(&receiver, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Log,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    } else if is_csharp_network_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    } else if is_csharp_response_sink(&lower, &final_lower) {
        let kind = if final_lower.contains("redirect") {
            SinkKind::Redirect
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
            metadata_entry("adapter", "csharp"),
        );
    }

    if is_csharp_sanitizer(&lower, &final_lower) {
        let kind = if lower.contains("htmlencoder") || final_lower == "encode" {
            SanitizerKind::Encoding
        } else if final_lower.contains("parse") || final_lower.starts_with("tryparse") {
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
            metadata_entry("adapter", "csharp"),
        );
    }

    let in_route_handler = containing_symbol_id(symbols, node)
        .as_ref()
        .is_some_and(|symbol_id| route_symbols.contains(symbol_id));
    if in_route_handler && final_lower == "readasstringasync" {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "csharp"),
        );
    }

    if node_text(node, source).contains("JsonSerializer.Deserialize") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Deserialization,
            callee,
            metadata_entry("adapter", "csharp"),
        );
    }
}

fn is_csharp_request_source(full_lower: &str, final_lower: &str) -> bool {
    full_lower.contains("request.query")
        || full_lower.contains("request.routevalues")
        || full_lower.contains("request.form")
        || full_lower.contains("request.headers")
        || matches!(final_lower, "readformasync" | "readfromjsonasync")
}

fn is_csharp_sql_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "fromsqlraw"
            | "executesqlraw"
            | "sqlqueryraw"
            | "executequery"
            | "executenonquery"
            | "executereader"
            | "query"
            | "execute"
    ) && (matches!(
        receiver,
        "db" | "context" | "database" | "connection" | "command"
    ) || full_lower.contains("fromsqlraw")
        || full_lower.contains("executesqlraw")
        || full_lower.contains("sqlcommand")
        || full_lower.contains("dapper"))
        || full_lower.starts_with("new sqlcommand")
}

fn is_csharp_command_sink(full_lower: &str, final_lower: &str) -> bool {
    (matches!(final_lower, "start") && full_lower.contains("process"))
        || full_lower.starts_with("new processstartinfo")
}

fn is_csharp_file_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower.starts_with("file.")
        && matches!(
            final_lower,
            "writealltext" | "writeallbytes" | "appendalltext" | "openwrite" | "create"
        )
        || full_lower.starts_with("new streamwriter")
}

fn is_csharp_log_sink(receiver: &str, final_lower: &str) -> bool {
    (receiver.contains("logger") || receiver == "console")
        && matches!(
            final_lower,
            "loginformation" | "logwarning" | "logerror" | "logcritical" | "writeline"
        )
}

fn is_csharp_network_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    receiver.contains("httpclient")
        || full_lower.contains("httpclient.")
        || matches!(
            final_lower,
            "getasync" | "postasync" | "putasync" | "deleteasync" | "sendasync"
        )
}

fn is_csharp_response_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower.starts_with("results.")
        || full_lower.starts_with("response.")
        || matches!(
            final_lower,
            "ok" | "created" | "badrequest" | "redirect" | "writeasync"
        )
}

fn is_csharp_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    full_lower.contains("modelstate.isvalid")
        || full_lower.contains("tryvalidatemodel")
        || full_lower.contains("validator")
        || full_lower.contains("htmlencoder")
        || final_lower.contains("parse")
        || final_lower.starts_with("tryparse")
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
    metadata.insert("adapter".to_string(), "csharp".to_string());
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

fn direct_method_declarations(class_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = child_of_kind(class_node, "declaration_list")
        .or_else(|| child_of_kind(class_node, "class_body"))
        .or_else(|| child_of_kind(class_node, "interface_body"))
    else {
        return descendants_of_kind(class_node, "method_declaration");
    };
    direct_named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "method_declaration")
        .collect()
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
        .or_else(|| child_of_kind(call, "argument_list"))
    else {
        return Vec::new();
    };
    direct_named_children(arguments)
}

fn normalize_handler_name(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.starts_with('(') || trimmed.contains("=>") {
        return None;
    }
    let final_name = trimmed
        .split(['.', '(', '<'])
        .next_back()
        .unwrap_or(trimmed)
        .trim();
    (!final_name.is_empty()).then(|| final_name.to_string())
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

    fn analyze_csharp(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/Api/UsersController.cs", "C#");
        file.service_id = Some("api".to_string());
        CSharpAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("csharp analysis succeeds")
    }

    #[test]
    fn extracts_controller_routes_sources_sinks_and_sanitizers() {
        let source = r#"
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Data.SqlClient;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get([FromRoute] string id, [FromQuery] string q, HttpRequest request)
    {
        if (!ModelState.IsValid) return BadRequest();
        var cmd = new SqlCommand("select * from Users where Id = " + id);
        cmd.ExecuteReader();
        _logger.LogInformation(q);
        return Results.Ok(id);
    }
}
"#;

        let facts = analyze_csharp(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module == "Microsoft.AspNetCore.Mvc"));
        assert!(facts
            .symbols
            .iter()
            .any(|fact| fact.name == "UsersController"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/[controller]/{id}"
                && route.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("id")));
        assert!(facts.sinks.iter().any(|sink| sink
            .name
            .as_deref()
            .is_some_and(|name| name.contains("SqlCommand"))
            && sink.kind == SinkKind::SqlQuery));
        assert!(facts.sinks.iter().any(|sink| sink.name.as_deref()
            == Some("_logger.LogInformation")
            && sink.kind == SinkKind::Log));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_minimal_api_routes_and_rejects_http_client_route_false_positive() {
        let source = r#"
using Microsoft.AspNetCore.Builder;
using System.Net.Http;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
var api = app.MapGroup("/api");

IResult GetUser(HttpRequest request, string id)
{
    var body = request.BodyReader.ReadAsync();
    var client = new HttpClient();
    client.GetAsync("/not-a-route");
    return Results.Ok(id);
}

api.MapGet("/users/{id}", GetUser);
app.MapPost("/users", (User user) => Results.Created("/users/1", user));
"#;

        let facts = analyze_csharp(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/{id}"
                && route.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/users"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/not-a-route"));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("client.GetAsync")
                && sink.kind == SinkKind::NetworkRequest));
    }

    #[test]
    fn direct_require_authorization_produces_authorization_evidence() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/admin", () => Results.Ok()).RequireAuthorization();
"#;

        let facts = analyze_csharp(source);
        let route = facts
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/admin")
            .expect("admin route");

        assert!(
            facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.name.as_deref() == Some("RequireAuthorization")
                    && sanitizer.file_id.as_deref() == route.file_id.as_deref()
                    && sanitizer.range.as_ref() == route.range.as_ref()
            }),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn handler_body_require_authorization_does_not_protect_endpoint() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();
var svc = new AuthService();

app.MapGet("/admin", () => svc.RequireAuthorization());
"#;

        let facts = analyze_csharp(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/admin"));
        assert!(
            !facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn chained_group_require_authorization_protects_child_route_facts() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();
var admin = app.MapGroup("/admin").RequireAuthorization();

admin.MapGet("/users", () => Results.Ok());
"#;

        let facts = analyze_csharp(source);
        let route = facts
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/admin/users")
            .expect("admin users route");

        assert!(
            facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.name.as_deref() == Some("RequireAuthorization")
                    && sanitizer.file_id.as_deref() == route.file_id.as_deref()
                    && sanitizer.range.as_ref() == route.range.as_ref()
            }),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn standalone_group_require_authorization_protects_child_route_facts() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();
var admin = app.MapGroup("/admin");

admin.RequireAuthorization();
admin.MapGet("/users", () => Results.Ok());

var publicGroup = app.MapGroup("/public");
publicGroup.MapGet("/users", () => Results.Ok());
"#;

        let facts = analyze_csharp(source);
        let route = facts
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/admin/users")
            .expect("admin users route");

        assert!(
            facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.name.as_deref() == Some("RequireAuthorization")
                    && sanitizer.file_id.as_deref() == route.file_id.as_deref()
                    && sanitizer.range.as_ref() == route.range.as_ref()
            }),
            "{:?}",
            facts.sanitizers
        );
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/public/users"));
        assert!(
            !facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.range.as_ref()
                        == facts
                            .routes
                            .iter()
                            .find(|route| route.path == "/public/users")
                            .and_then(|route| route.range.as_ref())
            }),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn allow_anonymous_after_standalone_group_require_authorization_keeps_child_route_public() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();
var admin = app.MapGroup("/admin");

admin.RequireAuthorization().AllowAnonymous();
admin.MapGet("/users", () => Results.Ok());
"#;

        let facts = analyze_csharp(source);
        let route = facts
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/admin/users")
            .expect("admin users route");

        assert!(
            !facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.name.as_deref() == Some("RequireAuthorization")
                    && sanitizer.file_id.as_deref() == route.file_id.as_deref()
                    && sanitizer.range.as_ref() == route.range.as_ref()
            }),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn minimal_api_allow_anonymous_does_not_count_as_authorization() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/admin", () => Results.Ok()).RequireAuthorization().AllowAnonymous();
"#;

        let facts = analyze_csharp(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/admin"));
        assert!(
            !facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn handler_body_allow_anonymous_does_not_suppress_route_chain_authorization() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();
var svc = new AuthService();

app.MapGet("/admin", () => svc.AllowAnonymous()).RequireAuthorization();
"#;

        let facts = analyze_csharp(source);
        let route = facts
            .routes
            .iter()
            .find(|route| route.method == "GET" && route.path == "/admin")
            .expect("admin route");

        assert!(
            facts.sanitizers.iter().any(|sanitizer| {
                sanitizer.kind == SanitizerKind::Authorization
                    && sanitizer.name.as_deref() == Some("RequireAuthorization")
                    && sanitizer.file_id.as_deref() == route.file_id.as_deref()
                    && sanitizer.range.as_ref() == route.range.as_ref()
            }),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn allow_anonymous_suppresses_authorization_sanitizer() {
        let source = r#"
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize]
[Route("api/users")]
public class UsersController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet("public")]
    public IActionResult Public() => Ok();
}
"#;

        let facts = analyze_csharp(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/users/public"));
        assert!(
            !facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn controller_allow_anonymous_suppresses_class_and_action_authorize_sanitizer() {
        let source = r#"
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[AllowAnonymous]
[Authorize]
[Route("api/public")]
public class PublicController : ControllerBase
{
    [Authorize]
    [HttpGet("status")]
    public IActionResult Status() => Ok();
}
"#;

        let facts = analyze_csharp(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/public/status"));
        assert!(
            !facts
                .sanitizers
                .iter()
                .any(|sanitizer| sanitizer.kind == SanitizerKind::Authorization),
            "{:?}",
            facts.sanitizers
        );
    }

    #[test]
    fn map_methods_expands_explicit_methods_and_uses_handler_argument() {
        let source = r#"
using Microsoft.AspNetCore.Builder;

var app = WebApplication.CreateBuilder(args).Build();

IResult Widgets() => Results.Ok();

app.MapMethods("/widgets", new[] { "GET", "POST" }, Widgets);
"#;

        let facts = analyze_csharp(source);
        let handler_id = facts
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Widgets")
            .map(|symbol| symbol.id.clone())
            .expect("handler symbol");

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/widgets"
                && route.symbol_id.as_deref() == Some(handler_id.as_str())
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/widgets"
                && route.symbol_id.as_deref() == Some(handler_id.as_str())
        }));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "ANY" && route.path == "/widgets"));
    }

    #[test]
    fn csharp_adapter_supports_common_alias_names() {
        for language in ["C#", "csharp", "c-sharp", "dotnet"] {
            let file = SourceFileFact::new("src/Program.cs", language);
            assert!(CSharpAdapter.supports(&file), "{language}");
        }
        let c_file = SourceFileFact::new("src/native.c", "C");
        assert!(!CSharpAdapter.supports(&c_file));
    }
}
