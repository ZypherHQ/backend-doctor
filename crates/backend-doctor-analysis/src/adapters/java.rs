use backend_doctor_core::{
    stable_fact_id, DataSourceKind, ImportKind, RouteFact, SanitizerKind, SinkKind, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

use super::common::{
    add_call, add_data_source, add_import, add_local_taint_edges, add_sanitizer, add_sink,
    add_symbol, argument_texts, child_of_kind, child_text, containing_symbol_id,
    direct_named_children, facts_with_source, join_paths, lower_final_segment, metadata_entry,
    node_text, parse_tree, range_for_node, walk_tree, SymbolSpan,
};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct JavaAdapter;

impl SourceAdapter for JavaAdapter {
    fn id(&self) -> &'static str {
        "java-tree-sitter-tier-a"
    }

    fn language(&self) -> &'static str {
        "Java"
    }

    fn analyze(
        &self,
        input: AdapterInput<'_>,
    ) -> Result<backend_doctor_core::AnalysisFacts, AnalysisError> {
        let tree = parse_tree(&input, tree_sitter_java::LANGUAGE.into())?;
        let root = tree.root_node();
        let mut facts = facts_with_source(&input);
        if root.has_error() {
            facts
                .metadata
                .insert("parseHasError".to_string(), "true".to_string());
        }

        let imports = collect_imports(&mut facts, input.source_file, root, input.contents);
        let symbols = collect_symbols(&mut facts, input.source_file, root, input.contents);
        collect_routes_and_parameter_sources(
            &mut facts,
            input.source_file,
            root,
            input.contents,
            &symbols,
            &imports,
        );
        collect_calls_and_flows(
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
        if node.kind() != "import_declaration" {
            return;
        }
        let text = node_text(node, source);
        let module = text
            .trim_start_matches("import")
            .trim()
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
        "enum_declaration" => {
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
        "method_declaration" | "constructor_declaration" => {
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
        "field_declaration" => {
            for declarator in direct_named_children(node) {
                if declarator.kind() == "variable_declarator" {
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
        }
        _ => {}
    });
    spans
}

fn collect_routes_and_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
    imports: &BTreeSet<String>,
) {
    walk_tree(root, &mut |class_node| {
        if !matches!(
            class_node.kind(),
            "class_declaration" | "record_declaration" | "interface_declaration"
        ) {
            return;
        }
        let class_annotations = annotations_for_node(class_node, source);
        let class_path = class_annotations.iter().find_map(class_level_path);
        let class_auth = class_annotations
            .iter()
            .find(|annotation| is_java_protective_auth_annotation(annotation));
        let framework = java_framework(imports, &class_annotations);
        for method_node in direct_method_declarations(class_node) {
            let method_annotations = annotations_for_node(method_node, source);
            let routes = routes_from_method_annotations(&method_annotations, class_path.as_deref());
            if !routes.is_empty() {
                collect_route_auth_sanitizer(
                    facts,
                    file,
                    method_node,
                    symbols,
                    class_auth,
                    &method_annotations,
                );
            }
            for route in routes {
                push_route(
                    facts,
                    file,
                    method_node,
                    symbols,
                    route.method,
                    route.path,
                    framework.clone(),
                    route.annotation,
                );
            }
            collect_parameter_sources(facts, file, method_node, source, symbols);
        }
    });
}

#[derive(Clone, Debug)]
struct JavaAnnotation {
    name: String,
    qualified_name: String,
    text: String,
    path: Option<String>,
    methods: Vec<&'static str>,
}

#[derive(Clone, Debug)]
struct JavaRoute {
    method: &'static str,
    path: String,
    annotation: String,
}

fn annotations_for_node(node: Node<'_>, source: &str) -> Vec<JavaAnnotation> {
    let Some(modifiers) = child_of_kind(node, "modifiers") else {
        return Vec::new();
    };
    direct_named_children(modifiers)
        .into_iter()
        .filter(|child| child.kind().contains("annotation"))
        .filter_map(|annotation| parse_java_annotation(node_text(annotation, source)))
        .collect()
}

fn parse_java_annotation(text: &str) -> Option<JavaAnnotation> {
    let trimmed = text.trim().strip_prefix('@')?;
    let name_end = trimmed
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.'))
        .unwrap_or(trimmed.len());
    let qualified_name = trimmed[..name_end].to_string();
    let name = qualified_name.rsplit('.').next().unwrap_or("").to_string();
    if name.is_empty() {
        return None;
    }
    let body = trimmed[name_end..]
        .split_once('(')
        .and_then(|(_, rest)| rest.rsplit_once(')').map(|(inside, _)| inside))
        .unwrap_or("");
    let path = first_quoted_fragment(body);
    let methods = request_methods_from_annotation(&name, body);
    Some(JavaAnnotation {
        name,
        qualified_name,
        text: text.to_string(),
        path,
        methods,
    })
}

fn request_methods_from_annotation(name: &str, body: &str) -> Vec<&'static str> {
    match name {
        "GetMapping" | "GET" | "Get" => vec!["GET"],
        "PostMapping" | "POST" | "Post" => vec!["POST"],
        "PutMapping" | "PUT" | "Put" => vec!["PUT"],
        "PatchMapping" | "PATCH" | "Patch" => vec!["PATCH"],
        "DeleteMapping" | "DELETE" | "Delete" => vec!["DELETE"],
        "Options" | "OPTIONS" => vec!["OPTIONS"],
        "Head" | "HEAD" => vec!["HEAD"],
        "RequestMapping" => request_mapping_method(body),
        _ => Vec::new(),
    }
}

fn request_mapping_method(body: &str) -> Vec<&'static str> {
    let Some(method_value) = annotation_attribute_value(body, "method") else {
        return vec!["ANY"];
    };
    let methods: Vec<_> = [
        ("RequestMethod.GET", "GET"),
        ("RequestMethod.POST", "POST"),
        ("RequestMethod.PUT", "PUT"),
        ("RequestMethod.PATCH", "PATCH"),
        ("RequestMethod.DELETE", "DELETE"),
        ("RequestMethod.OPTIONS", "OPTIONS"),
        ("RequestMethod.HEAD", "HEAD"),
    ]
    .into_iter()
    .filter_map(|(needle, method)| method_value.contains(needle).then_some(method))
    .collect();
    methods
}

fn annotation_attribute_value<'a>(body: &'a str, attribute: &str) -> Option<&'a str> {
    let mut rest = body;
    while let Some(index) = rest.find(attribute) {
        let candidate = &rest[index..];
        let before = index
            .checked_sub(1)
            .and_then(|before| rest[..=before].chars().last());
        let after = candidate[attribute.len()..].chars().next();
        let identifier_boundary_before =
            before.is_none_or(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'));
        let identifier_boundary_after =
            after.is_none_or(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'));
        if identifier_boundary_before && identifier_boundary_after {
            let after_attribute = candidate[attribute.len()..].trim_start();
            if let Some(value) = after_attribute.strip_prefix('=') {
                return Some(trim_attribute_value(value.trim_start()));
            }
        }
        rest = &candidate[attribute.len()..];
    }
    None
}

fn trim_attribute_value(value: &str) -> &str {
    let mut depth = 0i32;
    for (index, ch) in value.char_indices() {
        match ch {
            '{' | '(' => depth += 1,
            '}' | ')' => depth -= 1,
            ',' if depth <= 0 => return value[..index].trim(),
            _ => {}
        }
    }
    value.trim()
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

fn class_level_path(annotation: &JavaAnnotation) -> Option<String> {
    matches!(
        annotation.name.as_str(),
        "RequestMapping" | "Path" | "Controller"
    )
    .then(|| annotation.path.clone())
    .flatten()
}

fn routes_from_method_annotations(
    annotations: &[JavaAnnotation],
    class_path: Option<&str>,
) -> Vec<JavaRoute> {
    let local_path = annotations
        .iter()
        .find(|annotation| annotation.name == "Path")
        .and_then(|annotation| annotation.path.clone());
    annotations
        .iter()
        .flat_map(|annotation| {
            let path = annotation.path.clone().or_else(|| local_path.clone());
            annotation.methods.iter().map(move |method| JavaRoute {
                method,
                path: join_paths(class_path, path.as_deref()),
                annotation: annotation.text.clone(),
            })
        })
        .collect()
}

fn java_framework(imports: &BTreeSet<String>, annotations: &[JavaAnnotation]) -> String {
    if annotations.iter().any(|annotation| {
        matches!(
            annotation.name.as_str(),
            "RestController" | "Controller" | "RequestMapping"
        ) || annotation.name.ends_with("Mapping")
    }) {
        return "Spring".to_string();
    }
    if imports
        .iter()
        .any(|module| module.starts_with("io.micronaut.http.annotation"))
    {
        return "Micronaut".to_string();
    }
    if imports.iter().any(|module| {
        module.starts_with("jakarta.ws.rs")
            || module.starts_with("javax.ws.rs")
            || module.starts_with("org.jboss.resteasy")
    }) || annotations
        .iter()
        .any(|annotation| annotation.name == "Path")
    {
        return "JAX-RS".to_string();
    }
    if imports
        .iter()
        .any(|module| module.starts_with("org.springframework"))
    {
        return "Spring".to_string();
    }
    "Java HTTP".to_string()
}

fn collect_route_auth_sanitizer(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    method_node: Node<'_>,
    symbols: &[SymbolSpan],
    class_auth: Option<&JavaAnnotation>,
    method_annotations: &[JavaAnnotation],
) {
    let method_auth = method_annotations
        .iter()
        .find(|annotation| is_java_protective_auth_annotation(annotation));
    let method_permit_all = method_annotations.iter().any(is_java_permit_all_annotation);
    let auth_annotation =
        method_auth.or_else(|| (!method_permit_all).then_some(class_auth).flatten());
    let Some(annotation) = auth_annotation else {
        return;
    };
    let mut metadata = metadata_entry("adapter", "java");
    metadata.insert("annotation".to_string(), annotation.name.clone());
    if annotation.qualified_name != annotation.name {
        metadata.insert(
            "qualifiedAnnotation".to_string(),
            annotation.qualified_name.clone(),
        );
    }
    add_sanitizer(
        facts,
        file,
        symbols,
        method_node,
        SanitizerKind::Authorization,
        annotation.name.as_str(),
        metadata,
    );
}

fn is_java_protective_auth_annotation(annotation: &JavaAnnotation) -> bool {
    java_annotation_matches(
        annotation,
        "PreAuthorize",
        &["org.springframework.security.access.prepost.PreAuthorize"],
    ) || java_annotation_matches(
        annotation,
        "Secured",
        &["org.springframework.security.access.annotation.Secured"],
    ) || java_annotation_matches(
        annotation,
        "RolesAllowed",
        &[
            "jakarta.annotation.security.RolesAllowed",
            "javax.annotation.security.RolesAllowed",
        ],
    ) || java_annotation_matches(
        annotation,
        "DenyAll",
        &[
            "jakarta.annotation.security.DenyAll",
            "javax.annotation.security.DenyAll",
        ],
    )
}

fn is_java_permit_all_annotation(annotation: &JavaAnnotation) -> bool {
    java_annotation_matches(
        annotation,
        "PermitAll",
        &[
            "jakarta.annotation.security.PermitAll",
            "javax.annotation.security.PermitAll",
        ],
    )
}

fn java_annotation_matches(
    annotation: &JavaAnnotation,
    simple_name: &str,
    qualified_names: &[&str],
) -> bool {
    annotation.qualified_name == simple_name
        || qualified_names
            .iter()
            .any(|qualified_name| annotation.qualified_name == *qualified_name)
}

#[allow(clippy::too_many_arguments)]
fn push_route(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    method_node: Node<'_>,
    symbols: &[SymbolSpan],
    method: &'static str,
    path: String,
    framework: String,
    annotation: String,
) {
    let mut metadata = BTreeMap::new();
    metadata.insert("adapter".to_string(), "java".to_string());
    metadata.insert("annotation".to_string(), annotation);
    facts.routes.push(RouteFact {
        id: stable_fact_id(
            "route",
            [
                file.id.as_str(),
                method,
                &path,
                framework.as_str(),
                &method_node.start_byte().to_string(),
            ],
        ),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(symbols, method_node),
        service_id: file.service_id.clone(),
        method: method.to_string(),
        path,
        framework: Some(framework),
        range: range_for_node(method_node),
        metadata,
    });
}

fn collect_parameter_sources(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    method_node: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    for parameter in descendants_of_kind(method_node, "formal_parameter") {
        let text = node_text(parameter, source);
        let annotations = annotations_for_node(parameter, source);
        let request_body = annotations
            .iter()
            .any(|annotation| annotation.name == "RequestBody");
        let validation_annotation = request_body
            .then(|| {
                annotations
                    .iter()
                    .find_map(|annotation| match annotation.name.as_str() {
                        "Validated" => Some("Validated"),
                        "Valid" => Some("Valid"),
                        _ => None,
                    })
            })
            .flatten();
        if let Some(annotation) = validation_annotation {
            let mut metadata = metadata_entry("adapter", "java");
            metadata.insert("annotation".to_string(), annotation.to_string());
            add_sanitizer(
                facts,
                file,
                symbols,
                parameter,
                SanitizerKind::Validation,
                annotation,
                metadata,
            );
        }
        let annotation_name = [
            "RequestParam",
            "PathVariable",
            "RequestBody",
            "RequestHeader",
            "CookieValue",
            "QueryParam",
            "PathParam",
            "HeaderParam",
            "FormParam",
            "BeanParam",
        ]
        .into_iter()
        .find(|name| text.contains(&format!("@{name}")));
        if annotation_name.is_some()
            || text.contains("HttpServletRequest")
            || text.contains("ServerRequest")
            || text.contains("ContainerRequestContext")
        {
            let mut metadata = metadata_entry("adapter", "java");
            if let Some(annotation_name) = annotation_name {
                metadata.insert("annotation".to_string(), annotation_name.to_string());
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
}

fn collect_calls_and_flows(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    root: Node<'_>,
    source: &str,
    symbols: &[SymbolSpan],
) {
    walk_tree(root, &mut |node| {
        if !matches!(
            node.kind(),
            "method_invocation" | "constructor_invocation" | "object_creation_expression"
        ) {
            return;
        }
        let callee = java_callee_name(node, source);
        if callee.is_empty() {
            return;
        }
        let arguments = argument_texts(node, source);
        add_call(facts, file, symbols, node, callee.clone(), arguments);
        collect_flow_fact_from_call(facts, file, node, symbols, source, &callee);
    });
}

fn java_callee_name(node: Node<'_>, source: &str) -> String {
    if node.kind() == "object_creation_expression" {
        return node
            .child_by_field_name("type")
            .map(|type_node| format!("new {}", node_text(type_node, source)))
            .unwrap_or_else(|| node_text(node, source).to_string());
    }
    let name = child_text(node, "name", source).unwrap_or_default();
    let object = child_text(node, "object", source);
    if let Some(object) = object {
        format!("{object}.{name}")
    } else {
        name.to_string()
    }
}

fn collect_flow_fact_from_call(
    facts: &mut backend_doctor_core::AnalysisFacts,
    file: &backend_doctor_core::SourceFileFact,
    node: Node<'_>,
    symbols: &[SymbolSpan],
    source: &str,
    callee: &str,
) {
    let lower = callee.to_ascii_lowercase();
    let final_lower = lower_final_segment(callee);
    let receiver = callee
        .split_once('.')
        .map(|(receiver, _)| receiver.to_ascii_lowercase())
        .unwrap_or_default();

    if is_java_request_source(&lower, &final_lower) {
        add_data_source(
            facts,
            file,
            symbols,
            node,
            DataSourceKind::Request,
            callee,
            None,
            metadata_entry("adapter", "java"),
        );
    }

    if matches!(
        final_lower.as_str(),
        "exchange" | "execute" | "retrieve" | "exchangetomono" | "exchangetoflux"
    ) && java_method_invocation_is_proven_webclient_request(node, source)
    {
        let metadata = webclient_network_request_metadata(node, source);
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::NetworkRequest,
            callee,
            metadata,
        );
    } else if is_java_sql_sink(&receiver, &lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::SqlQuery,
            callee,
            metadata_entry("adapter", "java"),
        );
    } else if is_java_command_sink(&lower, &final_lower) {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::Command,
            callee,
            metadata_entry("adapter", "java"),
        );
    } else if is_java_response_sink(&lower, &final_lower) {
        let kind = if final_lower == "redirect" || lower.contains("redirectview") {
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
            metadata_entry("adapter", "java"),
        );
    } else if final_lower.contains("write") && lower.contains("file") {
        add_sink(
            facts,
            file,
            symbols,
            node,
            SinkKind::FileWrite,
            callee,
            metadata_entry("adapter", "java"),
        );
    }

    if is_java_sanitizer(&lower, &final_lower) {
        let kind = if final_lower.contains("escape") || final_lower == "encode" {
            SanitizerKind::Escaping
        } else if matches!(
            final_lower.as_str(),
            "parseint" | "parseboolean" | "valueof"
        ) {
            SanitizerKind::TypeCheck
        } else if lower.contains("preparedstatement") {
            SanitizerKind::Parameterization
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
            metadata_entry("adapter", "java"),
        );
    }
}

fn java_method_invocation_is_proven_webclient_request(node: Node<'_>, source: &str) -> bool {
    let chain = expanded_java_method_chain_node(node);
    if java_method_chain_has_direct_webclient_factory(chain, source) {
        return true;
    }

    let Some(receiver) = java_method_chain_root_receiver(chain) else {
        return false;
    };
    java_receiver_expression_is_proven_webclient(receiver, node, source)
}

fn java_receiver_expression_is_proven_webclient(
    receiver: Node<'_>,
    usage: Node<'_>,
    source: &str,
) -> bool {
    let receiver_text = node_text(receiver, source).trim();
    let Some((name, scope_filter)) = java_receiver_identifier_context(receiver_text) else {
        return false;
    };
    let variable_contexts = java_variable_contexts_for_timeout_search(usage, source);
    java_identifier_resolves_to_webclient(&variable_contexts, &name, scope_filter)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum JavaVariableContextLookupScope {
    Any,
    FieldOnly,
}

fn java_identifier_resolves_to_webclient(
    contexts: &[JavaVariableContext],
    name: &str,
    initial_scope_filter: JavaVariableContextLookupScope,
) -> bool {
    let mut queue = vec![(name.to_string(), initial_scope_filter)];
    let mut visited = BTreeSet::new();
    let mut expanded_contexts = 0usize;

    while let Some((identifier, scope_filter)) = queue.pop() {
        if !visited.insert((identifier.clone(), scope_filter)) {
            continue;
        }
        let Some(context) = latest_java_variable_context(contexts, &identifier, scope_filter)
        else {
            continue;
        };
        if java_context_proves_webclient(context) {
            return true;
        }
        queue.extend(
            java_webclient_provenance_alias_identifiers(context)
                .into_iter()
                .filter(|identifier| !visited.contains(identifier)),
        );
        expanded_contexts += 1;
        if expanded_contexts > 64 {
            return false;
        }
    }

    false
}

fn java_context_proves_webclient(context: &JavaVariableContext) -> bool {
    java_context_declares_webclient_type(context)
        || java_context_has_direct_webclient_factory(context)
}

fn java_context_declares_webclient_type(context: &JavaVariableContext) -> bool {
    let code = java_code_without_literals_and_comments(&context.text);
    let Some(name_start) = java_first_unqualified_identifier_start(&code, &context.name) else {
        return false;
    };
    let type_prefix = code[..name_start].trim_end();
    if type_prefix.is_empty() || type_prefix.ends_with('>') || type_prefix.ends_with(']') {
        return false;
    }
    java_final_identifier(type_prefix).as_deref() == Some("WebClient")
}

fn java_context_has_direct_webclient_factory(context: &JavaVariableContext) -> bool {
    let code = java_code_without_literals_and_comments(&context.text);
    let Some(value) = java_assignment_value_text(&code) else {
        return false;
    };
    java_expression_starts_with_webclient_static_factory_call(value)
}

fn java_context_proves_webclient_builder(context: &JavaVariableContext) -> bool {
    java_context_declares_webclient_builder_type(context)
        || java_context_has_direct_webclient_builder_factory(context)
}

fn java_context_declares_webclient_builder_type(context: &JavaVariableContext) -> bool {
    let code = java_code_without_literals_and_comments(&context.text);
    let Some(name_start) = java_first_unqualified_identifier_start(&code, &context.name) else {
        return false;
    };
    let type_prefix = code[..name_start].trim_end();
    if type_prefix.is_empty() || type_prefix.ends_with('>') || type_prefix.ends_with(']') {
        return false;
    }
    java_type_reference_ends_with_webclient_builder(type_prefix)
}

fn java_context_has_direct_webclient_builder_factory(context: &JavaVariableContext) -> bool {
    let code = java_code_without_literals_and_comments(&context.text);
    let Some(value) = java_assignment_value_text(&code) else {
        return false;
    };
    java_expression_starts_with_webclient_builder_factory_call(value)
}

fn java_webclient_provenance_alias_identifiers(
    context: &JavaVariableContext,
) -> Vec<(String, JavaVariableContextLookupScope)> {
    let code = java_code_without_literals_and_comments(&context.text);
    let Some(value) = java_assignment_value_text(&code) else {
        return Vec::new();
    };
    java_simple_assignment_alias_identifier(value)
        .into_iter()
        .collect()
}

fn java_assignment_value_text(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'=' {
            let previous = index.checked_sub(1).map(|previous| bytes[previous]);
            let next = bytes.get(index + 1).copied();
            if !matches!(previous, Some(b'=' | b'!' | b'<' | b'>')) && !matches!(next, Some(b'=')) {
                return Some(&text[index + 1..]);
            }
        }
        index += 1;
    }
    None
}

fn java_expression_starts_with_webclient_static_factory_call(text: &str) -> bool {
    java_expression_starts_with_webclient_factory_call(text, &["create", "builder"])
}

fn java_expression_starts_with_webclient_builder_factory_call(text: &str) -> bool {
    java_expression_starts_with_webclient_factory_call(text, &["builder"])
}

fn java_expression_starts_with_webclient_factory_call(text: &str, factories: &[&str]) -> bool {
    let text = text.trim_start();
    let mut search_from = 0;
    while let Some(relative_index) = text[search_from..].find("WebClient") {
        let webclient_start = search_from + relative_index;
        let webclient_end = webclient_start + "WebClient".len();
        let bytes = text.as_bytes();
        let starts_on_boundary =
            webclient_start == 0 || !java_identifier_byte(bytes[webclient_start - 1]);
        let ends_on_boundary =
            webclient_end == bytes.len() || !java_identifier_byte(bytes[webclient_end]);
        if starts_on_boundary
            && ends_on_boundary
            && java_is_optional_qualified_type_prefix(&text[..webclient_start])
        {
            let mut index = java_skip_ascii_whitespace(text, webclient_end);
            if index < bytes.len() && bytes[index] == b'.' {
                index = java_skip_ascii_whitespace(text, index + 1);
                for factory in factories {
                    let factory_end = index + factory.len();
                    if factory_end <= bytes.len()
                        && &text[index..factory_end] == *factory
                        && (factory_end == bytes.len() || !java_identifier_byte(bytes[factory_end]))
                        && java_method_call_open_paren(text, factory_end).is_some()
                    {
                        return true;
                    }
                }
            }
        }
        search_from = webclient_end;
    }
    false
}

fn java_identifier_sequence(text: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if current.is_empty() {
                if ch.is_ascii_alphabetic() || ch == '_' {
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        } else if !current.is_empty() {
            identifiers.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        identifiers.push(current);
    }
    identifiers
}

fn java_is_optional_qualified_type_prefix(text: &str) -> bool {
    let text = text.trim();
    if text.is_empty() {
        return true;
    }
    text.ends_with('.')
        && text[..text.len() - 1]
            .split('.')
            .all(java_is_unqualified_identifier)
}

fn java_first_unqualified_identifier_start(text: &str, identifier: &str) -> Option<usize> {
    let mut search_from = 0;
    while let Some(relative_index) = text[search_from..].find(identifier) {
        let identifier_start = search_from + relative_index;
        let identifier_end = identifier_start + identifier.len();
        let bytes = text.as_bytes();
        let starts_on_boundary =
            identifier_start == 0 || !java_identifier_byte(bytes[identifier_start - 1]);
        let ends_on_boundary =
            identifier_end == bytes.len() || !java_identifier_byte(bytes[identifier_end]);
        let is_qualified_access = identifier_start > 0 && bytes[identifier_start - 1] == b'.';
        if starts_on_boundary && ends_on_boundary && !is_qualified_access {
            return Some(identifier_start);
        }
        search_from = identifier_end;
    }
    None
}

fn java_code_without_literals_and_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'/' if index + 1 < bytes.len() && bytes[index + 1] == b'/' => {
                output.push_str("  ");
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    output.push(' ');
                    index += 1;
                }
            }
            b'/' if index + 1 < bytes.len() && bytes[index + 1] == b'*' => {
                output.push_str("  ");
                index += 2;
                while index < bytes.len() {
                    if bytes[index] == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                        output.push_str("  ");
                        index += 2;
                        break;
                    }
                    output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                    index += 1;
                }
            }
            b'"' | b'\'' => {
                let quote = bytes[index];
                output.push(' ');
                index += 1;
                while index < bytes.len() {
                    let byte = bytes[index];
                    output.push(if byte == b'\n' { '\n' } else { ' ' });
                    index += 1;
                    if byte == b'\\' && index < bytes.len() {
                        output.push(if bytes[index] == b'\n' { '\n' } else { ' ' });
                        index += 1;
                    } else if byte == quote {
                        break;
                    }
                }
            }
            byte => {
                output.push(byte as char);
                index += 1;
            }
        }
    }
    output
}

fn java_skip_ascii_whitespace(text: &str, mut index: usize) -> usize {
    let bytes = text.as_bytes();
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

fn java_receiver_identifier_context(
    receiver_text: &str,
) -> Option<(String, JavaVariableContextLookupScope)> {
    if java_is_unqualified_identifier(receiver_text) {
        return Some((
            receiver_text.to_string(),
            JavaVariableContextLookupScope::Any,
        ));
    }
    if java_is_this_field_reference(receiver_text) {
        return java_final_identifier(receiver_text)
            .map(|name| (name, JavaVariableContextLookupScope::FieldOnly));
    }
    None
}

fn webclient_network_request_metadata(node: Node<'_>, source: &str) -> BTreeMap<String, String> {
    let mut metadata = metadata_entry("adapter", "java");
    if let Some(kind) = webclient_timeout_evidence_kind(node, source) {
        metadata.insert("timeoutEvidence".to_string(), "present".to_string());
        metadata.insert("timeoutEvidenceKind".to_string(), kind.to_string());
    }
    metadata
}

fn webclient_timeout_evidence_kind(node: Node<'_>, source: &str) -> Option<&'static str> {
    let chain = expanded_java_method_chain_node(node);
    let chain_text = node_text(chain, source);
    let chain_code = java_code_without_literals_and_comments(chain_text);
    if let Some(kind) = java_timeout_evidence_kind(&chain_code) {
        return Some(kind);
    }

    let variable_contexts = java_variable_contexts_for_timeout_search(node, source);
    let mut queue = java_webclient_timeout_seed_identifiers(chain, source);
    let mut visited = BTreeSet::new();
    let mut expanded_contexts = 0usize;

    while let Some((identifier, scope_filter)) = queue.pop() {
        if !visited.insert((identifier.clone(), scope_filter)) {
            continue;
        }
        if let Some(context) =
            latest_java_variable_context(&variable_contexts, &identifier, scope_filter)
        {
            let context_code = java_code_without_literals_and_comments(&context.text);
            if let Some(kind) = java_timeout_evidence_kind(&context_code) {
                return Some(kind);
            }
            queue.extend(
                java_timeout_alias_identifiers(context, &context_code, &variable_contexts)
                    .into_iter()
                    .filter(|identifier| !visited.contains(identifier)),
            );
            expanded_contexts += 1;
            if expanded_contexts > 64 {
                return None;
            }
        }
    }

    None
}

fn java_webclient_timeout_seed_identifiers(
    chain: Node<'_>,
    source: &str,
) -> Vec<(String, JavaVariableContextLookupScope)> {
    let mut seeds = BTreeSet::new();
    if java_method_chain_has_direct_webclient_factory(chain, source) {
        seeds.extend(
            java_direct_webclient_factory_timeout_alias_identifiers(chain, source)
                .into_iter()
                .map(|identifier| (identifier, JavaVariableContextLookupScope::Any)),
        );
    } else if let Some(receiver) = java_method_chain_root_receiver(chain) {
        let receiver_text = node_text(receiver, source).trim();
        if let Some(seed) = java_receiver_identifier_context(receiver_text) {
            seeds.insert(seed);
        }
    }
    seeds.into_iter().collect()
}

fn java_direct_webclient_factory_timeout_alias_identifiers(
    chain: Node<'_>,
    source: &str,
) -> Vec<String> {
    let mut identifiers = BTreeSet::new();
    for invocation in java_method_chain_invocations_root_to_leaf(chain) {
        let name = child_text(invocation, "name", source).unwrap_or_default();
        if java_webclient_request_chain_method_starts_request(name) {
            break;
        }
        if java_webclient_config_method_may_carry_timeout_alias(name) {
            identifiers.extend(java_method_invocation_argument_identifiers(
                invocation, source,
            ));
        }
    }
    identifiers.into_iter().collect()
}

fn java_method_chain_invocations_root_to_leaf<'tree>(chain: Node<'tree>) -> Vec<Node<'tree>> {
    let mut invocations = Vec::new();
    let mut current = chain;
    loop {
        if current.kind() != "method_invocation" {
            break;
        }
        invocations.push(current);
        let Some(object) = current.child_by_field_name("object") else {
            break;
        };
        if object.kind() != "method_invocation" {
            break;
        }
        current = object;
    }
    invocations.reverse();
    invocations
}

fn java_webclient_request_chain_method_starts_request(name: &str) -> bool {
    matches!(
        name,
        "get"
            | "head"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "options"
            | "method"
            | "uri"
            | "retrieve"
            | "exchange"
            | "exchangeToMono"
            | "exchangeToFlux"
            | "execute"
    )
}

fn java_webclient_config_method_may_carry_timeout_alias(name: &str) -> bool {
    matches!(name, "clientConnector")
}

fn java_method_invocation_argument_identifiers(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(name) = node.child_by_field_name("name") else {
        return Vec::new();
    };
    let text = node_text(node, source);
    let method_end = name.end_byte().saturating_sub(node.start_byte());
    let Some(open_paren) = java_method_call_open_paren(text, method_end) else {
        return Vec::new();
    };
    let Some(arguments) = java_method_argument_texts(text, open_paren) else {
        return Vec::new();
    };
    let mut identifiers = BTreeSet::new();
    for argument in arguments {
        let argument_code = java_code_without_literals_and_comments(argument);
        identifiers.extend(java_identifiers(&argument_code));
    }
    identifiers.into_iter().collect()
}

fn java_timeout_alias_identifiers(
    context: &JavaVariableContext,
    text: &str,
    contexts: &[JavaVariableContext],
) -> Vec<(String, JavaVariableContextLookupScope)> {
    let mut identifiers = BTreeSet::new();
    if let Some(value) = java_assignment_value_text(text) {
        if let Some(alias) = java_simple_assignment_alias_identifier(value) {
            identifiers.insert(alias);
        }
        if java_context_proves_webclient(context) {
            if let Some(alias) =
                java_proven_webclient_builder_build_alias_identifier(value, contexts)
            {
                identifiers.insert(alias);
            }
        }
        identifiers.extend(
            java_relevant_timeout_argument_identifiers(value)
                .into_iter()
                .map(|identifier| (identifier, JavaVariableContextLookupScope::Any)),
        );
    }
    identifiers.into_iter().collect()
}

fn java_identifier_resolves_to_webclient_builder(
    contexts: &[JavaVariableContext],
    name: &str,
    initial_scope_filter: JavaVariableContextLookupScope,
) -> bool {
    let mut queue = vec![(name.to_string(), initial_scope_filter)];
    let mut visited = BTreeSet::new();
    let mut expanded_contexts = 0usize;

    while let Some((identifier, scope_filter)) = queue.pop() {
        if !visited.insert((identifier.clone(), scope_filter)) {
            continue;
        }
        let Some(context) = latest_java_variable_context(contexts, &identifier, scope_filter)
        else {
            continue;
        };
        if java_context_proves_webclient_builder(context) {
            return true;
        }
        queue.extend(
            java_webclient_provenance_alias_identifiers(context)
                .into_iter()
                .filter(|identifier| !visited.contains(identifier)),
        );
        expanded_contexts += 1;
        if expanded_contexts > 64 {
            return false;
        }
    }

    false
}

fn java_simple_assignment_alias_identifier(
    value: &str,
) -> Option<(String, JavaVariableContextLookupScope)> {
    let value = value.trim().trim_end_matches(';').trim();
    java_receiver_identifier_context(value)
}

fn java_proven_webclient_builder_build_alias_identifier(
    value: &str,
    contexts: &[JavaVariableContext],
) -> Option<(String, JavaVariableContextLookupScope)> {
    let alias = java_builder_build_alias_identifier(value)?;
    java_identifier_resolves_to_webclient_builder(contexts, &alias.0, alias.1).then_some(alias)
}

fn java_builder_build_alias_identifier(
    value: &str,
) -> Option<(String, JavaVariableContextLookupScope)> {
    let value = value.trim().trim_end_matches(';').trim();
    let mut search_from = 0;
    while let Some(relative_index) = value[search_from..].find("build") {
        let method_start = search_from + relative_index;
        let method_end = method_start + "build".len();
        if java_method_name_matches(value, method_start, method_end, true) {
            let open_paren = java_method_call_open_paren(value, method_end)?;
            let close_paren = java_empty_method_call_close_paren(value, open_paren)?;
            if !value[close_paren + 1..].trim().is_empty() {
                return None;
            }
            let receiver = value[..method_start - 1].trim();
            return java_receiver_identifier_context(receiver);
        }
        search_from = method_end;
    }
    None
}

fn java_relevant_timeout_argument_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = BTreeSet::new();
    for method in [
        "clientConnector",
        "addHandler",
        "addHandlerFirst",
        "addHandlerLast",
        "handler",
        "from",
    ] {
        java_collect_call_argument_identifiers(text, method, true, false, &mut identifiers);
    }
    java_collect_call_argument_identifiers(
        text,
        "ReactorClientHttpConnector",
        false,
        true,
        &mut identifiers,
    );
    identifiers.into_iter().collect()
}

fn java_collect_call_argument_identifiers(
    text: &str,
    call_name: &str,
    require_dot: bool,
    require_new: bool,
    identifiers: &mut BTreeSet<String>,
) {
    let mut search_from = 0;
    while let Some(relative_index) = text[search_from..].find(call_name) {
        let call_start = search_from + relative_index;
        let call_end = call_start + call_name.len();
        if java_method_name_matches(text, call_start, call_end, require_dot)
            && (!require_new || java_type_reference_is_after_new(text, call_start))
        {
            if let Some(open_paren) = java_method_call_open_paren(text, call_end) {
                if let Some(arguments) = java_method_argument_texts(text, open_paren) {
                    for argument in arguments {
                        identifiers.extend(java_identifiers(argument));
                    }
                }
            }
        }
        search_from = call_end;
    }
}

fn expanded_java_method_chain_node<'tree>(mut current: Node<'tree>) -> Node<'tree> {
    while let Some(parent) = current.parent() {
        if parent.kind() != "method_invocation" {
            break;
        }
        let Some(object) = parent.child_by_field_name("object") else {
            break;
        };
        if object.start_byte() <= current.start_byte() && current.end_byte() <= object.end_byte() {
            current = parent;
        } else {
            break;
        }
    }
    current
}

fn java_method_chain_has_direct_webclient_factory(chain: Node<'_>, source: &str) -> bool {
    let mut current = chain;
    loop {
        if current.kind() != "method_invocation" {
            return false;
        }
        let name = child_text(current, "name", source).unwrap_or_default();
        if matches!(name, "create" | "builder") {
            if let Some(object) = current.child_by_field_name("object") {
                if java_type_reference_ends_with_webclient(node_text(object, source)) {
                    return true;
                }
            }
        }
        let Some(object) = current.child_by_field_name("object") else {
            return false;
        };
        if object.kind() != "method_invocation" {
            return false;
        }
        current = object;
    }
}

fn java_method_chain_root_receiver<'tree>(chain: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = chain;
    loop {
        let object = current.child_by_field_name("object")?;
        if object.kind() == "method_invocation" {
            current = object;
        } else {
            return Some(object);
        }
    }
}

fn java_type_reference_ends_with_webclient(text: &str) -> bool {
    java_final_identifier(text).as_deref() == Some("WebClient")
}

fn java_type_reference_ends_with_webclient_builder(text: &str) -> bool {
    let identifiers = java_identifier_sequence(text);
    identifiers.len() >= 2
        && identifiers[identifiers.len() - 2] == "WebClient"
        && identifiers[identifiers.len() - 1] == "Builder"
}

#[derive(Clone, Debug)]
struct JavaVariableContext {
    name: String,
    text: String,
    start_byte: usize,
    scope: JavaVariableContextScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JavaVariableContextScope {
    Local,
    Field,
}

fn latest_java_variable_context<'a>(
    contexts: &'a [JavaVariableContext],
    name: &str,
    scope_filter: JavaVariableContextLookupScope,
) -> Option<&'a JavaVariableContext> {
    if scope_filter == JavaVariableContextLookupScope::Any {
        let latest_local = contexts
            .iter()
            .filter(|context| {
                context.name == name && context.scope == JavaVariableContextScope::Local
            })
            .max_by_key(|context| context.start_byte);
        if latest_local.is_some() {
            return latest_local;
        }
    }

    contexts
        .iter()
        .filter(|context| context.name == name && context.scope == JavaVariableContextScope::Field)
        .max_by_key(|context| context.start_byte)
}

fn java_variable_contexts_for_timeout_search(
    node: Node<'_>,
    source: &str,
) -> Vec<JavaVariableContext> {
    let mut contexts = Vec::new();
    if let Some(class_node) = containing_java_class(node) {
        collect_java_field_contexts(class_node, source, &mut contexts);
    }
    if let Some(executable) = containing_java_executable(node) {
        collect_java_local_variable_contexts(executable, source, node.start_byte(), &mut contexts);
    }
    contexts
}

fn collect_java_local_variable_contexts(
    scope: Node<'_>,
    source: &str,
    before_byte: usize,
    contexts: &mut Vec<JavaVariableContext>,
) {
    walk_tree(scope, &mut |candidate| {
        if candidate.start_byte() >= before_byte {
            return;
        }
        match candidate.kind() {
            "formal_parameter" => {
                let end_byte = containing_java_executable(candidate)
                    .map(|executable| executable.end_byte())
                    .unwrap_or_else(|| candidate.end_byte());
                if before_byte <= end_byte {
                    if let Some(name) = child_text(candidate, "name", source) {
                        contexts.push(JavaVariableContext {
                            name: name.to_string(),
                            text: node_text(candidate, source).to_string(),
                            start_byte: candidate.start_byte(),
                            scope: JavaVariableContextScope::Local,
                        });
                    }
                }
            }
            "variable_declarator" => {
                let end_byte = java_local_context_scope_end_byte(candidate);
                if before_byte <= end_byte {
                    if let Some(name) = child_text(candidate, "name", source) {
                        contexts.push(JavaVariableContext {
                            name: name.to_string(),
                            text: java_context_statement_text(candidate, source),
                            start_byte: candidate.start_byte(),
                            scope: JavaVariableContextScope::Local,
                        });
                    }
                }
            }
            "assignment_expression" => {
                if let Some((name, scope, _end_byte)) =
                    java_assignment_target_context(candidate, source, scope, before_byte)
                {
                    contexts.push(JavaVariableContext {
                        name,
                        text: java_context_statement_text(candidate, source),
                        start_byte: candidate.start_byte(),
                        scope,
                    });
                }
            }
            _ => {}
        }
    });
}

fn collect_java_field_contexts(
    class_node: Node<'_>,
    source: &str,
    contexts: &mut Vec<JavaVariableContext>,
) {
    let Some(body) = child_of_kind(class_node, "class_body") else {
        return;
    };
    for field in direct_named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "field_declaration")
    {
        for declarator in direct_named_children(field)
            .into_iter()
            .filter(|child| child.kind() == "variable_declarator")
        {
            if let Some(name) = child_text(declarator, "name", source) {
                contexts.push(JavaVariableContext {
                    name: name.to_string(),
                    text: node_text(field, source).to_string(),
                    start_byte: 0,
                    scope: JavaVariableContextScope::Field,
                });
            }
        }
    }
}

fn java_context_statement_text(node: Node<'_>, source: &str) -> String {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "local_variable_declaration" | "field_declaration" | "expression_statement"
        ) {
            return node_text(parent, source).to_string();
        }
        if matches!(
            parent.kind(),
            "method_declaration" | "constructor_declaration" | "class_declaration"
        ) {
            break;
        }
        current = parent;
    }
    node_text(node, source).to_string()
}

fn java_local_context_scope_end_byte(mut node: Node<'_>) -> usize {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "block"
                | "switch_block"
                | "for_statement"
                | "enhanced_for_statement"
                | "try_statement"
                | "catch_clause"
        ) {
            return parent.end_byte();
        }
        if matches!(
            parent.kind(),
            "method_declaration" | "constructor_declaration" | "class_declaration"
        ) {
            return parent.end_byte();
        }
        node = parent;
    }
    node.end_byte()
}

fn java_assignment_target_context(
    node: Node<'_>,
    source: &str,
    executable_scope: Node<'_>,
    usage_byte: usize,
) -> Option<(String, JavaVariableContextScope, usize)> {
    let target = node.child_by_field_name("left")?;
    let target_text = node_text(target, source).trim();
    if java_is_unqualified_identifier(target_text) {
        if let Some(end_byte) = java_active_local_scope_end_for_name(
            executable_scope,
            target_text,
            node.start_byte(),
            source,
        ) {
            if usage_byte > end_byte {
                return None;
            }
            return Some((
                target_text.to_string(),
                JavaVariableContextScope::Local,
                end_byte,
            ));
        }
        return Some((
            target_text.to_string(),
            JavaVariableContextScope::Field,
            usize::MAX,
        ));
    }
    if java_is_this_field_reference(target_text) {
        return java_final_identifier(target_text)
            .map(|name| (name, JavaVariableContextScope::Field, usize::MAX));
    }
    None
}

fn java_active_local_scope_end_for_name(
    scope: Node<'_>,
    name: &str,
    usage_byte: usize,
    source: &str,
) -> Option<usize> {
    let mut active = None::<(usize, usize)>;
    walk_tree(scope, &mut |candidate| {
        if candidate.start_byte() >= usage_byte {
            return;
        }
        if !matches!(candidate.kind(), "formal_parameter" | "variable_declarator") {
            return;
        }
        if child_text(candidate, "name", source) != Some(name) {
            return;
        }
        let end_byte = if candidate.kind() == "formal_parameter" {
            containing_java_executable(candidate)
                .map(|executable| executable.end_byte())
                .unwrap_or_else(|| candidate.end_byte())
        } else {
            java_local_context_scope_end_byte(candidate)
        };
        if usage_byte <= end_byte
            && active.is_none_or(|(current_start, _)| candidate.start_byte() > current_start)
        {
            active = Some((candidate.start_byte(), end_byte));
        }
    });
    active.map(|(_, end_byte)| end_byte)
}

fn java_is_unqualified_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn java_is_this_field_reference(text: &str) -> bool {
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    compact.starts_with("this.") || compact.contains(".this.")
}

fn java_final_identifier(text: &str) -> Option<String> {
    let mut last = None;
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if current.is_empty() {
                if ch.is_ascii_alphabetic() || ch == '_' {
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        } else if !current.is_empty() {
            last = Some(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        last = Some(current);
    }
    last
}

fn containing_java_executable<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if matches!(
            parent.kind(),
            "method_declaration" | "constructor_declaration"
        ) {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn containing_java_class<'tree>(mut node: Node<'tree>) -> Option<Node<'tree>> {
    while let Some(parent) = node.parent() {
        if matches!(parent.kind(), "class_declaration" | "record_declaration") {
            return Some(parent);
        }
        node = parent;
    }
    None
}

fn java_timeout_evidence_kind(text: &str) -> Option<&'static str> {
    if java_last_method_call_has_non_null_argument(text, "responseTimeout", false) == Some(true) {
        return Some("responseTimeout");
    }

    if java_last_method_call_has_non_null_argument(text, "setConnectTimeout", false) == Some(true)
        || java_last_method_call_has_non_null_argument(text, "connectTimeout", true) == Some(true)
        || java_contains_connect_timeout_option_call(text)
    {
        return Some("connectTimeout");
    }

    if java_last_method_call_has_non_null_argument(text, "setReadTimeout", false) == Some(true)
        || java_last_method_call_has_non_null_argument(text, "readTimeout", true) == Some(true)
        || java_last_constructor_call_has_non_null_argument(text, "ReadTimeoutHandler")
            == Some(true)
    {
        return Some("readTimeout");
    }

    if java_last_method_call_has_non_null_argument(text, "writeTimeout", true) == Some(true)
        || java_last_constructor_call_has_non_null_argument(text, "WriteTimeoutHandler")
            == Some(true)
    {
        return Some("writeTimeout");
    }

    java_contains_timeout_call(text).then_some("timeout")
}

fn java_contains_timeout_call(text: &str) -> bool {
    java_last_method_call_has_non_null_argument(text, "timeout", true) == Some(true)
}

fn java_contains_connect_timeout_option_call(text: &str) -> bool {
    let mut search_from = 0;
    while let Some(relative_index) = text[search_from..].find("option") {
        let method_start = search_from + relative_index;
        let method_end = method_start + "option".len();
        if java_method_name_matches(text, method_start, method_end, true) {
            if let Some(open_paren) = java_method_call_open_paren(text, method_end) {
                if let Some(arguments) = java_method_argument_texts(text, open_paren) {
                    if arguments.len() >= 2
                        && java_contains_identifier(arguments[0], "CONNECT_TIMEOUT_MILLIS")
                        && java_argument_is_non_null(arguments[1])
                    {
                        return true;
                    }
                }
            }
        }
        search_from = method_end;
    }
    false
}

fn java_last_method_call_has_non_null_argument(
    text: &str,
    method_name: &str,
    require_dot: bool,
) -> Option<bool> {
    let mut search_from = 0;
    let mut last_call_has_non_null_argument = None;
    while let Some(relative_index) = text[search_from..].find(method_name) {
        let method_start = search_from + relative_index;
        let method_end = method_start + method_name.len();
        if java_method_name_matches(text, method_start, method_end, require_dot) {
            if let Some(open_paren) = java_method_call_open_paren(text, method_end) {
                if let Some(argument) = java_first_method_argument_text(text, open_paren) {
                    last_call_has_non_null_argument = Some(java_argument_is_non_null(argument));
                }
            }
        }
        search_from = method_end;
    }
    last_call_has_non_null_argument
}

fn java_last_constructor_call_has_non_null_argument(text: &str, type_name: &str) -> Option<bool> {
    let mut search_from = 0;
    let mut last_call_has_non_null_argument = None;
    while let Some(relative_index) = text[search_from..].find(type_name) {
        let type_start = search_from + relative_index;
        let type_end = type_start + type_name.len();
        if java_method_name_matches(text, type_start, type_end, false)
            && java_type_reference_is_after_new(text, type_start)
        {
            if let Some(open_paren) = java_method_call_open_paren(text, type_end) {
                if let Some(argument) = java_first_method_argument_text(text, open_paren) {
                    last_call_has_non_null_argument = Some(java_argument_is_non_null(argument));
                }
            }
        }
        search_from = type_end;
    }
    last_call_has_non_null_argument
}

fn java_argument_is_non_null(argument: &str) -> bool {
    let argument = argument.trim();
    !argument.is_empty() && argument != "null"
}

fn java_type_reference_is_after_new(text: &str, type_start: usize) -> bool {
    let bytes = text.as_bytes();
    let mut qualified_start = type_start;
    while qualified_start > 0 {
        let previous = bytes[qualified_start - 1];
        if java_identifier_byte(previous) || previous == b'.' {
            qualified_start -= 1;
        } else {
            break;
        }
    }

    let prefix = text[..qualified_start].trim_end();
    let Some(new_start) = prefix.rfind("new") else {
        return false;
    };
    new_start + "new".len() == prefix.len()
        && (new_start == 0 || !java_identifier_byte(prefix.as_bytes()[new_start - 1]))
}

fn java_method_name_matches(
    text: &str,
    method_start: usize,
    method_end: usize,
    require_dot: bool,
) -> bool {
    let bytes = text.as_bytes();
    if method_end < bytes.len() && java_identifier_byte(bytes[method_end]) {
        return false;
    }
    if require_dot {
        method_start > 0 && bytes[method_start - 1] == b'.'
    } else {
        method_start == 0 || !java_identifier_byte(bytes[method_start - 1])
    }
}

fn java_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn java_contains_identifier(text: &str, identifier: &str) -> bool {
    let mut search_from = 0;
    while let Some(relative_index) = text[search_from..].find(identifier) {
        let identifier_start = search_from + relative_index;
        let identifier_end = identifier_start + identifier.len();
        let bytes = text.as_bytes();
        let starts_on_boundary =
            identifier_start == 0 || !java_identifier_byte(bytes[identifier_start - 1]);
        let ends_on_boundary =
            identifier_end == bytes.len() || !java_identifier_byte(bytes[identifier_end]);
        if starts_on_boundary && ends_on_boundary {
            return true;
        }
        search_from = identifier_end;
    }
    false
}

fn java_method_call_open_paren(text: &str, method_end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = method_end;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    (index < bytes.len() && bytes[index] == b'(').then_some(index)
}

fn java_empty_method_call_close_paren(text: &str, open_paren: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut index = java_skip_ascii_whitespace(text, open_paren + 1);
    if index < bytes.len() && bytes[index] == b')' {
        index = java_skip_ascii_whitespace(text, index + 1);
        if index == bytes.len() {
            return Some(index - 1);
        }
    }
    None
}

fn java_first_method_argument_text(text: &str, open_paren: usize) -> Option<&str> {
    let argument_start = open_paren + 1;
    let mut depth = 0usize;
    for (offset, ch) in text[argument_start..].char_indices() {
        let index = argument_start + offset;
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(&text[argument_start..index]),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return Some(&text[argument_start..index]),
            _ => {}
        }
    }
    None
}

fn java_method_argument_texts(text: &str, open_paren: usize) -> Option<Vec<&str>> {
    let arguments_start = open_paren + 1;
    let mut argument_start = arguments_start;
    let mut depth = 0usize;
    let mut arguments = Vec::new();
    for (offset, ch) in text[arguments_start..].char_indices() {
        let index = arguments_start + offset;
        match ch {
            '(' => depth += 1,
            ')' if depth == 0 => {
                if argument_start < index || !arguments.is_empty() {
                    arguments.push(&text[argument_start..index]);
                }
                return Some(arguments);
            }
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                arguments.push(&text[argument_start..index]);
                argument_start = index + 1;
            }
            _ => {}
        }
    }
    None
}

fn java_identifiers(text: &str) -> Vec<String> {
    let mut identifiers = BTreeSet::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            if current.is_empty() {
                if ch.is_ascii_alphabetic() || ch == '_' {
                    current.push(ch);
                }
            } else {
                current.push(ch);
            }
        } else if !current.is_empty() {
            identifiers.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        identifiers.insert(current);
    }
    identifiers.into_iter().collect()
}

fn is_java_request_source(full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "getparameter"
            | "getparametervalues"
            | "getheader"
            | "getcookies"
            | "body"
            | "pathvariable"
    ) || full_lower.contains("serverrequest.")
        || full_lower.contains("httpservletrequest.")
}

fn is_java_sql_sink(receiver: &str, full_lower: &str, final_lower: &str) -> bool {
    matches!(
        final_lower,
        "executequery" | "executeupdate" | "execute" | "query" | "queryforobject" | "update"
    ) && (matches!(
        receiver,
        "statement" | "stmt" | "connection" | "jdbc" | "jdbctemplate" | "entitymanager"
    ) || full_lower.contains("jdbctemplate")
        || full_lower.contains("entitymanager"))
}

fn is_java_command_sink(full_lower: &str, final_lower: &str) -> bool {
    matches!(final_lower, "exec" | "start")
        && (full_lower.contains("runtime")
            || full_lower.contains("processbuilder")
            || full_lower == "exec")
}

fn is_java_response_sink(full_lower: &str, final_lower: &str) -> bool {
    full_lower.contains("responseentity.")
        || full_lower.contains("response.")
        || matches!(
            final_lower,
            "ok" | "created" | "status" | "entity" | "redirect"
        )
}

fn is_java_sanitizer(full_lower: &str, final_lower: &str) -> bool {
    final_lower.contains("escape")
        || final_lower == "encode"
        || full_lower.contains("validator")
        || full_lower.contains("sanitize")
        || full_lower.contains("preparedstatement")
        || matches!(final_lower, "parseint" | "parseboolean" | "valueof")
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

fn direct_method_declarations(class_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = child_of_kind(class_node, "class_body")
        .or_else(|| child_of_kind(class_node, "record_body"))
        .or_else(|| child_of_kind(class_node, "interface_body"))
    else {
        return Vec::new();
    };
    direct_named_children(body)
        .into_iter()
        .filter(|child| child.kind() == "method_declaration")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::{ProjectGraph, SourceFileFact};
    use std::path::PathBuf;

    fn analyze_java(source: &str) -> backend_doctor_core::AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/main/java/com/acme/UserController.java", "Java");
        file.service_id = Some("api".to_string());
        JavaAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("java analysis succeeds")
    }

    #[test]
    fn extracts_java_routes_imports_symbols_and_flows() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;

@RestController
@RequestMapping("/api")
class UserController {
    @GetMapping("/users/{id}")
    ResponseEntity<String> getUser(@PathVariable String id, @RequestParam String q) {
        String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml4(q);
        jdbcTemplate.query("select * from users where name = " + safe, mapper);
        return ResponseEntity.ok(id);
    }
}

@Path("/v1")
class ItemResource {
    @POST
    @Path("/items")
    public Response create(@QueryParam("name") String name) {
        Runtime.getRuntime().exec(name);
        return Response.ok(name).build();
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts
            .imports
            .iter()
            .any(|fact| fact.module == "org.springframework.web.bind.annotation.*"));
        assert!(facts
            .symbols
            .iter()
            .any(|fact| fact.name == "UserController"));
        assert!(facts
            .calls
            .iter()
            .any(|fact| fact.callee_name == "jdbcTemplate.query"));
        assert!(
            facts.routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/api/users/{id}"
                    && route.framework.as_deref() == Some("JAX-RS")
            }) || facts.routes.iter().any(|route| {
                route.method == "GET"
                    && route.path == "/api/users/{id}"
                    && route.framework.as_deref() == Some("Spring")
            })
        );
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/v1/items"
                && route.framework.as_deref() == Some("JAX-RS")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("q")
                || source.name.as_deref() == Some("name")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("jdbcTemplate.query")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("Runtime.getRuntime().exec")));
        assert!(facts.sanitizers.iter().any(|sanitizer| sanitizer
            .name
            .as_deref()
            .is_some_and(|name| name.contains("escapeHtml4"))));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn webclient_network_requests_without_timeout_have_no_timeout_evidence() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient.create().get().uri("https://example.org/users").retrieve();
        WebClient.builder().build().get().uri("https://example.org/builder").retrieve();
        WebClient.create().post().uri("https://example.org/users").exchange();
        WebClient.create().get().uri("https://example.org/users").execute(request -> null);
        WebClient.create().get().uri("https://example.org/mono")
            .exchangeToMono(response -> response.bodyToMono(String.class));
        WebClient.create().get().uri("https://example.org/flux")
            .exchangeToFlux(response -> response.bodyToFlux(String.class));
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 6);
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("adapter")
            .is_some_and(|adapter| adapter == "java")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidenceKind")));
    }

    #[test]
    fn webclient_network_requests_are_detected_for_generic_client_variable_names() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient client = WebClient.create();

        client.get().uri("https://example.org/retrieve").retrieve();
        client.get().uri("https://example.org/mono")
            .exchangeToMono(response -> response.bodyToMono(String.class));
        client.get().uri("https://example.org/flux")
            .exchangeToFlux(response -> response.bodyToFlux(String.class));
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 3);
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("adapter")
            .is_some_and(|adapter| adapter == "java")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
    }

    #[test]
    fn webclient_execute_takes_precedence_over_sql_receiver_names() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient statement = WebClient.create();
        statement.get().uri("https://example.org").execute(request -> null);
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 1);
        assert_eq!(
            network_sinks[0].metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
    }

    #[test]
    fn non_webclient_wrapper_constructor_argument_is_not_webclient_receiver() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient delegate = WebClient.create();
        OtherClient client = new OtherClient(delegate);
        client.get().uri("/").retrieve();
    }
}
"#;

        let facts = analyze_java(source);

        assert!(!facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::NetworkRequest));
    }

    #[test]
    fn non_webclient_receiver_with_webclient_literal_is_not_network_request() {
        let source = r#"
package com.acme;

class Client {
    void run() {
        OtherClient client = new OtherClient("WebClient");
        client.get().uri("/").retrieve();

        OtherClient factoryArgClient = new OtherClient(WebClient.create());
        factoryArgClient.get().uri("/factory").retrieve();
    }
}
"#;

        let facts = analyze_java(source);

        assert!(!facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::NetworkRequest));
        assert!(facts
            .sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
    }

    #[test]
    fn webclient_exchange_to_mono_and_flux_preserve_timeout_evidence() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        HttpClient responseClient = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        WebClient webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(responseClient))
            .build();

        webClient.get().uri("https://example.org/mono")
            .exchangeToMono(response -> response.bodyToMono(String.class));
        webClient.get().uri("https://example.org/flux")
            .exchangeToFlux(response -> response.bodyToFlux(String.class));
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 2);
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("adapter")
            .is_some_and(|adapter| adapter == "java")));
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("timeoutEvidence")
            .is_some_and(|evidence| evidence == "present")));
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("timeoutEvidenceKind")
            .is_some_and(|kind| kind == "responseTimeout")));
    }

    #[test]
    fn webclient_builder_build_assignment_preserves_timeout_evidence() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        HttpClient configured = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        WebClient.Builder builder = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(configured));
        WebClient client = builder.build();
        client.get().uri("https://example.org/builder-variable").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("timeoutEvidence").map(String::as_str),
            Some("present")
        );
        assert_eq!(
            sink.metadata.get("timeoutEvidenceKind").map(String::as_str),
            Some("responseTimeout")
        );
    }

    #[test]
    fn unrelated_builder_build_assignment_does_not_mark_timeout_evidence() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.web.reactive.function.client.WebClient;

class OtherBuilder {
    static OtherBuilder create() {
        return new OtherBuilder();
    }

    OtherBuilder responseTimeout(Duration duration) {
        return this;
    }

    WebClient build() {
        return WebClient.create();
    }
}

class Client {
    void run() {
        OtherBuilder builder = OtherBuilder.create().responseTimeout(Duration.ofSeconds(2));
        WebClient client = builder.build();
        client.get().uri("https://example.org/unrelated-builder").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!sink.metadata.contains_key("timeoutEvidence"));
        assert!(!sink.metadata.contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn webclient_network_requests_with_timeout_evidence_are_marked() {
        let source = r#"
package com.acme;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        HttpClient responseClient = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        WebClient responseWebClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(responseClient))
            .build();
        responseWebClient.get().uri("https://example.org/response").retrieve();

        HttpClient connectClient = HttpClient.create()
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 10000);
        WebClient connectWebClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(connectClient))
            .build();
        connectWebClient.post().uri("https://example.org/connect").exchange();

        WebClient readWebClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(HttpClient.create()
                .doOnConnected(conn -> conn.addHandlerLast(new ReadTimeoutHandler(10)))))
            .build();
        readWebClient.get().uri("https://example.org/read").execute(request -> null);

        WebClient writeWebClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(HttpClient.create()
                .doOnConnected(conn -> conn.addHandlerLast(new WriteTimeoutHandler(10)))))
            .build();
        writeWebClient.get().uri("https://example.org/write").retrieve();

        WebClient setterConnectWebClient = WebClient.builder()
            .clientConnector(new ClientHttpConnectorFactory()
                .setConnectTimeout(1000)
                .build())
            .build();
        setterConnectWebClient.get().uri("https://example.org/set-connect").retrieve();

        WebClient setterReadWebClient = WebClient.builder()
            .clientConnector(new ClientHttpConnectorFactory()
                .setReadTimeout(1000)
                .build())
            .build();
        setterReadWebClient.get().uri("https://example.org/set-read").retrieve();

        WebClient.create()
            .get()
            .uri("https://example.org/reactor-timeout")
            .retrieve()
            .timeout(Duration.ofSeconds(1));
    }
}
"#;

        let facts = analyze_java(source);

        let response_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("responseWebClient"))
            })
            .expect("response timeout WebClient sink");
        assert_eq!(
            response_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            response_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("responseTimeout")
        );

        let connect_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("connectWebClient"))
            })
            .expect("connect timeout WebClient sink");
        assert_eq!(
            connect_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            connect_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("connectTimeout")
        );

        let read_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("readWebClient"))
            })
            .expect("read timeout WebClient sink");
        assert_eq!(
            read_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            read_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("readTimeout")
        );

        let write_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("writeWebClient"))
            })
            .expect("write timeout WebClient sink");
        assert_eq!(
            write_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            write_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("writeTimeout")
        );

        let setter_connect_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("setterConnectWebClient"))
            })
            .expect("setConnectTimeout WebClient sink");
        assert_eq!(
            setter_connect_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            setter_connect_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("connectTimeout")
        );

        let setter_read_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("setterReadWebClient"))
            })
            .expect("setReadTimeout WebClient sink");
        assert_eq!(
            setter_read_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            setter_read_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("readTimeout")
        );

        let reactor_timeout_sink = facts
            .sinks
            .iter()
            .find(|sink| {
                sink.kind == SinkKind::NetworkRequest
                    && sink
                        .name
                        .as_deref()
                        .is_some_and(|name| name.contains("reactor-timeout"))
            })
            .expect("Reactor timeout WebClient sink");
        assert_eq!(
            reactor_timeout_sink
                .metadata
                .get("timeoutEvidence")
                .map(String::as_str),
            Some("present")
        );
        assert_eq!(
            reactor_timeout_sink
                .metadata
                .get("timeoutEvidenceKind")
                .map(String::as_str),
            Some("timeout")
        );
    }

    #[test]
    fn webclient_timeout_evidence_uses_latest_same_name_context() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    private final HttpClient fieldConfigured = HttpClient.create().responseTimeout(Duration.ofSeconds(3));
    private WebClient webClient = WebClient.builder()
        .clientConnector(new ReactorClientHttpConnector(fieldConfigured))
        .build();

    void assignmentReplacesConfiguredClient() {
        HttpClient configured = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        WebClient webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(configured))
            .build();
        webClient = WebClient.create();
        webClient.get().uri("https://example.org/latest-assignment").retrieve();
    }

    void localDeclarationShadowsConfiguredField() {
        WebClient webClient = WebClient.create();
        webClient.get().uri("https://example.org/local-shadow").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 2);
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidenceKind")));
    }

    #[test]
    fn local_webclient_shadows_later_configured_same_name_field() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        WebClient webClient = WebClient.create();
        webClient.get().uri("https://example.org/local-before-field").retrieve();
    }

    private final HttpClient responseClient = HttpClient.create().responseTimeout(Duration.ofSeconds(5));
    private final WebClient webClient = WebClient.builder()
        .clientConnector(new ReactorClientHttpConnector(responseClient))
        .build();
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!sink.metadata.contains_key("timeoutEvidence"));
        assert!(!sink.metadata.contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn ended_inner_block_local_webclient_does_not_shadow_configured_field() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    private final HttpClient responseClient = HttpClient.create().responseTimeout(Duration.ofSeconds(5));
    private final WebClient webClient = WebClient.builder()
        .clientConnector(new ReactorClientHttpConnector(responseClient))
        .build();

    void run() {
        {
            WebClient webClient = WebClient.create();
        }

        webClient.get().uri("https://example.org/field-after-block").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert_eq!(
            sink.metadata.get("timeoutEvidence").map(String::as_str),
            Some("present")
        );
        assert_eq!(
            sink.metadata.get("timeoutEvidenceKind").map(String::as_str),
            Some("responseTimeout")
        );
    }

    #[test]
    fn qualified_field_assignment_does_not_override_same_name_local_webclient() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    private WebClient webClient;

    void run() {
        WebClient webClient = WebClient.create();
        HttpClient responseClient = HttpClient.create().responseTimeout(Duration.ofSeconds(5));
        this.webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(responseClient))
            .build();

        webClient.get().uri("https://example.org/local-after-field-assignment").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!sink.metadata.contains_key("timeoutEvidence"));
        assert!(!sink.metadata.contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn timeout_like_webclient_names_do_not_mark_timeout_evidence() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    private final WebClient readTimeoutWebClient = WebClient.create();
    private final WebClient connectTimeoutClient = WebClient.create();
    private final WebClient writeTimeoutClient = WebClient.create();

    void run() {
        WebClient connectNameWebClient = connectTimeoutClient;
        WebClient writeNameWebClient = writeTimeoutClient;

        readTimeoutWebClient.get().uri("https://example.org/read-name").retrieve();
        connectNameWebClient.get().uri("https://example.org/connect-name").retrieve();
        writeNameWebClient.get().uri("https://example.org/write-name").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 3);
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidenceKind")));
    }

    #[test]
    fn webclient_response_timeout_null_does_not_mark_timeout_evidence() {
        let source = r#"
package com.acme;

import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void responseTimeoutDisabled() {
        HttpClient responseClient = HttpClient.create().responseTimeout(null);
        WebClient webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(responseClient))
            .build();
        webClient.get().uri("https://example.org/response-timeout-null").retrieve();
    }

    void timeoutOperatorDisabled() {
        WebClient.create()
            .get()
            .uri("https://example.org/timeout-null")
            .retrieve()
            .timeout(null);
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 2);
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidenceKind")));
    }

    #[test]
    fn connect_timeout_identifier_without_option_call_does_not_mark_timeout_evidence() {
        let source = r#"
package com.acme;

import io.netty.channel.ChannelOption;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        WebClient headerReferenceWebClient = WebClient.builder()
            .defaultHeader("X-Option", ChannelOption.CONNECT_TIMEOUT_MILLIS.name())
            .build();
        headerReferenceWebClient.get()
            .uri("https://example.org/connect-timeout-token")
            .retrieve();

        HttpClient nullOptionClient = HttpClient.create()
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, null);
        WebClient nullOptionWebClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(nullOptionClient))
            .build();
        nullOptionWebClient.get()
            .uri("https://example.org/null-connect-timeout-option")
            .retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 2);
        assert!(network_sinks.iter().all(|sink| sink
            .metadata
            .get("adapter")
            .is_some_and(|adapter| adapter == "java")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidence")));
        assert!(network_sinks
            .iter()
            .all(|sink| !sink.metadata.contains_key("timeoutEvidenceKind")));
    }

    #[test]
    fn unrelated_timeout_tokens_do_not_mark_webclient_network_request() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        HttpClient unrelatedClient = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        Mono.just("unrelated").timeout(Duration.ofSeconds(1));
        WebClient webClient = WebClient.create();
        webClient.get().uri("https://example.org/users").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let sink = facts
            .sinks
            .iter()
            .find(|sink| sink.kind == SinkKind::NetworkRequest)
            .expect("WebClient network request sink");

        assert_eq!(
            sink.metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!sink.metadata.contains_key("timeoutEvidence"));
        assert!(!sink.metadata.contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn unrelated_request_chain_identifier_contexts_do_not_mark_timeout_evidence() {
        let source = r#"
package com.acme;

import java.time.Duration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

class Client {
    void run() {
        HttpClient uri = HttpClient.create().responseTimeout(Duration.ofSeconds(2));
        WebClient webClient = WebClient.create();
        webClient.get().uri("https://example.org").retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 1);
        assert_eq!(
            network_sinks[0].metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!network_sinks[0].metadata.contains_key("timeoutEvidence"));
        assert!(!network_sinks[0]
            .metadata
            .contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn timeout_calls_in_comments_do_not_mark_webclient_timeout_evidence() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient webClient = WebClient.builder()
            // .responseTimeout(Duration.ofSeconds(2))
            .defaultHeader("X-Test", "ok")
            .build();

        webClient.get()
            // .timeout(Duration.ofSeconds(1))
            .uri("https://example.org/comment")
            .retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 1);
        assert_eq!(
            network_sinks[0].metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!network_sinks[0].metadata.contains_key("timeoutEvidence"));
        assert!(!network_sinks[0]
            .metadata
            .contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn timeout_calls_in_strings_do_not_mark_webclient_timeout_evidence() {
        let source = r#"
package com.acme;

import org.springframework.web.reactive.function.client.WebClient;

class Client {
    void run() {
        WebClient webClient = WebClient.builder()
            .defaultHeader("X-Timeout", ".responseTimeout(Duration.ofSeconds(2))")
            .build();

        webClient.get()
            .uri("https://example.org/.timeout(Duration.ofSeconds(1))")
            .retrieve();
    }
}
"#;

        let facts = analyze_java(source);
        let network_sinks: Vec<_> = facts
            .sinks
            .iter()
            .filter(|sink| sink.kind == SinkKind::NetworkRequest)
            .collect();

        assert_eq!(network_sinks.len(), 1);
        assert_eq!(
            network_sinks[0].metadata.get("adapter").map(String::as_str),
            Some("java")
        );
        assert!(!network_sinks[0].metadata.contains_key("timeoutEvidence"));
        assert!(!network_sinks[0]
            .metadata
            .contains_key("timeoutEvidenceKind"));
    }

    #[test]
    fn extracts_validation_sanitizer_for_valid_request_body() {
        let source = r#"
package com.acme;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
class UserController {
    @PostMapping("/users")
    User create(@Valid @RequestBody User input) {
        return input;
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Validation
                && sanitizer.name.as_deref() == Some("Valid")
                && sanitizer
                    .metadata
                    .get("adapter")
                    .is_some_and(|adapter| adapter == "java")
                && sanitizer
                    .metadata
                    .get("annotation")
                    .is_some_and(|annotation| annotation == "Valid")
        }));
    }

    #[test]
    fn extracts_validation_sanitizer_for_validated_request_body() {
        let source = r#"
package com.acme;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
class UserController {
    @PostMapping("/users")
    User create(@Validated @RequestBody User input) {
        return input;
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Validation
                && sanitizer.name.as_deref() == Some("Validated")
                && sanitizer
                    .metadata
                    .get("adapter")
                    .is_some_and(|adapter| adapter == "java")
                && sanitizer
                    .metadata
                    .get("annotation")
                    .is_some_and(|annotation| annotation == "Validated")
        }));
    }

    #[test]
    fn extracts_validation_sanitizer_for_qualified_request_body_annotations() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
class UserController {
    @PostMapping("/users")
    User create(@jakarta.validation.Valid() @RequestBody User input) {
        return input;
    }

    @PostMapping("/admins")
    User createAdmin(@org.springframework.validation.annotation.Validated(AdminGroup.class) @RequestBody User input) {
        return input;
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Validation
                && sanitizer.name.as_deref() == Some("Valid")
                && sanitizer
                    .metadata
                    .get("annotation")
                    .is_some_and(|annotation| annotation == "Valid")
        }));
        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Validation
                && sanitizer.name.as_deref() == Some("Validated")
                && sanitizer
                    .metadata
                    .get("annotation")
                    .is_some_and(|annotation| annotation == "Validated")
        }));
    }

    #[test]
    fn rejects_prefixed_custom_validation_annotations_on_request_body() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
class UserController {
    @PostMapping("/users")
    User create(@ValidCustom @RequestBody User input) {
        return input;
    }

    @PostMapping("/admins")
    User createAdmin(@ValidatedCustom @RequestBody User input) {
        return input;
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.data_sources.iter().any(|source| {
            source.kind == DataSourceKind::Request && source.name.as_deref() == Some("input")
        }));
        assert!(!facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Validation));
    }

    #[test]
    fn rejects_non_validation_annotations_containing_valid_on_request_body() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
class UserController {
    @PostMapping("/users")
    User create(@NotValid @RequestBody User input) {
        return input;
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.data_sources.iter().any(|source| {
            source.kind == DataSourceKind::Request && source.name.as_deref() == Some("input")
        }));
        assert!(!facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Validation));
    }

    #[test]
    fn extracts_route_auth_sanitizers_for_method_and_class_annotations() {
        let source = r#"
package com.acme;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.*;

@RestController
@RolesAllowed("ADMIN")
class UserController {
    @GetMapping("/admin/users")
    String listUsers() { return "ok"; }

    @Secured("ROLE_ADMIN")
    @GetMapping("/admin/secure")
    String secureUsers() { return "ok"; }

    @jakarta.annotation.security.DenyAll
    @DeleteMapping("/admin/closed")
    String closed() { return "ok"; }
}
"#;

        let facts = analyze_java(source);

        let list_route = facts
            .routes
            .iter()
            .find(|route| route.path == "/admin/users")
            .expect("class-protected route");
        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Authorization
                && sanitizer.name.as_deref() == Some("RolesAllowed")
                && sanitizer.symbol_id == list_route.symbol_id
                && sanitizer
                    .metadata
                    .get("adapter")
                    .is_some_and(|adapter| adapter == "java")
        }));

        let secure_route = facts
            .routes
            .iter()
            .find(|route| route.path == "/admin/secure")
            .expect("method-protected route");
        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Authorization
                && sanitizer.name.as_deref() == Some("Secured")
                && sanitizer.symbol_id == secure_route.symbol_id
        }));

        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Authorization
                && sanitizer.name.as_deref() == Some("DenyAll")
                && sanitizer
                    .metadata
                    .get("qualifiedAnnotation")
                    .is_some_and(|annotation| annotation == "jakarta.annotation.security.DenyAll")
        }));
    }

    #[test]
    fn permit_all_does_not_emit_route_auth_sanitizer() {
        let source = r#"
package com.acme;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.*;

@RestController
@RolesAllowed("ADMIN")
class UserController {
    @PermitAll
    @GetMapping("/admin/public")
    String publicUsers() { return "ok"; }

    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/private")
    String privateUsers() { return "ok"; }
}
"#;

        let facts = analyze_java(source);

        let public_route = facts
            .routes
            .iter()
            .find(|route| route.path == "/admin/public")
            .expect("public route");
        assert!(!facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Authorization
                && sanitizer.symbol_id == public_route.symbol_id
        }));
        assert!(!facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("PermitAll")));

        let private_route = facts
            .routes
            .iter()
            .find(|route| route.path == "/admin/private")
            .expect("private route");
        assert!(facts.sanitizers.iter().any(|sanitizer| {
            sanitizer.kind == SanitizerKind::Authorization
                && sanitizer.name.as_deref() == Some("PreAuthorize")
                && sanitizer.symbol_id == private_route.symbol_id
                && sanitizer
                    .metadata
                    .get("qualifiedAnnotation")
                    .is_some_and(|annotation| {
                        annotation == "org.springframework.security.access.prepost.PreAuthorize"
                    })
        }));
    }

    #[test]
    fn request_mapping_methods_only_come_from_method_attribute() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
class SearchController {
    @RequestMapping("/get-report")
    String any() { return "ok"; }

    @RequestMapping(value = "/create", method = RequestMethod.POST)
    String create() { return "ok"; }

    @RequestMapping(path = "/read", method = { RequestMethod.GET })
    String read() { return "ok"; }
}
"#;

        let facts = analyze_java(source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "ANY"
                && route.path == "/api/get-report"
                && route.framework.as_deref() == Some("Spring")
        }));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "POST" && route.path == "/api/create"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/read"));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/api/get-report"));
    }

    #[test]
    fn nested_classes_do_not_inherit_outer_route_prefixes() {
        let source = r#"
package com.acme;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/outer")
class OuterController {
    @GetMapping("/own")
    String own() { return "ok"; }

    @RestController
    @RequestMapping("/inner")
    static class InnerController {
        @GetMapping("/item")
        String item() { return "ok"; }
    }
}
"#;

        let facts = analyze_java(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/outer/own"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.method == "GET" && route.path == "/inner/item"));
        assert!(!facts.routes.iter().any(|route| route.path == "/outer/item"));
        assert_eq!(
            facts
                .routes
                .iter()
                .filter(|route| route.method == "GET" && route.path == "/inner/item")
                .count(),
            1
        );
    }
}
