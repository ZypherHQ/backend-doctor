use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, Confidence, DataSourceFact, DataSourceKind,
    ImportFact, ImportKind, SanitizerFact, SanitizerKind, SinkFact, SinkKind, SourceFileFact,
    SourcePosition, SourceRange, SymbolFact, SymbolKind, TaintEdge, TaintEdgeKind,
};
use std::collections::BTreeMap;
use tree_sitter::{Language, Node, Parser, Tree};

use crate::{AdapterInput, AnalysisError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SymbolSpan {
    pub id: String,
    pub name: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

pub(crate) fn parse_tree(
    input: &AdapterInput<'_>,
    language: Language,
) -> Result<Tree, AnalysisError> {
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|error| AnalysisError::Parse {
            path: input.source_file.path.clone(),
            message: error.to_string(),
        })?;
    parser
        .parse(input.contents, None)
        .ok_or_else(|| AnalysisError::Parse {
            path: input.source_file.path.clone(),
            message: "parser returned no tree".to_string(),
        })
}

pub(crate) fn facts_with_source(input: &AdapterInput<'_>) -> AnalysisFacts {
    let mut facts = AnalysisFacts::empty();
    facts.source_files.push(
        input
            .source_file
            .clone()
            .with_content(input.contents.as_bytes()),
    );
    facts
}

pub(crate) fn range_for_node(node: Node<'_>) -> Option<SourceRange> {
    let start = node.start_position();
    let end = node.end_position();
    Some(SourceRange::new(
        SourcePosition::new(
            u32::try_from(start.row + 1).ok()?,
            u32::try_from(start.column + 1).ok()?,
        )
        .with_byte_offset(u32::try_from(node.start_byte()).ok()?),
        SourcePosition::new(
            u32::try_from(end.row + 1).ok()?,
            u32::try_from(end.column + 1).ok()?,
        )
        .with_byte_offset(u32::try_from(node.end_byte()).ok()?),
    ))
}

pub(crate) fn node_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("").trim()
}

pub(crate) fn child_text<'a>(node: Node<'_>, field_name: &str, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name(field_name)
        .map(|child| node_text(child, source))
        .filter(|text| !text.is_empty())
}

pub(crate) fn direct_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

pub(crate) fn walk_tree<'tree>(node: Node<'tree>, visit: &mut impl FnMut(Node<'tree>)) {
    visit(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_tree(child, visit);
    }
}

pub(crate) fn find_first_descendant<'tree>(
    node: Node<'tree>,
    predicate: &impl Fn(Node<'tree>) -> bool,
) -> Option<Node<'tree>> {
    if predicate(node) {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(found) = find_first_descendant(child, predicate) {
            return Some(found);
        }
    }
    None
}

pub(crate) fn string_value(node: Node<'_>, source: &str) -> Option<String> {
    let text = node_text(node, source);
    if text.is_empty() {
        return None;
    }
    if is_string_node(node.kind()) || looks_quoted(text) {
        return Some(strip_quotes(text));
    }

    let mut fragments = Vec::new();
    walk_tree(node, &mut |candidate| {
        if candidate == node {
            return;
        }
        let kind = candidate.kind();
        if is_string_fragment_node(kind) {
            let fragment = node_text(candidate, source);
            if !fragment.is_empty() {
                fragments.push(fragment.to_string());
            }
        }
    });
    if fragments.is_empty() {
        None
    } else {
        Some(fragments.join(""))
    }
}

pub(crate) fn first_string_descendant(node: Node<'_>, source: &str) -> Option<String> {
    find_first_descendant(node, &|candidate| {
        is_string_node(candidate.kind()) || looks_quoted(node_text(candidate, source))
    })
    .and_then(|candidate| string_value(candidate, source))
}

fn is_string_node(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
            | "template_string_fragment"
    )
}

fn is_string_fragment_node(kind: &str) -> bool {
    matches!(
        kind,
        "string_fragment"
            | "raw_string_literal_content"
            | "escape_sequence"
            | "template_chars"
            | "template_string_fragment"
    )
}

fn looks_quoted(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
        || (text.starts_with('`') && text.ends_with('`'))
}

pub(crate) fn strip_quotes(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.len() >= 2 {
        let first = trimmed.as_bytes()[0] as char;
        let last = trimmed.as_bytes()[trimmed.len() - 1] as char;
        if matches!(first, '"' | '\'' | '`') && first == last {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

pub(crate) fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub(crate) fn join_paths(prefix: Option<&str>, path: Option<&str>) -> String {
    let left = prefix
        .map(normalize_path)
        .unwrap_or_else(|| "/".to_string());
    let right = path.map(normalize_path).unwrap_or_else(|| "/".to_string());
    if left == "/" {
        return right;
    }
    if right == "/" {
        return left;
    }
    format!(
        "{}/{}",
        left.trim_end_matches('/'),
        right.trim_start_matches('/')
    )
}

pub(crate) fn final_segment(name: &str) -> &str {
    name.rsplit(['.', ':', '#']).next().unwrap_or(name)
}

pub(crate) fn lower_final_segment(name: &str) -> String {
    final_segment(name).to_ascii_lowercase()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_symbol(
    facts: &mut AnalysisFacts,
    spans: &mut Vec<SymbolSpan>,
    file: &SourceFileFact,
    node: Node<'_>,
    name: impl Into<String>,
    kind: SymbolKind,
    parent_symbol_id: Option<String>,
    source: &str,
) -> String {
    let name = name.into();
    let id = stable_fact_id(
        "symbol",
        [
            file.id.as_str(),
            &name,
            node.kind(),
            &node.start_byte().to_string(),
            &node.end_byte().to_string(),
        ],
    );
    let mut metadata = BTreeMap::new();
    metadata.insert("nodeKind".to_string(), node.kind().to_string());
    facts.symbols.push(SymbolFact {
        id: id.clone(),
        file_id: file.id.clone(),
        name: name.clone(),
        kind,
        range: range_for_node(node),
        signature: Some(short_signature(node, source)),
        visibility: visibility_for_text(node_text(node, source)),
        parent_symbol_id,
        metadata,
    });
    spans.push(SymbolSpan {
        id: id.clone(),
        name,
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
    });
    id
}

fn short_signature(node: Node<'_>, source: &str) -> String {
    let text = node_text(node, source);
    let without_body = text
        .split_once('{')
        .map_or(text, |(signature, _)| signature)
        .trim();
    without_body
        .lines()
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" ")
}

fn visibility_for_text(text: &str) -> Option<String> {
    let first = text.split_whitespace().next()?;
    match first {
        "public" | "private" | "protected" | "internal" | "export" => Some(first.to_string()),
        _ => None,
    }
}

pub(crate) fn containing_symbol_id(spans: &[SymbolSpan], node: Node<'_>) -> Option<String> {
    spans
        .iter()
        .filter(|span| span.start_byte <= node.start_byte() && span.end_byte >= node.end_byte())
        .max_by_key(|span| span.start_byte)
        .map(|span| span.id.clone())
}

pub(crate) fn symbol_id_by_name(spans: &[SymbolSpan], name: &str) -> Option<String> {
    spans
        .iter()
        .find(|span| span.name == name || span.name.ends_with(&format!(".{name}")))
        .map(|span| span.id.clone())
}

pub(crate) fn add_import(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    module: impl Into<String>,
    alias: Option<String>,
    imported_symbols: Vec<String>,
    kind: ImportKind,
    node: Node<'_>,
) {
    let module = module.into();
    let id = stable_fact_id(
        "import",
        [
            file.id.as_str(),
            &module,
            alias.as_deref().unwrap_or(""),
            &node.start_byte().to_string(),
        ],
    );
    facts.imports.push(ImportFact {
        id,
        file_id: Some(file.id.clone()),
        module,
        alias,
        imported_symbols,
        kind,
        range: range_for_node(node),
        metadata: BTreeMap::new(),
    });
}

pub(crate) fn add_call(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    spans: &[SymbolSpan],
    node: Node<'_>,
    callee_name: String,
    arguments: Vec<String>,
) -> String {
    let id = stable_fact_id(
        "call",
        [
            file.id.as_str(),
            &callee_name,
            &node.start_byte().to_string(),
            &node.end_byte().to_string(),
        ],
    );
    facts.calls.push(CallFact {
        id: id.clone(),
        file_id: Some(file.id.clone()),
        caller_symbol_id: containing_symbol_id(spans, node),
        callee_symbol_id: None,
        callee_name,
        range: range_for_node(node),
        arguments,
        metadata: BTreeMap::new(),
    });
    id
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_data_source(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    spans: &[SymbolSpan],
    node: Node<'_>,
    kind: DataSourceKind,
    name: impl Into<String>,
    endpoint: Option<String>,
    metadata: BTreeMap<String, String>,
) -> String {
    let name = name.into();
    let id = stable_fact_id(
        "data-source",
        [
            file.id.as_str(),
            &name,
            &node.start_byte().to_string(),
            &node.end_byte().to_string(),
        ],
    );
    facts.data_sources.push(DataSourceFact {
        id: id.clone(),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(spans, node),
        kind,
        name: Some(name),
        endpoint,
        range: range_for_node(node),
        metadata,
    });
    id
}

pub(crate) fn add_sink(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    spans: &[SymbolSpan],
    node: Node<'_>,
    kind: SinkKind,
    name: impl Into<String>,
    metadata: BTreeMap<String, String>,
) -> String {
    let name = name.into();
    let id = stable_fact_id(
        "sink",
        [
            file.id.as_str(),
            &name,
            &node.start_byte().to_string(),
            &node.end_byte().to_string(),
        ],
    );
    facts.sinks.push(SinkFact {
        id: id.clone(),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(spans, node),
        kind,
        name: Some(name),
        range: range_for_node(node),
        metadata,
    });
    id
}

pub(crate) fn add_sanitizer(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    spans: &[SymbolSpan],
    node: Node<'_>,
    kind: SanitizerKind,
    name: impl Into<String>,
    metadata: BTreeMap<String, String>,
) -> String {
    let name = name.into();
    let id = stable_fact_id(
        "sanitizer",
        [
            file.id.as_str(),
            &name,
            &node.start_byte().to_string(),
            &node.end_byte().to_string(),
        ],
    );
    facts.sanitizers.push(SanitizerFact {
        id: id.clone(),
        file_id: Some(file.id.clone()),
        symbol_id: containing_symbol_id(spans, node),
        kind,
        name: Some(name),
        range: range_for_node(node),
        metadata,
    });
    id
}

pub(crate) fn add_taint_edge(
    facts: &mut AnalysisFacts,
    source_id: String,
    target_id: String,
    kind: TaintEdgeKind,
    sanitizer_id: Option<String>,
) {
    let id = stable_fact_id(
        "taint-edge",
        [
            source_id.as_str(),
            target_id.as_str(),
            sanitizer_id.as_deref().unwrap_or(""),
        ],
    );
    facts.taint_edges.push(TaintEdge {
        id,
        source_id,
        target_id,
        sanitizer_id,
        kind,
        confidence: Confidence::Low,
        metadata: BTreeMap::new(),
    });
}

pub(crate) fn add_local_taint_edges(facts: &mut AnalysisFacts) {
    let sources: Vec<_> = facts
        .data_sources
        .iter()
        .filter_map(|source| {
            source
                .symbol_id
                .as_ref()
                .map(|symbol_id| (source.id.clone(), symbol_id.clone()))
        })
        .collect();
    let sinks: Vec<_> = facts
        .sinks
        .iter()
        .filter_map(|sink| {
            sink.symbol_id
                .as_ref()
                .map(|symbol_id| (sink.id.clone(), symbol_id.clone()))
        })
        .collect();
    let sanitizers: Vec<_> = facts
        .sanitizers
        .iter()
        .filter_map(|sanitizer| {
            sanitizer
                .symbol_id
                .as_ref()
                .map(|symbol_id| (sanitizer.id.clone(), symbol_id.clone()))
        })
        .collect();

    for (source_id, source_symbol_id) in &sources {
        for (sink_id, sink_symbol_id) in &sinks {
            if source_symbol_id == sink_symbol_id {
                add_taint_edge(
                    facts,
                    source_id.clone(),
                    sink_id.clone(),
                    TaintEdgeKind::SourceToSink,
                    None,
                );
            }
        }
        for (sanitizer_id, sanitizer_symbol_id) in &sanitizers {
            if source_symbol_id == sanitizer_symbol_id {
                add_taint_edge(
                    facts,
                    source_id.clone(),
                    sanitizer_id.clone(),
                    TaintEdgeKind::Sanitized,
                    Some(sanitizer_id.clone()),
                );
            }
        }
    }
}

pub(crate) fn argument_texts(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(arguments) = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))
        .or_else(|| child_of_kind(node, "argument_list"))
        .or_else(|| child_of_kind(node, "arguments"))
    else {
        return Vec::new();
    };
    direct_named_children(arguments)
        .into_iter()
        .map(|child| node_text(child, source).to_string())
        .filter(|text| !text.is_empty())
        .collect()
}

pub(crate) fn child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    let found = node
        .children(&mut cursor)
        .find(|child| child.kind() == kind);
    found
}

pub(crate) fn metadata_entry(key: &str, value: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(key.to_string(), value.to_string());
    metadata
}
