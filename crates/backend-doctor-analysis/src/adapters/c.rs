use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, DataSourceFact, DataSourceKind, ImportFact,
    ImportKind, RouteFact, SinkFact, SinkKind, SourceFileFact, SourcePosition, SourceRange,
    SymbolFact, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::common::{add_local_taint_edges, facts_with_source, normalize_path, strip_quotes};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct CAdapter;

impl SourceAdapter for CAdapter {
    fn id(&self) -> &'static str {
        "c-scan-tier-c"
    }

    fn language(&self) -> &'static str {
        "C"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        matches!(
            source_file.language.to_ascii_lowercase().as_str(),
            "c" | "libmicrohttpd" | "civetweb" | "mongoose"
        )
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let mut facts = facts_with_source(&input);
        let line_index = LineIndex::new(input.contents);
        let functions = collect_functions(input.source_file, input.contents, &line_index);
        let calls = collect_calls(input.source_file, input.contents, &line_index, &functions);

        facts
            .symbols
            .extend(functions.iter().map(FunctionSpan::to_symbol));
        collect_includes(&mut facts, input.source_file, input.contents, &line_index);
        facts.calls.extend(calls.iter().map(CallSite::to_fact));

        collect_c_routes_and_flows(
            &mut facts,
            input.source_file,
            input.contents,
            &line_index,
            &functions,
            &calls,
        );
        add_local_taint_edges(&mut facts);
        Ok(facts)
    }
}

fn collect_includes(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
) {
    for (line_idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#include") {
            continue;
        }
        let Some(module) = include_module(trimmed) else {
            continue;
        };
        let id = stable_fact_id("import", [file.id.as_str(), &module, &line_idx.to_string()]);
        facts.imports.push(ImportFact {
            id,
            file_id: Some(file.id.clone()),
            module,
            alias: None,
            imported_symbols: Vec::new(),
            kind: ImportKind::File,
            range: line_index.line_range(line_idx),
            metadata: metadata("adapter", "c"),
        });
    }
}

fn collect_c_routes_and_flows(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
    functions: &[FunctionSpan],
    calls: &[CallSite],
) {
    let mhd_handlers = registered_mhd_handlers(calls);
    let mut request_symbols = BTreeSet::new();

    for handler in &mhd_handlers {
        if let Some(function) = functions.iter().find(|function| &function.name == handler) {
            add_route(
                facts,
                file,
                Some(function.id.clone()),
                "ANY",
                "/*",
                "libmicrohttpd",
                function.range.clone(),
                metadata("handler", handler),
            );
            for name in mhd_request_parameters(&function.signature) {
                add_data_source(
                    facts,
                    file,
                    Some(function.id.clone()),
                    DataSourceKind::Request,
                    &name,
                    None,
                    function.range.clone(),
                    metadata("framework", "libmicrohttpd"),
                );
            }
            request_symbols.insert(function.id.clone());
        }
    }

    for call in calls {
        let final_name = final_call_segment(&call.callee_name);
        if final_name == "mg_set_request_handler" {
            if let Some(path) = call.arguments.get(1).and_then(|arg| string_literal(arg)) {
                let handler_symbol = call
                    .arguments
                    .get(2)
                    .and_then(|handler| symbol_for_name(functions, handler));
                add_route(
                    facts,
                    file,
                    handler_symbol,
                    "ANY",
                    &path,
                    "CivetWeb",
                    Some(call.range.clone()),
                    metadata("callee", "mg_set_request_handler"),
                );
            }
        } else if final_name == "mg_http_listen" {
            let handler_symbol = call
                .arguments
                .get(2)
                .and_then(|handler| symbol_for_name(functions, handler));
            let mut route_metadata = metadata("callee", "mg_http_listen");
            if let Some(endpoint) = call.arguments.get(1).and_then(|arg| string_literal(arg)) {
                route_metadata.insert("listener".to_string(), endpoint);
            }
            add_route(
                facts,
                file,
                handler_symbol,
                "ANY",
                "/*",
                "Mongoose",
                Some(call.range.clone()),
                route_metadata,
            );
        } else if let Some(path) = mongoose_route_match(call) {
            add_route(
                facts,
                file,
                call.caller_symbol_id.clone(),
                "ANY",
                &path,
                "Mongoose",
                Some(call.range.clone()),
                metadata("callee", final_name),
            );
        }

        if is_request_source_call(final_name) {
            add_data_source(
                facts,
                file,
                call.caller_symbol_id.clone(),
                DataSourceKind::Request,
                final_name,
                None,
                Some(call.range.clone()),
                metadata("adapter", "c"),
            );
            if let Some(symbol_id) = &call.caller_symbol_id {
                request_symbols.insert(symbol_id.clone());
            }
        }

        if is_database_source_call(final_name) {
            add_data_source(
                facts,
                file,
                call.caller_symbol_id.clone(),
                DataSourceKind::Database,
                final_name,
                None,
                Some(call.range.clone()),
                metadata("adapter", "c"),
            );
        }
    }

    for line_match in literal_uri_checks(source, line_index) {
        add_route(
            facts,
            file,
            containing_symbol(functions, line_match.start, line_match.end),
            "ANY",
            &line_match.path,
            "Mongoose",
            Some(line_match.range),
            metadata("detector", "literal-uri-check"),
        );
    }

    for call in calls {
        let final_name = final_call_segment(&call.callee_name);
        let sink_kind = sink_kind_for_c_call(final_name);
        let Some(kind) = sink_kind else {
            continue;
        };
        let is_sql = kind == SinkKind::SqlQuery;
        let request_scoped = call
            .caller_symbol_id
            .as_ref()
            .is_some_and(|symbol_id| request_symbols.contains(symbol_id))
            || call
                .arguments
                .iter()
                .any(|arg| argument_mentions_request(arg));
        if is_sql || request_scoped {
            add_sink(
                facts,
                file,
                call.caller_symbol_id.clone(),
                kind,
                final_name,
                Some(call.range.clone()),
                metadata("adapter", "c"),
            );
        }
    }
}

fn registered_mhd_handlers(calls: &[CallSite]) -> BTreeSet<String> {
    calls
        .iter()
        .filter(|call| final_call_segment(&call.callee_name) == "MHD_start_daemon")
        .filter_map(|call| call.arguments.get(4))
        .map(|handler| trim_casts_and_address(handler))
        .filter(|handler| !handler.is_empty())
        .collect()
}

fn mhd_request_parameters(signature: &str) -> Vec<String> {
    let Some(args) = between_outer(signature, '(', ')') else {
        return Vec::new();
    };
    split_top_level(args)
        .into_iter()
        .filter_map(|argument| {
            let name = last_identifier(&argument)?;
            if matches!(name.as_str(), "url" | "method" | "upload_data") {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

fn is_request_source_call(name: &str) -> bool {
    matches!(
        name,
        "MHD_lookup_connection_value"
            | "MHD_get_connection_values"
            | "MHD_create_post_processor"
            | "MHD_post_process"
            | "mg_get_request_info"
            | "mg_get_var"
            | "mg_get_header"
            | "mg_get_cookie"
            | "mg_read"
            | "mg_http_get_header"
            | "mg_http_get_var"
            | "mg_http_creds"
    )
}

fn is_database_source_call(name: &str) -> bool {
    matches!(
        name,
        "sqlite3_open" | "sqlite3_open_v2" | "PQconnectdb" | "mysql_real_connect" | "mysql_init"
    )
}

fn sink_kind_for_c_call(name: &str) -> Option<SinkKind> {
    if matches!(
        name,
        "sqlite3_exec"
            | "sqlite3_prepare"
            | "sqlite3_prepare_v2"
            | "sqlite3_prepare_v3"
            | "PQexec"
            | "PQexecParams"
            | "mysql_query"
            | "mysql_real_query"
            | "SQLExecDirect"
    ) {
        return Some(SinkKind::SqlQuery);
    }
    if matches!(
        name,
        "system" | "popen" | "execl" | "execle" | "execlp" | "execv" | "execve" | "execvp"
    ) {
        return Some(SinkKind::Command);
    }
    if matches!(name, "fopen" | "open" | "creat" | "write" | "fwrite") {
        return Some(SinkKind::FileWrite);
    }
    if matches!(name, "send" | "sendto" | "connect" | "curl_easy_perform") {
        return Some(SinkKind::NetworkRequest);
    }
    if matches!(
        name,
        "MHD_create_response_from_buffer" | "mg_http_reply" | "mg_send" | "mg_write"
    ) {
        return Some(SinkKind::HttpResponse);
    }
    None
}

fn mongoose_route_match(call: &CallSite) -> Option<String> {
    let name = final_call_segment(&call.callee_name);
    if name == "mg_http_match_uri" {
        return call
            .arguments
            .get(1)
            .and_then(|arg| string_literal(arg))
            .map(|path| normalize_path(&path));
    }
    if name == "mg_match" {
        let mentions_uri = call
            .arguments
            .first()
            .is_some_and(|arg| arg.contains("uri") || arg.contains("hm->"));
        if mentions_uri {
            return call
                .arguments
                .iter()
                .find_map(|arg| mg_str_literal(arg).or_else(|| string_literal(arg)))
                .map(|path| normalize_path(&path));
        }
    }
    None
}

fn literal_uri_checks(source: &str, line_index: &LineIndex<'_>) -> Vec<LiteralRouteMatch> {
    let mut matches = Vec::new();
    for (line_idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        let looks_like_uri_compare = (trimmed.contains("strcmp") || trimmed.contains("strncmp"))
            && (trimmed.contains("hm->uri")
                || trimmed.contains(".uri")
                || trimmed.contains("request_info->local_uri"));
        if !looks_like_uri_compare {
            continue;
        }
        for literal in string_literals(trimmed) {
            if literal.starts_with('/') {
                let start = line_index.line_start(line_idx);
                let end = start + line.len();
                matches.push(LiteralRouteMatch {
                    path: normalize_path(&literal),
                    start,
                    end,
                    range: line_index
                        .line_range(line_idx)
                        .unwrap_or_else(|| line_index.offset_range(start, end)),
                });
            }
        }
    }
    matches
}

#[derive(Clone, Debug)]
struct LiteralRouteMatch {
    path: String,
    start: usize,
    end: usize,
    range: SourceRange,
}

#[derive(Clone, Debug)]
struct FunctionSpan {
    id: String,
    name: String,
    signature: String,
    start: usize,
    end: usize,
    range: Option<SourceRange>,
    file_id: String,
}

impl FunctionSpan {
    fn to_symbol(&self) -> SymbolFact {
        SymbolFact {
            id: self.id.clone(),
            file_id: self.file_id.clone(),
            name: self.name.clone(),
            kind: SymbolKind::Function,
            range: self.range.clone(),
            signature: Some(self.signature.clone()),
            visibility: if self.signature.trim_start().starts_with("static") {
                Some("static".to_string())
            } else {
                None
            },
            parent_symbol_id: None,
            metadata: metadata("adapter", "c"),
        }
    }
}

#[derive(Clone, Debug)]
struct CallSite {
    id: String,
    file_id: String,
    caller_symbol_id: Option<String>,
    callee_name: String,
    arguments: Vec<String>,
    range: SourceRange,
}

impl CallSite {
    fn to_fact(&self) -> CallFact {
        CallFact {
            id: self.id.clone(),
            file_id: Some(self.file_id.clone()),
            caller_symbol_id: self.caller_symbol_id.clone(),
            callee_symbol_id: None,
            callee_name: self.callee_name.clone(),
            range: Some(self.range.clone()),
            arguments: self.arguments.clone(),
            metadata: metadata("adapter", "c"),
        }
    }
}

fn collect_functions(
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
) -> Vec<FunctionSpan> {
    let masked = mask_comments_keep_strings(source);
    let mut functions = Vec::new();
    let bytes = masked.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let signature_start = previous_boundary(&masked, i);
        let signature = source[signature_start..i].trim();
        if let Some(name) = function_name_from_signature(signature) {
            let end = find_matching_brace(&masked, i).unwrap_or(i + 1);
            let id = stable_fact_id(
                "symbol",
                [
                    file.id.as_str(),
                    &name,
                    &signature_start.to_string(),
                    &end.to_string(),
                ],
            );
            functions.push(FunctionSpan {
                id,
                name,
                signature: compact_signature(signature),
                start: signature_start,
                end,
                range: Some(line_index.offset_range(signature_start, end)),
                file_id: file.id.clone(),
            });
            i = end;
        } else {
            i += 1;
        }
    }
    functions
}

fn function_name_from_signature(signature: &str) -> Option<String> {
    if signature.len() > 500 || signature.contains('=') {
        return None;
    }
    let open = signature.rfind('(')?;
    let before = signature[..open].trim_end();
    let name = before
        .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':'))
        .find(|part| !part.is_empty())?;
    let final_name = name.rsplit("::").next().unwrap_or(name);
    if matches!(
        final_name,
        "if" | "for" | "while" | "switch" | "return" | "sizeof" | "CROW_ROUTE"
    ) || final_name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    Some(final_name.to_string())
}

fn collect_calls(
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
    functions: &[FunctionSpan],
) -> Vec<CallSite> {
    let masked = mask_comments_keep_strings(source);
    let bytes = masked.as_bytes();
    let mut calls = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'(' {
            i += 1;
            continue;
        }
        let Some(name_start) = call_name_start(&masked, i) else {
            i += 1;
            continue;
        };
        let callee = masked[name_start..i].trim();
        if callee.is_empty() || is_non_call_keyword(callee) {
            i += 1;
            continue;
        }
        let Some(end) = find_matching_paren(&masked, i) else {
            i += 1;
            continue;
        };
        let args = split_top_level(&source[i + 1..end]);
        let id = stable_fact_id(
            "call",
            [
                file.id.as_str(),
                callee,
                &name_start.to_string(),
                &end.to_string(),
            ],
        );
        calls.push(CallSite {
            id,
            file_id: file.id.clone(),
            caller_symbol_id: containing_symbol(functions, name_start, end),
            callee_name: callee.to_string(),
            arguments: args,
            range: line_index.offset_range(name_start, end + 1),
        });
        i = end + 1;
    }
    calls
}

fn call_name_start(source: &str, open_paren: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if open_paren == 0 {
        return None;
    }
    let mut start = open_paren;
    while start > 0 && bytes[start - 1].is_ascii_whitespace() {
        start -= 1;
    }
    let end = start;
    while start > 0 {
        let ch = bytes[start - 1] as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '.' | '>' | '-') {
            start -= 1;
        } else {
            break;
        }
    }
    if start == end {
        None
    } else {
        Some(start)
    }
}

fn is_non_call_keyword(name: &str) -> bool {
    matches!(
        final_call_segment(name),
        "if" | "for" | "while" | "switch" | "return" | "sizeof"
    )
}

#[allow(clippy::too_many_arguments)]
fn add_route(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbol_id: Option<String>,
    method: &str,
    path: &str,
    framework: &str,
    range: Option<SourceRange>,
    metadata: BTreeMap<String, String>,
) {
    let normalized = normalize_path(path);
    let id = stable_fact_id("route", [file.id.as_str(), method, &normalized, framework]);
    facts.routes.push(RouteFact {
        id,
        file_id: Some(file.id.clone()),
        symbol_id,
        service_id: file.service_id.clone(),
        method: method.to_string(),
        path: normalized,
        framework: Some(framework.to_string()),
        range,
        metadata,
    });
}

#[allow(clippy::too_many_arguments)]
fn add_data_source(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbol_id: Option<String>,
    kind: DataSourceKind,
    name: &str,
    endpoint: Option<String>,
    range: Option<SourceRange>,
    metadata: BTreeMap<String, String>,
) {
    let id = stable_fact_id(
        "data-source",
        [
            file.id.as_str(),
            name,
            &facts.data_sources.len().to_string(),
        ],
    );
    facts.data_sources.push(DataSourceFact {
        id,
        file_id: Some(file.id.clone()),
        symbol_id,
        kind,
        name: Some(name.to_string()),
        endpoint,
        range,
        metadata,
    });
}

fn add_sink(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    symbol_id: Option<String>,
    kind: SinkKind,
    name: &str,
    range: Option<SourceRange>,
    metadata: BTreeMap<String, String>,
) {
    let id = stable_fact_id(
        "sink",
        [file.id.as_str(), name, &facts.sinks.len().to_string()],
    );
    facts.sinks.push(SinkFact {
        id,
        file_id: Some(file.id.clone()),
        symbol_id,
        kind,
        name: Some(name.to_string()),
        range,
        metadata,
    });
}

fn symbol_for_name(functions: &[FunctionSpan], name: &str) -> Option<String> {
    let wanted = trim_casts_and_address(name);
    functions
        .iter()
        .find(|function| function.name == wanted || function.name.ends_with(&format!("::{wanted}")))
        .map(|function| function.id.clone())
}

fn containing_symbol(functions: &[FunctionSpan], start: usize, end: usize) -> Option<String> {
    functions
        .iter()
        .filter(|function| function.start <= start && function.end >= end)
        .max_by_key(|function| function.start)
        .map(|function| function.id.clone())
}

fn include_module(line: &str) -> Option<String> {
    let rest = line.strip_prefix("#include")?.trim();
    if rest.starts_with('<') && rest.ends_with('>') {
        return Some(rest[1..rest.len() - 1].to_string());
    }
    if rest.starts_with('"') && rest.ends_with('"') {
        return Some(strip_quotes(rest));
    }
    None
}

fn metadata(key: &str, value: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(key.to_string(), value.to_string());
    metadata
}

fn final_call_segment(name: &str) -> &str {
    name.rsplit(['.', ':', '>', '-'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn argument_mentions_request(argument: &str) -> bool {
    matches!(
        argument.trim(),
        "url" | "method" | "upload_data" | "hm" | "req" | "request"
    ) || argument.contains("hm->")
        || argument.contains("req->")
        || argument.contains("request_info")
        || argument.contains("upload_data")
}

fn trim_casts_and_address(text: &str) -> String {
    text.trim()
        .trim_start_matches('&')
        .trim()
        .trim_start_matches("(MHD_AccessHandlerCallback)")
        .trim()
        .trim_matches(|ch: char| ch == '(' || ch == ')' || ch == '*' || ch.is_whitespace())
        .to_string()
}

fn last_identifier(text: &str) -> Option<String> {
    let mut chars = text
        .trim()
        .chars()
        .rev()
        .skip_while(|ch| !is_ident_char(*ch));
    let mut ident = String::new();
    for ch in &mut chars {
        if is_ident_char(ch) {
            ident.push(ch);
        } else if !ident.is_empty() {
            break;
        }
    }
    if ident.is_empty() {
        None
    } else {
        Some(ident.chars().rev().collect())
    }
}

fn string_literal(text: &str) -> Option<String> {
    string_literals(text).into_iter().next()
}

fn mg_str_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if !trimmed.starts_with("mg_str") {
        return None;
    }
    between_outer(trimmed, '(', ')').and_then(string_literal)
}

fn string_literals(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i += 1;
        let mut escaped = false;
        while i < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[i] == b'\\' {
                escaped = true;
            } else if bytes[i] == b'"' {
                values.push(text[start..i].to_string());
                break;
            }
            i += 1;
        }
        i += 1;
    }
    values
}

fn split_top_level(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                let part = text[start..idx].trim();
                if !part.is_empty() {
                    parts.push(part.to_string());
                }
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    let part = text[start..].trim();
    if !part.is_empty() {
        parts.push(part.to_string());
    }
    parts
}

fn between_outer(text: &str, open: char, close: char) -> Option<&str> {
    let start = text.find(open)?;
    let end = text.rfind(close)?;
    if end > start {
        Some(&text[start + open.len_utf8()..end])
    } else {
        None
    }
}

fn previous_boundary(source: &str, index: usize) -> usize {
    source[..index]
        .rfind([';', '{', '}'])
        .map_or(0, |pos| pos + 1)
}

fn compact_signature(signature: &str) -> String {
    signature
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn mask_comments_keep_strings(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    let mut quote = None;
    let mut escaped = false;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if let Some(q) = quote {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            out.push(ch);
            i += 1;
        } else if ch == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                out.push(' ');
                i += 1;
            }
        } else if ch == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                out.push(if bytes[i] == b'\n' { '\n' } else { ' ' });
                i += 1;
            }
            if i + 1 < bytes.len() {
                out.push(' ');
                out.push(' ');
                i += 2;
            }
        } else {
            out.push(ch);
            i += 1;
        }
    }
    out
}

fn find_matching_paren(source: &str, open: usize) -> Option<usize> {
    find_matching_delimiter(source, open, b'(', b')')
}

fn find_matching_brace(source: &str, open: usize) -> Option<usize> {
    find_matching_delimiter(source, open, b'{', b'}')
}

fn find_matching_delimiter(
    source: &str,
    open: usize,
    open_byte: u8,
    close_byte: u8,
) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut quote = None;
    let mut escaped = false;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        let ch = *byte as char;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
        } else if *byte == open_byte {
            depth += 1;
        } else if *byte == close_byte {
            depth -= 1;
            if depth == 0 {
                return Some(idx);
            }
        }
    }
    None
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

#[derive(Clone, Debug)]
struct LineIndex<'a> {
    source: &'a str,
    starts: Vec<usize>,
}

impl<'a> LineIndex<'a> {
    fn new(source: &'a str) -> Self {
        let mut starts = vec![0];
        for (idx, ch) in source.char_indices() {
            if ch == '\n' {
                starts.push(idx + 1);
            }
        }
        Self { source, starts }
    }

    fn line_start(&self, line_idx: usize) -> usize {
        self.starts
            .get(line_idx)
            .copied()
            .unwrap_or(self.source.len())
    }

    fn line_range(&self, line_idx: usize) -> Option<SourceRange> {
        let start = self.starts.get(line_idx).copied()?;
        let end = self
            .starts
            .get(line_idx + 1)
            .copied()
            .unwrap_or(self.source.len());
        Some(self.offset_range(start, end))
    }

    fn offset_range(&self, start: usize, end: usize) -> SourceRange {
        SourceRange::new(self.position(start), self.position(end))
    }

    fn position(&self, offset: usize) -> SourcePosition {
        let idx = match self.starts.binary_search(&offset) {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        let line_start = self.starts.get(idx).copied().unwrap_or(0);
        SourcePosition::new(
            u32::try_from(idx + 1).unwrap_or(u32::MAX),
            u32::try_from(offset.saturating_sub(line_start) + 1).unwrap_or(u32::MAX),
        )
        .with_byte_offset(u32::try_from(offset).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::ProjectGraph;
    use std::path::PathBuf;

    fn analyze_c(source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/server.c", "C");
        file.service_id = Some("api".to_string());
        CAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("c analysis succeeds")
    }

    #[test]
    fn extracts_civetweb_routes_sources_sinks_and_taint() {
        let source = r#"
#include "civetweb.h"
#include <sqlite3.h>

static int users(struct mg_connection *conn, void *cbdata) {
    const struct mg_request_info *ri = mg_get_request_info(conn);
    sqlite3_exec(db, ri->query_string, 0, 0, 0);
    system(ri->query_string);
    return 200;
}

void mount(struct mg_context *ctx) {
    mg_set_request_handler(ctx, "/api/users", users, NULL);
}
"#;
        let facts = analyze_c(source);

        assert!(facts
            .imports
            .iter()
            .any(|import| import.module == "civetweb.h"));
        assert!(facts.routes.iter().any(|route| {
            route.framework.as_deref() == Some("CivetWeb") && route.path == "/api/users"
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("mg_get_request_info")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("sqlite3_exec")
                && sink.kind == SinkKind::SqlQuery));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("system") && sink.kind == SinkKind::Command));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn extracts_libmicrohttpd_callback_sources() {
        let source = r#"
#include <microhttpd.h>

static int answer(void *cls, struct MHD_Connection *connection, const char *url,
                  const char *method, const char *version, const char *upload_data,
                  size_t *upload_data_size, void **con_cls) {
    const char *token = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "token");
    return MHD_create_response_from_buffer(2, (void *) token, MHD_RESPMEM_MUST_COPY) != 0;
}

void start(void) {
    MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, 8080, NULL, NULL, answer, NULL, MHD_OPTION_END);
}
"#;
        let facts = analyze_c(source);

        assert!(facts.routes.iter().any(|route| {
            route.framework.as_deref() == Some("libmicrohttpd") && route.path == "/*"
        }));
        for name in [
            "url",
            "method",
            "upload_data",
            "MHD_lookup_connection_value",
        ] {
            assert!(
                facts
                    .data_sources
                    .iter()
                    .any(|source| source.name.as_deref() == Some(name)),
                "missing source {name}: {:?}",
                facts.data_sources
            );
        }
    }

    #[test]
    fn extracts_mongoose_literal_route_matches() {
        let source = r#"
#include "mongoose.h"

static void fn(struct mg_connection *c, int ev, void *ev_data) {
  struct mg_http_message *hm = (struct mg_http_message *) ev_data;
  if (mg_match(hm->uri, mg_str("/api/time"), NULL)) {
    char q[64];
    mg_http_get_var(&hm->query, "q", q, sizeof(q));
    mg_http_reply(c, 200, "", q);
  } else if (strcmp(hm->uri.buf, "/api/status") == 0) {
    send(fd, hm->body.buf, hm->body.len, 0);
  }
}

int main(void) {
  mg_http_listen(&mgr, "http://0.0.0.0:8000", fn, NULL);
}
"#;
        let facts = analyze_c(source);

        assert!(facts.routes.iter().any(
            |route| route.framework.as_deref() == Some("Mongoose") && route.path == "/api/time"
        ));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Mongoose")
                && route.path == "/api/status"));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("mg_http_get_var")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("send")
                && sink.kind == SinkKind::NetworkRequest));
    }
}
