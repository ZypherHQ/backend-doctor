use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, DataSourceFact, DataSourceKind, ImportFact,
    ImportKind, RouteFact, SinkFact, SinkKind, SourceFileFact, SourcePosition, SourceRange,
    SymbolFact, SymbolKind,
};
use std::collections::{BTreeMap, BTreeSet};

use super::common::{add_local_taint_edges, facts_with_source, normalize_path, strip_quotes};
use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct CppAdapter;

impl SourceAdapter for CppAdapter {
    fn id(&self) -> &'static str {
        "cpp-scan-tier-c"
    }

    fn language(&self) -> &'static str {
        "C++"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        matches!(
            source_file.language.to_ascii_lowercase().as_str(),
            "cpp" | "c++" | "cc" | "cxx" | "crow" | "drogon" | "cpp-httplib"
        )
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let mut facts = facts_with_source(&input);
        let line_index = LineIndex::new(input.contents);
        let functions = collect_functions(input.source_file, input.contents, &line_index);
        let classes = collect_classes(input.source_file, input.contents, &line_index);
        let calls = collect_calls(input.source_file, input.contents, &line_index, &functions);

        collect_includes(&mut facts, input.source_file, input.contents, &line_index);
        facts.symbols.extend(classes);
        facts
            .symbols
            .extend(functions.iter().map(FunctionSpan::to_symbol));
        facts.calls.extend(calls.iter().map(CallSite::to_fact));

        collect_cpp_routes_and_flows(
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
            metadata: metadata("adapter", "cpp"),
        });
    }
}

fn collect_cpp_routes_and_flows(
    facts: &mut AnalysisFacts,
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
    functions: &[FunctionSpan],
    calls: &[CallSite],
) {
    let httplib_receivers = collect_httplib_receiver_declarations(source, functions);
    let mut request_symbols = BTreeSet::new();

    for route in crow_routes(source, line_index) {
        add_route(
            facts,
            file,
            containing_symbol(functions, route.start, route.end),
            &route.method,
            &route.path,
            "Crow",
            Some(route.range),
            metadata("detector", "CROW_ROUTE"),
        );
    }

    for call in calls {
        let final_name = final_call_segment(&call.callee_name);
        let drogon_routes = drogon_routes_from_call(call, final_name);
        if !drogon_routes.is_empty() {
            for route in drogon_routes {
                let handler_symbol = route
                    .handler
                    .as_ref()
                    .and_then(|handler| symbol_for_name(functions, handler));
                add_route(
                    facts,
                    file,
                    handler_symbol.or_else(|| call.caller_symbol_id.clone()),
                    &route.method,
                    &route.path,
                    "Drogon",
                    Some(call.range.clone()),
                    route.metadata,
                );
            }
        } else if let Some(route) = httplib_route_from_call(call, final_name, &httplib_receivers) {
            let handler_symbol = call
                .arguments
                .get(1)
                .and_then(|handler| symbol_for_name(functions, handler));
            add_route(
                facts,
                file,
                handler_symbol.or_else(|| call.caller_symbol_id.clone()),
                route.method,
                &route.path,
                "cpp-httplib",
                Some(call.range.clone()),
                metadata("callee", &call.callee_name),
            );
        }

        if is_request_source_call(final_name, &call.callee_name) {
            add_data_source(
                facts,
                file,
                call.caller_symbol_id.clone(),
                DataSourceKind::Request,
                final_name,
                None,
                Some(call.range.clone()),
                metadata("adapter", "cpp"),
            );
            if let Some(symbol_id) = &call.caller_symbol_id {
                request_symbols.insert(symbol_id.clone());
            }
        }

        if is_database_source_call(final_name, &call.callee_name) {
            add_data_source(
                facts,
                file,
                call.caller_symbol_id.clone(),
                DataSourceKind::Database,
                final_name,
                None,
                Some(call.range.clone()),
                metadata("adapter", "cpp"),
            );
        }
    }

    for source_match in request_field_sources(source, line_index, functions) {
        add_data_source(
            facts,
            file,
            source_match.symbol_id.clone(),
            DataSourceKind::Request,
            &source_match.name,
            None,
            Some(source_match.range),
            metadata("detector", "request-field"),
        );
        if let Some(symbol_id) = source_match.symbol_id {
            request_symbols.insert(symbol_id);
        }
    }

    for call in calls {
        let final_name = final_call_segment(&call.callee_name);
        let Some(kind) = sink_kind_for_cpp_call(final_name, &call.callee_name) else {
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
        if is_sql || request_scoped || kind == SinkKind::HttpResponse {
            add_sink(
                facts,
                file,
                call.caller_symbol_id.clone(),
                kind,
                final_name,
                Some(call.range.clone()),
                metadata("adapter", "cpp"),
            );
        }
    }

    for line_sink in request_scoped_line_sinks(source, line_index, functions) {
        add_sink(
            facts,
            file,
            line_sink.symbol_id,
            line_sink.kind,
            &line_sink.name,
            Some(line_sink.range),
            metadata("detector", "request-scoped-line-sink"),
        );
    }
}

#[derive(Clone, Debug)]
struct ParsedRoute {
    method: String,
    path: String,
    start: usize,
    end: usize,
    range: SourceRange,
}

fn crow_routes(source: &str, line_index: &LineIndex<'_>) -> Vec<ParsedRoute> {
    let calls = raw_macro_calls(source, "CROW_ROUTE");
    let mut routes = Vec::new();
    for call in calls {
        let Some(path) = call.arguments.get(1).and_then(|arg| string_literal(arg)) else {
            continue;
        };
        let methods = crow_methods_after(source, call.end);
        let methods = if methods.is_empty() {
            vec!["GET".to_string()]
        } else {
            methods
        };
        for method in methods {
            routes.push(ParsedRoute {
                method,
                path: normalize_path(&path),
                start: call.start,
                end: call.end,
                range: line_index.offset_range(call.start, call.end),
            });
        }
    }
    routes
}

fn crow_methods_after(source: &str, offset: usize) -> Vec<String> {
    let window = &source[offset..source.len().min(offset + 300)];
    let Some(methods_pos) = window.find(".methods") else {
        return Vec::new();
    };
    let Some(open_rel) = window[methods_pos..].find('(') else {
        return Vec::new();
    };
    let open = offset + methods_pos + open_rel;
    let Some(close) = find_matching_paren(source, open) else {
        return Vec::new();
    };
    split_top_level(&source[open + 1..close])
        .into_iter()
        .filter_map(|arg| http_method_from_token(&arg))
        .collect()
}

fn drogon_routes_from_call(call: &CallSite, final_name: &str) -> Vec<DrogonRoute> {
    match final_name {
        "METHOD_ADD" | "ADD_METHOD_TO" | "ADD_METHOD_VIA_REGEX" => {
            let Some(path) = call.arguments.get(1).and_then(|arg| string_literal(arg)) else {
                return Vec::new();
            };
            let methods = drogon_methods(call.arguments.get(2..).unwrap_or(&[]));
            drogon_routes(
                call.arguments.first().map(|arg| arg.trim().to_string()),
                &path,
                methods,
                final_name,
                final_name == "ADD_METHOD_VIA_REGEX",
            )
        }
        "PATH_ADD" => {
            let Some(path) = call.arguments.first().and_then(|arg| string_literal(arg)) else {
                return Vec::new();
            };
            let methods = drogon_methods(call.arguments.get(1..).unwrap_or(&[]));
            drogon_routes(None, &path, methods, final_name, false)
        }
        "registerHandler" => {
            let Some(path) = call.arguments.first().and_then(|arg| string_literal(arg)) else {
                return Vec::new();
            };
            let methods = drogon_methods(call.arguments.get(2..).unwrap_or(&[]));
            drogon_routes(
                call.arguments.get(1).map(|arg| arg.trim().to_string()),
                &path,
                methods,
                "registerHandler",
                false,
            )
        }
        _ => Vec::new(),
    }
}

fn drogon_routes(
    handler: Option<String>,
    path: &str,
    methods: Vec<String>,
    callee: &str,
    regex: bool,
) -> Vec<DrogonRoute> {
    let methods = if methods.is_empty() {
        vec!["ANY".to_string()]
    } else {
        methods
    };
    methods
        .into_iter()
        .map(|method| {
            let mut metadata = metadata("callee", callee);
            if regex {
                metadata.insert("routeKind".to_string(), "regex".to_string());
            }
            DrogonRoute {
                handler: handler.clone(),
                method,
                path: normalize_path(path),
                metadata,
            }
        })
        .collect()
}

#[derive(Clone, Debug)]
struct DrogonRoute {
    handler: Option<String>,
    method: String,
    path: String,
    metadata: BTreeMap<String, String>,
}

fn drogon_methods(arguments: &[String]) -> Vec<String> {
    let mut methods = Vec::new();
    for arg in arguments {
        for token in arg.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_') {
            let method = match token {
                "Get" => "GET",
                "Post" => "POST",
                "Put" => "PUT",
                "Delete" => "DELETE",
                "Patch" => "PATCH",
                "Options" => "OPTIONS",
                "Head" => "HEAD",
                _ => continue,
            };
            methods.push(method.to_string());
        }
    }
    methods
}

fn httplib_route_from_call(
    call: &CallSite,
    final_name: &str,
    receiver_declarations: &[HttplibReceiverDeclaration],
) -> Option<HttplibRoute> {
    let receiver = httplib_call_receiver(&call.callee_name)?;
    if httplib_receiver_kind_at_call(receiver_declarations, receiver, call)
        != Some(HttplibReceiverKind::Server)
    {
        return None;
    }
    let method = match final_name {
        "Get" => "GET",
        "Post" => "POST",
        "Put" => "PUT",
        "Delete" => "DELETE",
        "Patch" => "PATCH",
        "Options" => "OPTIONS",
        _ => return None,
    };
    let path = call.arguments.first().and_then(|arg| string_literal(arg))?;
    Some(HttplibRoute {
        method,
        path: normalize_path(&path),
    })
}

#[derive(Clone, Debug)]
struct HttplibRoute {
    method: &'static str,
    path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttplibReceiverKind {
    Server,
    Client,
}

#[derive(Clone, Debug)]
struct HttplibReceiverDeclaration {
    name: String,
    kind: HttplibReceiverKind,
    start: usize,
    scope_start: usize,
    scope_end: usize,
}

#[derive(Clone, Copy, Debug)]
struct LexicalScope {
    start: usize,
    end: usize,
}

fn collect_httplib_receiver_declarations(
    source: &str,
    functions: &[FunctionSpan],
) -> Vec<HttplibReceiverDeclaration> {
    let masked = mask_comments_keep_strings(source);
    let scopes = collect_lexical_scopes(&masked);
    let parameter_lists = collect_parenthetical_scopes(&masked);
    let mut declarations = Vec::new();
    let mut line_start = 0;

    for line in masked.split_inclusive('\n') {
        for (needle, kind) in [
            ("httplib::Server", HttplibReceiverKind::Server),
            ("httplib::SSLServer", HttplibReceiverKind::Server),
            ("httplib::Client", HttplibReceiverKind::Client),
            ("httplib::SSLClient", HttplibReceiverKind::Client),
        ] {
            let mut search_start = 0;
            while let Some(found) = line[search_start..].find(needle) {
                let type_start_in_line = search_start + found;
                let declaration_start = line_start + type_start_in_line;
                let tail = &line[type_start_in_line + needle.len()..];
                if let Some(name) = httplib_receiver_name_after_type(tail) {
                    let scope = httplib_declaration_scope(
                        declaration_start,
                        source.len(),
                        &masked,
                        &scopes,
                        &parameter_lists,
                        functions,
                    );
                    declarations.push(HttplibReceiverDeclaration {
                        name,
                        kind,
                        start: declaration_start,
                        scope_start: scope.start,
                        scope_end: scope.end,
                    });
                }
                search_start = type_start_in_line + needle.len();
            }
        }
        line_start += line.len();
    }

    declarations.sort_by_key(|declaration| declaration.start);
    declarations
}

fn httplib_receiver_name_after_type(tail: &str) -> Option<String> {
    let tail = tail.trim_start_matches([' ', '\t', '*', '&']);
    let name: String = tail
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

fn httplib_declaration_scope(
    declaration_start: usize,
    source_len: usize,
    source: &str,
    scopes: &[LexicalScope],
    parameter_lists: &[LexicalScope],
    functions: &[FunctionSpan],
) -> LexicalScope {
    if let Some(scope) =
        httplib_parameter_body_scope(declaration_start, source, scopes, parameter_lists)
    {
        return scope;
    }

    scopes
        .iter()
        .filter(|scope| scope.start <= declaration_start && declaration_start <= scope.end)
        .min_by_key(|scope| scope.end.saturating_sub(scope.start))
        .copied()
        .or_else(|| {
            functions
                .iter()
                .filter(|function| {
                    function.start <= declaration_start && declaration_start <= function.end
                })
                .min_by_key(|function| function.end.saturating_sub(function.start))
                .map(|function| LexicalScope {
                    start: function.start,
                    end: function.end,
                })
        })
        .unwrap_or(LexicalScope {
            start: 0,
            end: source_len,
        })
}

fn httplib_parameter_body_scope(
    declaration_start: usize,
    source: &str,
    scopes: &[LexicalScope],
    parameter_lists: &[LexicalScope],
) -> Option<LexicalScope> {
    let parameter_list = parameter_lists
        .iter()
        .filter(|parameter_list| {
            parameter_list.start < declaration_start && declaration_start < parameter_list.end
        })
        .min_by_key(|parameter_list| parameter_list.end.saturating_sub(parameter_list.start))?;
    let body_start = body_start_after_parameter_list(source, parameter_list.end)?;
    scopes
        .iter()
        .find(|scope| scope.start == body_start)
        .copied()
}

fn body_start_after_parameter_list(source: &str, close_paren: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut idx = close_paren + 1;
    let mut quote = None;
    let mut escaped = false;
    let mut paren_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut angle_depth = 0i32;

    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            idx += 1;
            continue;
        }

        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' => paren_depth += 1,
            ')' if paren_depth > 0 => paren_depth -= 1,
            '[' => bracket_depth += 1,
            ']' if bracket_depth > 0 => bracket_depth -= 1,
            '<' => angle_depth += 1,
            '>' if angle_depth > 0 => angle_depth -= 1,
            '{' if paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 => return Some(idx),
            ';' | '=' | ')' if paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 => {
                return None;
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

fn httplib_receiver_kind_at_call(
    declarations: &[HttplibReceiverDeclaration],
    receiver: &str,
    call: &CallSite,
) -> Option<HttplibReceiverKind> {
    declarations
        .iter()
        .filter(|declaration| {
            declaration.name == receiver
                && declaration.start <= call.start
                && declaration.scope_start <= call.start
                && call.end <= declaration.scope_end
        })
        .max_by_key(|declaration| (declaration.scope_start, declaration.start))
        .map(|declaration| declaration.kind)
}

fn collect_lexical_scopes(source: &str) -> Vec<LexicalScope> {
    collect_delimited_scopes(source, b'{', b'}')
}

fn collect_parenthetical_scopes(source: &str) -> Vec<LexicalScope> {
    collect_delimited_scopes(source, b'(', b')')
}

fn collect_delimited_scopes(source: &str, open_byte: u8, close_byte: u8) -> Vec<LexicalScope> {
    let bytes = source.as_bytes();
    let mut scopes = Vec::new();
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;

    for (idx, byte) in bytes.iter().enumerate() {
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
            stack.push(idx);
        } else if *byte == close_byte {
            if let Some(start) = stack.pop() {
                scopes.push(LexicalScope { start, end: idx });
            }
        }
    }

    scopes
}

fn httplib_call_receiver(callee: &str) -> Option<&str> {
    let end = callee
        .rfind("->")
        .or_else(|| callee.rfind('.'))
        .unwrap_or(usize::MAX);
    if end == usize::MAX {
        return None;
    }
    let receiver = callee[..end].trim();
    (!receiver.is_empty()).then_some(receiver)
}

fn is_request_source_call(final_name: &str, callee: &str) -> bool {
    matches!(
        final_name,
        "get_header_value"
            | "get_body_params"
            | "getParameter"
            | "getOptionalParameter"
            | "getHeader"
            | "getCookie"
            | "getJsonObject"
            | "get_param_value"
            | "get_param_values"
    ) || callee.contains("url_params.get")
        || callee.contains("req.get")
}

fn is_database_source_call(final_name: &str, callee: &str) -> bool {
    matches!(
        final_name,
        "sqlite3_open" | "sqlite3_open_v2" | "PQconnectdb" | "mysql_real_connect"
    ) || callee.contains("newPgClient")
        || callee.contains("getDbClient")
}

fn sink_kind_for_cpp_call(final_name: &str, callee: &str) -> Option<SinkKind> {
    if matches!(
        final_name,
        "sqlite3_exec"
            | "sqlite3_prepare"
            | "sqlite3_prepare_v2"
            | "PQexec"
            | "PQexecParams"
            | "mysql_query"
            | "mysql_real_query"
            | "executeSql"
            | "execSqlSync"
            | "execSqlAsync"
    ) || callee.contains(".execSql")
        || callee.contains(".executeSql")
    {
        return Some(SinkKind::SqlQuery);
    }
    if matches!(final_name, "system" | "popen") || callee.contains("std::system") {
        return Some(SinkKind::Command);
    }
    if matches!(final_name, "fopen" | "open" | "write" | "send" | "sendto") {
        return if matches!(final_name, "send" | "sendto") {
            Some(SinkKind::NetworkRequest)
        } else {
            Some(SinkKind::FileWrite)
        };
    }
    if matches!(
        final_name,
        "newHttpJsonResponse" | "newHttpResponse" | "set_content" | "set_redirect"
    ) || callee.contains("crow::response")
    {
        return if final_name == "set_redirect" {
            Some(SinkKind::Redirect)
        } else {
            Some(SinkKind::HttpResponse)
        };
    }
    None
}

#[derive(Clone, Debug)]
struct RequestFieldSource {
    name: String,
    symbol_id: Option<String>,
    range: SourceRange,
}

#[derive(Clone, Debug)]
struct LineSink {
    name: String,
    kind: SinkKind,
    symbol_id: Option<String>,
    range: SourceRange,
}

fn request_field_sources(
    source: &str,
    line_index: &LineIndex<'_>,
    functions: &[FunctionSpan],
) -> Vec<RequestFieldSource> {
    let mut sources = Vec::new();
    for (line_idx, line) in source.lines().enumerate() {
        for needle in [
            "req.body",
            "request.body",
            "hm->body",
            "req.url",
            "req.matches",
        ] {
            if let Some(column) = line.find(needle) {
                let start = line_index.line_start(line_idx) + column;
                let end = start + needle.len();
                sources.push(RequestFieldSource {
                    name: needle.to_string(),
                    symbol_id: containing_symbol(functions, start, end),
                    range: line_index.offset_range(start, end),
                });
            }
        }
    }
    sources
}

fn request_scoped_line_sinks(
    source: &str,
    line_index: &LineIndex<'_>,
    functions: &[FunctionSpan],
) -> Vec<LineSink> {
    let mut sinks = Vec::new();
    for (line_idx, line) in source.lines().enumerate() {
        let Some((name, kind)) = line_sink_for_text(line) else {
            continue;
        };
        if !argument_mentions_request(line) {
            continue;
        }
        let start = line_index.line_start(line_idx);
        let end = start + line.len();
        sinks.push(LineSink {
            name,
            kind,
            symbol_id: containing_symbol(functions, start, end),
            range: line_index.offset_range(start, end),
        });
    }
    sinks
}

fn line_sink_for_text(line: &str) -> Option<(String, SinkKind)> {
    if line.contains("system(") || line.contains("std::system(") || line.contains("popen(") {
        return Some(("system".to_string(), SinkKind::Command));
    }
    if line.contains("set_content(") {
        return Some(("set_content".to_string(), SinkKind::HttpResponse));
    }
    if line.contains("std::ofstream") || line.contains("ofstream ") {
        return Some(("std::ofstream".to_string(), SinkKind::FileWrite));
    }
    if line.contains("std::filesystem::copy")
        || line.contains("std::filesystem::remove")
        || line.contains("std::filesystem::rename")
    {
        return Some(("std::filesystem".to_string(), SinkKind::FileWrite));
    }
    None
}

#[derive(Clone, Debug)]
struct RawMacroCall {
    start: usize,
    end: usize,
    arguments: Vec<String>,
}

fn raw_macro_calls(source: &str, name: &str) -> Vec<RawMacroCall> {
    let masked = mask_comments_keep_strings(source);
    let mut calls = Vec::new();
    let mut offset = 0;
    while let Some(found) = masked[offset..].find(name) {
        let start = offset + found;
        let after_name = start + name.len();
        if !masked[after_name..].trim_start().starts_with('(') {
            offset = after_name;
            continue;
        }
        let open = after_name + masked[after_name..].find('(').unwrap_or(0);
        let Some(close) = find_matching_paren(&masked, open) else {
            offset = after_name;
            continue;
        };
        calls.push(RawMacroCall {
            start,
            end: close + 1,
            arguments: split_top_level(&source[open + 1..close]),
        });
        offset = close + 1;
    }
    calls
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
            kind: if self.name.contains("::") {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            },
            range: self.range.clone(),
            signature: Some(self.signature.clone()),
            visibility: visibility_from_signature(&self.signature),
            parent_symbol_id: None,
            metadata: metadata("adapter", "cpp"),
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
    start: usize,
    end: usize,
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
            metadata: metadata("adapter", "cpp"),
        }
    }
}

fn collect_classes(
    file: &SourceFileFact,
    source: &str,
    line_index: &LineIndex<'_>,
) -> Vec<SymbolFact> {
    let mut symbols = Vec::new();
    for (line_idx, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        let keyword = if trimmed.starts_with("class ") {
            Some(("class", SymbolKind::Class))
        } else if trimmed.starts_with("struct ") {
            Some(("struct", SymbolKind::Struct))
        } else {
            None
        };
        let Some((keyword, kind)) = keyword else {
            continue;
        };
        let name = trimmed[keyword.len()..]
            .trim_start()
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
            .next()
            .unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let id = stable_fact_id("symbol", [file.id.as_str(), name, &line_idx.to_string()]);
        symbols.push(SymbolFact {
            id,
            file_id: file.id.clone(),
            name: name.to_string(),
            kind,
            range: line_index.line_range(line_idx),
            signature: Some(trimmed.to_string()),
            visibility: None,
            parent_symbol_id: None,
            metadata: metadata("adapter", "cpp"),
        });
    }
    symbols
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
            arguments: split_top_level(&source[i + 1..end]),
            start: name_start,
            end: end + 1,
            range: line_index.offset_range(name_start, end + 1),
        });
        i = end + 1;
    }
    calls
}

fn function_name_from_signature(signature: &str) -> Option<String> {
    if signature.len() > 700 || signature.contains("=>") {
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
    Some(name.to_string())
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
    let wanted = name
        .trim()
        .trim_start_matches('&')
        .trim()
        .trim_matches(|ch: char| ch == '(' || ch == ')' || ch == '*' || ch.is_whitespace());
    let final_wanted = wanted.rsplit("::").next().unwrap_or(wanted);
    functions
        .iter()
        .find(|function| {
            function.name == wanted
                || function.name.ends_with(&format!("::{final_wanted}"))
                || function.name == final_wanted
        })
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

fn http_method_from_token(token: &str) -> Option<String> {
    let trimmed = token.trim();
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
        if trimmed.contains(method) {
            return Some(method.to_string());
        }
    }
    for (needle, method) in [
        ("Get", "GET"),
        ("Post", "POST"),
        ("Put", "PUT"),
        ("Delete", "DELETE"),
        ("Patch", "PATCH"),
        ("Options", "OPTIONS"),
        ("Head", "HEAD"),
    ] {
        if trimmed.contains(needle) {
            return Some(method.to_string());
        }
    }
    None
}

fn argument_mentions_request(argument: &str) -> bool {
    argument.contains("req")
        || argument.contains("request")
        || argument.contains("body")
        || argument.contains("url_params")
        || argument.contains("getParameter")
        || argument.contains("get_param")
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
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '.' | '>' | '-' | '~') {
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
        "if" | "for" | "while" | "switch" | "return" | "sizeof" | "new"
    )
}

fn final_call_segment(name: &str) -> &str {
    name.rsplit(['.', ':', '>', '-'])
        .find(|part| !part.is_empty())
        .unwrap_or(name)
}

fn string_literal(text: &str) -> Option<String> {
    string_literals(text).into_iter().next()
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

fn visibility_from_signature(signature: &str) -> Option<String> {
    let trimmed = signature.trim_start();
    for visibility in ["public:", "private:", "protected:", "static"] {
        if trimmed.starts_with(visibility) {
            return Some(visibility.trim_end_matches(':').to_string());
        }
    }
    None
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

fn metadata(key: &str, value: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(key.to_string(), value.to_string());
    metadata
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

    fn analyze_cpp(source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new("src/server.cpp", "C++");
        file.service_id = Some("api".to_string());
        CppAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("cpp analysis succeeds")
    }

    fn cpp_httplib_routes(facts: &AnalysisFacts) -> Vec<(&str, &str)> {
        let mut routes = facts
            .routes
            .iter()
            .filter(|route| route.framework.as_deref() == Some("cpp-httplib"))
            .map(|route| (route.method.as_str(), route.path.as_str()))
            .collect::<Vec<_>>();
        routes.sort_unstable();
        routes
    }

    #[test]
    fn extracts_crow_routes_sources_and_sql_sinks() {
        let source = r#"
#include "crow.h"

void routes(crow::SimpleApp& app) {
  CROW_ROUTE(app, "/users/<int>")
    .methods(crow::HTTPMethod::Get, "PATCH"_method)
    ([](const crow::request& req, int id) {
      auto token = req.get_header_value("Authorization");
      auto q = req.url_params.get("q");
      sqlite3_exec(db, q, nullptr, nullptr, nullptr);
      return crow::response(200, token);
    });
}
"#;
        let facts = analyze_cpp(source);

        assert!(facts.routes.iter().any(|route| {
            route.framework.as_deref() == Some("Crow")
                && route.path == "/users/<int>"
                && route.method == "GET"
        }));
        assert!(facts.routes.iter().any(|route| route.method == "PATCH"));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("get_header_value")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("sqlite3_exec")
                && sink.kind == SinkKind::SqlQuery));
    }

    #[test]
    fn extracts_drogon_controller_and_registered_routes() {
        let source = r#"
#include <drogon/HttpController.h>
using namespace drogon;

class User : public drogon::HttpController<User> {
public:
  METHOD_LIST_BEGIN
  METHOD_ADD(User::login, "/token?userId={1}", Post);
  ADD_METHOD_TO(User::info, "/api/users/{1}", Get);
  METHOD_LIST_END
};

void login(const HttpRequestPtr &req) {
  auto user = req->getParameter("userId");
  app().registerHandler("/api/ping", [](const HttpRequestPtr &req, auto &&cb) {
    cb(HttpResponse::newHttpJsonResponse(Json::Value()));
  }, {Get});
}
"#;
        let facts = analyze_cpp(source);

        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Drogon")
                && route.path == "/token?userId={1}"
                && route.method == "POST"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.framework.as_deref() == Some("Drogon")
                && route.path == "/api/users/{1}"
                && route.method == "GET"));
        assert!(facts
            .routes
            .iter()
            .any(|route| route.path == "/api/ping" && route.method == "GET"));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("getParameter")));
    }

    #[test]
    fn extracts_cpp_httplib_routes_and_request_scoped_sinks() {
        let source = r#"
#include "httplib.h"

void mount() {
  httplib::Server server;
  server.Post("/upload", [](const httplib::Request& req, httplib::Response& res) {
    std::ofstream out(req.body);
    system(req.body.c_str());
    res.set_content(req.body, "text/plain");
  });

  httplib::Client cli("localhost", 8080);
  cli.Get("/users");
  cli.Post("/client-post", "body", "text/plain");
}
"#;
        let facts = analyze_cpp(source);

        assert!(facts.routes.iter().any(|route| {
            route.framework.as_deref() == Some("cpp-httplib")
                && route.path == "/upload"
                && route.method == "POST"
        }));
        assert!(!facts.routes.iter().any(|route| {
            route.framework.as_deref() == Some("cpp-httplib")
                && matches!(route.path.as_str(), "/users" | "/client-post")
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("req.body")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("system") && sink.kind == SinkKind::Command));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("set_content")
                && sink.kind == SinkKind::HttpResponse));
    }

    #[test]
    fn cpp_httplib_global_server_receiver_emits_route() {
        let source = r#"
#include "httplib.h"

httplib::Server app;

void mount_global() {
  app.Get("/global", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });
}
"#;
        let facts = analyze_cpp(source);

        assert_eq!(cpp_httplib_routes(&facts), vec![("GET", "/global")]);
    }

    #[test]
    fn cpp_httplib_ssl_server_receiver_emits_route() {
        let source = r#"
#include "httplib.h"

void mount_tls() {
  httplib::SSLServer app("cert.pem", "key.pem");
  app.Get("/secure", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });
}
"#;
        let facts = analyze_cpp(source);

        assert_eq!(cpp_httplib_routes(&facts), vec![("GET", "/secure")]);
    }

    #[test]
    fn cpp_httplib_ssl_client_shadowing_suppresses_outer_server_route() {
        let source = r#"
#include "httplib.h"

void mount_routes() {
  httplib::Server app;
  {
    httplib::SSLClient app("localhost", 443);
    app.Get("/ssl-client");
  }
}
"#;
        let facts = analyze_cpp(source);

        assert!(cpp_httplib_routes(&facts).is_empty());
        assert!(!facts.routes.iter().any(|route| route.path == "/ssl-client"));
    }

    #[test]
    fn cpp_httplib_lambda_client_parameter_does_not_shadow_outer_server_after_lambda() {
        let source = r#"
#include "httplib.h"

void mount_routes() {
  httplib::Server app;
  auto fetch = [](httplib::Client app) {
    app.Get("/lambda-client");
  };

  app.Get("/outer-after", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });
  app.Post("/outer-post", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });
}
"#;
        let facts = analyze_cpp(source);

        assert_eq!(
            cpp_httplib_routes(&facts),
            vec![("GET", "/outer-after"), ("POST", "/outer-post")]
        );
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/lambda-client"));
    }

    #[test]
    fn cpp_httplib_lambda_server_parameter_shadows_outer_client_only_inside_lambda() {
        let source = r#"
#include "httplib.h"

void mount_routes() {
  httplib::Client app("localhost", 8080);
  app.Get("/outer-client");

  auto install = [](httplib::Server app) {
    app.Get("/nested-server", [](const httplib::Request& req, httplib::Response& res) {
      res.set_content("ok", "text/plain");
    });
  };

  app.Post("/outer-client-post", "body", "text/plain");
}
"#;
        let facts = analyze_cpp(source);

        assert_eq!(cpp_httplib_routes(&facts), vec![("GET", "/nested-server")]);
        assert!(!facts.routes.iter().any(|route| {
            matches!(route.path.as_str(), "/outer-client" | "/outer-client-post")
        }));
    }

    #[test]
    fn cpp_httplib_receiver_shadowing_uses_current_declaration() {
        let source = r#"
#include "httplib.h"

void mount_routes() {
  httplib::Server app;
  app.Get("/server", [](const httplib::Request& req, httplib::Response& res) {
    res.set_content("ok", "text/plain");
  });
}

void fetch_remote() {
  httplib::Client app("localhost", 8080);
  app.Get("/client");
  app.Post("/client-post", "body", "text/plain");
}

void shadow_in_block() {
  httplib::Server scoped;
  {
    httplib::Client scoped("localhost", 8080);
    scoped.Get("/shadow-client");
  }
}
"#;
        let facts = analyze_cpp(source);
        let httplib_routes = facts
            .routes
            .iter()
            .filter(|route| route.framework.as_deref() == Some("cpp-httplib"))
            .collect::<Vec<_>>();

        assert_eq!(httplib_routes.len(), 1);
        assert_eq!(httplib_routes[0].path, "/server");
        assert_eq!(httplib_routes[0].method, "GET");
    }
}
