use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, Confidence, DataSourceFact, DataSourceKind,
    ImportFact, ImportKind, RouteFact, SanitizerFact, SanitizerKind, SinkFact, SinkKind,
    SourceFileFact, SourcePosition, SourceRange, SymbolFact, SymbolKind, TaintEdge, TaintEdgeKind,
};
use std::collections::{BTreeMap, BTreeSet};

use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct ElixirAdapter;

impl SourceAdapter for ElixirAdapter {
    fn id(&self) -> &'static str {
        "elixir-line-scanner-tier-c"
    }

    fn language(&self) -> &'static str {
        "Elixir"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        matches!(
            source_file.language.to_ascii_lowercase().as_str(),
            "elixir" | "phoenix"
        )
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let mut analyzer = ElixirAnalyzer::new(input);
        analyzer.analyze();
        Ok(analyzer.facts)
    }
}

struct ElixirAnalyzer<'a> {
    input: AdapterInput<'a>,
    facts: AnalysisFacts,
    lines: Vec<LineInfo<'a>>,
    blocks: Vec<ElixirBlock>,
    module_stack: Vec<String>,
    symbols_by_name: BTreeMap<String, String>,
    emitted_imports: BTreeSet<String>,
}

#[derive(Clone)]
struct LineInfo<'a> {
    number: u32,
    start_byte: usize,
    end_byte: usize,
    text: &'a str,
}

#[derive(Clone)]
struct ElixirBlock {
    kind: ElixirBlockKind,
    symbol_id: Option<String>,
}

#[derive(Clone)]
enum ElixirBlockKind {
    Module(String),
    Def,
    Scope {
        prefix: String,
        alias_prefix: Option<String>,
    },
    Pipeline,
    Other,
}

struct ElixirRoute {
    method: &'static str,
    path: String,
    framework: &'static str,
    target: Option<String>,
    provenance: String,
}

impl<'a> ElixirAnalyzer<'a> {
    fn new(input: AdapterInput<'a>) -> Self {
        let mut facts = AnalysisFacts::empty();
        facts.source_files.push(
            input
                .source_file
                .clone()
                .with_content(input.contents.as_bytes()),
        );
        let lines = source_lines(input.contents);
        Self {
            input,
            facts,
            lines,
            blocks: Vec::new(),
            module_stack: Vec::new(),
            symbols_by_name: BTreeMap::new(),
            emitted_imports: BTreeSet::new(),
        }
    }

    fn analyze(&mut self) {
        for line in self.lines.clone() {
            let trimmed = line.text.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            self.collect_import(&line, trimmed);

            if trimmed == "end" {
                self.pop_block();
                continue;
            }

            if let Some(module) = parse_defmodule(trimmed) {
                let id = self.add_symbol(&line, &module, SymbolKind::Module, None, Some(trimmed));
                self.module_stack.push(module.clone());
                self.blocks.push(ElixirBlock {
                    kind: ElixirBlockKind::Module(module),
                    symbol_id: Some(id),
                });
                continue;
            }

            if let Some((name, signature)) = parse_def(trimmed) {
                let qualified = self
                    .current_module()
                    .map_or_else(|| name.clone(), |module| format!("{module}.{name}"));
                let parent = self.current_module_symbol_id();
                let id = self.add_symbol(
                    &line,
                    &qualified,
                    SymbolKind::Function,
                    parent,
                    Some(trimmed),
                );
                self.blocks.push(ElixirBlock {
                    kind: ElixirBlockKind::Def,
                    symbol_id: Some(id),
                });
                self.collect_signature_sources(&line, &signature);
                self.collect_sanitizers(&line, trimmed);
                self.collect_data_and_sink_facts(&line, trimmed);
                continue;
            }

            if let Some(name) = parse_pipeline(trimmed) {
                self.blocks.push(ElixirBlock {
                    kind: ElixirBlockKind::Pipeline,
                    symbol_id: None,
                });
                let mut meta = metadata("adapter", "elixir");
                meta.insert("framework".to_string(), "Phoenix".to_string());
                meta.insert("source".to_string(), "pipeline".to_string());
                self.add_sanitizer(
                    &line,
                    if contains_auth_hint(&name) {
                        SanitizerKind::Authentication
                    } else {
                        SanitizerKind::Unknown
                    },
                    &format!("pipeline:{name}"),
                    meta,
                );
                continue;
            }

            if let Some((prefix, alias_prefix)) = parse_scope(trimmed) {
                self.blocks.push(ElixirBlock {
                    kind: ElixirBlockKind::Scope {
                        prefix,
                        alias_prefix,
                    },
                    symbol_id: None,
                });
                continue;
            }

            self.collect_pipe_through(&line, trimmed);
            self.collect_sanitizers(&line, trimmed);

            if let Some(resource) = parse_resource(trimmed) {
                self.emit_resource_routes(&line, &resource);
            }

            if let Some(route) = self.parse_route_line(&line, trimmed) {
                self.emit_route(&line, route);
            } else if opens_block(trimmed) {
                self.blocks.push(ElixirBlock {
                    kind: ElixirBlockKind::Other,
                    symbol_id: self.current_symbol_id(),
                });
            }

            self.collect_request_sources(&line, trimmed);
            self.collect_data_and_sink_facts(&line, trimmed);
        }
        self.add_local_taint_edges();
    }

    fn pop_block(&mut self) {
        if let Some(block) = self.blocks.pop() {
            if let ElixirBlockKind::Module(name) = block.kind {
                if self.module_stack.last() == Some(&name) {
                    self.module_stack.pop();
                }
            }
        }
    }

    fn collect_import(&mut self, line: &LineInfo<'_>, text: &str) {
        let module = text
            .strip_prefix("alias ")
            .or_else(|| text.strip_prefix("import "))
            .or_else(|| text.strip_prefix("require "))
            .map(|rest| {
                rest.split([',', '{'])
                    .next()
                    .unwrap_or(rest)
                    .trim()
                    .to_string()
            })
            .filter(|module| !module.is_empty());
        let Some(module) = module else {
            return;
        };
        if !self.emitted_imports.insert(module.clone()) {
            return;
        }
        self.facts.imports.push(ImportFact {
            id: stable_fact_id("import", [&self.input.source_file.id, &module, "elixir"]),
            file_id: Some(self.input.source_file.id.clone()),
            module,
            alias: None,
            imported_symbols: Vec::new(),
            kind: ImportKind::Module,
            range: range_for_line(line),
            metadata: metadata("adapter", "elixir"),
        });
    }

    fn collect_signature_sources(&mut self, line: &LineInfo<'_>, signature: &str) {
        for name in split_args(signature) {
            let binding = match name.as_str() {
                "conn" => "conn",
                "params" => "params",
                _ => continue,
            };
            let mut meta = metadata("adapter", "elixir");
            meta.insert("binding".to_string(), binding.to_string());
            self.add_data_source(line, DataSourceKind::Request, &name, None, meta);
        }
    }

    fn collect_request_sources(&mut self, line: &LineInfo<'_>, text: &str) {
        let sources = [
            ("conn.params", "params"),
            ("params[", "params"),
            ("Plug.Conn.read_body", "body"),
            ("read_body(conn", "body"),
            ("Plug.Conn.get_req_header", "header"),
            ("get_req_header(conn", "header"),
            ("fetch_query_params", "query"),
            ("conn.query_params", "query"),
            ("get_session(conn", "session"),
            ("conn.cookies", "cookies"),
        ];
        for (needle, binding) in sources {
            if text.contains(needle) {
                let mut meta = metadata("adapter", "elixir");
                meta.insert("binding".to_string(), binding.to_string());
                self.add_data_source(line, DataSourceKind::Request, needle, None, meta);
            }
        }
    }

    fn collect_pipe_through(&mut self, line: &LineInfo<'_>, text: &str) {
        let Some(rest) = text.strip_prefix("pipe_through ") else {
            return;
        };
        for pipeline in atoms_in(rest) {
            let kind = if contains_auth_hint(&pipeline) {
                SanitizerKind::Authentication
            } else {
                SanitizerKind::Unknown
            };
            let mut meta = metadata("adapter", "elixir");
            meta.insert("framework".to_string(), "Phoenix".to_string());
            meta.insert("source".to_string(), "pipe_through".to_string());
            self.add_sanitizer(line, kind, &format!("pipeline:{pipeline}"), meta);
        }
    }

    fn collect_sanitizers(&mut self, line: &LineInfo<'_>, text: &str) {
        if text.contains("protect_from_forgery") {
            let mut meta = metadata("adapter", "elixir");
            meta.insert("framework".to_string(), "Phoenix".to_string());
            self.add_sanitizer(
                line,
                SanitizerKind::Validation,
                "protect_from_forgery",
                meta,
            );
        }
        if text.contains("put_secure_browser_headers") {
            let mut meta = metadata("adapter", "elixir");
            meta.insert("framework".to_string(), "Phoenix".to_string());
            self.add_sanitizer(
                line,
                SanitizerKind::Encoding,
                "put_secure_browser_headers",
                meta,
            );
        }
        if text.starts_with("plug ") && contains_auth_hint(text) {
            let mut meta = metadata("adapter", "elixir");
            meta.insert("framework".to_string(), "Phoenix".to_string());
            self.add_sanitizer(line, SanitizerKind::Authentication, "auth_plug", meta);
        }
        if contains_any(
            text,
            &[
                "changeset(",
                "validate_required(",
                "validate_format(",
                "validate_length(",
                "cast(",
            ],
        ) {
            self.add_sanitizer(
                line,
                SanitizerKind::Validation,
                "ecto_changeset_validation",
                metadata("adapter", "elixir"),
            );
        }
    }

    fn collect_data_and_sink_facts(&mut self, line: &LineInfo<'_>, text: &str) {
        for callee in elixir_callees(text) {
            self.add_call(line, &callee);
            let final_name = callee.rsplit('.').next().unwrap_or(callee.as_str());
            if is_repo_read(&callee, final_name) {
                self.add_data_source(
                    line,
                    DataSourceKind::Database,
                    &callee,
                    None,
                    metadata("adapter", "elixir"),
                );
            } else if is_repo_write(&callee, final_name) {
                self.add_sink(
                    line,
                    SinkKind::SqlQuery,
                    &callee,
                    metadata("adapter", "elixir"),
                );
            } else if is_context_persistence_call(&callee, final_name) {
                let mut meta = metadata("adapter", "elixir");
                meta.insert("category".to_string(), "context_persistence".to_string());
                self.add_sink(line, SinkKind::SqlQuery, &callee, meta);
            }
        }
        if text.contains("Ecto.Query.from") || text.trim_start().starts_with("from(") {
            self.add_data_source(
                line,
                DataSourceKind::Database,
                "Ecto.Query.from",
                None,
                metadata("adapter", "elixir"),
            );
        }
    }

    fn parse_route_line(&self, line: &LineInfo<'_>, text: &str) -> Option<ElixirRoute> {
        let (method, rest, framework) = if let Some(verb) = phoenix_http_verb(text) {
            (verb, text[verb.len()..].trim_start(), "Phoenix")
        } else if let Some(rest) = text.strip_prefix("live ") {
            ("GET", rest.trim_start(), "Phoenix LiveView")
        } else if let Some(rest) = text.strip_prefix("forward ") {
            ("ANY", rest.trim_start(), "Phoenix")
        } else {
            return None;
        };
        let path = first_quoted(rest)?;
        let full_path = join_paths(&self.current_route_prefix(), &path);
        let target = route_target(rest, self.current_alias_prefix().as_deref());
        Some(ElixirRoute {
            method,
            path: full_path,
            framework,
            target,
            provenance: format!("{}:{}", self.input.source_file.path.display(), line.number),
        })
    }

    fn emit_resource_routes(&mut self, line: &LineInfo<'_>, resource: &ResourceRoute) {
        let base = join_paths(&self.current_route_prefix(), &resource.path);
        let controller = qualify_phoenix_controller(
            &resource.controller,
            self.current_alias_prefix().as_deref(),
        );
        let routes = [
            ("GET", base.clone(), "index"),
            ("GET", join_paths(&base, "new"), "new"),
            ("POST", base.clone(), "create"),
            ("GET", join_paths(&base, ":id"), "show"),
            ("GET", join_paths(&base, ":id/edit"), "edit"),
            ("PATCH", join_paths(&base, ":id"), "update"),
            ("PUT", join_paths(&base, ":id"), "update"),
            ("DELETE", join_paths(&base, ":id"), "delete"),
        ];
        for (method, path, action) in routes {
            if !resource.includes_action(action) {
                continue;
            }
            self.emit_route(
                line,
                ElixirRoute {
                    method,
                    path,
                    framework: "Phoenix",
                    target: Some(format!("{controller}.{action}")),
                    provenance: "resource_route".to_string(),
                },
            );
        }
    }

    fn emit_route(&mut self, line: &LineInfo<'_>, route: ElixirRoute) {
        let symbol_id = route
            .target
            .as_deref()
            .and_then(|target| self.symbols_by_name.get(target).cloned());
        let mut meta = metadata("adapter", "elixir");
        meta.insert("provenance".to_string(), route.provenance);
        if let Some(target) = &route.target {
            meta.insert("target".to_string(), target.clone());
        }
        self.facts.routes.push(RouteFact {
            id: stable_fact_id(
                "route",
                [
                    &self.input.source_file.id,
                    route.method,
                    &route.path,
                    route.framework,
                    &line.start_byte.to_string(),
                ],
            ),
            file_id: Some(self.input.source_file.id.clone()),
            symbol_id,
            service_id: self.input.source_file.service_id.clone(),
            method: route.method.to_string(),
            path: route.path,
            framework: Some(route.framework.to_string()),
            range: range_for_line(line),
            metadata: meta,
        });
    }

    fn add_symbol(
        &mut self,
        line: &LineInfo<'_>,
        name: &str,
        kind: SymbolKind,
        parent_symbol_id: Option<String>,
        signature: Option<&str>,
    ) -> String {
        let id = stable_fact_id(
            "symbol",
            [
                &self.input.source_file.id,
                name,
                &line.number.to_string(),
                &line.start_byte.to_string(),
            ],
        );
        self.facts.symbols.push(SymbolFact {
            id: id.clone(),
            file_id: self.input.source_file.id.clone(),
            name: name.to_string(),
            kind,
            range: range_for_line(line),
            signature: signature.map(str::to_string),
            visibility: None,
            parent_symbol_id,
            metadata: metadata("adapter", "elixir"),
        });
        self.symbols_by_name.insert(name.to_string(), id.clone());
        id
    }

    fn add_call(&mut self, line: &LineInfo<'_>, callee: &str) {
        self.facts.calls.push(CallFact {
            id: stable_fact_id(
                "call",
                [
                    &self.input.source_file.id,
                    callee,
                    &line.number.to_string(),
                    &line.start_byte.to_string(),
                ],
            ),
            file_id: Some(self.input.source_file.id.clone()),
            caller_symbol_id: self.current_symbol_id(),
            callee_symbol_id: None,
            callee_name: callee.to_string(),
            range: range_for_line(line),
            arguments: Vec::new(),
            metadata: metadata("adapter", "elixir"),
        });
    }

    fn add_data_source(
        &mut self,
        line: &LineInfo<'_>,
        kind: DataSourceKind,
        name: &str,
        endpoint: Option<String>,
        meta: BTreeMap<String, String>,
    ) -> String {
        let id = stable_fact_id(
            "data-source",
            [
                &self.input.source_file.id,
                name,
                &line.number.to_string(),
                &line.start_byte.to_string(),
            ],
        );
        self.facts.data_sources.push(DataSourceFact {
            id: id.clone(),
            file_id: Some(self.input.source_file.id.clone()),
            symbol_id: self.current_symbol_id(),
            kind,
            name: Some(name.to_string()),
            endpoint,
            range: range_for_line(line),
            metadata: meta,
        });
        id
    }

    fn add_sink(
        &mut self,
        line: &LineInfo<'_>,
        kind: SinkKind,
        name: &str,
        meta: BTreeMap<String, String>,
    ) -> String {
        let id = stable_fact_id(
            "sink",
            [
                &self.input.source_file.id,
                name,
                &line.number.to_string(),
                &line.start_byte.to_string(),
            ],
        );
        self.facts.sinks.push(SinkFact {
            id: id.clone(),
            file_id: Some(self.input.source_file.id.clone()),
            symbol_id: self.current_symbol_id(),
            kind,
            name: Some(name.to_string()),
            range: range_for_line(line),
            metadata: meta,
        });
        id
    }

    fn add_sanitizer(
        &mut self,
        line: &LineInfo<'_>,
        kind: SanitizerKind,
        name: &str,
        meta: BTreeMap<String, String>,
    ) -> String {
        let id = stable_fact_id(
            "sanitizer",
            [
                &self.input.source_file.id,
                name,
                &line.number.to_string(),
                &line.start_byte.to_string(),
            ],
        );
        self.facts.sanitizers.push(SanitizerFact {
            id: id.clone(),
            file_id: Some(self.input.source_file.id.clone()),
            symbol_id: self.current_symbol_id(),
            kind,
            name: Some(name.to_string()),
            range: range_for_line(line),
            metadata: meta,
        });
        id
    }

    fn add_local_taint_edges(&mut self) {
        for source in &self.facts.data_sources {
            let Some(source_symbol_id) = source.symbol_id.as_ref() else {
                continue;
            };
            for sink in &self.facts.sinks {
                if sink.symbol_id.as_ref() == Some(source_symbol_id) {
                    self.facts.taint_edges.push(TaintEdge {
                        id: stable_fact_id("taint-edge", [&source.id, &sink.id, "elixir"]),
                        source_id: source.id.clone(),
                        target_id: sink.id.clone(),
                        sanitizer_id: None,
                        kind: TaintEdgeKind::SourceToSink,
                        confidence: Confidence::Low,
                        metadata: metadata("adapter", "elixir"),
                    });
                }
            }
            for sanitizer in &self.facts.sanitizers {
                if sanitizer.symbol_id.as_ref() == Some(source_symbol_id) {
                    self.facts.taint_edges.push(TaintEdge {
                        id: stable_fact_id("taint-edge", [&source.id, &sanitizer.id, "elixir"]),
                        source_id: source.id.clone(),
                        target_id: sanitizer.id.clone(),
                        sanitizer_id: Some(sanitizer.id.clone()),
                        kind: TaintEdgeKind::Sanitized,
                        confidence: Confidence::Low,
                        metadata: metadata("adapter", "elixir"),
                    });
                }
            }
        }
    }

    fn current_symbol_id(&self) -> Option<String> {
        self.blocks
            .iter()
            .rev()
            .find_map(|block| block.symbol_id.clone())
    }

    fn current_module(&self) -> Option<&str> {
        self.module_stack.last().map(String::as_str)
    }

    fn current_module_symbol_id(&self) -> Option<String> {
        self.blocks.iter().rev().find_map(|block| {
            if matches!(block.kind, ElixirBlockKind::Module(_)) {
                block.symbol_id.clone()
            } else {
                None
            }
        })
    }

    fn current_route_prefix(&self) -> String {
        self.blocks
            .iter()
            .filter_map(|block| match &block.kind {
                ElixirBlockKind::Scope { prefix, .. } => Some(prefix.as_str()),
                ElixirBlockKind::Module(_)
                | ElixirBlockKind::Def
                | ElixirBlockKind::Pipeline
                | ElixirBlockKind::Other => None,
            })
            .fold("/".to_string(), |prefix, segment| {
                join_paths(&prefix, segment)
            })
    }

    fn current_alias_prefix(&self) -> Option<String> {
        self.blocks
            .iter()
            .filter_map(|block| match &block.kind {
                ElixirBlockKind::Scope {
                    alias_prefix: Some(alias_prefix),
                    ..
                } => Some(alias_prefix.as_str()),
                ElixirBlockKind::Module(_)
                | ElixirBlockKind::Def
                | ElixirBlockKind::Scope { .. }
                | ElixirBlockKind::Pipeline
                | ElixirBlockKind::Other => None,
            })
            .fold(None, |prefix, segment| {
                Some(join_elixir_alias_segments(prefix.as_deref(), segment))
            })
    }
}

struct ResourceRoute {
    path: String,
    controller: String,
    only: BTreeSet<String>,
    except: BTreeSet<String>,
}

impl ResourceRoute {
    fn includes_action(&self, action: &str) -> bool {
        (self.only.is_empty() || self.only.contains(action)) && !self.except.contains(action)
    }
}

fn source_lines(source: &str) -> Vec<LineInfo<'_>> {
    let mut offset = 0usize;
    source
        .split_inclusive('\n')
        .enumerate()
        .map(|(index, raw)| {
            let text = raw.trim_end_matches('\n').trim_end_matches('\r');
            let start_byte = offset;
            offset += raw.len();
            LineInfo {
                number: u32::try_from(index + 1).unwrap_or(u32::MAX),
                start_byte,
                end_byte: start_byte + text.len(),
                text,
            }
        })
        .collect()
}

fn range_for_line(line: &LineInfo<'_>) -> Option<SourceRange> {
    Some(SourceRange::new(
        SourcePosition::new(line.number, 1).with_byte_offset(u32::try_from(line.start_byte).ok()?),
        SourcePosition::new(line.number, u32::try_from(line.text.len() + 1).ok()?)
            .with_byte_offset(u32::try_from(line.end_byte).ok()?),
    ))
}

fn metadata(key: &str, value: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(key.to_string(), value.to_string())])
}

fn parse_defmodule(text: &str) -> Option<String> {
    let rest = text.strip_prefix("defmodule ")?.trim();
    let name = rest.split_whitespace().next()?.trim_end_matches("do");
    Some(name.to_string()).filter(|name| !name.is_empty())
}

fn parse_def(text: &str) -> Option<(String, String)> {
    let rest = text
        .strip_prefix("def ")
        .or_else(|| text.strip_prefix("defp "))?
        .trim();
    let name_end = rest
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '?' || ch == '!'))
        .unwrap_or(rest.len());
    let name = rest[..name_end].to_string();
    let signature = rest[name_end..]
        .split_once('(')
        .and_then(|(_, tail)| tail.rsplit_once(')').map(|(inside, _)| inside.to_string()))
        .unwrap_or_default();
    Some((name, signature)).filter(|(name, _)| !name.is_empty())
}

fn parse_pipeline(text: &str) -> Option<String> {
    text.strip_prefix("pipeline ")
        .and_then(|rest| atoms_in(rest).into_iter().next())
}

fn parse_scope(text: &str) -> Option<(String, Option<String>)> {
    let rest = text.strip_prefix("scope ")?;
    let prefix = first_quoted(rest).unwrap_or_else(|| "/".to_string());
    let alias_prefix = rest
        .split(',')
        .nth(1)
        .map(str::trim)
        .filter(|part| !part.starts_with("as:") && !part.starts_with("private:"))
        .map(|part| part.trim_end_matches(" do").to_string())
        .filter(|part| !part.is_empty());
    Some((prefix, alias_prefix))
}

fn parse_resource(text: &str) -> Option<ResourceRoute> {
    let rest = text.strip_prefix("resources ")?;
    let path = first_quoted(rest)?;
    let controller = rest
        .split(',')
        .nth(1)?
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(',')
        .to_string();
    let only = parse_resource_actions_option(rest, "only:");
    let except = parse_resource_actions_option(rest, "except:");
    Some(ResourceRoute {
        path,
        controller,
        only,
        except,
    })
    .filter(|route| !route.controller.is_empty())
}

fn parse_resource_actions_option(text: &str, keyword: &str) -> BTreeSet<String> {
    let Some((_, rest)) = text.split_once(keyword) else {
        return BTreeSet::new();
    };
    let value = rest.trim_start();
    if let Some(list) = value
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']').map(|(list, _)| list))
    {
        return atoms_in(list).into_iter().collect();
    }
    parse_action_atom(value).into_iter().collect()
}

fn parse_action_atom(text: &str) -> Option<String> {
    let rest = text.trim_start().strip_prefix(':')?;
    let end = rest
        .find(|candidate: char| !(candidate.is_ascii_alphanumeric() || candidate == '_'))
        .unwrap_or(rest.len());
    (end > 0).then(|| rest[..end].to_string())
}

fn phoenix_http_verb(text: &str) -> Option<&'static str> {
    [
        ("get ", "GET"),
        ("post ", "POST"),
        ("put ", "PUT"),
        ("patch ", "PATCH"),
        ("delete ", "DELETE"),
        ("head ", "HEAD"),
        ("options ", "OPTIONS"),
    ]
    .into_iter()
    .find_map(|(prefix, method)| text.starts_with(prefix).then_some(method))
}

fn route_target(text: &str, alias_prefix: Option<&str>) -> Option<String> {
    let mut parts = text.split(',').map(str::trim);
    parts.next()?;
    let controller = parts.next()?.split_whitespace().next()?.trim();
    let action = parts
        .next()
        .and_then(|part| atoms_in(part).into_iter().next())
        .unwrap_or_else(|| "index".to_string());
    let qualified = qualify_phoenix_controller(controller, alias_prefix);
    Some(format!("{qualified}.{action}"))
}

fn qualify_phoenix_controller(controller: &str, alias_prefix: Option<&str>) -> String {
    match alias_prefix {
        Some(alias_prefix) if !controller.contains('.') => {
            join_elixir_alias_segments(Some(alias_prefix), controller)
        }
        _ => controller.to_string(),
    }
}

fn join_elixir_alias_segments(prefix: Option<&str>, segment: &str) -> String {
    let segment = segment.trim_matches('.');
    match prefix.map(str::trim).filter(|prefix| !prefix.is_empty()) {
        Some(prefix)
            if segment == prefix.trim_matches('.')
                || segment.starts_with(&format!("{}.", prefix.trim_matches('.'))) =>
        {
            segment.to_string()
        }
        Some(prefix) if !segment.is_empty() => {
            format!("{}.{}", prefix.trim_matches('.'), segment)
        }
        Some(prefix) => prefix.trim_matches('.').to_string(),
        None => segment.to_string(),
    }
}

fn split_args(signature: &str) -> Vec<String> {
    signature
        .split(',')
        .filter_map(|part| {
            let name = part
                .trim()
                .split([' ', '\\', '=', ':'])
                .next()
                .unwrap_or("")
                .trim_matches(['{', '}', '[', ']']);
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

fn atoms_in(text: &str) -> Vec<String> {
    let mut atoms = Vec::new();
    for (index, ch) in text.char_indices() {
        if ch != ':' {
            continue;
        }
        let rest = &text[index + 1..];
        let end = rest
            .find(|candidate: char| !(candidate.is_ascii_alphanumeric() || candidate == '_'))
            .unwrap_or(rest.len());
        if end > 0 {
            atoms.push(rest[..end].to_string());
        }
    }
    atoms
}

fn first_quoted(text: &str) -> Option<String> {
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

fn opens_block(text: &str) -> bool {
    text.ends_with(" do")
        || text.starts_with("if ")
        || text.starts_with("case ")
        || text.starts_with("cond do")
        || text.starts_with("try do")
}

fn join_paths(prefix: &str, path: &str) -> String {
    let left = normalize_path(prefix);
    let right = normalize_path(path);
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

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn contains_auth_hint(text: &str) -> bool {
    contains_any(
        &text.to_ascii_lowercase(),
        &["auth", "current_user", "authorize", "ensure_authenticated"],
    )
}

fn elixir_callees(text: &str) -> Vec<String> {
    let mut callees = Vec::new();
    for (index, _) in text.match_indices('(') {
        let before = text[..index].trim_end();
        let end = before
            .rfind(|ch: char| {
                !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '!' || ch == '?')
            })
            .map_or(0, |pos| pos + 1);
        let callee = before[end..].trim();
        if !callee.is_empty() && (callee.contains('.') || callee == "from") {
            callees.push(callee.to_string());
        }
    }
    callees
}

fn is_repo_read(callee: &str, final_name: &str) -> bool {
    callee.contains("Repo.")
        && matches!(
            final_name,
            "get" | "get!" | "get_by" | "get_by!" | "one" | "one!" | "all" | "preload"
        )
}

fn is_repo_write(callee: &str, final_name: &str) -> bool {
    callee.contains("Repo.")
        && matches!(
            final_name,
            "insert" | "insert!" | "update" | "update!" | "delete" | "delete!"
        )
}

fn is_context_persistence_call(callee: &str, final_name: &str) -> bool {
    callee.contains('.')
        && (matches!(
            final_name,
            "create" | "create!" | "update" | "update!" | "delete" | "delete!"
        ) || final_name.starts_with("create_")
            || final_name.starts_with("update_")
            || final_name.starts_with("delete_"))
        && !callee.contains("Repo.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::ProjectGraph;
    use std::path::PathBuf;

    fn analyze_elixir(path: &str, source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new(path, "Elixir");
        file.service_id = Some("api".to_string());
        ElixirAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("elixir analysis succeeds")
    }

    #[test]
    fn extracts_phoenix_router_routes_pipelines_and_live_routes() {
        let source = r#"
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :authenticate_user
  end

  scope "/api", MyAppWeb do
    pipe_through [:browser, :auth]
    get "/users/:id", UserController, :show
    resources "/posts", PostController
    live "/dashboard", DashboardLive, :index
  end
end
"#;
        let facts = analyze_elixir("lib/my_app_web/router.ex", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/users/:id"
                && route.framework.as_deref() == Some("Phoenix")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/api/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.PostController.create")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/dashboard"
                && route.framework.as_deref() == Some("Phoenix LiveView")
        }));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("protect_from_forgery")));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Authentication));
    }

    #[test]
    fn filters_phoenix_resource_routes_with_only_and_except_options() {
        let source = r#"
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  scope "/api", MyAppWeb.Admin do
    resources "/posts", PostController, only: [:index, :show]
    resources "/comments", CommentController, except: [:delete]
  end
end
"#;
        let facts = analyze_elixir("lib/my_app_web/router.ex", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.PostController.index")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/api/posts/:id"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.PostController.show")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route
                .metadata
                .get("target")
                .is_some_and(|target| target == "MyAppWeb.Admin.PostController.create")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route
                .metadata
                .get("target")
                .is_some_and(|target| target == "MyAppWeb.Admin.PostController.update")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route
                .metadata
                .get("target")
                .is_some_and(|target| target == "MyAppWeb.Admin.PostController.delete")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/api/comments"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.CommentController.create")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "PATCH"
                && route.path == "/api/comments/:id"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.CommentController.update")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route.method == "DELETE"
                && route.path == "/api/comments/:id"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.CommentController.delete")
        }));
    }

    #[test]
    fn composes_nested_phoenix_scope_aliases_for_resources() {
        let source = r#"
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  scope "/", MyAppWeb do
    scope "/admin", Admin do
      resources "/posts", PostController
    end
  end
end
"#;
        let facts = analyze_elixir("lib/my_app_web/router.ex", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "MyAppWeb.Admin.PostController.index")
        }));
    }

    #[test]
    fn extracts_controller_sources_repo_flows_and_changeset_validation() {
        let source = r#"
defmodule MyAppWeb.UserController do
  alias MyApp.Repo

  def show(conn, params) do
    id = params["id"]
    user = Repo.get!(User, id)
    body = Plug.Conn.read_body(conn)
    Accounts.update_user(user, params)
    User.changeset(user, params) |> validate_required([:name])
    json(conn, user)
  end
end
"#;
        let facts = analyze_elixir("lib/my_app_web/controllers/user_controller.ex", source);

        assert!(facts.symbols.iter().any(|symbol| {
            symbol.name == "MyAppWeb.UserController.show" && symbol.kind == SymbolKind::Function
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("params")));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("Repo.get!")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("Accounts.update_user")));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.name.as_deref() == Some("ecto_changeset_validation")));
        assert!(!facts.taint_edges.is_empty());
    }
}
