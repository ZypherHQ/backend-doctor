use backend_doctor_core::{
    stable_fact_id, AnalysisFacts, CallFact, Confidence, DataSourceFact, DataSourceKind,
    ImportFact, ImportKind, RouteFact, SanitizerFact, SanitizerKind, SinkFact, SinkKind,
    SourceFileFact, SourcePosition, SourceRange, SymbolFact, SymbolKind, TaintEdge, TaintEdgeKind,
};
use std::collections::{BTreeMap, BTreeSet};

use crate::{AdapterInput, AnalysisError, SourceAdapter};

#[derive(Clone, Copy, Debug, Default)]
pub struct RubyAdapter;

impl SourceAdapter for RubyAdapter {
    fn id(&self) -> &'static str {
        "ruby-line-scanner-tier-c"
    }

    fn language(&self) -> &'static str {
        "Ruby"
    }

    fn supports(&self, source_file: &SourceFileFact) -> bool {
        matches!(
            source_file.language.to_ascii_lowercase().as_str(),
            "ruby" | "rails" | "sinatra"
        )
    }

    fn analyze(&self, input: AdapterInput<'_>) -> Result<AnalysisFacts, AnalysisError> {
        let mut analyzer = RubyAnalyzer::new(input);
        analyzer.analyze();
        Ok(analyzer.facts)
    }
}

struct RubyAnalyzer<'a> {
    input: AdapterInput<'a>,
    facts: AnalysisFacts,
    lines: Vec<LineInfo<'a>>,
    blocks: Vec<RubyBlock>,
    class_stack: Vec<String>,
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
struct RubyBlock {
    kind: RubyBlockKind,
    symbol_id: Option<String>,
}

#[derive(Clone)]
enum RubyBlockKind {
    Scope(RouteScope),
    Class(String),
    Module(String),
    Def,
    Other,
}

#[derive(Clone)]
struct RouteScope {
    path_prefix: String,
    controller_prefix: Option<String>,
}

impl RouteScope {
    fn path_only(path_prefix: String) -> Self {
        Self {
            path_prefix,
            controller_prefix: None,
        }
    }

    fn controller_only(controller_prefix: String) -> Self {
        Self {
            path_prefix: "/".to_string(),
            controller_prefix: Some(controller_prefix.trim_matches('/').to_string()),
        }
    }

    fn path_and_controller(path_prefix: String, controller_prefix: String) -> Self {
        Self {
            path_prefix,
            controller_prefix: Some(controller_prefix.trim_matches('/').to_string()),
        }
    }

    fn namespace(value: String) -> Self {
        let value = value.trim_matches('/').to_string();
        Self {
            path_prefix: format!("/{value}"),
            controller_prefix: Some(value),
        }
    }
}

struct RubyRoute {
    method: &'static str,
    path: String,
    framework: &'static str,
    target: Option<String>,
    provenance: String,
}

struct ResourceRoute {
    name: String,
    only: BTreeSet<String>,
    except: BTreeSet<String>,
}

impl ResourceRoute {
    fn includes_action(&self, action: &str) -> bool {
        (self.only.is_empty() || self.only.contains(action)) && !self.except.contains(action)
    }
}

impl<'a> RubyAnalyzer<'a> {
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
            class_stack: Vec::new(),
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

            if let Some(module) = parse_declaration_name(trimmed, "module") {
                let id = self.add_symbol(&line, &module, SymbolKind::Module, None, Some(trimmed));
                self.class_stack.push(module.clone());
                self.blocks.push(RubyBlock {
                    kind: RubyBlockKind::Module(module),
                    symbol_id: Some(id),
                });
                continue;
            }

            if let Some(class_name) = parse_declaration_name(trimmed, "class") {
                let qualified = qualify_name(&self.class_stack, &class_name);
                let id = self.add_symbol(&line, &qualified, SymbolKind::Class, None, Some(trimmed));
                self.class_stack.push(class_name.clone());
                self.blocks.push(RubyBlock {
                    kind: RubyBlockKind::Class(class_name),
                    symbol_id: Some(id),
                });
                self.collect_controller_sanitizer(&line, trimmed);
                continue;
            }

            if let Some(method) = parse_declaration_name(trimmed, "def") {
                let symbol_name = if let Some(class_name) = self.current_class_name() {
                    format!(
                        "{}#{method}",
                        controller_qualified_name(&self.class_stack, class_name)
                    )
                } else {
                    method.clone()
                };
                let parent = self.current_class_symbol_id();
                let id = self.add_symbol(
                    &line,
                    &symbol_name,
                    SymbolKind::Method,
                    parent,
                    Some(trimmed),
                );
                self.blocks.push(RubyBlock {
                    kind: RubyBlockKind::Def,
                    symbol_id: Some(id),
                });
                self.collect_controller_sanitizer(&line, trimmed);
                self.collect_request_sources(&line, trimmed);
                self.collect_data_and_sink_facts(&line, trimmed);
                continue;
            }

            if let Some(prefix) = parse_namespace_or_scope(trimmed) {
                self.blocks.push(RubyBlock {
                    kind: RubyBlockKind::Scope(prefix),
                    symbol_id: None,
                });
                continue;
            }

            let mut opened_resource_scope = false;
            if let Some(resource) = parse_resource(trimmed, "resources") {
                self.emit_resource_routes(&line, &resource, false);
                if trimmed.ends_with(" do") {
                    self.blocks.push(RubyBlock {
                        kind: RubyBlockKind::Scope(RouteScope::path_only(format!(
                            "/{}/:{}_id",
                            resource.name, resource.name
                        ))),
                        symbol_id: None,
                    });
                    opened_resource_scope = true;
                }
            } else if let Some(resource) = parse_resource(trimmed, "resource") {
                self.emit_resource_routes(&line, &resource, true);
                if trimmed.ends_with(" do") {
                    self.blocks.push(RubyBlock {
                        kind: RubyBlockKind::Scope(RouteScope::path_only(format!(
                            "/{}",
                            resource.name
                        ))),
                        symbol_id: None,
                    });
                    opened_resource_scope = true;
                }
            }

            if let Some(route) = self.parse_route_line(&line, trimmed) {
                self.emit_route(&line, route);
                if trimmed.ends_with(" do") {
                    self.blocks.push(RubyBlock {
                        kind: RubyBlockKind::Other,
                        symbol_id: self.current_symbol_id(),
                    });
                }
            } else if !opened_resource_scope && opens_plain_block(trimmed) {
                self.blocks.push(RubyBlock {
                    kind: RubyBlockKind::Other,
                    symbol_id: self.current_symbol_id(),
                });
            }

            self.collect_controller_sanitizer(&line, trimmed);
            self.collect_request_sources(&line, trimmed);
            self.collect_data_and_sink_facts(&line, trimmed);
        }
        self.add_local_taint_edges();
    }

    fn pop_block(&mut self) {
        if let Some(block) = self.blocks.pop() {
            match block.kind {
                RubyBlockKind::Class(name) | RubyBlockKind::Module(name) => {
                    if self.class_stack.last() == Some(&name) {
                        self.class_stack.pop();
                    }
                }
                RubyBlockKind::Scope(_) | RubyBlockKind::Def | RubyBlockKind::Other => {}
            }
        }
    }

    fn collect_import(&mut self, line: &LineInfo<'_>, trimmed: &str) {
        let module = if let Some(rest) = trimmed.strip_prefix("require ") {
            first_quoted(rest)
        } else if let Some(rest) = trimmed.strip_prefix("require_relative ") {
            first_quoted(rest)
        } else {
            None
        };
        let Some(module) = module else {
            return;
        };
        if !self.emitted_imports.insert(module.clone()) {
            return;
        }
        self.facts.imports.push(ImportFact {
            id: stable_fact_id("import", [&self.input.source_file.id, &module, "ruby"]),
            file_id: Some(self.input.source_file.id.clone()),
            module,
            alias: None,
            imported_symbols: Vec::new(),
            kind: ImportKind::Module,
            range: range_for_line(line),
            metadata: metadata("adapter", "ruby"),
        });
    }

    fn collect_controller_sanitizer(&mut self, line: &LineInfo<'_>, text: &str) {
        if text.contains("params.expect") || text.contains(".permit(") || text.contains(" permit(")
        {
            self.add_sanitizer(
                line,
                SanitizerKind::Validation,
                "strong_parameters",
                "rails",
            );
        }
        if text.contains("http_basic_authenticate_with") {
            self.add_sanitizer(
                line,
                SanitizerKind::Authentication,
                "http_basic_authenticate_with",
                "rails",
            );
        }
        if (text.contains("before_action") || text.starts_with("before "))
            && contains_authentication_hint(text)
        {
            let kind = if text.contains("authorize") || text.contains("policy") {
                SanitizerKind::Authorization
            } else {
                SanitizerKind::Authentication
            };
            self.add_sanitizer(
                line,
                kind,
                "before_auth_filter",
                framework_for_path(&self.input),
            );
        }
        let auth_call = text.trim_end_matches('!');
        if matches!(
            auth_call,
            "authenticate" | "authenticate_user" | "authorize" | "require_login"
        ) {
            let kind = if auth_call == "authorize" {
                SanitizerKind::Authorization
            } else {
                SanitizerKind::Authentication
            };
            self.add_sanitizer(line, kind, auth_call, framework_for_path(&self.input));
        }
    }

    fn collect_request_sources(&mut self, line: &LineInfo<'_>, text: &str) {
        let sources = [
            ("params", "params"),
            ("request.body", "body"),
            ("request.query_parameters", "query"),
            ("request.headers", "header"),
            ("request.env", "env"),
            ("session", "session"),
            ("cookies", "cookies"),
        ];
        for (needle, binding) in sources {
            if text.contains(needle) {
                let mut meta = metadata("adapter", "ruby");
                meta.insert("binding".to_string(), binding.to_string());
                self.add_data_source(line, DataSourceKind::Request, needle, None, meta);
            }
        }
        if text.contains("request.params") {
            let mut meta = metadata("adapter", "ruby");
            meta.insert("binding".to_string(), "params".to_string());
            self.add_data_source(line, DataSourceKind::Request, "request.params", None, meta);
        }
    }

    fn collect_data_and_sink_facts(&mut self, line: &LineInfo<'_>, text: &str) {
        for callee in ruby_callees(text) {
            self.add_call(line, &callee);
            let final_name = callee.rsplit('.').next().unwrap_or(callee.as_str());
            if matches!(
                final_name,
                "find" | "find_by" | "where" | "all" | "first" | "last"
            ) {
                self.add_data_source(
                    line,
                    DataSourceKind::Database,
                    &callee,
                    None,
                    metadata("adapter", "ruby"),
                );
            } else if matches!(
                final_name,
                "save" | "save!" | "update" | "destroy" | "create"
            ) {
                self.add_sink(
                    line,
                    SinkKind::SqlQuery,
                    &callee,
                    metadata("adapter", "ruby"),
                );
            }
            if matches!(
                final_name,
                "perform_async" | "perform_later" | "deliver_later"
            ) {
                let mut meta = metadata("adapter", "ruby");
                meta.insert("category".to_string(), "queue_or_mail".to_string());
                self.add_sink(line, SinkKind::Unknown, &callee, meta);
            }
        }

        if contains_any(
            text,
            &[
                "ActiveRecord::Base.connection.execute",
                ".execute(",
                "find_by_sql",
                "select_all",
            ],
        ) && contains_sql_hint(text)
        {
            self.add_sink(
                line,
                SinkKind::SqlQuery,
                "sql_execution",
                metadata("adapter", "ruby"),
            );
        }
        if contains_any(
            text,
            &["Rails.cache.read", "Redis.current.get", ".redis.get"],
        ) {
            self.add_data_source(
                line,
                DataSourceKind::Cache,
                "cache_read",
                None,
                metadata("adapter", "ruby"),
            );
        }
        if contains_any(
            text,
            &[
                "Rails.cache.write",
                "Rails.cache.delete",
                "Redis.current.set",
                ".redis.set",
            ],
        ) {
            let mut meta = metadata("adapter", "ruby");
            meta.insert("category".to_string(), "cache_write".to_string());
            self.add_sink(line, SinkKind::Unknown, "cache_write", meta);
        }
    }

    fn parse_route_line(&self, line: &LineInfo<'_>, text: &str) -> Option<RubyRoute> {
        let (method, rest) = if let Some(rest) = text.strip_prefix("root ") {
            ("GET", rest)
        } else {
            let verb = ruby_http_verb(text)?;
            let rest = text[verb.len()..].trim_start();
            (verb, rest)
        };
        let path = if text.starts_with("root ") {
            "/".to_string()
        } else {
            first_quoted(rest).or_else(|| first_symbol_path(rest))?
        };
        let full_path = join_paths(&self.current_route_prefix(), &path);
        let target = rails_route_target(text).map(|target| {
            qualify_rails_route_target(&target, self.current_route_controller_prefix().as_deref())
        });
        let framework = if target.is_some() || self.input.source_file.path.ends_with("routes.rb") {
            "Rails"
        } else if text.ends_with(" do") || text.contains(" do ") {
            "Sinatra"
        } else {
            return None;
        };
        let provenance = format!("{}:{}", self.input.source_file.path.display(), line.number);
        Some(RubyRoute {
            method,
            path: full_path,
            framework,
            target,
            provenance,
        })
    }

    fn emit_resource_routes(
        &mut self,
        line: &LineInfo<'_>,
        resource: &ResourceRoute,
        singular: bool,
    ) {
        let prefix = self.current_route_prefix();
        let base = join_paths(&prefix, &resource.name);
        let controller = qualify_rails_controller(
            &resource.name,
            self.current_route_controller_prefix().as_deref(),
        );
        let mut routes = Vec::new();
        if singular {
            routes.extend([
                ("GET", base.clone(), "show"),
                ("GET", join_paths(&base, "new"), "new"),
                ("POST", base.clone(), "create"),
                ("GET", join_paths(&base, "edit"), "edit"),
                ("PATCH", base.clone(), "update"),
                ("PUT", base.clone(), "update"),
                ("DELETE", base, "destroy"),
            ]);
        } else {
            routes.extend([
                ("GET", base.clone(), "index"),
                ("GET", join_paths(&base, "new"), "new"),
                ("POST", base.clone(), "create"),
                ("GET", join_paths(&base, ":id"), "show"),
                ("GET", join_paths(&base, ":id/edit"), "edit"),
                ("PATCH", join_paths(&base, ":id"), "update"),
                ("PUT", join_paths(&base, ":id"), "update"),
                ("DELETE", join_paths(&base, ":id"), "destroy"),
            ]);
        }
        for (method, path, action) in routes {
            if !resource.includes_action(action) {
                continue;
            }
            self.emit_route(
                line,
                RubyRoute {
                    method,
                    path,
                    framework: "Rails",
                    target: Some(format!("{controller}#{action}")),
                    provenance: "resource_route".to_string(),
                },
            );
        }
    }

    fn emit_route(&mut self, line: &LineInfo<'_>, route: RubyRoute) {
        let symbol_id = route
            .target
            .as_deref()
            .and_then(|target| self.symbol_for_route_target(target))
            .or_else(|| {
                if route.framework == "Sinatra" {
                    Some(self.add_symbol(
                        line,
                        &format!("Sinatra {} {}", route.method, route.path),
                        SymbolKind::Function,
                        None,
                        Some(&route.provenance),
                    ))
                } else {
                    None
                }
            });
        let mut metadata = metadata("adapter", "ruby");
        metadata.insert("provenance".to_string(), route.provenance);
        if let Some(target) = &route.target {
            metadata.insert("target".to_string(), target.clone());
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
            metadata,
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
            metadata: metadata("adapter", "ruby"),
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
            metadata: metadata("adapter", "ruby"),
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
        framework: &str,
    ) -> String {
        let mut meta = metadata("adapter", "ruby");
        meta.insert("framework".to_string(), framework.to_string());
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
                        id: stable_fact_id("taint-edge", [&source.id, &sink.id, "ruby"]),
                        source_id: source.id.clone(),
                        target_id: sink.id.clone(),
                        sanitizer_id: None,
                        kind: TaintEdgeKind::SourceToSink,
                        confidence: Confidence::Low,
                        metadata: metadata("adapter", "ruby"),
                    });
                }
            }
            for sanitizer in &self.facts.sanitizers {
                if sanitizer.symbol_id.as_ref() == Some(source_symbol_id) {
                    self.facts.taint_edges.push(TaintEdge {
                        id: stable_fact_id("taint-edge", [&source.id, &sanitizer.id, "ruby"]),
                        source_id: source.id.clone(),
                        target_id: sanitizer.id.clone(),
                        sanitizer_id: Some(sanitizer.id.clone()),
                        kind: TaintEdgeKind::Sanitized,
                        confidence: Confidence::Low,
                        metadata: metadata("adapter", "ruby"),
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

    fn current_class_symbol_id(&self) -> Option<String> {
        self.blocks.iter().rev().find_map(|block| {
            if matches!(block.kind, RubyBlockKind::Class(_)) {
                block.symbol_id.clone()
            } else {
                None
            }
        })
    }

    fn current_class_name(&self) -> Option<&str> {
        self.class_stack.last().map(String::as_str)
    }

    fn current_route_prefix(&self) -> String {
        self.blocks
            .iter()
            .filter_map(|block| match &block.kind {
                RubyBlockKind::Scope(scope) => Some(scope.path_prefix.as_str()),
                RubyBlockKind::Class(_)
                | RubyBlockKind::Module(_)
                | RubyBlockKind::Def
                | RubyBlockKind::Other => None,
            })
            .fold("/".to_string(), |prefix, segment| {
                join_paths(&prefix, segment)
            })
    }

    fn current_route_controller_prefix(&self) -> Option<String> {
        self.blocks
            .iter()
            .filter_map(|block| match &block.kind {
                RubyBlockKind::Scope(scope) => scope.controller_prefix.as_deref(),
                RubyBlockKind::Class(_)
                | RubyBlockKind::Module(_)
                | RubyBlockKind::Def
                | RubyBlockKind::Other => None,
            })
            .fold(None, |prefix, segment| {
                Some(join_controller_segments(prefix.as_deref(), segment))
            })
    }

    fn symbol_for_route_target(&self, target: &str) -> Option<String> {
        let (controller, action) = target.split_once('#')?;
        let class_name = controller
            .split('/')
            .map(camelize)
            .collect::<Vec<_>>()
            .join("::");
        let candidates = [
            format!("{class_name}Controller#{action}"),
            format!("{class_name}::{action}"),
            format!("{class_name}#{action}"),
        ];
        candidates
            .iter()
            .find_map(|name| self.symbols_by_name.get(name).cloned())
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

fn parse_declaration_name(text: &str, keyword: &str) -> Option<String> {
    let rest = text.strip_prefix(keyword)?.trim_start();
    if rest.is_empty() {
        return None;
    }
    let end = rest
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' || ch == '?'))
        .unwrap_or(rest.len());
    Some(rest[..end].trim_start_matches("self.").to_string()).filter(|name| !name.is_empty())
}

fn parse_namespace_or_scope(text: &str) -> Option<RouteScope> {
    if !text.ends_with(" do") {
        return None;
    }
    if let Some(rest) = text.strip_prefix("namespace ") {
        return parse_symbol_or_string(rest).map(RouteScope::namespace);
    }
    if let Some(rest) = text.strip_prefix("scope ") {
        return parse_scope(rest);
    }
    None
}

fn parse_scope(text: &str) -> Option<RouteScope> {
    let path_prefix =
        keyword_string_value(text, "path:").or_else(|| parse_leading_scope_path(text));
    let controller_prefix = keyword_string_value(text, "module:");
    match (path_prefix, controller_prefix) {
        (Some(path_prefix), Some(controller_prefix)) => Some(RouteScope::path_and_controller(
            path_prefix,
            controller_prefix,
        )),
        (Some(path_prefix), None) => Some(RouteScope::path_only(path_prefix)),
        (None, Some(controller_prefix)) => Some(RouteScope::controller_only(controller_prefix)),
        (None, None) => None,
    }
}

fn parse_leading_scope_path(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    if ["module:", "path:", "as:", "constraints:", "defaults:"]
        .iter()
        .any(|keyword| trimmed.starts_with(keyword))
    {
        return None;
    }
    parse_symbol_or_string(trimmed)
}

fn parse_resource(text: &str, keyword: &str) -> Option<ResourceRoute> {
    let rest = text.strip_prefix(keyword)?.trim_start();
    let name = parse_symbol_or_string(rest).map(|value| value.trim_matches('/').to_string())?;
    let only = parse_resource_actions_option(rest, "only:");
    let except = parse_resource_actions_option(rest, "except:");
    Some(ResourceRoute { name, only, except })
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
        return list.split(',').filter_map(parse_symbol_or_string).collect();
    }
    parse_symbol_or_string(value).into_iter().collect()
}

fn parse_symbol_or_string(text: &str) -> Option<String> {
    first_quoted(text).or_else(|| {
        let rest = text.trim_start();
        let rest = rest.strip_prefix(':').unwrap_or(rest);
        let end = rest
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '/'))
            .unwrap_or(rest.len());
        Some(rest[..end].to_string()).filter(|value| !value.is_empty())
    })
}

fn ruby_http_verb(text: &str) -> Option<&'static str> {
    [
        ("get ", "GET"),
        ("post ", "POST"),
        ("put ", "PUT"),
        ("patch ", "PATCH"),
        ("delete ", "DELETE"),
        ("options ", "OPTIONS"),
        ("head ", "HEAD"),
        ("link ", "LINK"),
        ("unlink ", "UNLINK"),
    ]
    .into_iter()
    .find_map(|(prefix, method)| text.starts_with(prefix).then_some(method))
}

fn rails_route_target(text: &str) -> Option<String> {
    if let Some((_, rest)) = text.split_once("to:") {
        return first_quoted(rest);
    }
    if let (Some(controller), Some(action)) = (
        keyword_string_value(text, "controller:"),
        keyword_string_value(text, "action:"),
    ) {
        return Some(format!("{controller}#{action}"));
    }
    None
}

fn qualify_rails_route_target(target: &str, controller_prefix: Option<&str>) -> String {
    let Some((controller, action)) = target.split_once('#') else {
        return target.to_string();
    };
    format!(
        "{}#{action}",
        qualify_rails_controller(controller, controller_prefix)
    )
}

fn qualify_rails_controller(controller: &str, controller_prefix: Option<&str>) -> String {
    let controller = controller.trim_matches('/');
    match controller_prefix {
        Some(prefix) if !controller.contains('/') => {
            join_controller_segments(Some(prefix), controller)
        }
        _ => controller.to_string(),
    }
}

fn join_controller_segments(prefix: Option<&str>, segment: &str) -> String {
    let segment = segment.trim_matches('/');
    match prefix.map(str::trim).filter(|prefix| !prefix.is_empty()) {
        Some(prefix) if !segment.is_empty() => {
            format!("{}/{}", prefix.trim_matches('/'), segment)
        }
        Some(prefix) => prefix.trim_matches('/').to_string(),
        None => segment.to_string(),
    }
}

fn keyword_string_value(text: &str, keyword: &str) -> Option<String> {
    text.split_once(keyword)
        .and_then(|(_, rest)| parse_symbol_or_string(rest.trim()))
}

fn first_symbol_path(text: &str) -> Option<String> {
    parse_symbol_or_string(text).filter(|value| value.starts_with('/'))
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

fn opens_plain_block(text: &str) -> bool {
    text.ends_with(" do")
        || text.ends_with(" {")
        || text.starts_with("if ")
        || text.starts_with("unless ")
        || text.starts_with("begin")
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

fn qualify_name(stack: &[String], name: &str) -> String {
    if name.contains("::") || stack.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", stack.join("::"))
    }
}

fn controller_qualified_name(stack: &[String], class_name: &str) -> String {
    if class_name.contains("::") || stack.len() <= 1 {
        class_name.to_string()
    } else {
        let prefix = &stack[..stack.len() - 1];
        format!("{}::{class_name}", prefix.join("::"))
    }
}

fn camelize(value: &str) -> String {
    value
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn framework_for_path(input: &AdapterInput<'_>) -> &'static str {
    if input
        .source_file
        .path
        .to_string_lossy()
        .contains("config/routes")
    {
        "rails"
    } else {
        "ruby"
    }
}

fn contains_authentication_hint(text: &str) -> bool {
    contains_any(
        &text.to_ascii_lowercase(),
        &[
            "authenticate",
            "authorize",
            "current_user",
            "logged_in",
            "policy",
        ],
    )
}

fn contains_sql_hint(text: &str) -> bool {
    contains_any(
        &text.to_ascii_lowercase(),
        &[
            "select ", "insert ", "update ", "delete ", "from ", "where ",
        ],
    )
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}

fn ruby_callees(text: &str) -> Vec<String> {
    let mut callees = Vec::new();
    for (index, _) in text.match_indices('(') {
        let before = text[..index].trim_end();
        let end = before
            .rfind(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '!'))
            .map_or(0, |pos| pos + 1);
        let callee = before[end..].trim_matches('.');
        if callee.contains('.') && !callee.starts_with("params.") && !callee.is_empty() {
            callees.push(callee.to_string());
        }
    }
    callees
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_doctor_core::ProjectGraph;
    use std::path::PathBuf;

    fn analyze_ruby(path: &str, source: &str) -> AnalysisFacts {
        let project = ProjectGraph::empty(PathBuf::from("."));
        let mut file = SourceFileFact::new(path, "Ruby");
        file.service_id = Some("api".to_string());
        RubyAdapter
            .analyze(AdapterInput {
                project: &project,
                source_file: &file,
                contents: source,
            })
            .expect("ruby analysis succeeds")
    }

    #[test]
    fn extracts_rails_routes_sources_sinks_and_sanitizers() {
        let source = r#"
namespace :admin do
  get "/users/:id", to: "users#show"
  resources :posts
end

class UsersController < ApplicationController
  before_action :authenticate_user!

  def show
    id = params[:id]
    user = User.find(id)
    ActiveRecord::Base.connection.execute("select * from users where id = #{id}")
    params.require(:user).permit(:name)
  end
end
"#;
        let facts = analyze_ruby("config/routes.rb", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/users/:id"
                && route.framework.as_deref() == Some("Rails")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/admin/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/posts#create")
        }));
        assert!(facts.symbols.iter().any(|symbol| {
            symbol.name == "UsersController#show" && symbol.kind == SymbolKind::Method
        }));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("params")));
        assert!(facts
            .data_sources
            .iter()
            .any(|source| source.name.as_deref() == Some("User.find")));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.kind == SinkKind::SqlQuery));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Authentication));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Validation));
        assert!(!facts.taint_edges.is_empty());
    }

    #[test]
    fn filters_namespaced_rails_resource_routes_with_only_and_except_options() {
        let source = r#"
namespace :admin do
  resources :posts, only: [:index]
  resources :comments, except: :destroy
end
"#;
        let facts = analyze_ruby("config/routes.rb", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/posts#index")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route
                .metadata
                .get("target")
                .is_some_and(|target| target == "admin/posts#create")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route
                .metadata
                .get("target")
                .is_some_and(|target| target == "admin/posts#destroy")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/comments"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/comments#index")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/admin/comments"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/comments#create")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route.method == "DELETE"
                && route.path == "/admin/comments/:id"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/comments#destroy")
        }));
    }

    #[test]
    fn qualifies_rails_scope_module_resource_targets_without_path_prefix() {
        let source = r#"
scope module: "admin" do
  resources :articles
end
"#;
        let facts = analyze_ruby("config/routes.rb", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/articles"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/articles#index")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "POST"
                && route.path == "/articles"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/articles#create")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route.path.starts_with("/admin/articles")
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target.starts_with("admin/articles#"))
        }));
    }

    #[test]
    fn composes_nested_rails_namespaces_for_resource_targets() {
        let source = r#"
namespace :admin do
  namespace :v1 do
    resources :posts
  end
end
"#;
        let facts = analyze_ruby("config/routes.rb", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/v1/posts"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/v1/posts#index")
        }));
    }

    #[test]
    fn nested_resource_block_does_not_leak_scope_to_sibling_routes() {
        let source = r#"
namespace :admin do
  resources :posts do
    get "preview", to: "posts#preview"
  end
  get "dashboard", to: "dashboard#show"
end
"#;
        let facts = analyze_ruby("config/routes.rb", source);

        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/posts/:posts_id/preview"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/posts#preview")
        }));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/dashboard"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/dashboard#show")
        }));
        assert!(!facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/admin/posts/:posts_id/dashboard"
                && route
                    .metadata
                    .get("target")
                    .is_some_and(|target| target == "admin/dashboard#show")
        }));
    }

    #[test]
    fn extracts_sinatra_routes_and_auth_filters_without_client_false_positive() {
        let source = r#"
require "sinatra"

before "/admin/*" do
  authenticate!
end

get "/hello/:name" do
  name = params[:name]
  CacheClient.get("/not-a-route")
  Mailer.deliver_later(name)
end
"#;
        let facts = analyze_ruby("app.rb", source);

        assert!(facts
            .imports
            .iter()
            .any(|import| import.module == "sinatra"));
        assert!(facts.routes.iter().any(|route| {
            route.method == "GET"
                && route.path == "/hello/:name"
                && route.framework.as_deref() == Some("Sinatra")
        }));
        assert!(!facts
            .routes
            .iter()
            .any(|route| route.path == "/not-a-route"));
        assert!(facts
            .sanitizers
            .iter()
            .any(|sanitizer| sanitizer.kind == SanitizerKind::Authentication));
        assert!(facts
            .sinks
            .iter()
            .any(|sink| sink.name.as_deref() == Some("Mailer.deliver_later")));
    }
}
