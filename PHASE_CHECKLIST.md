# Phase Checklist

## Phase 0 - Repository Bootstrap

- [x] Rust workspace exists, observed through npm wrapper Cargo fallback.
- [x] CLI crate exists, observed through npm wrapper Cargo fallback.
- [x] CLI help works through `node npm/backend-doctor/bin/backend-doctor.js --help`.
- [x] Node wrapper package skeleton exists.
- [x] Node wrapper forwards arguments to packaged binary or local Cargo fallback.
- [x] Node wrapper gives a clear bootstrap error when no Rust CLI is available.
- [x] Fixtures directory exists.
- [x] Schemas directory exists.
- [x] CI workflow scaffold exists.
- [x] README quick start exists.
- [x] Documentation scaffold exists.
- [x] Codex skill scaffold exists.

## Phase 1 - Finding Model, Config, Scoring, Report Output

- [x] Rule metadata model implemented and covered by workspace tests.
- [x] Finding model implemented and covered by workspace tests.
- [x] Config parsing and defaults implemented and covered by workspace tests.
- [x] Score algorithm implemented; empty fixture verified at score `100`.
- [x] Terminal summary renderer implemented.
- [x] Verbose renderer implemented; empty fixture `--verbose` output verified useful.
- [x] JSON output implemented; empty fixture `--json` verified parseable with score `100` and no findings.
- [x] Empty fixture acceptance verified.
- [x] Config and report schemas exist for the Phase 1 surfaces.
- [x] Release report fixtures, schema gates, and regression tests cover the current output surface.

## Phase 2 - Stack Detection And Project Graph

- [x] File inventory implemented and verified through polyglot project graph output.
- [x] Root detection implemented and verified through polyglot project graph output.
- [x] Language detection implemented with confidence and verified for Go, Java, and Node.
- [x] Monorepo detection implemented and verified through three detected services.
- [x] Service graph implemented and exposed in JSON output.
- [x] Framework detection basics implemented and verified for Express, Gin, and Spring Boot.
- [x] Infrastructure detection implemented for OpenAPI specs and migrations; verified with `api/openapi.yaml` and `db/migrations/001_init.sql`.
- [x] Diff plumbing exposed through debug/JSON output.
- [x] Debug output implemented and verified without secret-like values.
- [x] Polyglot fixture verified with `--debug`, `--json`, and `--score`.
- [x] Language finding rules implemented for release-scope Tier 1, Tier 2, and Tier 3 integrations.

## Phase 3 - Go Plugin MVP

- [x] Go fixture-backed heuristic scanner verified against `fixtures/go-bad-service`.
- [x] Go findings emitted through terminal, verbose, direct `--json`, and `--json-out` paths.
- [x] Go scan verification observed score `0`, `29` findings, and `1` suppressed finding.
- [x] Representative Go rule IDs verified, including `go/http-client-no-timeout`, `go/sql-string-concat`, `go/global-mutable-state`, `go/gin-route-missing-auth`, `go/fiber-cors-wildcard`, and `go/gofmt-required`.
- [x] Go findings sampled with location, evidence, remediation, and fix metadata.
- [x] `--fix-safe --dry-run` reported two `go/gofmt-required` safe fixes without modifying files.
- [x] Secret-like evidence check passed.
- [x] Empty and polyglot regression scans still pass.
- [x] Phase 3 verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] Release-scope Go rules and local checks verified.
- [ ] Optional network-backed external Go tool execution in hosted environments with explicit configuration.

## Phase 4 - Node/TypeScript Plugin MVP

- [x] Node/TypeScript fixture-backed heuristic scanner verified against `fixtures/node-express-bad-service`.
- [x] Node findings emitted through terminal, verbose, and `--json-out` paths.
- [x] Node scan verification observed score `15`, grade `Critical`, and `26` findings.
- [x] `node/floating-promise` verified at `src/routes/auth.ts:7:3` with evidence, remediation, and guided fix metadata.
- [x] `--fix-safe --dry-run` reported only two `node/console-log-production` safe fixes without modifying the fixture.
- [x] Redaction check passed.
- [x] Go, polyglot, and empty regression scans still pass.
- [x] Phase 4 re-verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] Release-scope Node/TypeScript rules and safe console-log remediation verified.
- [ ] Optional network-backed `npm audit` execution in hosted environments with explicit configuration.

## Phase 5 - Java/Spring Plugin MVP

- [x] Java/Spring fixture-backed heuristic scanner verified against `fixtures/java-spring-bad-service`.
- [x] Java findings emitted through verbose and `--json-out` paths.
- [x] Java scan verification observed score `19`, grade `Critical`, and `25` findings.
- [x] Java and Spring detection verified in the bad-service fixture.
- [x] Representative Java rule metadata verified, including `java/sql-string-concat`, hardcoded secret findings, `java/transactional-remote-call`, and `java/controller-bypasses-service-layer`.
- [x] Redaction check passed for SQL string concatenation and hardcoded secret findings.
- [x] Targeted location checks passed: `java/transactional-remote-call` only at `UserService.java:22`; `java/controller-bypasses-service-layer` only at `UserController.java:27` and `UserController.java:37`.
- [x] Go, Node, polyglot, and empty regression scans still pass.
- [x] Phase 5 re-verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] Release-scope Java/Spring rules verified.
- [ ] Optional Maven/Gradle/SpotBugs/Error Prone/OWASP Dependency-Check execution in hosted environments with explicit configuration.

## Phase 6 - Security, Dependencies, And Secrets

- [x] Security/dependency/secrets fixture-backed heuristic scanner verified against `fixtures/security-bad-service`.
- [x] Security findings emitted through verbose, direct JSON, and `--json-out` paths.
- [x] Security scan verification observed score `0`, grade `Critical`, and `22` findings.
- [x] Direct JSON verification observed `10` security findings and `11` dependency findings.
- [x] Fallback secret scanning verified with `7` `security/hardcoded-secret` findings and `7` secret fingerprints.
- [x] Redaction verified; raw fake secrets were not present in terminal or JSON output.
- [x] Representative rules verified, including `security/sensitive-logging`, `security/curl-pipe-shell`, `supply-chain/vulnerable-dependency`, unpinned GitHub action, unpinned Docker base, wildcard-version, git-dependency, and missing-lockfile checks.
- [x] Supply-chain fallback checks verified without network/tool execution by default.
- [x] Score caps verified at `39` and `49` for critical security/dependency cases.
- [x] Sensitive logging coverage verified through `security/sensitive-logging`.
- [x] Gitleaks, OSV, Trivy, Semgrep, and CodeQL SARIF parser helpers covered by tests.
- [x] Phase 6 verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] Regression scores verified: Go `0`/`29` findings, Node `11`/`28` findings, Java `0`/`27` findings with cap `39`, polyglot `88`/`7` findings, empty `100`/`0` findings.
- [x] SARIF output schema validation passed in release gates.
- [x] External stdout/stderr capture is bounded, redacted, and timeout-cleanup bounded.
- [ ] Optional external Gitleaks/OSV/Trivy/Semgrep/CodeQL execution in hosted environments with explicit configuration.

## Phase 7 - Infrastructure Plugin MVP

- [x] Infrastructure fixture-backed heuristic scanner verified against `fixtures/infra-bad-config`.
- [x] Infrastructure findings emitted through verbose, direct JSON, and `--json-out` paths.
- [x] Infrastructure scan verification observed score `0`, grade `Critical`, and `88` findings.
- [x] Direct JSON verification also observed `88` findings.
- [x] Representative Docker and Compose fallback rules verified.
- [x] Representative Kubernetes and Helm fallback rules verified.
- [x] Representative Terraform fallback rules verified.
- [x] Representative CI configuration fallback rules verified.
- [x] Representative OpenAPI and migration fallback rules verified.
- [x] Representative cross-layer fallback rules verified.
- [x] Sampled findings included location, evidence, remediation, and fix metadata.
- [x] Redaction verified with `24` redacted findings and no raw `bd_fixture` values.
- [x] Hadolint, Trivy, KubeLinter, Checkov, and Conftest parser helpers covered by tests.
- [x] Phase 7 verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] Regression scores verified: security `0`/`28` findings, Go `0`/`29` findings, Node `11`/`28` findings, Java `0`/`27` findings, polyglot `45`/`21` findings, empty `100`/`0` findings.
- [x] SARIF output schema validation passed in release gates.
- [x] Cache miss/hit comparison gates passed for infra fixtures.
- [ ] Optional external Hadolint/Trivy/KubeLinter/Checkov/Conftest execution in hosted environments with explicit configuration.

## Phase 8 - Autofix And Remediation Engine

- [x] Finding model includes fix safety and optional patch data for implemented fixable findings.
- [x] `--plan-fixes` exists and was verified with `fixtures/infra-bad-config`.
- [x] `--fix-safe --dry-run` was verified as non-mutating for Go and Node safe fixes.
- [x] `--fix-safe --yes` was verified on a temporary Node fixture copy and applied expected `.backend-doctor.toml` and `console.log` removals.
- [x] `--fix-rule` filter behavior was verified.
- [x] `--fix-finding` filter behavior was verified.
- [x] Guided semantic fix output was verified as preview by default, with guarded application only under explicit `--fix-guided --yes` temporary-copy safeguards.
- [x] Patch application checks original content before edit and applies fixes atomically per file.
- [x] Secret redaction applies to fix previews.
- [x] Safe fixes are implemented for supported deterministic fix families, including gofmt, Node console-log removal, basic `.dockerignore`, and config init.
- [x] Rollback failure behavior is covered by `atomic_write_failure_restores_original_and_cleans_sidecars`.
- [x] Phase 8 verifier passed `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`.
- [x] `cargo test -p backend-doctor-fix` passed 9 tests.
- [x] Guarded guided semantic fix application is implemented and verified only under explicit `--fix-guided --yes` temporary-copy safeguards.
- [x] Release-scope MVP remediation readiness verified.

## Phase 9 - CI, SARIF, Release

- [x] SARIF rendering includes release-scope metadata, including `runAutomationDetails` IDs.
- [x] SARIF readiness/structural checks are covered in CI/tests.
- [x] GitHub annotation generation is implemented.
- [x] `--fail-on` implements deterministic CI threshold behavior.
- [x] CI artifacts/upload readiness is implemented.
- [x] Release dry-run workflow is implemented.
- [x] npm wrapper dry-run publishability is verified.
- [x] CLI MVP commands `explain`, `init`, and `install --agent codex --yes` are deterministic.
- [x] Reserved advanced flags fail explicitly before subcommands.
- [x] Agent Slop MVP rules and Slop Index JSON/verbose output are implemented without AI/authorship claims.
- [x] Unsupported-language detection/generic coverage is implemented.
- [x] Representative generated report JSON Schema validation is covered.
- [x] 10,000-finding report rendering performance smoke gate is covered.
- [x] Full SARIF schema validation passed in release gates.
- [x] Local release binary, checksums, help, Docker build/run, and Homebrew formula generation are verified.
- [x] Tier 2 Python/C#/.NET/PHP/Rust and Tier 3 Ruby/Kotlin/Scala/Elixir/C/C++ release-scope integrations are verified.
- [x] Tier 2 clean Python/C#/.NET/PHP/Rust JSON and SARIF report goldens are verified locally at commit `256e109`.
- [x] PHP SQL AnalysisFacts consumption for `php/pdo-query-string-concat` is verified locally at commit `8ec7fda`.
- [ ] GitHub-hosted code scanning upload executed from GitHub with configured repository credentials.
- [ ] Public npm/Docker/Homebrew/GitHub release publishing after credentials, remotes, and hosted artifact URLs are configured.
- [ ] Homebrew formula syntax/audit on macOS with Ruby/Homebrew.
