# Backend Doctor

> Polyglot backend code-health CLI. Scan a repository, detect the backend stacks in it, report issues, get a 0–100 health score, and apply verified safe fixes.

Backend Doctor walks a project, figures out which backend languages and frameworks it uses, runs built-in rules across security, reliability, correctness, architecture, dependencies, infrastructure, testing, and maintainability, and prints a React-Doctor-style terminal report with a branded score card. It can also emit machine-readable JSON or SARIF, gate CI builds, and preview or apply remediations.

It runs **locally by default** and does not upload your source, findings, or secrets.

---

## Contents

- [Quick start](#quick-start)
- [What it checks](#what-it-checks)
- [Install](#install)
- [Output formats](#output-formats)
- [CI gating](#ci-gating)
- [Fixes](#fixes)
- [Documentation](#documentation)
- [Project layout](#project-layout)
- [Status](#status)
- [License](#license)

---

## Quick start

Once the package is published, the fastest path is npm:

```bash
npx -y @zypherhq/backend-doctor@latest .
```

Working from source in this repository:

```bash
# Human report for the current directory
cargo run -q -p backend-doctor-cli -- .

# Numeric score only
cargo run -q -p backend-doctor-cli -- . --score

# Full flag list
cargo run -q -p backend-doctor-cli -- . --help
```

The default scan streams live progress, then prints detection checkmarks, grouped findings, and a 0–100 score card. See [docs/getting-started.md](docs/getting-started.md) for a guided first run.

---

## What it checks

**Languages detected:** Go, Node/TypeScript/JavaScript, Java, Python, Ruby, PHP, Rust, C#/.NET, Kotlin, Scala, Elixir, C, C++ (plus Clojure detection).

**Categories:** architecture, correctness, dependencies, infrastructure, reliability, security, testing, maintainability.

**Examples of built-in rules** (~150 rules across 13 language adapters plus security, infrastructure, CI, API/OpenAPI, dependency, secrets, and agent-generated-code checks):

- `go/http-client-no-timeout`, `go/gin-route-missing-auth`, `go/error-ignored`
- `csharp/sql-string-interpolation`, `csharp/cors-allow-any-origin`
- `api/openapi-missing-auth`, `api/route-spec-drift`
- `ci/curl-pipe-shell`, `ci/github-action-unpinned`, `ci/secrets-printed`
- `agent/placeholder-test`, `agent/swallowed-error`, `agent/spaghetti-control-flow`

Browse the rule catalogue in [docs/rules.md](docs/rules.md). Explain any rule or location:

```bash
cargo run -q -p backend-doctor-cli -- . explain go/http-client-no-timeout
cargo run -q -p backend-doctor-cli -- . explain src/server.go:42
```

---

## Install

| Method | Command | Notes |
| --- | --- | --- |
| npm (after publish) | `npx -y @zypherhq/backend-doctor@latest .` | Node ≥ 18; downloads the matching Linux, macOS, or Windows binary |
| From source | `cargo run -q -p backend-doctor-cli -- .` | Needs the Rust toolchain |
| Local npm wrapper | `node npm/backend-doctor/bin/backend-doctor.js .` | Wrapper used during development |
| Docker | `docker build -t backend-doctor . && docker run --rm -v "$PWD":/work backend-doctor /work` | Entry point is `backend-doctor` |

Full instructions, including the wrapper fallback chain and Homebrew, are in [docs/installation.md](docs/installation.md).

---

## Output formats

```bash
backend-doctor .                      # human terminal report (default)
backend-doctor . --json               # machine-readable JSON on stdout
backend-doctor . --score              # numeric score only
backend-doctor . --json-out report.json --sarif report.sarif   # sidecar files
backend-doctor . --github-annotations # GitHub workflow annotations
```

SARIF output is schema-validated and loads into GitHub code scanning. Details and the JSON shape are in [docs/output-formats.md](docs/output-formats.md).

---

## CI gating

```bash
backend-doctor . --ci --min-score 80 --max-critical 0 --fail-on security
```

Exit codes: `0` pass, `1` a gate failed, `2` usage/config error, `3` operation could not complete, `4` internal error. A ready-to-copy GitHub Actions job is in [docs/ci-integration.md](docs/ci-integration.md).

---

## Fixes

```bash
backend-doctor . --plan-fixes                 # preview a fix plan, write nothing
backend-doctor . --fix-safe --yes             # apply safe fixes
backend-doctor . --fix-guided --yes           # apply guided fixes with copy safeguards
```

Safe fixes apply only with `--yes`. Guided (semantic / riskier) fixes preview by default and apply only with the explicit `--fix-guided --yes`. See [docs/cli-reference.md](docs/cli-reference.md#fix-flags).

---

## Documentation

All guides live in [`docs/`](docs/):

- [Installation](docs/installation.md) — npm, source, Docker, the wrapper fallback chain
- [Getting started](docs/getting-started.md) — first scan, reading the report
- [CLI reference](docs/cli-reference.md) — every subcommand and flag
- [Configuration](docs/configuration.md) — the `.backend-doctor.toml` file
- [Scoring](docs/scoring.md) — how the 0–100 score is computed
- [Rules](docs/rules.md) — categories, severities, language coverage
- [Output formats](docs/output-formats.md) — human, JSON, SARIF, annotations
- [CI integration](docs/ci-integration.md) — gates, exit codes, GitHub Actions
- [Agent integration](docs/agent-integration.md) — the Claude/Codex skill and `install`
- [Architecture](docs/architecture.md) — crate workspace and building from source
- [Privacy & security](docs/privacy-security.md) — local-by-default and redaction

---

## Project layout

```
crates/                 Rust workspace
  backend-doctor-cli      command-line entry point
  backend-doctor-detect   stack detection and project graph
  backend-doctor-analysis language adapters (13 languages)
  backend-doctor-rules    built-in rule engine
  backend-doctor-core     finding model, config, scoring
  backend-doctor-fix      fix planning and application
  backend-doctor-report   terminal / JSON / SARIF rendering
  backend-doctor-cache    diff and deep-scan caching
  backend-doctor-plugin-api  plugin surface
npm/backend-doctor/     npm command wrapper
schemas/                JSON Schema for the report
fixtures/               per-language good/bad test projects
docs/                   user documentation
skills/backend-doctor/  agent skill definition
```

---

## Status

Local release candidate. The Rust CLI, npm wrapper, stack detection, scoring, JSON/SARIF output, CI mode, diff/deep cache, and safe/guided autofix are implemented and verified locally. Tier 1 (Go, Node/TypeScript, Java, security, infrastructure, API/OpenAPI, agent-slop) rules are the most mature; Tier 2 (Python, C#/.NET, PHP, Rust) and Tier 3 (Ruby, Kotlin, Scala, Elixir, C, C++) have fixture-backed integrations that are intentionally shallow. Public npm publishing and hosted binary distribution require release credentials.

---

## License

MIT. See the workspace manifest and `npm/backend-doctor/package.json`.
