# Architecture

Backend Doctor is a Rust workspace (edition 2021) of focused crates, plus an npm command wrapper. This page is for contributors and anyone building from source.

## Crate workspace

Defined in [`Cargo.toml`](../Cargo.toml) (resolver 2):

| Crate | Responsibility |
| --- | --- |
| `backend-doctor-cli` | Command-line entry point; clap parsing, scan orchestration, exit codes. |
| `backend-doctor-detect` | Stack detection and project-graph construction from evidence. |
| `backend-doctor-analysis` | Per-language source adapters (13 languages under `src/adapters/`). |
| `backend-doctor-rules` | Built-in rule engine; runs rules over analysis facts. |
| `backend-doctor-core` | Finding model, config (`.backend-doctor.toml`), scoring, categories/severities. |
| `backend-doctor-fix` | Fix planning, selection, and application (safe / guided). |
| `backend-doctor-report` | Rendering: terminal, JSON, SARIF, GitHub annotations. |
| `backend-doctor-cache` | Diff and deep-scan caching. |
| `backend-doctor-plugin-api` | Plugin surface for extending analysis/rules. |

### Data flow

```
detect  →  analysis  →  rules  →  core (findings + score)  →  report
                                        ↑                        ↓
                                     config                  fix (optional)
```

`detect` identifies stacks and builds a project graph; `analysis` adapters turn sources into facts; `rules` produces findings; `core` applies config, suppressions, and scoring; `report` renders; `fix` optionally plans and applies remediations.

## Language adapters

Adapters live in `crates/backend-doctor-analysis/src/adapters/`: `c`, `cpp`, `csharp`, `elixir`, `go`, `java`, `kotlin`, `node`, `php`, `python`, `ruby`, `rust`, `scala` (plus `common`). Each turns source files into the analysis facts the rule engine consumes.

## npm wrapper

`npm/backend-doctor/` is a thin Node wrapper (`bin/backend-doctor.js`) that runs a packaged platform binary, or falls back to `cargo run` against a source checkout. Its allowlisted `files` and release-staging scripts are in `npm/backend-doctor/package.json`. See [Installation](installation.md) for the resolution order.

## Building and testing

```bash
# Build everything
cargo build --release

# Run the full test suite
cargo test

# Run the CLI
cargo run -q -p backend-doctor-cli -- .

# npm wrapper tests
npm test --prefix npm/backend-doctor
```

The Docker build pins `rust 1.93` (see [`Dockerfile`](../Dockerfile)).

## Fixtures and golden files

- `fixtures/<lang>-good-service` / `fixtures/<lang>-bad-service` — canonical clean vs. flagged projects per language.
- `crates/backend-doctor-cli/tests/golden/reports/*.json` — golden JSON reports (the source of truth for finding counts).
- `crates/backend-doctor-cli/tests/golden/sarif/*.sarif.json` — golden SARIF outputs.
- `schemas/backend-doctor-report.schema.json` — the report JSON Schema, validated in CI.

When a rule change moves a fixture's findings, regenerate and commit the matching golden files, and note score-affecting changes in [`CHANGELOG.md`](../CHANGELOG.md).

## Release

Release packaging stages verified platform binaries and checksums into the npm package before `npm pack`/`npm publish`. The process is documented in [`RELEASE_RUNBOOK.md`](../RELEASE_RUNBOOK.md), with publishing workflows under `.github/workflows/`.
