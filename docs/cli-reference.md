# CLI Reference

```
backend-doctor [PATH] [SCAN FLAGS]
backend-doctor [PATH] <SUBCOMMAND>
```

`PATH` is the project directory to scan and defaults to `.`. With no subcommand, Backend Doctor runs a scan. The flag list below is exhaustive — it mirrors the clap definition in `crates/backend-doctor-cli/src/lib.rs`.

> In a source checkout, prefix everything with `cargo run -q -p backend-doctor-cli --`, e.g. `cargo run -q -p backend-doctor-cli -- . --json`.

## Subcommands

### `explain <TARGET>`

Explain a rule id, or the findings at a `file:line` location.

```bash
backend-doctor . explain go/http-client-no-timeout
backend-doctor . explain src/server.go:42
```

### `rules`

List built-in rules.

| Flag | Description |
| --- | --- |
| `--language <LANG>` | Show only rules for this language. |
| `--category <CAT>` | Show only rules in this category. |
| `--json` | Print rule metadata as JSON. |

```bash
backend-doctor . rules --language go
backend-doctor . rules --category security --json
```

### `init`

Create a default `.backend-doctor.toml` in the project.

| Flag | Description |
| --- | --- |
| `--yes` | Confirm writing the config in non-interactive mode. |

### `install`

Print local agent integration instructions (see [Agent integration](agent-integration.md)).

| Flag | Description |
| --- | --- |
| `--agent <NAME>` | Agent integration to describe. |
| `--yes` | Confirm install guidance in non-interactive mode. |

## Scan flags

### Output and verbosity

| Flag | Description |
| --- | --- |
| `-v`, `--verbose` | Print the verbose human report (full finding detail). |
| `--debug` | Include detection and project-graph debug details. |
| `--trace` | Print trace diagnostics to stderr; stdout format is preserved. |
| `--score` | Print only the numeric score. |
| `--json` | Print the full report as JSON on stdout. |
| `--json-out <PATH>` | Write a JSON report sidecar file (stdout stays human). |
| `--sarif <PATH>` | Write a SARIF report sidecar file (stdout stays human). |
| `--github-annotations` | Emit GitHub workflow annotations for findings. |

### Scope

| Flag | Description |
| --- | --- |
| `--diff <BASE>` | Scan only changes relative to a git base ref. |
| `--include-gitignored` | Include files normally ignored by `.gitignore`. |

### CI gates

| Flag | Description |
| --- | --- |
| `--ci` | Use CI output behavior and configured gates. |
| `--min-score <N>` | Fail when the score is below `N`. |
| `--max-critical <N>` | Fail when critical findings exceed `N`. |
| `--max-errors <N>` | Fail when error findings exceed `N`. |
| `--fail-on <LIST>` | Fail on severities or categories, comma-separated (e.g. `security,critical`). |
| `--no-fail` | Always exit `0` after a completed scan. |

See [CI integration](ci-integration.md) for exit-code semantics.

### Fix flags

| Flag | Description |
| --- | --- |
| `--plan-fixes` | Print a fix plan without applying changes. |
| `--fix-safe` | Apply safe fixes (requires `--yes`). |
| `--fix-guided` | Preview guided fixes; apply only with `--yes`. |
| `--fix-rule <ID>` | Restrict fixes to one rule id. |
| `--fix-finding <ID>` | Restrict fixes to one finding id or fingerprint. |
| `--dry-run` | Preview fixes without writing files. |
| `--yes` | Confirm non-interactive fix application. |

**Safety model.** Safe fixes apply only when you pass `--yes`. Guided (semantic / riskier) fixes **preview by default** and apply only with the explicit `--fix-guided --yes`, which uses temporary-copy safeguards. In CI, `--fix-guided` requires `--yes` for an explicit guided preview.

### External / network checks (opt-in)

These are off by default and require explicit flags (or config). See [Privacy & security](privacy-security.md).

| Flag | Description |
| --- | --- |
| `--deep` | Enable configured deep external checks. |
| `--run-tests` | Allow configured test-running external checks. |
| `--scan-history` | Allow configured git history scans. |
| `--install-missing-tools` | Allow configured missing-tool installation. |
| `--network` | Allow network-capable checks. |

## Color control

The human report is TTY-aware. Color is disabled automatically for `NO_COLOR`, non-TTY captures, `--json`, `--score`, CI, and fix-plan modes.

| Variable | Effect |
| --- | --- |
| `NO_COLOR` | Disables color; always overrides forced color. |
| `BACKEND_DOCTOR_COLOR=always` | Force color (when `NO_COLOR` is unset). |
| `BACKEND_DOCTOR_COLOR=never` | Disable color. |
| `CLICOLOR_FORCE=1` | Force color (when `NO_COLOR` is unset). |
| `CLICOLOR=0` | Disable color. |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and all gates passed. |
| `1` | A configured gate failed (score / critical / errors / `--fail-on`). |
| `2` | Usage or configuration error. |
| `3` | The requested operation could not complete (e.g. explain target not found, fix conflict). |
| `4` | Internal error (e.g. report serialization failure). |

`--no-fail` forces exit `0` after any completed scan.
