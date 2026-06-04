# Output Formats

Backend Doctor can emit a human report, machine JSON, SARIF, GitHub annotations, or a bare score. stdout defaults to the human report; sidecar flags write files without changing stdout.

## Human terminal report (default)

```bash
backend-doctor .
```

Prints live progress, detection checkmarks, findings grouped by category and severity, and a 0–100 score card with per-category bars. Color is TTY-aware; control it with `NO_COLOR` / `BACKEND_DOCTOR_COLOR` / `CLICOLOR*` (see [CLI reference](cli-reference.md#color-control)).

```bash
backend-doctor . --verbose   # full finding detail
backend-doctor . --debug     # + detection / project-graph internals
```

## JSON

```bash
backend-doctor . --json                  # to stdout (machine-readable)
backend-doctor . --json-out report.json  # to a file (stdout stays human)
```

The JSON report conforms to the schema at [`schemas/backend-doctor-report.schema.json`](../schemas/backend-doctor-report.schema.json) and includes the score, summary counts, detection, and the full list of findings (id, rule, category, severity, confidence, location, fix metadata). The schema is gate-validated in CI.

## SARIF

```bash
backend-doctor . --sarif report.sarif    # to a file (stdout stays human)
```

SARIF output is schema-validated and loads into GitHub code scanning and other SARIF-aware tools. Golden SARIF fixtures live under `crates/backend-doctor-cli/tests/golden/sarif/`.

Upload it in CI:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```

## GitHub annotations

```bash
backend-doctor . --github-annotations
```

Emits `::warning`/`::error` workflow commands so findings appear inline on a pull request. See [CI integration](ci-integration.md).

## Score only

```bash
backend-doctor . --score
```

Prints just the numeric score on stdout — ideal for badges, dashboards, or shell conditionals. See [Scoring](scoring.md).

## Combining

`--json-out` and `--sarif` can be combined; the human report still prints to stdout while both files are written:

```bash
backend-doctor . --json-out report.json --sarif report.sarif
```

Use `--json` or `--score` when you need a machine-readable **stdout** instead of the human report.
