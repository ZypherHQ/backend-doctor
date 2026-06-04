# Getting Started

This walks through a first scan and how to read the result. Commands use the source form (`cargo run ...`); substitute `backend-doctor` if you installed it with npm or another method (see [Installation](installation.md)).

## 1. Scan a project

```bash
cargo run -q -p backend-doctor-cli -- /path/to/your/service
```

With no flags, Backend Doctor:

1. Detects the backend stacks in the directory (Go, Node, Java, Python, …).
2. Builds a project graph and runs every applicable built-in rule.
3. Streams live progress, then prints a terminal report.

The report has three parts:

- **Detection** — checkmarks for the languages, frameworks, and infrastructure found.
- **Findings** — grouped by category and severity, each with a rule id and location.
- **Score card** — a 0–100 health score with a label (Excellent / Great / Needs Work / Critical) and per-category bars.

## 2. Just the number

For dashboards or quick checks:

```bash
cargo run -q -p backend-doctor-cli -- . --score
```

This prints only the numeric score on stdout. See [Scoring](scoring.md) for how it is computed.

## 3. See more detail

```bash
cargo run -q -p backend-doctor-cli -- . --verbose   # full finding detail
cargo run -q -p backend-doctor-cli -- . --debug     # + detection / project-graph internals
cargo run -q -p backend-doctor-cli -- . --trace     # trace diagnostics to stderr
```

## 4. Understand a finding

Every finding carries a rule id. Explain it, or inspect a location:

```bash
cargo run -q -p backend-doctor-cli -- . explain go/http-client-no-timeout
cargo run -q -p backend-doctor-cli -- . explain internal/client/client.go:12
```

List the rules that exist:

```bash
cargo run -q -p backend-doctor-cli -- . rules --language go
cargo run -q -p backend-doctor-cli -- . rules --category security --json
```

## 5. Scan only what changed

In a git repository, restrict the scan to changes against a base ref:

```bash
cargo run -q -p backend-doctor-cli -- . --diff main
```

## 6. Machine-readable output

```bash
cargo run -q -p backend-doctor-cli -- . --json                       # JSON to stdout
cargo run -q -p backend-doctor-cli -- . --json-out report.json       # JSON sidecar file
cargo run -q -p backend-doctor-cli -- . --sarif report.sarif         # SARIF sidecar file
```

With `--json-out`/`--sarif` the human report still prints to stdout while the files are written alongside. See [Output formats](output-formats.md).

## 7. Add a config (optional)

Generate a starter `.backend-doctor.toml` in the project:

```bash
cargo run -q -p backend-doctor-cli -- . init --yes
```

This lets you set gate thresholds, disable rules, and suppress known findings. See [Configuration](configuration.md).

## 8. Try a fix

```bash
cargo run -q -p backend-doctor-cli -- . --plan-fixes      # preview only, writes nothing
cargo run -q -p backend-doctor-cli -- . --fix-safe --yes  # apply safe fixes
```

Full fix semantics are in the [CLI reference](cli-reference.md#fix-flags).

## Where to go next

- [CLI reference](cli-reference.md) — the complete flag surface.
- [CI integration](ci-integration.md) — fail a build when the score drops.
- [Rules](rules.md) — what gets checked and why.
