# Configuration

Backend Doctor reads an optional `.backend-doctor.toml` file from the scan root. Without it, sensible defaults apply. Generate a starter file with:

```bash
backend-doctor . init --yes
```

All keys use **kebab-case** and unknown keys are rejected (`deny_unknown_fields`), so a typo surfaces as an error rather than being silently ignored.

## Full example

```toml
# Include files normally ignored by .gitignore
include-gitignored = false

# Allow network-capable checks
network = false

# Default human/JSON output mode: "summary" | "verbose" | "json"
output-mode = "summary"

# Rules to turn off entirely
disabled-rules = ["go/global-mutable-state"]

[thresholds]
min-score = 75        # gate: fail below this score
max-critical = 0      # gate: fail above this many critical findings
max-errors = 10       # gate: fail above this many error findings

[external-tools]
deep = false
run-tests = false
scan-history = false
install-missing-tools = false
network = false
default-timeout-ms = 30000

[cache]
enabled = true
location = "project"               # or another supported location
# directory = ".backend-doctor-cache"

[analysis]
enabled = true
cache = true
# adapters = ["go", "node", "java"]   # restrict to specific language adapters

# Per-rule overrides
[rules."go/http-client-no-timeout"]
# severity / enabled overrides supported per rule

# Suppress known findings
[[suppressions]]
rule = "go/global-mutable-state"
path = "internal/state/state.go"
reason = "Single global is intentional here; documented in ADR-7."
```

## Key reference

### Top level

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `include-gitignored` | bool | `false` | Scan files normally ignored by `.gitignore`. |
| `network` | bool | `false` | Allow network-capable checks. |
| `output-mode` | enum | `summary` | `summary`, `verbose`, or `json`. |
| `disabled-rules` | array | `[]` | Rule ids to disable completely. |

### `[thresholds]` — CI gates

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `min-score` | int | `75` | Fail when the score is below this. |
| `max-critical` | int | unset | Fail when critical findings exceed this. |
| `max-errors` | int | unset | Fail when error findings exceed this. |

CLI flags `--min-score`, `--max-critical`, `--max-errors` override these for a single run.

### `[external-tools]` — opt-in checks

All default to `false`. They mirror the `--deep`, `--run-tests`, `--scan-history`, `--install-missing-tools`, and `--network` flags. `default-timeout-ms` bounds external tool execution.

### `[cache]`

Controls the diff/deep scan cache. `enabled` toggles caching; `location`/`directory` choose where it lives.

### `[analysis]`

| Key | Meaning |
| --- | --- |
| `enabled` | Turn the language-analysis layer on/off. |
| `cache` | Cache analysis results. |
| `adapters` | Restrict analysis to a subset of language adapters. |

### `[rules."<id>"]`

Per-rule configuration table, keyed by rule id (e.g. `"go/http-client-no-timeout"`).

### `[[suppressions]]`

Repeatable table to silence a specific finding.

| Field | Required | Meaning |
| --- | --- | --- |
| `rule` | yes | Rule id to suppress. |
| `path` | yes | File path the suppression applies to. |
| `reason` | recommended | Why it is suppressed (kept for auditability). |

Suppressed findings contribute **zero** penalty to the score (see [Scoring](scoring.md)).

## Precedence

CLI flags override config-file values, which override built-in defaults.
