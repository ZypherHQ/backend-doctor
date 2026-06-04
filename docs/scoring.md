# Scoring

Backend Doctor reports a deterministic **0–100** health score plus a score per category. The same inputs always produce the same score.

## Labels

| Score | Label |
| --- | --- |
| 90–100 | Excellent |
| 75–89 | Great |
| 50–74 | Needs Work |
| 0–49 | Critical |

An empty project scores `100`.

## How a score is computed

The overall score and each category score use the same formula:

```
score = round( 100 − Σ penalty(finding) ) clamped to [0, 100]
```

### Per-finding penalty

```
penalty = severity_weight × confidence_multiplier × fix_safety_multiplier × location_multiplier
```

**Severity weight**

| Severity | Weight |
| --- | --- |
| critical | 12.0 |
| error | 5.0 |
| warning | 2.0 |
| info | 0.5 |
| note | 0.0 |

**Confidence multiplier**

| Confidence | Multiplier |
| --- | --- |
| high | 1.0 |
| medium | 0.75 |
| low | 0.35 |

**Fix-safety multiplier** — findings with a known safe fix are penalized slightly less:

| Fix safety | Multiplier |
| --- | --- |
| safe | 0.9 |
| none / guided / risky | 1.0 |

**Location multiplier** — a finding under a `testdata/` path is multiplied by `0.25` (test fixtures matter less than production code).

**Suppressed findings** contribute `0` (see suppressions in [Configuration](configuration.md)).

## Category scores

The score is computed once over all findings for the overall value, and once per category (architecture, correctness, dependencies, infrastructure, reliability, security, testing, maintainability) for the per-category bars shown in the report.

## Score caps

Certain high-risk findings **cap** the maximum score — for example critical secrets or critical vulnerabilities can pull the ceiling down regardless of an otherwise clean project. The overall value is the minimum of the base score and every applicable cap.

## Using the score

- `--score` prints only the numeric value, for automation.
- `--min-score <N>` (or `thresholds.min-score`, default `75`) fails CI when the score drops below `N`.

Rule changes that affect scores are documented in release notes. The checked-in fixture reports under `crates/backend-doctor-cli/tests/golden/reports/` are the source of truth for exact counts.
