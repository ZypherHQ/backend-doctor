# Rules

Backend Doctor ships ~150 built-in rules (`backend-doctor . rules` lists 148). Each rule has an id of the form `domain/short-name` (e.g. `go/http-client-no-timeout`), a category, a severity, a confidence, and an optional fix.

The authoritative, generated list is [`RULE_REGISTRY.md`](../RULE_REGISTRY.md). This page explains the scheme and coverage. List rules live from the CLI:

```bash
backend-doctor . rules                       # all rules
backend-doctor . rules --language go         # one language
backend-doctor . rules --category security   # one category
backend-doctor . rules --json                # machine-readable
```

## Categories

| Category | Focus |
| --- | --- |
| architecture | Structure, layering, coupling. |
| correctness | Bugs and incorrect logic. |
| dependencies | Vulnerable / risky dependencies and supply chain. |
| infrastructure | Docker, Kubernetes, Terraform, CI config. |
| reliability | Timeouts, error handling, concurrency, resilience. |
| security | Auth, injection, secrets, CORS, exposure. |
| testing | Missing / fake / placeholder tests. |
| maintainability | Readability, duplication, dead code. |

## Severities

From most to least severe: `critical`, `error`, `warning`, `info`, `note`. Severity drives both the score penalty (see [Scoring](scoring.md)) and CI gates (`--max-critical`, `--max-errors`, `--fail-on`).

## Rule domains and coverage

Rule ids are grouped by domain. Counts are approximate (run `backend-doctor . rules` for the live list):

| Domain | Rules | Notes |
| --- | --- | --- |
| `node` | ~126 | Node / TypeScript / JavaScript |
| `java` | ~106 | Java / Spring |
| `go` | ~72 | Go / Gin / Fiber |
| `infra` | ~65 | Docker, Kubernetes, infrastructure config |
| `python` | ~63 | Python / FastAPI / Django / Flask |
| `agent` | ~42 | Agent-generated "slop" code patterns |
| `csharp` | ~38 | C# / .NET |
| `php` | ~34 | PHP / Laravel / Symfony |
| `rust` | ~30 | Rust |
| `ci` | ~26 | CI workflow safety |
| `terraform` | ~20 | Terraform |
| `security` | ~20 | Cross-language security |
| `api` | ~19 | API / OpenAPI contract checks |
| `migration` | ~13 | Database migrations |
| `kotlin` | ~11 | Kotlin / Ktor |
| `ruby` | ~10 | Ruby / Rails |
| `cpp` | ~10 | C++ |
| `scala` | ~9 | Scala |
| `elixir` | ~9 | Elixir / Phoenix |
| `core` | ~9 | Bootstrap / unsupported-language coverage |
| `c` | ~7 | C |
| `gitleaks`, `net`, `js`, `symfony` | a few | Secrets and framework-specific |

## Maturity tiers

Coverage depth differs by language:

- **Tier 1 (most mature):** Go, Node/TypeScript, Java, plus the cross-cutting security, infrastructure, API/OpenAPI, dependency, secrets, and agent-slop rules.
- **Tier 2:** Python, C#/.NET, PHP, Rust — fixture-backed but narrower.
- **Tier 3:** Ruby, Kotlin, Scala, Elixir, C, C++ — intentionally shallow first integrations.

See [`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) for the per-tier detail.

## Language detection

Detection is evidence-based: manifest files (`go.mod`, `pom.xml`, `pyproject.toml`, `Gemfile`, `composer.json`, `Cargo.toml`, `mix.exs`, `build.sbt`, `package.json`, …) and source extensions map to languages, and framework markers (e.g. `github.com/gin-gonic/gin`, `org.springframework.boot`) refine the result. Detected languages include Go, Java, Kotlin, Node/TypeScript/JavaScript, Python, Ruby, PHP, C#, Rust, Clojure, Scala, Elixir, C, and C++.

## Explaining and suppressing

- Explain a rule or a location with `explain` (see [CLI reference](cli-reference.md#explain-target)).
- Disable a rule globally via `disabled-rules`, or silence a specific finding via `[[suppressions]]` (see [Configuration](configuration.md)).

The fixtures under `fixtures/<lang>-good-service` and `fixtures/<lang>-bad-service` are the canonical examples of clean vs. flagged code for each language.
