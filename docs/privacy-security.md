# Privacy & Security

## Local by default

Backend Doctor runs entirely on your machine. It does **not** upload source code, findings, dependency metadata, or secrets. There is no telemetry in the default scan.

Any check that could reach the network or run external tooling is **off by default** and must be explicitly enabled, per run or in config:

| Capability | Flag | Config (`[external-tools]`) |
| --- | --- | --- |
| Network-capable checks | `--network` | `network` |
| Deep external checks | `--deep` | `deep` |
| Test-running checks | `--run-tests` | `run-tests` |
| Git history scans | `--scan-history` | `scan-history` |
| Installing missing tools | `--install-missing-tools` | `install-missing-tools` |

See [Configuration](configuration.md) and the [CLI reference](cli-reference.md#external--network-checks-opt-in).

## Secret redaction

Findings and diagnostics redact raw secret values. Reports surface the location and rule of a secret finding (e.g. `gitleaks/secret`) without echoing the secret material itself.

## Suppressions are auditable

Silencing a finding is explicit and recorded in `.backend-doctor.toml` with a `reason`, so suppressions are reviewable in version control rather than hidden:

```toml
[[suppressions]]
rule = "go/global-mutable-state"
path = "internal/state/state.go"
reason = "Documented in ADR-7."
```

## Determinism

Scores are deterministic for the same inputs, so results are reproducible across machines and CI runs.

## Reporting a vulnerability

Security policy and the responsible-disclosure process are in [`SECURITY.md`](../SECURITY.md).
