# Backend Doctor Documentation

Everything needed to install, run, configure, and integrate Backend Doctor.

## Start here

1. [Installation](installation.md) — get the CLI on your machine (npm, source, Docker).
2. [Getting started](getting-started.md) — run your first scan and read the report.

## Reference

- [CLI reference](cli-reference.md) — every subcommand and flag, with examples.
- [Configuration](configuration.md) — the `.backend-doctor.toml` file and all its keys.
- [Output formats](output-formats.md) — human terminal, JSON, SARIF, GitHub annotations.
- [Scoring](scoring.md) — how the 0–100 health score and category scores are computed.
- [Rules](rules.md) — categories, severities, language coverage, and the rule id scheme.

## Integration

- [CI integration](ci-integration.md) — gates, exit codes, and a GitHub Actions example.
- [Agent integration](agent-integration.md) — the Backend Doctor skill and the `install` command.
- [Privacy & security](privacy-security.md) — the local-by-default and redaction model.

## Contributing / internals

- [Architecture](architecture.md) — the crate workspace and building from source.

## Repository references

- [`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) — what is implemented and verified.
- [`RULE_REGISTRY.md`](../RULE_REGISTRY.md) — the authoritative rule list.
- [`SECURITY.md`](../SECURITY.md) — security policy and reporting.
- [`CHANGELOG.md`](../CHANGELOG.md) — release notes.
