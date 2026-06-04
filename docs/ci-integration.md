# CI Integration

Backend Doctor is built to gate builds. Run it with `--ci` plus thresholds, and it exits non-zero when a gate fails.

## Gates and exit codes

```bash
backend-doctor . --ci --min-score 80 --max-critical 0 --max-errors 5 --fail-on security
```

| Flag | Fails the build when… |
| --- | --- |
| `--min-score <N>` | the score is below `N`. |
| `--max-critical <N>` | critical findings exceed `N`. |
| `--max-errors <N>` | error findings exceed `N`. |
| `--fail-on <LIST>` | any finding matches a listed severity or category (comma-separated). |

Gates can also live in `.backend-doctor.toml` under `[thresholds]` (see [Configuration](configuration.md)); CLI flags override the file.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed; all gates passed. |
| `1` | A gate failed. |
| `2` | Usage / configuration error. |
| `3` | Operation could not complete. |
| `4` | Internal error. |

`--no-fail` forces exit `0` after a completed scan (useful when you only want to publish a report, not block the build).

> A gate is only enforced when at least one of `--ci`, `--min-score`, `--max-critical`, `--max-errors`, or `--fail-on` is set. A plain scan exits `0`.

## GitHub Actions

A minimal job that scans, annotates the PR, and uploads SARIF to code scanning:

```yaml
name: backend-doctor
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Run Backend Doctor
        run: npx -y backend-doctor@latest . \
               --ci --min-score 80 --max-critical 0 \
               --github-annotations \
               --sarif backend-doctor.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: backend-doctor.sarif
```

`--github-annotations` makes findings show up inline on the PR. `if: always()` uploads the SARIF even when the gate failed the previous step.

### Scan only changed files

For fast PR checks, restrict to the diff against the base branch:

```bash
backend-doctor . --diff "${{ github.base_ref }}" --ci --min-score 80
```

## Other CI systems

Any system works — call the binary, set thresholds, and react to the exit code:

```bash
backend-doctor . --ci --min-score 80 || exit 1
```

## This repository's own CI

The workflow at [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs Rust format/lint/test, npm wrapper tests, fixture/report checks, JSON Schema and SARIF validation, cache comparison, GitHub-annotation readiness, release dry-run checks, and a bounded 10,000-finding rendering performance smoke test.
