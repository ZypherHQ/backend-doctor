# Agent Integration

Backend Doctor is designed to be driven by coding agents (Claude Code, Codex, and similar) so an agent can audit a repository, triage findings, and fix them until the score reaches 100.

## The Backend Doctor skill

The skill definition lives at [`skills/backend-doctor/SKILL.md`](../skills/backend-doctor/SKILL.md). It tells an agent when and how to run Backend Doctor and how to iterate on fixes.

A typical agent invocation runs a deep scan without failing the process, so the agent can read every finding:

```bash
backend-doctor <PROJECT> --deep --no-fail
```

### Command selection for agents

The skill prefers verified workflows, in order:

```bash
# Published package
npm install -g @zypherhq/backend-doctor@latest
backend-doctor <PROJECT> --deep --no-fail

# From source
cargo run -q -p backend-doctor-cli -- <PROJECT> --deep --no-fail

# Local npm wrapper (validates wrapper behavior)
node npm/backend-doctor/bin/backend-doctor.js <PROJECT> --deep --no-fail

# Staged release binary, if built
./dist/backend-doctor-x86_64-unknown-linux-gnu/backend-doctor <PROJECT> --deep --no-fail

# Debug build fallback
./target/debug/backend-doctor <PROJECT> --deep --no-fail
```

## The `install` command

`install` prints local integration instructions for an agent:

```bash
backend-doctor . install
backend-doctor . install --agent <name>
backend-doctor . install --yes        # non-interactive
```

## Recommended agent loop

1. Scan with `--deep --no-fail --json` to get structured findings.
2. For each finding, `explain <rule-id>` (or `explain file:line`) to understand it.
3. Preview fixes with `--plan-fixes`; apply safe ones with `--fix-safe --yes`.
4. For semantic fixes, use `--fix-guided --yes` (temporary-copy safeguarded).
5. Re-scan and repeat until the score reaches 100.

Scope fixes with `--fix-rule <id>` or `--fix-finding <id>` to keep each change small and reviewable. The fix safety model is described in the [CLI reference](cli-reference.md#fix-flags).
