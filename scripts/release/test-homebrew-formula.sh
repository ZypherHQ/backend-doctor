#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
formula="${1:-$repo_root/dist/homebrew/backend-doctor.rb}"

test -f "$formula"

if command -v ruby >/dev/null 2>&1; then
  ruby -c "$formula"
else
  printf 'Ruby is unavailable; skipped formula syntax check: %s\n' "$formula"
fi

if ! command -v brew >/dev/null 2>&1; then
  printf 'Homebrew is unavailable; skipped Homebrew audit: %s\n' "$formula"
  exit 0
fi

brew audit --formula --strict --online=false "$formula"
