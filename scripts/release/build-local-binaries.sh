#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${BACKEND_DOCTOR_TARGET:-$(rustc -vV | awk '/^host: / { print $2 }')}"
out_dir="${BACKEND_DOCTOR_RELEASE_DIR:-$repo_root/dist}/backend-doctor-$target"
binary_name="backend-doctor"

case "$target" in
  *windows*|*msvc*) binary_name="backend-doctor.exe" ;;
esac

if [ -n "${BACKEND_DOCTOR_TARGET:-}" ]; then
  cargo_args=(build --locked --release -p backend-doctor-cli --target "$target")
  binary_path="$repo_root/target/$target/release/$binary_name"
else
  cargo_args=(build --locked --release -p backend-doctor-cli)
  binary_path="$repo_root/target/release/$binary_name"
fi

(
  cd "$repo_root"
  cargo "${cargo_args[@]}"
)

test -f "$binary_path"
rm -rf "$out_dir"
mkdir -p "$out_dir"
cp "$binary_path" "$out_dir/$binary_name"

if [ "$binary_name" = "backend-doctor" ]; then
  chmod +x "$out_dir/$binary_name"
fi

(
  cd "$out_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$binary_name" > SHA256SUMS
    sha256sum -c SHA256SUMS
  else
    shasum -a 256 "$binary_name" > SHA256SUMS
    shasum -a 256 -c SHA256SUMS
  fi
)

printf 'backend-doctor release artifact: %s\n' "$out_dir"
