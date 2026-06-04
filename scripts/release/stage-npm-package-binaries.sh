#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source_root="${1:-${BACKEND_DOCTOR_RELEASE_DIR:-$repo_root/dist}}"
package_root="${BACKEND_DOCTOR_NPM_PACKAGE_DIR:-$repo_root/npm/backend-doctor}"
destination_root="${BACKEND_DOCTOR_NPM_BINARY_DIR:-$package_root/dist}"

if [ ! -d "$source_root" ]; then
  echo "backend-doctor npm staging source does not exist: $source_root" >&2
  exit 1
fi

declare -a artifact_dirs=()
declare -a artifact_targets=()
declare -a artifact_binaries=()

verify_checksum() {
  local dir="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$dir" && sha256sum -c SHA256SUMS >/dev/null)
  else
    (cd "$dir" && shasum -a 256 -c SHA256SUMS >/dev/null)
  fi
}

while IFS= read -r -d '' artifact_dir; do
  artifact_name="$(basename "$artifact_dir")"
  target="${artifact_name#backend-doctor-}"

  if [ -z "$target" ] || [ "$target" = "$artifact_name" ]; then
    continue
  fi

  binary_name=""
  if [ -f "$artifact_dir/backend-doctor" ]; then
    binary_name="backend-doctor"
  elif [ -f "$artifact_dir/backend-doctor.exe" ]; then
    binary_name="backend-doctor.exe"
  elif [ -f "$artifact_dir/SHA256SUMS" ]; then
    echo "backend-doctor npm staging found checksums without a binary in $artifact_dir" >&2
    exit 1
  else
    continue
  fi

  if [ ! -f "$artifact_dir/SHA256SUMS" ]; then
    echo "backend-doctor npm staging missing SHA256SUMS next to $artifact_dir/$binary_name" >&2
    exit 1
  fi

  duplicate_dir=""
  for existing_index in "${!artifact_targets[@]}"; do
    if [ "${artifact_targets[$existing_index]}" = "$target" ]; then
      duplicate_dir="${artifact_dirs[$existing_index]}"
      break
    fi
  done

  if [ -n "$duplicate_dir" ]; then
    echo "backend-doctor npm staging found duplicate target $target in $artifact_dir and $duplicate_dir" >&2
    exit 1
  fi

  verify_checksum "$artifact_dir"

  artifact_dirs+=("$artifact_dir")
  artifact_targets+=("$target")
  artifact_binaries+=("$binary_name")
done < <(find "$source_root" -type d -name 'backend-doctor-*' -print0)

if [ "${#artifact_dirs[@]}" -eq 0 ]; then
  echo "backend-doctor npm staging found no verified release binaries under $source_root" >&2
  exit 1
fi

rm -rf "$destination_root"
mkdir -p "$destination_root"

for index in "${!artifact_dirs[@]}"; do
  artifact_dir="${artifact_dirs[$index]}"
  target="${artifact_targets[$index]}"
  binary_name="${artifact_binaries[$index]}"
  target_dir="$destination_root/$target"

  mkdir -p "$target_dir"
  cp "$artifact_dir/$binary_name" "$target_dir/$binary_name"
  cp "$artifact_dir/SHA256SUMS" "$target_dir/SHA256SUMS"

  if [ "$binary_name" = "backend-doctor" ]; then
    chmod +x "$target_dir/$binary_name"
  fi

  printf 'staged npm binary: %s/%s\n' "$target" "$binary_name"
done

printf 'backend-doctor npm staged %s verified platform binary set(s) into %s\n' "${#artifact_dirs[@]}" "$destination_root"
