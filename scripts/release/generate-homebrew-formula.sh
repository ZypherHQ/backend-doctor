#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target="${BACKEND_DOCTOR_TARGET:-$(rustc -vV | awk '/^host: / { print $2 }')}"
release_dir="${BACKEND_DOCTOR_RELEASE_DIR:-$repo_root/dist}"
artifact_dir="$release_dir/backend-doctor-$target"
homebrew_dir="$release_dir/homebrew"
template="$repo_root/packaging/homebrew/backend-doctor.rb.tmpl"
formula="${BACKEND_DOCTOR_FORMULA_OUT:-$homebrew_dir/backend-doctor.rb}"
version="${BACKEND_DOCTOR_VERSION:-$(awk -F '"' '/^version = / { print $2; exit }' "$repo_root/Cargo.toml")}"
tarball="$homebrew_dir/backend-doctor-$target.tar.gz"
binary_name="backend-doctor"
default_homepage="https://github.com/REPLACE_WITH_OWNER/backend-doctor"

usage() {
  cat <<'USAGE'
Usage: scripts/release/generate-homebrew-formula.sh

Environment:
  BACKEND_DOCTOR_HOMEBREW_HOMEPAGE
      Formula homepage. Required for hosted/public formula generation.
  BACKEND_DOCTOR_HOMEBREW_URL
      Full formula tarball URL. Existing override; use an HTTPS URL for public formulas.
  BACKEND_DOCTOR_HOMEBREW_URL_ROOT
      HTTPS directory/root URL used to build the tarball URL from the generated tarball name.

Without BACKEND_DOCTOR_HOMEBREW_URL or BACKEND_DOCTOR_HOMEBREW_URL_ROOT, the formula
uses a local file:// tarball for dry-run validation.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

is_placeholder_url() {
  case "$1" in
    *REPLACE_WITH_OWNER*|*example.com*|*localhost*|*127.0.0.1*) return 0 ;;
    *) return 1 ;;
  esac
}

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[#\/&]/\\&/g'
}

case "$target" in
  *windows*|*msvc*) binary_name="backend-doctor.exe" ;;
esac

if [ ! -f "$artifact_dir/$binary_name" ] || [ ! -f "$artifact_dir/SHA256SUMS" ]; then
  "$repo_root/scripts/release/build-local-binaries.sh"
fi

mkdir -p "$homebrew_dir" "$(dirname "$formula")"
rm -f "$tarball"

(
  cd "$artifact_dir"
  tar -czf "$tarball" "$binary_name" SHA256SUMS
)

if command -v sha256sum >/dev/null 2>&1; then
  tarball_sha="$(sha256sum "$tarball" | awk '{ print $1 }')"
else
  tarball_sha="$(shasum -a 256 "$tarball" | awk '{ print $1 }')"
fi

homepage="${BACKEND_DOCTOR_HOMEBREW_HOMEPAGE:-$default_homepage}"

if [ -n "${BACKEND_DOCTOR_HOMEBREW_URL:-}" ] && [ -n "${BACKEND_DOCTOR_HOMEBREW_URL_ROOT:-}" ]; then
  die "set only one of BACKEND_DOCTOR_HOMEBREW_URL or BACKEND_DOCTOR_HOMEBREW_URL_ROOT"
fi

if [ -n "${BACKEND_DOCTOR_HOMEBREW_URL_ROOT:-}" ]; then
  url_root="${BACKEND_DOCTOR_HOMEBREW_URL_ROOT%/}"
  case "$url_root" in
    https://*) ;;
    http://*) die "BACKEND_DOCTOR_HOMEBREW_URL_ROOT must use HTTPS for hosted formula generation: $url_root" ;;
    *) die "BACKEND_DOCTOR_HOMEBREW_URL_ROOT must be an HTTPS URL for hosted formula generation: $url_root" ;;
  esac
  url="$url_root/$(basename "$tarball")"
elif [ -n "${BACKEND_DOCTOR_HOMEBREW_URL:-}" ]; then
  url="$BACKEND_DOCTOR_HOMEBREW_URL"
  case "$url" in
    https://*) ;;
    http://*) die "BACKEND_DOCTOR_HOMEBREW_URL must use HTTPS for hosted formula generation: $url" ;;
    *) die "BACKEND_DOCTOR_HOMEBREW_URL must be an HTTPS URL for hosted formula generation: $url" ;;
  esac
else
  url="file://$tarball"
fi

hosted_formula=false
case "$url" in
  file://*) ;;
  https://*) hosted_formula=true ;;
  http://*) die "Homebrew public artifact URL must use HTTPS: $url" ;;
  *) die "Homebrew artifact URL must be file:// for local dry runs or HTTPS for hosted release artifacts: $url" ;;
esac

if [ "$hosted_formula" = true ]; then
  case "$homepage" in
    https://*) ;;
    *) die "BACKEND_DOCTOR_HOMEBREW_HOMEPAGE must be an HTTPS URL for hosted formula generation" ;;
  esac

  if is_placeholder_url "$homepage"; then
    die "BACKEND_DOCTOR_HOMEBREW_HOMEPAGE must not be a placeholder for hosted formula generation"
  fi

  if is_placeholder_url "$url"; then
    die "Homebrew artifact URL must not be a placeholder for hosted formula generation"
  fi
fi

homepage_sed="$(escape_sed_replacement "$homepage")"
url_sed="$(escape_sed_replacement "$url")"

sed \
  -e "s#__BACKEND_DOCTOR_VERSION__#$version#g" \
  -e "s#__BACKEND_DOCTOR_HOMEPAGE__#$homepage_sed#g" \
  -e "s#__BACKEND_DOCTOR_URL__#$url_sed#g" \
  -e "s#__BACKEND_DOCTOR_SHA256__#$tarball_sha#g" \
  "$template" > "$formula"

printf 'backend-doctor Homebrew formula: %s\n' "$formula"
