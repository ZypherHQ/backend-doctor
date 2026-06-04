#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "${script_dir}/../.." && pwd -P)"
cwd="$(pwd -P)"

blockers=0
warnings=0

info() {
  printf 'info: %s\n' "$*"
}

warn() {
  warnings=$((warnings + 1))
  printf 'warning: %s\n' "$*" >&2
}

block() {
  blockers=$((blockers + 1))
  printf 'blocker: %s\n' "$*" >&2
}

has_control_chars() {
  case "$1" in
    *$'\n'*|*$'\r'*|*$'\t'*)
      return 0
      ;;
  esac
  printf '%s' "$1" | LC_ALL=C grep -q '[[:cntrl:]]'
}

is_placeholder_or_local() {
  case "$1" in
    ""|*"<"*">"*|*REPLACE_WITH*|*example.com*|*localhost*|*127.0.0.1*|*0.0.0.0*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_github_repo_ref() {
  local value="$1"
  case "$value" in
    https://github.com/*.git)
      value="${value#https://github.com/}"
      value="${value%.git}"
      ;;
    https://github.com/*)
      value="${value#https://github.com/}"
      ;;
    git@github.com:*.git)
      value="${value#git@github.com:}"
      value="${value%.git}"
      ;;
  esac
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38}[A-Za-z0-9])?/[A-Za-z0-9._-]+$ ]]
}

is_github_homebrew_tap_ref() {
  local value="$1"
  case "$value" in
    https://github.com/*.git)
      value="${value#https://github.com/}"
      value="${value%.git}"
      ;;
    https://github.com/*)
      value="${value#https://github.com/}"
      ;;
    git@github.com:*.git)
      value="${value#git@github.com:}"
      value="${value%.git}"
      ;;
  esac
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38}[A-Za-z0-9])?/homebrew-[A-Za-z0-9._-]+$ ]]
}

docker_host_from_image() {
  local image="$1"
  printf '%s' "${image%%/*}"
}

docker_host_without_port() {
  local host="$1"
  case "$host" in
    \[*\]) printf '%s' "$host" ;;
    *:*) printf '%s' "${host%%:*}" ;;
    *) printf '%s' "$host" ;;
  esac
}

is_private_or_local_docker_host() {
  local host="$1"
  local bare_host first_octet second_octet
  bare_host="$(docker_host_without_port "$host")"
  case "$bare_host" in
    ""|"<"*|*">"*|*REPLACE_WITH*|*replace*|*PLACEHOLDER*|*placeholder*|example|example.*|*.example|*.example.*|localhost|*.localhost|0.0.0.0|127.*|*.local)
      return 0
      ;;
  esac
  if [[ "$bare_host" =~ ^10\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
    return 0
  fi
  if [[ "$bare_host" =~ ^192\.168\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    return 0
  fi
  if [[ "$bare_host" =~ ^172\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    second_octet="${BASH_REMATCH[1]}"
    if (( second_octet >= 16 && second_octet <= 31 )); then
      return 0
    fi
  fi
  if [[ "$bare_host" =~ ^169\.254\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    return 0
  fi
  if [[ "$bare_host" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    first_octet="${BASH_REMATCH[1]}"
    second_octet="${BASH_REMATCH[2]}"
    if (( first_octet == 100 && second_octet >= 64 && second_octet <= 127 )); then
      return 0
    fi
  fi
  return 1
}

require_env() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "$value" ]]; then
    block "missing required environment variable: ${name}"
    return
  fi
  if has_control_chars "$value"; then
    block "${name} must not contain control characters or newlines"
  fi
}

require_https_env() {
  local name="$1"
  local value="${!name:-}"
  require_env "$name"
  [[ -z "$value" ]] && return
  case "$value" in
    https://*) ;;
    *) block "${name} must be an HTTPS URL" ;;
  esac
  if is_placeholder_or_local "$value"; then
    block "${name} must not be a placeholder or local URL"
  fi
}

require_boolean_env() {
  local name="$1"
  local value="${!name:-}"
  require_env "$name"
  [[ -z "$value" ]] && return
  case "$value" in
    true|false) ;;
    *) block "${name} must be exactly true or false" ;;
  esac
}

expected_cargo_package_name() {
  printf '%s' "${BACKEND_DOCTOR_CARGO_PACKAGE_NAME:-${cli_cargo_package_name:-backend-doctor-cli}}"
}

is_crates_io_cargo_install_command() {
  local value="$1"
  case "$value" in
    cargo\ install\ *) ;;
    *) return 1 ;;
  esac
  cargo_install_uses_default_crates_io "$value" || return 1
  [[ "$(first_cargo_install_package "$value")" == "$(expected_cargo_package_name)" ]] || return 1
  cargo_install_has_locked_flag "$value" || return 1
  cargo_install_has_version_flag "$value"
}

cargo_install_uses_default_crates_io() {
  local value="$1"
  if [[ "$value" =~ (^|[[:space:]])--(config|registry|index|git|path)(=|[[:space:]]|$) ]]; then
    return 1
  fi
  if [[ "$value" =~ (^|[[:space:]])([A-Za-z][A-Za-z0-9+.-]*://|git@|\./|\.\./|/) ]]; then
    return 1
  fi
}

cargo_install_has_locked_flag() {
  [[ "$1" =~ (^|[[:space:]])--locked($|[[:space:]]) ]]
}

cargo_install_has_version_flag() {
  [[ "$1" =~ (^|[[:space:]])--version=([0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)($|[[:space:]]) || "$1" =~ (^|[[:space:]])--version[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?)($|[[:space:]]) ]]
}

extract_cargo_install_version_flag() {
  local value="$1"
  if [[ "$value" =~ (^|[[:space:]])--version=([^[:space:]]+) ]]; then
    printf '%s' "${BASH_REMATCH[2]}"
    return 0
  fi
  if [[ "$value" =~ (^|[[:space:]])--version[[:space:]]+([^[:space:]]+) ]]; then
    printf '%s' "${BASH_REMATCH[2]}"
    return 0
  fi
  return 1
}

first_cargo_install_package() {
  local value="$1"
  local tail package
  tail="${value#cargo install }"
  package="${tail%%[[:space:]]*}"
  printf '%s' "$package"
}

workflow_has_job() {
  local workflow_path="$1"
  local job="$2"

  awk -v job="$job" '
    function indent_of(line) {
      match(line, /^ */)
      return RLENGTH
    }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) {
        next
      }
      indent = indent_of(line)
      if (line ~ /^jobs:[[:space:]]*$/) {
        in_jobs = 1
        next
      }
      if (in_jobs && indent == 0) {
        in_jobs = 0
      }
      if (in_jobs && indent == 2 && line ~ /^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*$/) {
        current_job = line
        sub(/^[[:space:]]*/, "", current_job)
        sub(/:[[:space:]]*$/, "", current_job)
        if (current_job == job) {
          found = 1
          exit
        }
      }
    }
    END { exit found ? 0 : 1 }
  ' "$workflow_path"
}

workflow_job_has_permission() {
  local workflow_path="$1"
  local job="$2"
  local permission="$3"
  local level="$4"

  awk -v job="$job" -v permission="$permission" -v level="$level" '
    function indent_of(line) {
      match(line, /^ */)
      return RLENGTH
    }
    {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      if (line ~ /^[[:space:]]*$/) {
        next
      }

      indent = indent_of(line)
      if (line ~ /^jobs:[[:space:]]*$/) {
        in_jobs = 1
        next
      }
      if (in_jobs && indent == 0) {
        in_jobs = 0
        in_target = 0
        in_permissions = 0
      }

      if (in_jobs && indent == 2 && line ~ /^[[:space:]]*[A-Za-z0-9_-]+:[[:space:]]*$/) {
        current_job = line
        sub(/^[[:space:]]*/, "", current_job)
        sub(/:[[:space:]]*$/, "", current_job)
        in_target = (current_job == job)
        in_permissions = 0
        next
      }

      if (!in_target) {
        next
      }

      if (in_permissions && indent <= permissions_indent) {
        in_permissions = 0
      }
      if (!in_permissions && indent == 4 && line ~ /^[[:space:]]*permissions:[[:space:]]*$/) {
        in_permissions = 1
        permissions_indent = indent
        next
      }
      if (in_permissions && indent > permissions_indent) {
        key = line
        sub(/^[[:space:]]*/, "", key)
        split(key, parts, /:[[:space:]]*/)
        if (parts[1] == permission && parts[2] == level) {
          found = 1
          exit
        }
      }
    }
    END { exit found ? 0 : 1 }
  ' "$workflow_path"
}

require_job_workflow_permission() {
  local workflow_path="$1"
  local job="$2"
  local permission="$3"
  local level="$4"
  local description="$5"

  if ! workflow_job_has_permission "$workflow_path" "$job" "$permission" "$level"; then
    block ".github/workflows/public-release.yml job ${job} must include ${permission}: ${level} for ${description}"
  fi
}

check_public_release_workflow_action_pins() {
  local workflow_path="${repo_root}/.github/workflows/public-release.yml"
  local findings

  if [[ ! -f "$workflow_path" ]]; then
    return
  fi

  findings="$(
    awk '
      {
        line = $0
        sub(/[[:space:]]*#.*/, "", line)
        if (line ~ /^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^[:space:]]+/) {
          ref = line
          sub(/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*/, "", ref)
          sub(/[[:space:]].*/, "", ref)
          if (ref ~ /^\.\//) {
            next
          }
          if (ref !~ /@/) {
            printf "%d:%s missing @<sha> pin\n", NR, ref
            next
          }
          sha = ref
          sub(/^.*@/, "", sha)
          if (sha !~ /^[0-9a-fA-F]{40}$/) {
            printf "%d:%s must use a full 40-character commit SHA\n", NR, ref
          }
        }
      }
    ' "$workflow_path"
  )"

  if [[ -n "$findings" ]]; then
    while IFS= read -r finding; do
      block ".github/workflows/public-release.yml external action pin violation: ${finding}"
    done <<< "$findings"
  fi
}

check_public_release_workflow_permissions() {
  local workflow_path="${repo_root}/.github/workflows/public-release.yml"

  if [[ ! -f "$workflow_path" ]]; then
    return
  fi

  require_job_workflow_permission "$workflow_path" "github-release" "contents" "write" "GitHub release creation and asset upload"
  require_job_workflow_permission "$workflow_path" "github-release" "attestations" "write" "GitHub release artifact attestations"
  require_job_workflow_permission "$workflow_path" "github-release" "id-token" "write" "OIDC-backed release attestations"

  require_job_workflow_permission "$workflow_path" "docker-provenance-publish" "contents" "read" "repository checkout and image metadata reads"
  require_job_workflow_permission "$workflow_path" "docker-provenance-publish" "packages" "write" "GHCR/Docker publishing"
  require_job_workflow_permission "$workflow_path" "docker-provenance-publish" "attestations" "write" "Docker artifact attestations"
  require_job_workflow_permission "$workflow_path" "docker-provenance-publish" "id-token" "write" "OIDC-backed Docker provenance"

  require_job_workflow_permission "$workflow_path" "hosted-sarif-upload" "contents" "read" "repository checkout for hosted SARIF upload"
  require_job_workflow_permission "$workflow_path" "hosted-sarif-upload" "security-events" "write" "hosted SARIF/code scanning upload"

  if workflow_has_job "$workflow_path" "npm-provenance-publish"; then
    require_job_workflow_permission "$workflow_path" "npm-provenance-publish" "contents" "read" "repository checkout for npm provenance publishing"
    require_job_workflow_permission "$workflow_path" "npm-provenance-publish" "id-token" "write" "OIDC-backed npm provenance publishing"
  fi
}

extract_cargo_version() {
  awk '
    /^\[workspace\.package\]/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "${repo_root}/Cargo.toml"
}

extract_cli_cargo_package_name() {
  awk '
    /^\[package\]/ { in_package = 1; next }
    /^\[/ && in_package { exit }
    in_package && $1 == "name" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "${repo_root}/crates/backend-doctor-cli/Cargo.toml"
}

extract_npm_version() {
  if command -v jq >/dev/null 2>&1; then
    jq -r '.version // empty' "${repo_root}/npm/backend-doctor/package.json"
  else
    sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
      "${repo_root}/npm/backend-doctor/package.json" | sed -n '1p'
  fi
}

printf 'Backend Doctor public release preflight\n'
printf 'repo_root: %s\n' "$repo_root"

if [[ "$cwd" != "$repo_root" ]]; then
  block "run this checker from the repository root: ${repo_root}"
fi

for required_file in \
  "Cargo.toml" \
  "Cargo.lock" \
  "crates/backend-doctor-cli/Cargo.toml" \
  "npm/backend-doctor/package.json" \
  ".github/workflows/public-release.yml" \
  ".orchestration/p0-public-release-evidence-template.md" \
  ".orchestration/validate-p0-release-evidence.sh" \
  "scripts/release/generate-homebrew-formula.sh" \
  "scripts/release/test-homebrew-formula.sh"
do
  if [[ ! -f "${repo_root}/${required_file}" ]]; then
    block "required release file is missing: ${required_file}"
  fi
done

check_public_release_workflow_action_pins
check_public_release_workflow_permissions

for cmd in git gh npm docker cargo jq sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    block "required command is not available on PATH: ${cmd}"
  fi
done

for cmd in brew ruby; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "optional Homebrew audit command is not available on PATH: ${cmd}"
  fi
done

if [[ -d "${repo_root}/.git" ]] || git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
  remote_url="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
  if [[ -z "$remote_url" ]]; then
    block "git remote 'origin' is not configured"
  elif is_placeholder_or_local "$remote_url"; then
    block "git remote 'origin' is placeholder/local: ${remote_url}"
  else
    case "$remote_url" in
      git@github.com:*|https://github.com/*)
        info "git origin configured: ${remote_url}"
        ;;
      *)
        warn "git origin is not a GitHub remote; verify hosted workflow availability: ${remote_url}"
        ;;
    esac
  fi
else
  block "workspace is not inside a Git checkout"
fi

cargo_version="$(extract_cargo_version || true)"
cli_cargo_package_name="$(extract_cli_cargo_package_name || true)"
npm_version="$(extract_npm_version || true)"
if [[ -z "$cargo_version" ]]; then
  block "could not read [workspace.package] version from Cargo.toml"
fi
if [[ -z "$cli_cargo_package_name" ]]; then
  block "could not read CLI package name from crates/backend-doctor-cli/Cargo.toml"
fi
if [[ -z "$npm_version" ]]; then
  block "could not read npm/backend-doctor package version"
fi
if [[ -n "$cargo_version" && -n "$npm_version" && "$cargo_version" != "$npm_version" ]]; then
  block "npm package version (${npm_version}) does not match Cargo workspace version (${cargo_version})"
fi

release_version="${BACKEND_DOCTOR_RELEASE_VERSION:-}"
require_env BACKEND_DOCTOR_RELEASE_VERSION
if [[ -n "$release_version" ]]; then
  if [[ ! "$release_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    block "BACKEND_DOCTOR_RELEASE_VERSION must be SemVer without a leading v"
  fi
  if [[ -n "$cargo_version" && "$release_version" != "$cargo_version" ]]; then
    block "BACKEND_DOCTOR_RELEASE_VERSION (${release_version}) does not match Cargo workspace version (${cargo_version})"
  fi
  expected_confirmation="publish backend-doctor ${release_version} publicly"
  if [[ "${BACKEND_DOCTOR_PUBLIC_RELEASE_CONFIRMATION:-}" != "$expected_confirmation" ]]; then
    block "BACKEND_DOCTOR_PUBLIC_RELEASE_CONFIRMATION must exactly equal: ${expected_confirmation}"
  fi
  if ! git -C "$repo_root" rev-parse -q --verify "refs/tags/v${release_version}" >/dev/null 2>&1; then
    block "release tag is missing locally: v${release_version}"
  fi
fi

release_notes_path="${BACKEND_DOCTOR_RELEASE_NOTES_PATH:-CHANGELOG.md}"
case "$release_notes_path" in
  /*|*..*) block "BACKEND_DOCTOR_RELEASE_NOTES_PATH must be a relative repository path without '..'" ;;
esac
if [[ ! -f "${repo_root}/${release_notes_path}" ]]; then
  block "release notes path does not exist locally: ${release_notes_path}"
fi

require_env BACKEND_DOCTOR_PUBLIC_REPO
if [[ -n "${BACKEND_DOCTOR_PUBLIC_REPO:-}" ]]; then
  if is_placeholder_or_local "$BACKEND_DOCTOR_PUBLIC_REPO"; then
    block "BACKEND_DOCTOR_PUBLIC_REPO must not be placeholder/local"
  fi
  if ! is_github_repo_ref "$BACKEND_DOCTOR_PUBLIC_REPO"; then
    block "BACKEND_DOCTOR_PUBLIC_REPO must be exactly owner/repo, https://github.com/owner/repo(.git), or git@github.com:owner/repo.git"
  fi
fi

require_https_env BACKEND_DOCTOR_HOMEBREW_HOMEPAGE
require_env BACKEND_DOCTOR_HOMEBREW_TAP
if [[ -n "${BACKEND_DOCTOR_HOMEBREW_TAP:-}" ]]; then
  if [[ "$BACKEND_DOCTOR_HOMEBREW_TAP" =~ [[:space:]] ]] || is_placeholder_or_local "$BACKEND_DOCTOR_HOMEBREW_TAP"; then
    block "BACKEND_DOCTOR_HOMEBREW_TAP must not contain whitespace and must not be placeholder/local"
  fi
  if ! is_github_homebrew_tap_ref "$BACKEND_DOCTOR_HOMEBREW_TAP"; then
    block "BACKEND_DOCTOR_HOMEBREW_TAP must be exactly owner/homebrew-tap-name or a GitHub URL for that tap repository"
  fi
fi
if [[ -z "${BACKEND_DOCTOR_HOMEBREW_URL_ROOT:-}" && -z "${BACKEND_DOCTOR_HOMEBREW_URL:-}" ]]; then
  block "set BACKEND_DOCTOR_HOMEBREW_URL_ROOT or BACKEND_DOCTOR_HOMEBREW_URL to a public HTTPS artifact URL"
else
  if [[ -n "${BACKEND_DOCTOR_HOMEBREW_URL_ROOT:-}" ]]; then
    require_https_env BACKEND_DOCTOR_HOMEBREW_URL_ROOT
  fi
  if [[ -n "${BACKEND_DOCTOR_HOMEBREW_URL:-}" ]]; then
    require_https_env BACKEND_DOCTOR_HOMEBREW_URL
  fi
fi

require_boolean_env BACKEND_DOCTOR_NPM_PUBLISH_READY
if [[ "${BACKEND_DOCTOR_NPM_PUBLISH_READY:-}" != "true" ]]; then
  block "BACKEND_DOCTOR_NPM_PUBLISH_READY must be true after npm trusted publishing or NPM_TOKEN is configured"
fi

require_env BACKEND_DOCTOR_CARGO_PACKAGE_NAME
if [[ -n "${BACKEND_DOCTOR_CARGO_PACKAGE_NAME:-}" ]]; then
  if [[ ! "$BACKEND_DOCTOR_CARGO_PACKAGE_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
    block "BACKEND_DOCTOR_CARGO_PACKAGE_NAME must be a valid lowercase crates.io package name"
  fi
  if [[ -n "$cli_cargo_package_name" && "$BACKEND_DOCTOR_CARGO_PACKAGE_NAME" != "$cli_cargo_package_name" ]]; then
    block "BACKEND_DOCTOR_CARGO_PACKAGE_NAME must match crates/backend-doctor-cli/Cargo.toml package name (${cli_cargo_package_name})"
  fi
fi

require_env BACKEND_DOCTOR_CARGO_INSTALL_COMMAND
if [[ -n "${BACKEND_DOCTOR_CARGO_INSTALL_COMMAND:-}" ]]; then
  expected_cargo_package="$(expected_cargo_package_name)"
  case "$BACKEND_DOCTOR_CARGO_INSTALL_COMMAND" in
    cargo\ install\ *) ;;
    *) block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND must start with 'cargo install ${expected_cargo_package}'" ;;
  esac
  if ! cargo_install_uses_default_crates_io "$BACKEND_DOCTOR_CARGO_INSTALL_COMMAND"; then
    block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND must use the default crates.io source and must not use --config, --registry, --index, --git, --path, URL, git, or local path sources"
  fi
  cargo_install_package="$(first_cargo_install_package "$BACKEND_DOCTOR_CARGO_INSTALL_COMMAND")"
  if [[ "$cargo_install_package" != "$expected_cargo_package" ]]; then
    block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND must install BACKEND_DOCTOR_CARGO_PACKAGE_NAME (${expected_cargo_package}) as the crates.io package"
  fi
  if ! cargo_install_has_locked_flag "$BACKEND_DOCTOR_CARGO_INSTALL_COMMAND"; then
    block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND must include --locked"
  fi
  cargo_install_version="$(extract_cargo_install_version_flag "$BACKEND_DOCTOR_CARGO_INSTALL_COMMAND" || true)"
  if [[ -z "$cargo_install_version" ]]; then
    block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND must include --version ${BACKEND_DOCTOR_RELEASE_VERSION:-<BACKEND_DOCTOR_RELEASE_VERSION>} or --version=${BACKEND_DOCTOR_RELEASE_VERSION:-<BACKEND_DOCTOR_RELEASE_VERSION>}"
  elif [[ -n "${BACKEND_DOCTOR_RELEASE_VERSION:-}" && "$cargo_install_version" != "$BACKEND_DOCTOR_RELEASE_VERSION" ]]; then
    block "BACKEND_DOCTOR_CARGO_INSTALL_COMMAND --version (${cargo_install_version}) must match BACKEND_DOCTOR_RELEASE_VERSION (${BACKEND_DOCTOR_RELEASE_VERSION}) without a leading v"
  fi
fi

require_boolean_env BACKEND_DOCTOR_CARGO_PUBLISH_READY
if [[ "${BACKEND_DOCTOR_CARGO_PUBLISH_READY:-}" != "true" ]]; then
  block "BACKEND_DOCTOR_CARGO_PUBLISH_READY must be true after crates.io ownership/credentials or trusted publishing are configured"
fi

require_boolean_env BACKEND_DOCTOR_CARGO_RELEASE_ORDER_READY
if [[ "${BACKEND_DOCTOR_CARGO_RELEASE_ORDER_READY:-}" != "true" ]]; then
  block "BACKEND_DOCTOR_CARGO_RELEASE_ORDER_READY must be true after internal crates are published or a crates.io-compatible publish order is ready"
fi

require_boolean_env BACKEND_DOCTOR_DOCKER_PUBLISH
if [[ "${BACKEND_DOCTOR_DOCKER_PUBLISH:-}" == "true" ]]; then
  require_env BACKEND_DOCTOR_DOCKER_IMAGE
  require_env BACKEND_DOCTOR_DOCKER_REGISTRY
  if [[ -n "${BACKEND_DOCTOR_DOCKER_IMAGE:-}" ]]; then
    if [[ ! "$BACKEND_DOCTOR_DOCKER_IMAGE" =~ ^[a-z0-9]+([._:-][a-z0-9]+)*/[a-z0-9]+([._/-][a-z0-9]+)*$ ]]; then
      block "BACKEND_DOCTOR_DOCKER_IMAGE must be lowercase and must not include a tag or digest"
    fi
    docker_image_host="$(docker_host_from_image "$BACKEND_DOCTOR_DOCKER_IMAGE")"
    if is_private_or_local_docker_host "$docker_image_host"; then
      block "BACKEND_DOCTOR_DOCKER_IMAGE must use a public registry host, not localhost, loopback, private IP, .local, or placeholder host"
    fi
  fi
  if [[ -n "${BACKEND_DOCTOR_DOCKER_REGISTRY:-}" ]]; then
    case "$BACKEND_DOCTOR_DOCKER_REGISTRY" in
      *://*|*/*) block "BACKEND_DOCTOR_DOCKER_REGISTRY must be a registry host, not a URL or image path" ;;
    esac
    if is_private_or_local_docker_host "$BACKEND_DOCTOR_DOCKER_REGISTRY"; then
      block "BACKEND_DOCTOR_DOCKER_REGISTRY must be a public registry host, not localhost, loopback, private IP, .local, or placeholder host"
    fi
    if [[ -n "${BACKEND_DOCTOR_DOCKER_IMAGE:-}" ]]; then
      case "$BACKEND_DOCTOR_DOCKER_IMAGE" in
        "${BACKEND_DOCTOR_DOCKER_REGISTRY}"/*) ;;
        *) block "BACKEND_DOCTOR_DOCKER_IMAGE must start with BACKEND_DOCTOR_DOCKER_REGISTRY followed by '/'" ;;
      esac
    fi
    if [[ "$BACKEND_DOCTOR_DOCKER_REGISTRY" != "ghcr.io" ]]; then
      require_env BACKEND_DOCTOR_DOCKER_USERNAME_SECRET
      require_env BACKEND_DOCTOR_DOCKER_TOKEN_SECRET
      for secret_name in BACKEND_DOCTOR_DOCKER_USERNAME_SECRET BACKEND_DOCTOR_DOCKER_TOKEN_SECRET; do
        secret_value="${!secret_name:-}"
        if [[ -n "$secret_value" && ! "$secret_value" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
          block "${secret_name} must be a valid GitHub Actions secret identifier"
        fi
      done
    fi
  fi
else
  block "BACKEND_DOCTOR_DOCKER_PUBLISH must be true after Docker registry publishing is configured"
fi

require_boolean_env BACKEND_DOCTOR_SARIF_UPLOAD_READY
if [[ "${BACKEND_DOCTOR_SARIF_UPLOAD_READY:-}" != "true" ]]; then
  block "BACKEND_DOCTOR_SARIF_UPLOAD_READY must be true after hosted GitHub code scanning is available"
fi

if [[ -x "${repo_root}/.orchestration/validate-p0-release-evidence.sh" ]]; then
  info "release evidence validator is executable"
else
  block "release evidence validator is not executable: .orchestration/validate-p0-release-evidence.sh"
fi

printf '\nPreflight summary: %d blocker(s), %d warning(s)\n' "$blockers" "$warnings"
if [[ "$blockers" -ne 0 ]]; then
  printf 'Public release prerequisites are incomplete. Resolve blockers before running .github/workflows/public-release.yml.\n' >&2
  exit 1
fi

printf 'Public release prerequisites are locally complete for the configured inputs. This does not publish or prove public readiness.\n'
