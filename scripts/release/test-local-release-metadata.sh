#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/backend-doctor-local-release-metadata.XXXXXX")"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

artifact_dir="$tmp_dir/artifacts"
output_dir="$tmp_dir/metadata"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{ print $1 }'
  else
    shasum -a 256 "$1" | awk '{ print $1 }'
  fi
}

mkdir -p "$artifact_dir/nested"
printf 'linux-binary\n' > "$artifact_dir/backend-doctor-linux-x64"
printf 'windows-binary\n' > "$artifact_dir/nested/backend-doctor.exe"
printf 'npm-package\n' > "$artifact_dir/backend-doctor-0.0.0.tgz"

linux_sha="$(sha256_file "$artifact_dir/backend-doctor-linux-x64")"
windows_sha="$(sha256_file "$artifact_dir/nested/backend-doctor.exe")"
npm_sha="$(sha256_file "$artifact_dir/backend-doctor-0.0.0.tgz")"

env \
  HTTP_PROXY="http://127.0.0.1:9" \
  HTTPS_PROXY="http://127.0.0.1:9" \
  http_proxy="http://127.0.0.1:9" \
  https_proxy="http://127.0.0.1:9" \
  NO_PROXY="" \
  no_proxy="" \
  "$repo_root/scripts/release/generate-local-release-metadata.sh" "$artifact_dir" "$output_dir"

test -f "$output_dir/artifact-manifest.json"
test -f "$output_dir/provenance-draft.intoto.json"
test -f "$output_dir/artifact-sbom.spdx.json"

if command -v jq >/dev/null 2>&1; then
  jq -e . "$output_dir/artifact-manifest.json" >/dev/null
  jq -e . "$output_dir/provenance-draft.intoto.json" >/dev/null
  jq -e . "$output_dir/artifact-sbom.spdx.json" >/dev/null
fi

node - "$output_dir" "$linux_sha" "$windows_sha" "$npm_sha" <<'NODE'
const fs = require('fs');
const path = require('path');

const outputDir = process.argv[2];
const expected = new Map([
  ['backend-doctor-linux-x64', { sha256: process.argv[3], byteSize: 13 }],
  ['nested/backend-doctor.exe', { sha256: process.argv[4], byteSize: 15 }],
  ['backend-doctor-0.0.0.tgz', { sha256: process.argv[5], byteSize: 12 }],
]);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(outputDir, name), 'utf8'));
}

function assert(condition, message) {
  if (!condition) {
    console.error(`error: ${message}`);
    process.exit(1);
  }
}

function strictArtifactMap(label, entries, readName, readSha256, readByteSize = null) {
  assert(Array.isArray(entries), `${label} entries are not an array`);
  assert(entries.length === expected.size, `${label} entry count mismatch`);

  const seen = new Set();
  for (const entry of entries) {
    const name = readName(entry);
    assert(typeof name === 'string' && name.length > 0, `${label} entry has invalid name`);
    assert(!seen.has(name), `${label} duplicate entry for ${name}`);
    seen.add(name);

    const expectedEntry = expected.get(name);
    assert(expectedEntry, `${label} unexpected entry for ${name}`);
    assert(readSha256(entry) === expectedEntry.sha256, `${label} digest mismatch for ${name}`);
    if (readByteSize) {
      assert(readByteSize(entry) === expectedEntry.byteSize, `${label} byte size mismatch for ${name}`);
    }
  }

  for (const name of expected.keys()) {
    assert(seen.has(name), `${label} missing entry for ${name}`);
  }
}

function sha256FromChecksums(entry) {
  const checksum = Array.isArray(entry.checksums)
    ? entry.checksums.find((candidate) => candidate.algorithm === 'SHA256')
    : null;
  return checksum && checksum.checksumValue;
}

const manifest = readJson('artifact-manifest.json');
assert(manifest.metadataType === 'backend-doctor.localArtifactManifest.v1', 'unexpected manifest metadata type');
assert(manifest.localDryRun === true && manifest.unsigned === true, 'manifest markers missing');
assert(manifest.artifactCount === expected.size && manifest.artifacts.length === expected.size, 'manifest artifact count mismatch');
strictArtifactMap('manifest artifacts', manifest.artifacts, (entry) => entry.name, (entry) => entry.sha256, (entry) => entry.byteSize);
for (const artifact of manifest.artifacts) {
  assert(artifact.path === artifact.name, `manifest path/name mismatch for ${artifact.name}`);
}

const provenance = readJson('provenance-draft.intoto.json');
assert(provenance._type === 'https://in-toto.io/Statement/v1', 'unexpected provenance _type');
assert(provenance.predicateType === 'https://slsa.dev/provenance/v1', 'unexpected provenance predicateType');
assert(provenance.predicate.buildDefinition.externalParameters.localDryRun === true, 'provenance local marker missing');
assert(provenance.predicate.buildDefinition.externalParameters.unsigned === true, 'provenance unsigned marker missing');
assert(provenance.predicate.buildDefinition.externalParameters.publicReleaseEvidence === false, 'provenance public evidence marker missing');
strictArtifactMap('provenance subjects', provenance.subject, (entry) => entry.name, (entry) => entry.digest && entry.digest.sha256);

const sbom = readJson('artifact-sbom.spdx.json');
assert(sbom.spdxVersion === 'SPDX-2.3', 'unexpected SPDX version');
assert(sbom.comment.includes('LOCAL DRY RUN DRAFT'), 'SPDX local notice missing');
strictArtifactMap('SPDX packages', sbom.packages, (entry) => entry.packageFileName, sha256FromChecksums);
strictArtifactMap('SPDX files', sbom.files, (entry) => entry.fileName, sha256FromChecksums);
NODE

printf 'backend-doctor local release metadata test passed: %s\n' "$output_dir"
