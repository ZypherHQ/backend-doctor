#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_dir="${1:-}"
output_dir="${2:-}"

usage() {
  cat <<'USAGE'
Usage: scripts/release/generate-local-release-metadata.sh <artifact-dir> <output-dir>

Generates unsigned local dry-run release metadata only:
  - artifact-manifest.json
  - provenance-draft.intoto.json
  - artifact-sbom.spdx.json

The output is for local auditability and does not replace hosted GitHub
attestations, npm provenance, Docker provenance/SBOM, or public release evidence.
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

if [ "${artifact_dir:-}" = "--help" ] || [ "${artifact_dir:-}" = "-h" ]; then
  usage
  exit 0
fi

if [ -z "$artifact_dir" ] || [ -z "$output_dir" ]; then
  usage >&2
  exit 1
fi

if [ ! -d "$artifact_dir" ]; then
  die "artifact directory does not exist: $artifact_dir"
fi

if ! command -v node >/dev/null 2>&1; then
  die "node is required to generate release metadata JSON"
fi

mkdir -p "$output_dir"

artifact_dir="$(cd "$artifact_dir" && pwd -P)"
output_dir="$(cd "$output_dir" && pwd -P)"

node - "$artifact_dir" "$output_dir" "$repo_root" <<'NODE'
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const artifactRoot = process.argv[2];
const outputRoot = process.argv[3];
const repoRoot = process.argv[4];
const localNotice = 'LOCAL DRY RUN DRAFT: unsigned metadata generated from local artifacts only; not public release evidence.';

function fail(message) {
  console.error(`error: ${message}`);
  process.exit(1);
}

function posixRelative(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function isInside(parent, candidate) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function listFiles(root) {
  const files = [];

  function visit(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (isInside(outputRoot, fullPath)) {
        continue;
      }
      if (entry.isDirectory()) {
        visit(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  visit(root);
  return files.sort((left, right) => posixRelative(root, left).localeCompare(posixRelative(root, right), 'en'));
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function sha256Object(value) {
  return crypto.createHash('sha256').update(`${JSON.stringify(value, null, 2)}\n`).digest('hex');
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function gitValue(args) {
  try {
    return execFileSync('git', args, {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim() || null;
  } catch {
    return null;
  }
}

function spdxId(name, index) {
  const safe = name.replace(/[^A-Za-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '');
  return `SPDXRef-Artifact-${index + 1}${safe ? `-${safe}` : ''}`;
}

function strictArtifactMap(label, entries, readName, readSha256, readByteSize = null) {
  if (!Array.isArray(entries)) {
    fail(`${label} entries are not an array`);
  }

  const expectedByName = new Map(artifacts.map((artifact) => [artifact.name, artifact]));
  const seen = new Set();

  if (entries.length !== expectedByName.size) {
    fail(`${label} entry count ${entries.length} does not match manifest artifact count ${expectedByName.size}`);
  }

  for (const entry of entries) {
    const name = readName(entry);
    if (typeof name !== 'string' || name.length === 0) {
      fail(`${label} entry has an invalid artifact name`);
    }
    if (seen.has(name)) {
      fail(`${label} contains duplicate artifact entry: ${name}`);
    }
    seen.add(name);

    const expected = expectedByName.get(name);
    if (!expected) {
      fail(`${label} contains unexpected artifact entry: ${name}`);
    }

    const sha256 = readSha256(entry);
    if (sha256 !== expected.sha256) {
      fail(`${label} sha256 mismatch for ${name}`);
    }

    if (readByteSize) {
      const byteSize = readByteSize(entry);
      if (byteSize !== expected.byteSize) {
        fail(`${label} byte size mismatch for ${name}`);
      }
    }
  }

  for (const name of expectedByName.keys()) {
    if (!seen.has(name)) {
      fail(`${label} is missing artifact entry: ${name}`);
    }
  }
}

const files = listFiles(artifactRoot);
if (files.length === 0) {
  fail(`artifact directory has no regular files: ${artifactRoot}`);
}

const generatedAt = new Date().toISOString();
const gitHead = gitValue(['rev-parse', '--verify', 'HEAD']);
const gitBranch = gitValue(['rev-parse', '--abbrev-ref', 'HEAD']);
const artifacts = files.map((filePath) => {
  const relativePath = posixRelative(artifactRoot, filePath);
  const stat = fs.statSync(filePath);
  return {
    name: relativePath,
    path: relativePath,
    byteSize: stat.size,
    sha256: sha256File(filePath),
  };
});

const manifest = {
  metadataType: 'backend-doctor.localArtifactManifest.v1',
  localDryRun: true,
  unsigned: true,
  notice: localNotice,
  generatedAt,
  artifactRoot,
  artifactCount: artifacts.length,
  artifacts,
};

const provenance = {
  _type: 'https://in-toto.io/Statement/v1',
  predicateType: 'https://slsa.dev/provenance/v1',
  subject: artifacts.map((artifact) => ({
    name: artifact.name,
    digest: {
      sha256: artifact.sha256,
    },
  })),
  predicate: {
    buildDefinition: {
      buildType: 'https://backend-doctor.local/release-metadata-dry-run/v1',
      externalParameters: {
        artifactDirectory: artifactRoot,
        outputDirectory: outputRoot,
        localDryRun: true,
        unsigned: true,
        publicReleaseEvidence: false,
      },
      internalParameters: {
        generator: 'scripts/release/generate-local-release-metadata.sh',
        repositoryRoot: repoRoot,
        gitHead,
        gitBranch,
        hostPlatform: os.platform(),
        hostArch: os.arch(),
      },
      resolvedDependencies: [],
    },
    runDetails: {
      builder: {
        id: 'https://backend-doctor.local/builders/local-release-metadata-dry-run',
      },
      metadata: {
        invocationId: `local-release-metadata:${repoRoot}:${artifactRoot}:${generatedAt}`,
        startedOn: generatedAt,
        finishedOn: generatedAt,
      },
      byproducts: [
        {
          name: 'artifact-manifest.json',
          digest: {
            sha256: sha256Object(manifest),
          },
        },
      ],
    },
  },
};

const sbom = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: 'backend-doctor-local-artifact-sbom-draft',
  documentNamespace: `https://backend-doctor.local/spdx/local-artifact-sbom/${encodeURIComponent(generatedAt)}`,
  documentDescribes: artifacts.map((artifact, index) => spdxId(artifact.name, index)),
  comment: localNotice,
  creationInfo: {
    created: generatedAt,
    creators: [
      'Tool: scripts/release/generate-local-release-metadata.sh',
      'Organization: backend-doctor local dry run',
    ],
  },
  packages: artifacts.map((artifact, index) => ({
    name: artifact.name,
    SPDXID: spdxId(artifact.name, index),
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: true,
    packageFileName: artifact.path,
    licenseConcluded: 'NOASSERTION',
    licenseDeclared: 'NOASSERTION',
    supplier: 'NOASSERTION',
    originator: 'NOASSERTION',
    versionInfo: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    checksums: [
      {
        algorithm: 'SHA256',
        checksumValue: artifact.sha256,
      },
    ],
    comment: 'Local dry-run artifact package entry; unsigned and not public provenance.',
  })),
  files: artifacts.map((artifact, index) => ({
    fileName: artifact.path,
    SPDXID: `${spdxId(artifact.name, index)}-File`,
    licenseConcluded: 'NOASSERTION',
    copyrightText: 'NOASSERTION',
    checksums: [
      {
        algorithm: 'SHA256',
        checksumValue: artifact.sha256,
      },
    ],
    comment: 'Local dry-run artifact file entry; unsigned and not public provenance.',
  })),
};

const manifestPath = path.join(outputRoot, 'artifact-manifest.json');
const provenancePath = path.join(outputRoot, 'provenance-draft.intoto.json');
const sbomPath = path.join(outputRoot, 'artifact-sbom.spdx.json');

writeJson(manifestPath, manifest);
writeJson(provenancePath, provenance);
writeJson(sbomPath, sbom);

const verifyManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const verifyProvenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
const verifySbom = JSON.parse(fs.readFileSync(sbomPath, 'utf8'));

if (verifyManifest.localDryRun !== true || verifyManifest.unsigned !== true) {
  fail('artifact manifest is missing local dry-run/unsigned markers');
}
if (verifyManifest.artifactCount !== artifacts.length || verifyManifest.artifacts.length !== artifacts.length) {
  fail('artifact manifest count does not match scanned artifacts');
}

strictArtifactMap(
  'artifact manifest',
  verifyManifest.artifacts,
  (entry) => entry.name,
  (entry) => entry.sha256,
  (entry) => entry.byteSize,
);

for (const artifact of verifyManifest.artifacts) {
  if (artifact.path !== artifact.name) {
    fail(`manifest path/name mismatch for ${artifact.name}`);
  }
  const filePath = path.join(artifactRoot, artifact.path);
  if (!fs.existsSync(filePath)) {
    fail(`manifest references missing artifact: ${artifact.path}`);
  }
  const stat = fs.statSync(filePath);
  const digest = sha256File(filePath);
  if (artifact.byteSize !== stat.size || artifact.sha256 !== digest) {
    fail(`manifest digest or size mismatch for ${artifact.path}`);
  }
}

if (verifyProvenance._type !== 'https://in-toto.io/Statement/v1') {
  fail('provenance draft has an unexpected _type');
}
if (verifyProvenance.predicateType !== 'https://slsa.dev/provenance/v1') {
  fail('provenance draft has an unexpected predicateType');
}
if (verifyProvenance.predicate.buildDefinition.externalParameters.localDryRun !== true) {
  fail('provenance draft is missing local dry-run marker');
}
if (verifyProvenance.predicate.buildDefinition.externalParameters.unsigned !== true) {
  fail('provenance draft is missing unsigned marker');
}
strictArtifactMap(
  'provenance subjects',
  verifyProvenance.subject,
  (entry) => entry.name,
  (entry) => entry.digest && entry.digest.sha256,
);

if (verifySbom.spdxVersion !== 'SPDX-2.3' || !verifySbom.comment.includes('LOCAL DRY RUN DRAFT')) {
  fail('SPDX draft is missing version or local dry-run notice');
}
strictArtifactMap(
  'SPDX packages',
  verifySbom.packages,
  (entry) => entry.packageFileName,
  (entry) => {
    const checksum = Array.isArray(entry.checksums)
      ? entry.checksums.find((candidate) => candidate.algorithm === 'SHA256')
      : null;
    return checksum && checksum.checksumValue;
  },
);
strictArtifactMap(
  'SPDX files',
  verifySbom.files,
  (entry) => entry.fileName,
  (entry) => {
    const checksum = Array.isArray(entry.checksums)
      ? entry.checksums.find((candidate) => candidate.algorithm === 'SHA256')
      : null;
    return checksum && checksum.checksumValue;
  },
);

console.log(`backend-doctor local artifact manifest: ${manifestPath}`);
console.log(`backend-doctor local provenance draft: ${provenancePath}`);
console.log(`backend-doctor local SPDX draft: ${sbomPath}`);
NODE
