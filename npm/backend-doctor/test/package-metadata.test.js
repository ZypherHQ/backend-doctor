'use strict';

const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const packageRoot = path.resolve(__dirname, '..');
const manifestPath = path.join(packageRoot, 'package.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const workspaceManifest = fs.readFileSync(path.join(packageRoot, '..', '..', 'Cargo.toml'), 'utf8');
const workspaceVersion = workspaceManifest.match(/\[workspace\.package\][\s\S]*?\nversion = "([^"]+)"/)?.[1];

assert.equal(manifest.private, undefined, 'package must not be marked private for release dry-runs');
assert.equal(manifest.name, '@zypherhq/backend-doctor', 'npm package name should use the publishable ZypherHQ scope');
assert.equal(manifest.license, 'MIT', 'npm package license should match the Rust workspace license');
assert.equal(manifest.version, workspaceVersion, 'npm package version should match the Rust workspace version');
assert.equal(manifest.bin['backend-doctor'], 'bin/backend-doctor.js', 'CLI bin mapping should stay stable');

const expectedFiles = [
  'README.md',
  'bin/backend-doctor.js',
  'bin/*/backend-doctor',
  'bin/*/backend-doctor.exe',
  'bin/*/SHA256SUMS',
  'vendor/*/backend-doctor',
  'vendor/*/backend-doctor.exe',
  'vendor/*/SHA256SUMS',
  'dist/*/backend-doctor',
  'dist/*/backend-doctor.exe',
  'dist/*/SHA256SUMS'
];

assert.deepEqual(manifest.files, expectedFiles, 'package files allowlist should include only wrapper docs and runnable binaries');

const wrapperPath = path.join(packageRoot, manifest.bin['backend-doctor']);
const wrapper = fs.readFileSync(wrapperPath, 'utf8');

assert.match(wrapper, /^#!\/usr\/bin\/env node/, 'wrapper must keep its executable shebang');
assert.match(wrapper, /vendor.*dist/s, 'wrapper should still know about future binary package locations');
assert.match(wrapper, /SHA256SUMS/, 'wrapper must verify packaged binaries before executing them');

console.log('package metadata test passed');
