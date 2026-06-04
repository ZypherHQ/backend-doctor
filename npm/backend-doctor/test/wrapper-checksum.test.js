'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const sourceWrapper = path.resolve(__dirname, '..', 'bin', 'backend-doctor.js');

function platformTriple() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'linux' && arch === 'x64') return 'x86_64-unknown-linux-gnu';
  if (platform === 'linux' && arch === 'arm64') return 'aarch64-unknown-linux-gnu';
  if (platform === 'darwin' && arch === 'x64') return 'x86_64-apple-darwin';
  if (platform === 'darwin' && arch === 'arm64') return 'aarch64-apple-darwin';
  if (platform === 'win32' && arch === 'x64') return 'x86_64-pc-windows-msvc';

  return `${arch}-${platform}`;
}

function binaryName() {
  return process.platform === 'win32' ? 'backend-doctor.exe' : 'backend-doctor';
}

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function makePackageFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'backend-doctor-wrapper-'));
  const packageRoot = path.join(root, 'npm', 'backend-doctor');
  const wrapperPath = path.join(packageRoot, 'bin', 'backend-doctor.js');

  fs.mkdirSync(path.dirname(wrapperPath), { recursive: true });
  fs.copyFileSync(sourceWrapper, wrapperPath);

  return { root, packageRoot, wrapperPath };
}

function writeFakeBinary(packageRoot, location, label, checksum) {
  const triple = platformTriple();
  const dir = path.join(packageRoot, location, triple);
  const binaryPath = path.join(dir, binaryName());
  const script = process.platform === 'win32'
    ? `@echo off\r\necho ${label} %*\r\n`
    : `#!/bin/sh\necho ${label} "$@"\n`;

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(binaryPath, script);
  fs.chmodSync(binaryPath, 0o755);
  fs.writeFileSync(path.join(dir, 'SHA256SUMS'), `${checksum || sha256(binaryPath)}  ${binaryName()}\n`);

  return binaryPath;
}

function runWrapper(wrapperPath, packageRoot) {
  return spawnSync(process.execPath, [wrapperPath, '--version'], {
    cwd: packageRoot,
    encoding: 'utf8'
  });
}

{
  const { root, packageRoot, wrapperPath } = makePackageFixture();
  writeFakeBinary(packageRoot, 'vendor', 'verified-binary');

  const result = runWrapper(wrapperPath, packageRoot);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /verified-binary --version/);

  fs.rmSync(root, { recursive: true, force: true });
}

{
  const { root, packageRoot, wrapperPath } = makePackageFixture();
  writeFakeBinary(packageRoot, 'bin', 'bad-binary', '0'.repeat(64));
  writeFakeBinary(packageRoot, 'vendor', 'fallback-binary');

  const result = runWrapper(wrapperPath, packageRoot);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /fallback-binary --version/);
  assert.doesNotMatch(result.stdout, /bad-binary/);

  fs.rmSync(root, { recursive: true, force: true });
}

{
  const { root, packageRoot, wrapperPath } = makePackageFixture();
  const triple = platformTriple();
  const dir = path.join(packageRoot, 'vendor', triple);
  const binaryPath = path.join(dir, binaryName());

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(binaryPath, process.platform === 'win32' ? '@echo off\r\n' : '#!/bin/sh\n');
  fs.chmodSync(binaryPath, 0o755);

  const result = runWrapper(wrapperPath, packageRoot);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /missing checksum file|no runnable Phase 0 CLI binary/);

  fs.rmSync(root, { recursive: true, force: true });
}

console.log('wrapper checksum test passed');
