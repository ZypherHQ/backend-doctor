#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const args = process.argv.slice(2);
const packageRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(packageRoot, '..', '..');

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

function candidateBinaryPaths() {
  const triple = platformTriple();
  const name = binaryName();

  return [
    path.join(packageRoot, 'bin', triple, name),
    path.join(packageRoot, 'vendor', triple, name),
    path.join(packageRoot, 'dist', triple, name)
  ];
}

function isExecutableFile(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return fs.statSync(filePath).isFile();
  } catch (_) {
    return false;
  }
}

function parseChecksumLine(line) {
  const match = line.trim().match(/^([a-fA-F0-9]{64})\s+[* ]?(.+)$/);
  if (!match) return null;

  return {
    sha256: match[1].toLowerCase(),
    fileName: path.basename(match[2].trim())
  };
}

function expectedChecksum(candidate) {
  const sumsPath = path.join(path.dirname(candidate), 'SHA256SUMS');
  const candidateName = path.basename(candidate);

  if (!fs.existsSync(sumsPath)) {
    return {
      ok: false,
      reason: `missing checksum file ${sumsPath}`
    };
  }

  const lines = fs.readFileSync(sumsPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const parsed = parseChecksumLine(line);
    if (parsed && parsed.fileName === candidateName) {
      return { ok: true, sha256: parsed.sha256 };
    }
  }

  return {
    ok: false,
    reason: `missing checksum entry for ${candidateName} in ${sumsPath}`
  };
}

function actualChecksum(candidate) {
  return crypto.createHash('sha256').update(fs.readFileSync(candidate)).digest('hex');
}

function verifyPackagedBinary(candidate) {
  if (!isExecutableFile(candidate)) {
    return { ok: false, missing: true };
  }

  const expected = expectedChecksum(candidate);
  if (!expected.ok) {
    return { ok: false, reason: expected.reason };
  }

  const actual = actualChecksum(candidate);
  if (actual !== expected.sha256) {
    return {
      ok: false,
      reason: `checksum mismatch for ${candidate}: expected ${expected.sha256}, got ${actual}`
    };
  }

  return { ok: true };
}

function run(command, commandArgs, options) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    stdio: 'inherit',
    shell: false
  });

  if (result.error) {
    return { ok: false, error: result.error };
  }

  return { ok: true, status: result.status === null ? 1 : result.status };
}

function runPackagedBinary() {
  const verificationFailures = [];

  for (const candidate of candidateBinaryPaths()) {
    const verification = verifyPackagedBinary(candidate);
    if (verification.missing) {
      continue;
    }

    if (!verification.ok) {
      verificationFailures.push(`${candidate}: ${verification.reason}`);
      continue;
    }

    const result = run(candidate, args, { cwd: process.cwd() });
    result.verificationFailures = verificationFailures;
    return result;
  }

  if (verificationFailures.length > 0) {
    return {
      ok: false,
      status: 1,
      noVerifiedBinary: true,
      verificationFailures
    };
  }

  return null;
}

function runCargoFallback() {
  const manifest = path.join(repoRoot, 'Cargo.toml');
  if (!fs.existsSync(manifest)) {
    return null;
  }

  return run('cargo', ['run', '-q', '-p', 'backend-doctor-cli', '--', ...args], {
    cwd: repoRoot
  });
}

function printBootstrapError(packagedResult, cargoResult) {
  const triple = platformTriple();

  console.error('backend-doctor: no runnable Phase 0 CLI binary is available yet.');
  console.error(`Looked for packaged binaries for ${triple} under npm/backend-doctor/bin, vendor, and dist.`);

  if (packagedResult && packagedResult.verificationFailures) {
    for (const failure of packagedResult.verificationFailures) {
      console.error(`Packaged binary verification failed: ${failure}`);
    }
  }

  if (cargoResult && cargoResult.error) {
    console.error(`Cargo fallback failed to start: ${cargoResult.error.message}`);
  } else if (!cargoResult) {
    console.error('Cargo fallback is unavailable because the Rust workspace has not been created yet.');
  }

  if (packagedResult && packagedResult.error) {
    console.error(`Packaged binary failed to start: ${packagedResult.error.message}`);
  }

  console.error('Once the Rust worker creates backend-doctor-cli, this wrapper will forward all arguments, including --help.');
}

const packagedResult = runPackagedBinary();
if (packagedResult && !packagedResult.noVerifiedBinary) {
  if (packagedResult.ok) process.exit(packagedResult.status);
  printBootstrapError(packagedResult, null);
  process.exit(1);
}

const cargoResult = runCargoFallback();
if (cargoResult) {
  if (cargoResult.ok) process.exit(cargoResult.status);
  printBootstrapError(null, cargoResult);
  process.exit(1);
}

printBootstrapError(null, null);
process.exit(1);
