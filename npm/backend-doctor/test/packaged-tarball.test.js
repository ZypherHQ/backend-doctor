'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const packageRoot = path.resolve(__dirname, '..');
const manifest = require(path.join(packageRoot, 'package.json'));

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

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || packageRoot,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false'
    }
  });

  if (result.error) {
    throw result.error;
  }

  return result;
}

function assertSuccess(result, command) {
  assert.equal(
    result.status,
    0,
    `${command} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`
  );
}

function expectedChecksum(sumsPath, name) {
  const lines = fs.readFileSync(sumsPath, 'utf8').split(/\r?\n/);

  for (const line of lines) {
    const match = line.trim().match(/^([a-fA-F0-9]{64})\s+[* ]?(.+)$/);
    if (match && path.basename(match[2].trim()) === name) {
      return match[1].toLowerCase();
    }
  }

  return null;
}

const triple = platformTriple();
const name = binaryName();
const binaryRel = `dist/${triple}/${name}`;
const sumsRel = `dist/${triple}/SHA256SUMS`;
const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'backend-doctor-package-'));

try {
  const packDir = path.join(tempRoot, 'pack');
  const installRoot = path.join(tempRoot, 'install-root');
  const runtimeCwd = path.join(tempRoot, 'runtime-cwd');
  fs.mkdirSync(packDir, { recursive: true });
  fs.mkdirSync(runtimeCwd, { recursive: true });

  const pack = run('npm', ['pack', '--json', '--pack-destination', packDir]);
  assertSuccess(pack, 'npm pack --json');

  const packuments = JSON.parse(pack.stdout);
  assert.equal(packuments.length, 1, 'npm pack should produce one package');

  const packedFiles = packuments[0].files.map((file) => file.path).sort();
  assert.ok(packedFiles.includes('README.md'), 'package should include README evidence');
  assert.ok(packedFiles.includes('bin/backend-doctor.js'), 'package should include the wrapper');
  assert.ok(packedFiles.includes('package.json'), 'package should include package.json');
  assert.ok(
    packedFiles.some((file) => /^dist\/[^/]+\/backend-doctor(?:\.exe)?$/.test(file)),
    'package should include at least one platform binary under dist/<target>/'
  );
  assert.ok(
    packedFiles.some((file) => /^dist\/[^/]+\/SHA256SUMS$/.test(file)),
    'package should include checksum evidence next to staged binaries'
  );
  assert.ok(packedFiles.includes(binaryRel), `package should include current platform binary ${binaryRel}`);
  assert.ok(packedFiles.includes(sumsRel), `package should include current platform checksum ${sumsRel}`);

  const tarballPath = path.join(packDir, packuments[0].filename);
  assert.ok(fs.existsSync(tarballPath), `npm pack should create ${tarballPath}`);

  const install = run('npm', ['install', tarballPath, '--prefix', installRoot, '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: tempRoot
  });
  assertSuccess(install, 'npm install local tarball');

  const installedPackage = path.join(installRoot, 'node_modules', manifest.name);
  assert.notEqual(path.resolve(installedPackage), packageRoot, 'test must use the installed tarball, not the source checkout');
  assert.equal(fs.existsSync(path.join(installRoot, 'Cargo.toml')), false, 'test install root must not be a Rust source checkout');

  const installedBinary = path.join(installedPackage, binaryRel);
  const installedSums = path.join(installedPackage, sumsRel);
  assert.ok(fs.statSync(installedBinary).isFile(), `installed package should contain ${binaryRel}`);
  assert.ok(fs.statSync(installedSums).isFile(), `installed package should contain ${sumsRel}`);

  if (process.platform !== 'win32') {
    fs.accessSync(installedBinary, fs.constants.X_OK);
  }

  assert.equal(
    sha256(installedBinary),
    expectedChecksum(installedSums, name),
    'installed binary should match packaged SHA256SUMS evidence'
  );

  const wrapper = path.join(installedPackage, manifest.bin['backend-doctor']);
  const runtime = run(process.execPath, [wrapper, '--help'], { cwd: runtimeCwd });
  assertSuccess(runtime, 'installed backend-doctor wrapper --help');
  assert.match(runtime.stdout + runtime.stderr, /Usage: backend-doctor|backend-doctor/i);
  assert.doesNotMatch(runtime.stderr, /Cargo fallback|no runnable Phase 0 CLI binary/);
} finally {
  fs.rmSync(tempRoot, { recursive: true, force: true });
}

console.log('packaged tarball test passed');
