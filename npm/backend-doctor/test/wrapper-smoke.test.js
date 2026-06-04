'use strict';

const assert = require('node:assert');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const wrapper = path.resolve(__dirname, '..', 'bin', 'backend-doctor.js');

const result = spawnSync(process.execPath, [wrapper, '--help'], {
  cwd: path.resolve(__dirname, '..'),
  encoding: 'utf8'
});

if (result.status === 0) {
  assert.match(
    result.stdout,
    /Usage: backend-doctor|backend-doctor/i,
    'wrapper should forward help output when the Rust CLI exists'
  );
} else {
  assert.match(
    result.stderr,
    /no runnable Phase 0 CLI binary is available yet|backend-doctor-cli|could not compile/,
    'wrapper should explain the missing Rust CLI or fallback failure'
  );
}

console.log('wrapper smoke test passed');
