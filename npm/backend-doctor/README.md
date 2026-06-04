# Backend Doctor npm Wrapper

This package is the npm command wrapper for Backend Doctor.

Expected user command after public npm publication is complete and `npm view backend-doctor version` succeeds:

```bash
npx -y backend-doctor@latest .
```

Supported published binaries:

- Linux x64: `x86_64-unknown-linux-gnu`
- Linux ARM64: `aarch64-unknown-linux-gnu`
- macOS Intel: `x86_64-apple-darwin`
- macOS Apple Silicon: `aarch64-apple-darwin`
- Windows x64: `x86_64-pc-windows-msvc`

Current local-development behavior:

- forwards all arguments to a packaged `backend-doctor` binary when one is included under `bin/<platform>/`, `vendor/<platform>/`, or `dist/<platform>/`;
- falls back to `cargo run -q -p backend-doctor-cli -- <args>` from the repository root for local development when a Rust workspace exists;
- prints a clear bootstrap error when neither a packaged binary nor a local Rust workspace is available.

Package contents are intentionally allowlisted. Release packaging must stage verified platform binaries and adjacent checksum files before `npm pack` or `npm publish`. Staged files match:

- `bin/<platform>/backend-doctor` or `backend-doctor.exe`
- `vendor/<platform>/backend-doctor` or `backend-doctor.exe`
- `dist/<platform>/backend-doctor` or `backend-doctor.exe`

Local release dry runs stage platform binaries from `dist/backend-doctor-<target>/` into `npm/backend-doctor/dist/<target>/`. Public npm publishing requires hosted release artifacts, npm credentials, and the same staged tarball verification from `npm/backend-doctor`, not the repository root.

Release dry-run checks:

```bash
scripts/release/build-local-binaries.sh
scripts/release/stage-npm-package-binaries.sh
npm test --prefix npm/backend-doctor
(cd npm/backend-doctor && npm pack --dry-run)
```
