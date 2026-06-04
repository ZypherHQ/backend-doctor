# Installation

Backend Doctor ships as a single `backend-doctor` binary. There are four ways to run it.

## 1. npm (recommended once published)

Requires **Node ≥ 18**. The npm package is a thin wrapper that runs a packaged platform binary.

```bash
# Run without installing
npx -y @zypherhq/backend-doctor@latest .

# Or install it
npm install -g @zypherhq/backend-doctor
backend-doctor .
```

> The public package is published when `npm view @zypherhq/backend-doctor version` succeeds. Until then, use one of the local methods below.

Supported npm binaries:

- Linux x64: `x86_64-unknown-linux-gnu`
- Linux ARM64: `aarch64-unknown-linux-gnu`
- macOS Intel: `x86_64-apple-darwin`
- macOS Apple Silicon: `aarch64-apple-darwin`
- Windows x64: `x86_64-pc-windows-msvc`

### How the wrapper resolves a binary

`npm/backend-doctor/bin/backend-doctor.js` forwards all arguments to the first thing it finds:

1. A packaged platform binary under `bin/<platform>/`, `vendor/<platform>/`, or `dist/<platform>/`.
2. Otherwise, a local Rust workspace — it falls back to `cargo run -q -p backend-doctor-cli -- <args>`.
3. Otherwise, it prints a clear bootstrap error.

This means the same wrapper works for published users (packaged binary) and for contributors (cargo fallback).

## 2. From source (Rust)

Requires the **Rust toolchain** (the Docker build pins `rust 1.93`).

```bash
git clone <repo-url>
cd backend-doctor

# Run directly
cargo run -q -p backend-doctor-cli -- .

# Or build a release binary
cargo build --release -p backend-doctor-cli
./target/release/backend-doctor .
```

The local npm wrapper also works against a source checkout:

```bash
node npm/backend-doctor/bin/backend-doctor.js .
```

## 3. Docker

The repository ships a [`Dockerfile`](../Dockerfile) that builds the release binary and runs it as a non-root user with `WORKDIR /work`.

```bash
docker build -t backend-doctor .

# Scan the current directory (mounted read into /work)
docker run --rm -v "$PWD":/work backend-doctor /work
```

The image entry point is `backend-doctor`, so anything after the image name is passed straight to the CLI:

```bash
docker run --rm -v "$PWD":/work backend-doctor /work --json
```

## 4. Homebrew

A Homebrew formula can be generated as part of the release process (see `dist/homebrew/`). Formula audit needs a macOS/Ruby/Homebrew environment.

## Verifying the install

```bash
backend-doctor --version
backend-doctor --help
```

Next: [Getting started](getting-started.md).
