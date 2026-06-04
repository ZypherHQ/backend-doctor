# Release Runbook

See [docs/release-runbook.md](/home/backend-doctor/docs/release-runbook.md).

Local release packaging, binary checksums, npm wrapper checksum verification, Docker build/run, and Homebrew formula generation are verified. Public package publishing, binary hosting, Homebrew tap publishing, Docker registry pushes, and GitHub uploads require configured credentials, remotes, and release URLs. Homebrew syntax/audit still needs macOS with Ruby/Homebrew.
