# Security Policy

Backend Doctor is a local-first CLI. Security reports should be handled privately so maintainers can validate impact, prepare a fix, and coordinate disclosure before exploit details become public.

## Supported Versions

Backend Doctor has local release artifacts and dry-run packaging evidence, but public registry and hosted artifact release evidence are not complete yet. Until the first public release is cut, security fixes are supported on the default development branch and the latest release-candidate artifacts only.

| Version or branch | Security support |
| --- | --- |
| Default branch | Supported for unreleased fixes |
| Latest `0.1.x` release-candidate artifacts | Best-effort support until public release |
| Older local snapshots and untagged builds | Unsupported |

Release-owner input required before public launch: replace this table with the exact support window for published npm, Cargo, Docker, Homebrew, and binary artifacts.

## Reporting A Vulnerability

Do not report suspected vulnerabilities through public GitHub issues, public pull requests, social posts, or package-registry comments.

Preferred private channels:

- Use GitHub private vulnerability reporting on the hosted repository when it is enabled.
- If private reporting is not yet enabled, contact the release owner through the private security contact for the project.

Release-owner input required before public launch: publish the real private security contact here. Do not ship a public release with only a placeholder contact.

Include as much of the following as possible:

- affected version, commit, package, or artifact;
- operating system and installation method;
- steps to reproduce using a minimal repository or fixture when possible;
- expected and actual behavior;
- security impact, including whether source code, reports, cache entries, SARIF, secrets, credentials, paths, or external command output can be exposed or modified;
- proof-of-concept material that avoids real third-party secrets and avoids destructive actions;
- whether the issue is already public or shared with another party.

## In Scope

Security reports are in scope when they affect Backend Doctor users, their scanned repositories, or release artifacts. Examples include:

- source, secret, dependency, or report data leaving the machine without explicit opt-in;
- raw secret values appearing in terminal output, JSON, SARIF, cache records, logs, or diagnostics;
- path traversal, symlink, or fix-application behavior that modifies files outside the scanned repository;
- unsafe handling of external scanner output, command arguments, environment values, or cached replay records;
- malicious or tampered release artifacts, package wrappers, checksums, or install scripts;
- CI, SARIF, annotation, or artifact behavior that leaks private repository data beyond the configured CI boundary.

Third-party vulnerabilities in dependencies are in scope when Backend Doctor introduces reachable risk or unsafe packaging. General vulnerability reports for external tools that Backend Doctor merely parses or optionally invokes should also be reported upstream to those projects.

## Response Expectations

Maintainers should use these targets for private reports:

| Stage | Target |
| --- | --- |
| Acknowledge receipt | Within 3 business days |
| Initial triage and severity assessment | Within 7 business days |
| Remediation plan for accepted high or critical issues | As soon as practical after triage |
| Coordinated disclosure | After a fix or mitigation is available, unless active exploitation requires a different timeline |

These are response targets, not service-level guarantees. If a report is incomplete, maintainers may ask for a reproducer or additional impact evidence before assigning severity.

## Advisory, GHSA, And CVE Process

For accepted vulnerabilities in a public GitHub-hosted release:

1. Open or convert the report into a private repository security advisory when the hosted repository supports it.
2. Prepare the fix on a private branch or temporary fork with access limited to maintainers and trusted collaborators.
3. Request a CVE through GitHub Security Advisory tooling when the issue meets CVE criteria and no CVE already exists.
4. Publish the advisory only after patched artifacts, release notes, and upgrade guidance are ready, unless coordinated disclosure needs a different path.
5. Credit reporters when requested and appropriate.

If GitHub Security Advisories are unavailable for the release location, maintainers should coordinate through the release owner, the affected package registry security process, or another appropriate CVE Numbering Authority.

## Safe Harbor

Backend Doctor encourages good-faith security research. Within the maintainers' authority, the project will not pursue action against researchers who:

- avoid accessing, modifying, deleting, or exfiltrating data that is not their own;
- stop testing and report promptly after identifying a vulnerability;
- do not disrupt services, package registries, CI infrastructure, or other users;
- do not use social engineering, phishing, physical attacks, or credential theft;
- keep vulnerability details private until coordinated disclosure;
- provide enough detail for maintainers to reproduce and validate the issue.

This safe harbor does not authorize testing against systems, services, repositories, registries, or accounts that the project maintainers do not control.

## Privacy During Reporting

Do not send real secrets, production credentials, private customer data, or full proprietary repositories unless a maintainer explicitly asks for a secure transfer path. Prefer minimized fixtures, redacted logs, fingerprints, hashes, and short excerpts that demonstrate impact.

Maintainers should keep private reports, reproducers, and advisory drafts access-limited until disclosure.
