# Threat model

A short security summary for reviewers and security tooling (for example, as
the threat-model file for Codex Security Review). It describes the current
local-first CLI, not planned services. Project Remediator is experimental and
not production-ready.

## What the system does

The developer CLI (`python -m remediator.cli`) scans a local directory with a
trusted OSV-Scanner executable, inventories Python manifests, and writes a
normalized JSON report plus raw artifacts. The FastAPI app exposes only health
and documentation endpoints; there is no scan API, persistence, or worker.

## Entry points and who controls them

| Input | Controlled by | Trust |
|---|---|---|
| CLI arguments (target, `--executable`, `--artifacts`, `--output`, `--offline-database`, `--asset-key`) | Local operator | Trusted |
| OSV-Scanner executable and its offline database | Operator | Trusted configuration; must not come from the scanned repository |
| Scanned repository content: files, names, symlinks, `.gitignore`, `osv-scanner.toml`, manifests | Repository author, possibly an attacker | **Untrusted** |
| Scanner stdout and stderr | Scanner, shaped by repository content | Untrusted data; validated and bounded |
| Online advisory data from the OSV API | Third party | Not reproducible; recorded as time-bound |

## Trust boundaries and assumptions

- Repository content is never executed, imported, built, or installed. The
  manifest inventory only reads bounded bytes, walking with directory file
  descriptors and `O_NOFOLLOW`.
- The scanner runs with an explicit argument list, no shell, DEVNULL stdin, a
  timeout, bounded output, an adapter-owned configuration that overrides
  repository configuration, and process-group cleanup. This is bounded
  execution, **not** OS-level isolation: a malicious scanner binary is out of
  scope.
- Report outputs and artifacts are created exclusively with mode 0600 (artifact
  directories 0700), outside the target, without following symlinks.
- Inherited environment variables reach the scanner. Only `OSV_*` names, never
  values, are recorded.

## Sensitive data

Raw artifacts and reports contain local paths, dependency inventories, and
advisory text. They must not be committed or published.

## Priorities for review

1. **False success.** Anything that lets a failed, partial, or incomplete scan,
   or repository-controlled exclusions or configuration, appear clean or fully
   covered. Future verification depends on this evidence being trustworthy.
2. Path handling that follows symlinks, escapes the target or output
   directories, or overwrites existing files.
3. Subprocess handling that permits shell interpretation, unbounded time or
   output, or surviving descendants.
4. Provenance that is fabricated or misattributed between scanner and adapter.
