# AGENTS.md

Guidance for coding and review agents, including Codex. Project Remediator
closes the vulnerability remediation loop (Detect → Normalize → Plan → Apply →
Verify) with evidence-backed verification. Read [`docs/vision.md`](docs/vision.md)
and [`docs/roadmap.md`](docs/roadmap.md) for goals and scope, and
[`CLAUDE.md`](CLAUDE.md) for commands, architecture boundaries, and the issue
workflow; they apply to every agent. Security context for reviews is in
[`docs/threat-model.md`](docs/threat-model.md).

## Code Review Rules

### False success

- Flag any path where a failed, partial, interrupted, or unparseable scan, or
  missing evidence, can produce a `success` status, `no_known_gaps` coverage, or
  any other clean-looking result. Safe path: keep the uncertainty explicit as
  `partial`, `failed`, `unknown`, or a limitation with a reason.
- Flag code that treats an unknown fix as `no_fix`, or that would treat a
  finding's disappearance as proof of remediation. A correlation entry such as
  `only_before` is a relationship between observations, never a verdict.
- Flag correlation changes that turn an uncertain relationship (alias splits or
  merges, duplicate slots, moved manifests, missing asset keys) into a match.
- Flag fix candidates derived from unconfirmed installed versions, lexical
  version comparison, other packages' ranges, or disagreeing advisories (never
  pick the highest fix silently).

### Evidence and provenance

- Flag code that guesses, infers, or fabricates provenance (scanner version,
  advisory source, fingerprints, timestamps) or labels adapter-computed data
  with `origin: scanner`. Safe path: a null value with a `detail`.
- Flag changes to `src/remediator/domain/` that break loading existing
  serialized reports, or that import scanner, FastAPI, or persistence code.

### Scanner adapters (`src/remediator/scanners/`)

Scanned repositories are untrusted input; see
[`docs/osv-scanner.md`](docs/osv-scanner.md).

- Flag anything that executes, imports, builds, or installs repository content,
  follows a symlink at any path component, or reads repository files without a
  size bound. Safe path: descriptor-relative opens with `O_NOFOLLOW`.
- Flag repository-controlled input that can change scan results: scanner
  configuration, exclusions, or advisory data inside the target. The adapter
  passes its own `--config`, and the offline database must be outside the target.
- Flag any change that counts a package as confidently assessed without a
  successful scan, a scanner package record with a non-empty version, and an
  exact pin or lockfile, or that lets a supported manifest the scanner did not
  report disappear from coverage. Every gap needs a `CoverageNote` reason.
- Flag scanner execution without an explicit argument list, `shell=False`, a
  finite timeout, bounded output, and process-group cleanup.

### Out of scope

- Ignore formatting, lint, and typing; CI enforces them.
