# Project Remediator — Roadmap

This roadmap turns the [vision](vision.md) into a sequence of milestones.
Milestones are ordered by **dependency and learning value, not by deadlines**.
There are no release dates, and nothing here promises a production launch.

Each milestone is delivered as one or more small, reviewable issues. Its scope
is fixed when the issue is written, not here.

**Status:** ✅ done · 🔜 next · ⏳ planned

| # | Milestone | Workflow stage | Status |
|---|---|---|---|
| 1 | Application foundation | — | ✅ |
| 2 | Domain contracts | Normalize | ✅ |
| 3 | First scanner integration | Detect, Normalize | ✅ |
| 4 | Remediation prerequisites | Normalize → Plan, Verify | 🔜 |
| 5 | Deterministic remediation planning | Plan | ⏳ |
| 6 | Remediation application | Apply | ⏳ |
| 7 | Independent verification | Verify | ⏳ |
| 8 | Expanded integrations and automation | All | ⏳ |

## ✅ Milestone 1 — Application foundation

Python 3.12, uv, FastAPI health and documentation endpoints, Docker Compose,
pytest, Ruff, strict mypy, and GitHub Actions CI.

[Issue #1](https://github.com/tsaena/project-remediator/issues/1) ·
[PR #3](https://github.com/tsaena/project-remediator/pull/3) (merged).
[Issue #2](https://github.com/tsaena/project-remediator/issues/2) was closed as
a duplicate of #1.

## ✅ Milestone 2 — Domain contracts

Scanner-independent assets, components, vulnerabilities, findings, scanner
evidence, fix information, and scan results, with invariants that keep failed
or partial scans from being read as clean. See the
[domain model guide](domain-model.md).

[Issue #4](https://github.com/tsaena/project-remediator/issues/4) ·
[PR #5](https://github.com/tsaena/project-remediator/pull/5) (merged).

## ✅ Milestone 3 — First scanner integration

OSV-Scanner v2 source scanning, JSON normalization, provenance, explicit
handling of exit codes and malformed output, retained raw artifacts, and
controlled execution: adapter-owned scanner configuration, recursive manifest
discovery, timeouts, bounded output, and process-group cleanup. See the
[OSV-Scanner guide](osv-scanner.md).

[Issue #6](https://github.com/tsaena/project-remediator/issues/6) ·
[PR #7](https://github.com/tsaena/project-remediator/pull/7) (merged).

Known limitations carried forward: fix
information is always `unknown`, related advisory IDs are separate findings,
and execution is bounded but not isolated.

## 🔜 Milestone 4 — Remediation prerequisites

Progress: scan coverage and provenance ([issue #9](https://github.com/tsaena/project-remediator/issues/9)) records which manifests
and packages were actually assessed and which scanner, settings, and advisory
source produced a report. Advisory grouping, finding identity, and fixed
versions remain.

**Goal:** trustworthy fixed-version intelligence and stable finding
correlation. Planning needs the first; verification needs the second.

The system must distinguish:

- **Unknown fixes** from **known available fixes**, derived from advisory data
  without inventing versions.
- **Advisory aliases** (one vulnerability published under several IDs) from
  **genuinely distinct vulnerabilities**.
- **The same finding across different scan executions**, through an identity
  that does not depend on execution IDs or timestamps.
- **Real changes in vulnerability state** from **changes in scanner behavior
  or coverage**. This requires recording enough provenance to compare two
  executions: scanner version, advisory data source, and scanned coverage.

**Exit criteria:** fixed versions are populated only when advisory data
supports them; alias groups and finding identity are deterministic and tested
against real scanner output; scan results carry the provenance needed to say
whether two executions are comparable.

## ⏳ Milestone 5 — Deterministic remediation planning

**Goal:** explainable, non-executing remediation proposals for supported
dependency ecosystems, starting with a narrow Python dependency use case (for
example, pinned requirements).

Each proposal states the finding it addresses, the proposed change, the
evidence behind it, and what remains unknown. Findings without a defensible
candidate are reported as such rather than guessed.

**Exit criteria:** for the vulnerable Python fixture, the planner proposes
specific upgrades with evidence, and refuses to propose one when fix data is
missing or ambiguous.

## ⏳ Milestone 6 — Remediation application

**Goal:** controlled, human-approved dependency modifications.

Changes are applied only after approval, are reviewable as a diff, and are
recorded as evidence. Application stays separate from verification: applying a
change never marks it as fixed.

**Exit criteria:** an approved plan produces exactly the proposed change, and
no change is applied without approval.

## ⏳ Milestone 7 — Independent verification

**Goal:** evidence-backed verification outcomes.

Rescan after remediation; correlate findings; validate that scan coverage,
scanner configuration, and scanner provenance are comparable; compare
dependency state; and produce **verified fixed**, **still vulnerable**,
**inconclusive**, or **newly introduced** outcomes with documented semantics.
When comparability cannot be established, the outcome is inconclusive.

**Exit criteria:** the full Detect → Normalize → Plan → Apply → Verify loop
works on a deliberately vulnerable repository, and adversarial cases (a
suppressed finding, a hidden manifest, a failed rescan, a changed scanner)
produce inconclusive or still-vulnerable outcomes, never verified fixed.

## ⏳ Milestone 8 — Expanded integrations and automation

Additional scanners such as Trivy, container-image assessment, GitHub
pull-request and CI/CD workflows, constrained AI-assisted remediation,
persistent scan histories and job execution, and broader deployment options.
Each is added when a concrete use case requires it, not in advance.

## Cross-cutting concerns

These span several milestones and need decisions before the milestone that
depends on them:

- **Execution isolation.** Scans are currently bounded, not sandboxed. Running
  against untrusted repositories, or applying changes automatically, needs
  isolation appropriate to that threat model (Milestones 6–8).
- **Reproducible advisory data.** By default OSV-Scanner queries the live OSV
  API, so results drift as advisories change. Verification needs either a
  pinned advisory snapshot or a recorded basis for comparing results
  (Milestones 4 and 7).

## Open product decisions

- Precise semantics for each verification outcome, especially where
  **inconclusive** ends and **still vulnerable** begins.
- Whether to keep honoring `.gitignore` during scans, and how coverage
  differences are reported.
- How far Milestone 6 automation goes before AI-assisted remediation is
  considered (Milestone 8).
- Whether source repositories or container images come next after the Python
  dependency slice.

## How milestones are delivered

**Define issue → Review architecture → Implement → Independent review → Test →
Merge**

Each issue states the problem, the architectural approach, alternatives
considered, security and correctness implications, how success is measured,
and what is deliberately deferred. Pull requests are reviewed independently
and are not merged automatically.
