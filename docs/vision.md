# Project Remediator — Vision & Engineering Principles

This is the canonical statement of what Project Remediator is for and how it is
built. The milestone sequence lives in the [roadmap](roadmap.md); repository
conventions for coding agents live in [`CLAUDE.md`](../CLAUDE.md).

## Mission

Project Remediator is an open-source, scanner-agnostic vulnerability remediation
and verification engine.

Its purpose is to bridge the gap between identifying vulnerabilities and
producing trustworthy, evidence-backed proof that remediation was successful.

> **Finding a vulnerability is the beginning of the workflow, not the end.**

## The problem

Vulnerability scanners identify security issues, but remediation and
verification are often fragmented across developer workflows, security
platforms, CI pipelines, and manual processes.

A vulnerability disappearing from a scanner report does not necessarily prove
that it was fixed. It might have disappeared because:

- Scanner coverage changed.
- A manifest was excluded.
- A repository-controlled configuration suppressed findings.
- The underlying dependency or asset identity changed.
- An advisory database or scanner version changed.
- A scan failed or returned incomplete results.

Project Remediator aims to distinguish genuine remediation from these
alternative explanations.

## Core workflow

**Detect → Normalize → Plan → Apply → Verify**

### 1. Detect

Use established vulnerability scanners, such as OSV-Scanner and eventually
Trivy, to identify known vulnerabilities. Do not reinvent existing
vulnerability detection engines.

### 2. Normalize

Convert scanner-specific observations into consistent internal domain models.
Preserve scanner provenance, asset and component identity, advisory
identifiers, timestamps, scan status, and references to original evidence.

### 3. Plan

Generate evidence-backed remediation recommendations using vulnerability
advisories, dependency information, available fixed versions, and
compatibility constraints. Distinguish confirmed information from assumptions
and unknowns.

Initially, favor deterministic, explainable remediation planning over
AI-generated guesses.

### 4. Apply

Support human-reviewed remediation changes first. Eventually support
deterministic automated modifications and constrained AI-assisted remediation,
including agents capable of proposing patches or pull requests.

The remediation executor is not responsible for independently declaring its
own work successful.

### 5. Verify

Independently reassess the affected asset following a remediation. Compare
pre-remediation and post-remediation evidence to determine whether the original
vulnerability was addressed. A finding disappearing is not sufficient proof by
itself.

Verification must consider:

- Whether the same asset and relevant components were assessed.
- Whether scanner coverage remained sufficient.
- Whether scanner configuration or exclusions changed.
- Whether the original vulnerable dependency was upgraded, removed, or
  otherwise addressed.
- Whether the scan completed successfully.
- Whether the vulnerability identity can be reliably correlated across
  observations.
- Whether new vulnerabilities appeared following the change.

Verification produces explicit outcomes, such as:

- **Verified fixed**
- **Still vulnerable**
- **Inconclusive**
- **Newly introduced findings**

Each outcome must have clear, documented semantics and supporting evidence.

## Guiding engineering principles

### Evidence over assertions

Every meaningful vulnerability and remediation claim must be traceable to
evidence. Do not claim successful remediation solely because a command
completed or an advisory disappeared.

### Unknown is not safe

Incomplete scans, missing advisory information, unsupported package formats,
uncertain vulnerability matches, and missing evidence must remain explicit.
Never silently transform uncertainty into a clean or verified result.

### Scanner independence

Integrate existing scanners rather than duplicating their detection
capabilities. Keep scanner-specific interpretation in adapters, and keep domain
models independent of individual vendors.

### Verification independence

Verification must not blindly trust the system that proposed or performed
remediation. An agent must not be able to make its own remediation appear
successful by changing scanner configuration, hiding manifests, or suppressing
findings.

### Controlled execution

Treat repository content, dependency metadata, and external inputs as
potentially untrusted. Use least privilege, bounded execution, controlled
configuration, and isolation appropriate to the threat model.

A read-only scanning command is not automatically a sandbox.

### Deterministic foundations before AI

Establish correct parsing, normalization, finding correlation, remediation
planning, and verification before adding autonomous agents. AI should improve
the remediation workflow, not become the source of truth for verification.

### Incremental engineering

Prefer small, working vertical slices over speculative infrastructure. Do not
introduce distributed systems, databases, workers, orchestration layers, or
abstractions before a concrete use case requires them.

### Explainability and auditability

A user should be able to understand:

- What was detected.
- Why it matters.
- What remediation was proposed.
- What changed.
- What was verified.
- What remains uncertain.

## Initial product scope

The first useful product is a local-first, developer-oriented vulnerability
remediation and verification tool. In priority order:

1. Local source repositories.
2. Dependency vulnerabilities.
3. OSV-Scanner integration.
4. Normalized findings and evidence.
5. Deterministic remediation recommendations.
6. Human-reviewed changes.
7. Independent rescanning and verification.

The CLI is the initial workflow interface. The existing FastAPI foundation
remains available for future service capabilities, but HTTP scan APIs are not
immediately necessary.

## Longer-term direction

Potential capabilities include:

- Trivy and other scanner adapters.
- Container-image assessment and remediation workflows.
- Automated package upgrade proposals.
- Dependency compatibility and regression testing.
- Constrained AI agents for complex remediation.
- GitHub pull-request automation.
- CI/CD verification workflows.
- Persistent scan histories.
- Background workers and job orchestration.
- An API and dashboard for engineering and security teams.

These are directions, not commitments to build all of this infrastructure
immediately.

## Definition of success

Given a deliberately vulnerable repository, Project Remediator should
eventually:

1. Detect known vulnerable dependencies.
2. Normalize findings with traceable evidence.
3. Identify defensible remediation candidates.
4. Propose a specific change.
5. Apply or accept a human-approved modification.
6. Independently rescan the repository.
7. Compare the original and new observations.
8. Produce a trustworthy verification outcome with evidence.

A successful outcome must be reproducible, understandable, and auditable.

## Current status

**Project Remediator is experimental and not production-ready.**

As of November 2026, the **Detect** and **Normalize** stages exist for local
source repositories. **Plan**, **Apply**, and **Verify** are not implemented.

Merged into `main`:

- **Application foundation** — Python 3.12, uv, FastAPI health and
  documentation endpoints, Docker Compose, Ruff, strict mypy, pytest, and
  GitHub Actions CI ([issue #1](https://github.com/tsaena/project-remediator/issues/1), [PR #3](https://github.com/tsaena/project-remediator/pull/3)).
- **Domain contracts** — scanner-independent Pydantic v2 models for assets,
  components, vulnerabilities, findings, scanner evidence, fix information, and
  scan results ([domain model guide](domain-model.md); [issue #4](https://github.com/tsaena/project-remediator/issues/4), [PR #5](https://github.com/tsaena/project-remediator/pull/5)).
- **OSV-Scanner v2 integration** — controlled local source scans, conservative
  JSON normalization, retained raw artifacts, and a developer CLI
  ([OSV-Scanner guide](osv-scanner.md); [issue #6](https://github.com/tsaena/project-remediator/issues/6), [PR #7](https://github.com/tsaena/project-remediator/pull/7)).

No pull requests are currently under review.

Known gaps that affect the later stages:

- Fix information is always `unknown`. Fixed versions are not yet derived from
  advisory data.
- Scanner version is not recorded in scan results.
- Related advisory IDs for the same underlying vulnerability (for example
  PYSEC and GHSA records that share a CVE) are reported as separate findings.
- Findings have no identity that can be correlated across scan executions.
- Scans honor the repository's `.gitignore`, do not resolve transitive
  dependencies, and run without OS-level isolation.

The [roadmap](roadmap.md) describes how these gaps are addressed.
