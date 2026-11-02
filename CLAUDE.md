# CLAUDE.md

Project Remediator closes the vulnerability remediation loop
(**Detect → Normalize → Plan → Apply → Verify**) with trustworthy,
evidence-backed verification. It is experimental and not production-ready.

Read [`docs/vision.md`](docs/vision.md) and [`docs/roadmap.md`](docs/roadmap.md)
before proposing significant architecture changes or implementing major
features. Component details live in [`docs/domain-model.md`](docs/domain-model.md)
and [`docs/osv-scanner.md`](docs/osv-scanner.md).

## Technology

Python 3.12 · uv · FastAPI · Pydantic v2 · Ruff (lint and format) · strict mypy ·
pytest · Docker Compose · GitHub Actions.

The authoritative commands are in the README's **Verification** section,
`pyproject.toml`, and `.github/workflows/ci.yml`. Before reporting work as done,
run at least:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Real OSV-Scanner tests are opt-in (`RUN_OSV_INTEGRATION=1`); see
`docs/osv-scanner.md`. Change dependencies only when an issue requires it, and
commit `pyproject.toml` and `uv.lock` together.

## Architecture boundaries

- `src/remediator/domain/` holds normalized models. They must not depend on
  scanners, FastAPI, or persistence.
- Scanner-specific execution and parsing belong in adapters under
  `src/remediator/scanners/`.
- Preserve advisory and scanner provenance. Never discard evidence silently.
- Keep remediation planning separate from execution.
- Keep verification independent of remediation.
- Do not add abstractions, services, databases, workers, or infrastructure
  before a concrete use case requires them.

## Security and correctness rules

- Never interpret a failed or partial scan as clean.
- Never infer that an unknown fix means no fix exists.
- Never declare remediation verified solely because a finding disappeared.
- Never trust repository-controlled scanner exclusions or configuration for
  independent verification.
- Avoid executing untrusted repository code unnecessarily.
- Never commit secrets or real scanner artifacts; test fixtures are synthetic
  or public advisory data.
- Run subprocesses with explicit argument lists, timeouts, bounded output, and
  cleanup.

## Working on an issue

1. Read the complete issue, including acceptance criteria and out-of-scope items.
2. Inspect the relevant code and existing tests.
3. Propose an approach consistent with the vision: the problem, the approach,
   alternatives considered, security and correctness implications, how success
   is measured, and what is deliberately deferred.
4. Keep changes within the issue's scope.
5. Add positive and negative tests, especially for false-success conditions.
6. Run all applicable quality checks.
7. Report exact results, including any checks that were not run and why.
8. Open a pull request that closes the issue, and leave it unmerged unless
   explicitly told otherwise.

A passing CI run is not proof of correctness. For security-sensitive changes,
write adversarial tests and verify scanner behavior against upstream source or
the real binary rather than assumptions. Do not accept earlier AI-generated
code or decisions without checking them; challenge them when evidence
supports it.
