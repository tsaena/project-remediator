# Project Remediator

An open-source vulnerability remediation and verification engine, currently at
the API foundation and vulnerability domain-contract stage. A health endpoint,
scanner-independent domain models, and development tooling are implemented.
Scanning, remediation, verification, storage, workers, and AI integrations are
not implemented.

**Experimental and not production-ready.**

## Prerequisites

- Python 3.12 (or allow uv to install it automatically).
- [uv](https://docs.astral.sh/uv/getting-started/installation/); CI and Docker use
  uv 0.13.5.
- Git for cloning. Docker Engine/Desktop with the Compose plugin for container
  execution; Docker is not needed for local development or tests.

## Local setup and execution

```sh
git clone https://github.com/tsaena/project-remediator.git
cd project-remediator
uv sync --locked
uv run uvicorn remediator.api.main:app --host 127.0.0.1 --port 8000
```

The committed `.python-version` selects Python 3.12. `uv sync --locked` installs
the package and development tools in `.venv` from `uv.lock`. No secrets or
external services are required.

In another terminal, verify the API:

```sh
curl --fail http://localhost:8000/health
```

Expected HTTP 200 response:

```json
{"status":"healthy","service":"project-remediator"}
```

Open <http://localhost:8000/docs> for interactive OpenAPI documentation. The schema
is available at <http://localhost:8000/openapi.json>. Stop the local server with
Ctrl-C. For optional local auto-reload, append `--reload` to the Uvicorn command.

## Docker Compose

With Docker running, from the repository root:

```sh
docker compose up --build
```

Use the same health and documentation URLs above. Compose binds port 8000 to
`127.0.0.1` only. Stop any local server using that port first. The image installs
locked runtime dependencies, runs as a non-root user, and starts without secrets,
bind mounts, or auto-reload. Stop with Ctrl-C, then remove the container with:

```sh
docker compose down
```

## Verification

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
docker compose config --quiet
docker build -t project-remediator:local .
```

Tests require no Docker or external services. API tests use HTTPX's ASGI
transport in-process to check the health response, documentation page, and
OpenAPI route. Domain tests validate synthetic fixtures and model invariants.
GitHub Actions runs lint, formatting, type checking, tests, and a Docker build on
pull requests and pushes to `main`.

To apply formatting during development:

```sh
uv run ruff format .
```

When intentionally changing dependencies, update `pyproject.toml`, run `uv lock`
and `uv sync --locked`, and commit both `pyproject.toml` and `uv.lock`.

## Domain models

See [the domain model guide](docs/domain-model.md) for normalized vulnerability,
provenance, fix-information, and scan-status contracts and synthetic examples.
The domain contracts add no HTTP endpoints.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Developer dependency scans

The first scanner adapter supports controlled local source scans with OSV-Scanner.
See [installation, CLI usage, mapping decisions and optional live tests](docs/osv-scanner.md).
No API scan endpoint or remediation is included.
