# Local OSV-Scanner integration

Install the official **OSV-Scanner v2.3.0** binary for your platform from
https://github.com/google/osv-scanner/releases/tag/v2.3.0 and verify its checksum
against the release before use. Place it on PATH or pass `--executable`.
This adapter targets the v2 source JSON schema, not image scans or v1 commands.
The executable is trusted configuration; do not select one from an untrusted repo.

```sh
uv sync --locked
uv run python -m remediator.cli tests/fixtures/vulnerable-python \
  --executable /path/to/osv-scanner --artifacts /tmp/remediator-artifacts \
  --output /tmp/normalized-scan.json
```

The developer CLI emits `ScanResult.model_dump_json(indent=2)`. Its exit code is
0 for successful scans (including vulnerability findings), 2 for partial/failed
scans or invalid CLI configuration. A typical finding includes:

```json
{
  "component": {"name": "Django", "ecosystem": "PyPI", "installed_version": "2.2.0", "location": "/repo/requirements.txt"},
  "fix": {"status": "unknown", "fixed_versions": []}
}
```

Actual output also contains advisory IDs/aliases, source text and references,
repository asset, execution ID, scanner identity, UTC observation time and an
artifact URI. Advisory IDs and package spelling are preserved. Scanner version
is null: the adapter does not infer a version from the executable filename.
Record `osv-scanner --version` alongside a development run for reproducibility.

## Execution and artifacts

The command is an explicit argument list with `shell=False`:
`osv-scanner scan source --format=json --no-resolve ABSOLUTE_DIRECTORY`.
It does not install dependencies, invoke repository build/test scripts, enable
call analysis, or perform transitive manifest resolution. This is a baseline
read-only scan, not OS-level isolation. OSV configuration/ignore rules can affect
coverage. Use trusted, controlled local fixtures. There is no remote ingestion,
repository checkout, remediation, HTTP endpoint or background worker.

Defaults: 120-second timeout and 10 MiB total retained output. The subprocess is
killed on timeout or excess output. Temporary file sizes are polled every 20ms;
they can overshoot between polls. This is not a disk quota or process sandbox.
The adapter retains capped `stdout.json` and `stderr.txt` under
`ARTIFACT_DIRECTORY/EXECUTION_ID/`, including for failed and clean scans.
The directory must be outside the target. Each run directory is private (0700).
An artifact write failure is raised, rather than reported as a successful scan.
Raw output can contain sensitive paths, package inventory and advisory text;
control access/retention and never commit real scan artifacts. CLI `--output`
should also point outside the repository. `.remediator-artifacts/` is ignored.
For parsing externally retained output, call `normalize(..., artifact_reference=...)`.
The caller is responsible for bounding that input and retaining the referenced data.

## Mapping and limits

The schema and exit codes were checked against v2.3.0 upstream
`pkg/models/results.go` and `cmd/osv-scanner/internal/cmd/run.go` at
`b0b6027aa7b2b50fd3fe5fe185d609f481f02a44`.
Exit 0 is completion; 1 means vulnerabilities; 127 is generic error, 128 no
packages, 129 API failure, 130 invalid configuration. All other codes (including
signals) produce diagnostics. Valid findings from interrupted/error runs yield
`partial`; errors without findings yield `failed`. Exit 1 without supported
findings also fails. Malformed JSON never becomes a clean scan.

Only package findings from `lockfile` and `sbom` sources are supported.
Unsupported or malformed sources/packages/advisories produce indexed diagnostics;
valid sibling records survive. A partial result can have findings; an entirely
rejected result fails. Optional unknown OSV fields remain in the raw artifact.
Distinct advisory IDs (even aliases of one another) and manifests remain separate;
only identical normalized observations in the same run are collapsed.

Fix information stays **unknown**, even when OSV lists fixed range events:
this first adapter does not establish which range/fix applies to the installed
version or select upgrade candidates. It never copies unrelated package fixes,
claims no fix, or invents versions. Severity and CVSS are not derived from scores;
severity remains null. Original advisory references, summary and details are
mapped when present. Full affected ranges, scores, source type and scanner-only
metadata are retained in the separate raw artifact. Domain models and FastAPI
behavior are unchanged.

## Tests and live demo

```sh
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner -s
```

Offline fixtures under `tests/fixtures/osv` are synthetic v2.3.0-shaped records
with deliberately fictional advisory IDs; they are not captured sensitive output.
They cover clean, single, multiple, minimal metadata, malformed and partial/failed
cases. Unit execution tests mock the CLI. The opt-in test uses a synthetic Python
manifest pinned to Django 2.2.0; **never install these vulnerable dependencies**.
The live scan needs OSV database/network availability. Advisory counts/IDs and
metadata drift, so the test asserts a Django finding rather than an exact count.
CI remains offline for unit tests; the integration test is skipped by default.
