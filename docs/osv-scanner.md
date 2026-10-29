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
`osv-scanner scan source --format=json --no-resolve --recursive --config ADAPTER_CONFIG ABSOLUTE_DIRECTORY`.
It does not install dependencies, invoke repository build/test scripts, enable
call analysis, or perform transitive manifest resolution. This is a baseline
read-only scan, not OS-level isolation. The adapter writes an empty, private
configuration in its own temporary working directory and passes its absolute
path via `--config`. In v2.3.0, `ConfigManager.UseOverride` replaces all discovered
repository configurations; it is not a fallback default. Repository
`IgnoredVulns` and `PackageOverrides` cannot suppress adapter findings. The
configuration is removed after execution. The trusted executable runs from that
controlled directory with stdin connected to DEVNULL.

Recursive discovery includes supported nested manifests, but still honors
`.gitignore` (the adapter does not pass `--no-ignore`). OSV's extractor selection,
unsupported manifests, symlinks (not traversed in v2.3.0), missing/unpinned versions,
and disabled transitive resolution limit coverage. A successful scan describes
what OSV observed; it does not certify that every dependency was scanned.
There is no remote ingestion, repository checkout, remediation, HTTP endpoint or
background worker.

Defaults: 120-second timeout and 10 MiB combined stdout/stderr. Configure them with
`--timeout` and `--max-output-bytes` (or the adapter constructor). Timeouts must be
finite and positive. Nonblocking pipes retain at most the configured byte limit;
there are no scanner-controlled temporary disk spools. Each read uses at most
64 KiB extra memory, in addition to pipe buffers, retained bytes, and JSON parsing.
Overflow or timeout kills the POSIX process group, waits for the direct child,
and closes pipes. Cleanup also runs when the leader exits before its descendants.
Execution errors cannot become clean successful results.

Supported execution requires POSIX process groups, selectors, directory file
descriptors, and O_NOFOLLOW/O_EXCL; validated on Linux. Other platforms, including
Windows, fail explicitly instead of claiming child-tree cleanup or private file
creation. A future Windows implementation needs Job Objects and appropriate ACLs.
The adapter deliberately avoids `preexec_fn` (unsafe in threaded callers),
`RLIMIT_AS` (not a reliable portable bound for the Go runtime), and disk-file
polling. These controls do not bound the scanner's own memory/CPU or stop a
malicious executable escaping its process group. Use a trusted scanner binary;
stronger enforcement requires a separately configured container/cgroup sandbox.

The adapter retains capped `stdout.json` and `stderr.txt` under
`ARTIFACT_DIRECTORY/EXECUTION_ID/`, including for failed and clean scans.
The artifact reference is the URI of this directory, containing those two files,
not an individual JSON file. The execution ID ties it to the normalized result.
The artifact directory must be outside the target; path components cannot be
symlinks. Each run directory is private (0700) and files are exclusive (0600).
An artifact write failure is raised, rather than reported as a successful scan.
Raw output can contain sensitive paths, package inventory and advisory text;
control access/retention and never commit real scan artifacts.

CLI `--output` must be outside the scanned target and artifact directory, with
an existing parent directory. Existing files, directories, symlinks (including
parent components), and special files are rejected. It is reserved exclusively
before scanning and written with mode 0600, regardless of umask. Failures produce
an argparse error with a `scan/output failed` explanation and exit 2. Interrupted
or failed output writes may leave a private incomplete file; choose a fresh path
for the next run. Standard output remains available when `--output` is omitted.
`.remediator-artifacts/` is ignored. For externally retained output, call
`normalize(..., artifact_reference=...)`; the caller must bound that input and
retain the referenced data.

For builds behind a TLS-inspecting proxy, the Dockerfile accepts an optional
BuildKit CA secret without persisting it in the image:
`docker build --secret id=proxy_ca,src=/path/to/combined-ca-bundle.pem -t project-remediator:local .`.
Normal builds need no secret and retain normal TLS verification.

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
with fictional advisory IDs, except `django-advisory.json`. That fixture is a
reduced public GHSA-6c3j-c64m-qhgq / CVE-2019-11358 record, retaining the PyPI
affected entries from OSV-Scanner v2.3.0's
`internal/remediation/testdata/santatracker/vulns.json`; its `database_specific`
source points to the GitHub Advisory Database. It is test evidence, not a product
advisory database or a captured repository scan.

Execution tests launch lightweight real fake-scanner processes and assert the
full command and subprocess options. They cover exit codes, malformed JSON,
non-finite timeouts, DEVNULL stdin, nested paths, controlled config, stdout and
stderr overflow, and descendant cleanup (including an already-exited leader).
CLI tests cover output containment, overwrite rejection, parent/final symlinks,
file modes and understandable errors. Default tests require no network or scanner.

Two opt-in tests use the real checksum-verified v2.3.0 executable:

```sh
# No network: generate a temporary OSV cache containing the one public advisory.
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner_offline -v
# Live API: database/network availability required; advisory data can drift.
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner -v
```

The offline integration test uses OSV's built-in offline matcher through a trusted
test wrapper. For both advisory and package ignore rules it first proves that a
normal scan is suppressed, then proves that the adapter reports the known advisory
from a nested Django 2.1.0 manifest despite root and nested configurations.
The live test scans nested Django 2.2.0 with attempted repository suppression.
Never install these deliberately vulnerable fixture dependencies.

Validation for this security correction: Ruff, strict mypy, default pytest,
Docker build with the proxy CA mounted, and both real offline integration cases
pass. The live API test was attempted but could not complete because the managed
network policy returned Forbidden for `api.osv.dev/v1/querybatch`; it is not a
successful integration test. The official Linux amd64 binary reported 2.3.0,
commit `b0b6027aa7b2b50fd3fe5fe185d609f481f02a44`, and matched the release checksum
`e774e5770c31d60745c067be5f69bf3b46641b6d0e0ed87fd65e569cda35dc50`.
