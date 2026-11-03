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
  --asset-key example/vulnerable-python --output /tmp/normalized-scan.json
```

Optional flags: `--asset-key KEY` records a caller-chosen stable identity on the
asset (checkout paths are not identity; future cross-scan comparison will require
it), and `--offline-database DIR` selects a local OSV database (see
[Provenance](#provenance)).

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
artifact URI. Advisory IDs and package spelling are preserved. Reports use
schema version 2 and also carry [coverage evidence](#coverage-evidence) and
[provenance](#provenance), including the scanner version that `--version`
reported (never inferred from the executable name).

## Execution and artifacts

The command is an explicit argument list with `shell=False`:
`osv-scanner scan source --format=json --no-resolve --recursive --all-packages --config ADAPTER_CONFIG ABSOLUTE_DIRECTORY`,
with `--offline --local-db-path=DIR` inserted before `--config` when an offline
database is selected. A separate `osv-scanner --version` run precedes it with
the same process controls, a 30-second cap, and a 64 KiB output bound.
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

The adapter retains capped `stdout.json` and `stderr.txt`, plus `version.txt`
(the bounded `--version` output), under
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

## Coverage evidence

**A successful exit and zero findings are not evidence that anything was
assessed.** OSV-Scanner v2.3.0 omits clean packages unless `--all-packages` is
passed, never lists empty manifests or `.gitignore`-excluded manifests, reports
the lower bound of `requests>=2.0` as version `2.0`, and silently skips several
Python manifest formats. Each report therefore carries a `coverage` record built
from two independent sources:

1. **Scanner package records** (`--all-packages`), including packages with no
   advisories.
2. **An independent, read-only inventory** of Python manifests under the target.

The inventory is bounded (depth 32, 100,000 directory entries) and walks with
directory file descriptors and `O_NOFOLLOW`, so symlinks are never followed at
any path component. It skips only `.git`. It reads at most 1 MiB of a manifest
(and only to classify it: requirement lines, emptiness, or whether
`pyproject.toml`/`setup.cfg` declare dependencies). It never executes, imports,
or builds anything, including `setup.py`.

| Patterns | Inventory classification |
|---|---|
| `*requirements*.txt` (case-sensitive, as OSV matches), `Pipfile.lock`, `pdm.lock`, `poetry.lock`, `uv.lock` | Supported: must be reported by the scanner |
| `setup.py`; `setup.cfg` and `pyproject.toml` that declare dependencies; `Pipfile`; `pylock*.toml`; `*requirements*.in`; case variants such as `Requirements.txt`; `*.txt` inside a `requirements/` directory | Unsupported: declared dependencies are not assessed |
| Symlinked manifests and symlinked directories | Excluded: not followed by the inventory or OSV-Scanner |

These patterns mirror the osv-scalibr v0.4.0 extractors enabled by OSV-Scanner
v2.3.0 source scans (`requirements`, `pipfilelock`, `pdmlock`, `poetrylock`,
`uvlock`). Other ecosystems are not inventoried.

Per manifest, `status` is `assessed` (the scanner reported package records),
`not_reported`, `excluded`, `unsupported`, or `unknown` (reported by a scan that
did not succeed). Per package:

- `assessment` is `assessed` only for a successful scan, ecosystem `PyPI`, and a
  non-empty version. An empty version (for example `idna>=2,<3` or `==1.24.*`)
  is `not_assessed`: OSV filtered it before matching. Other ecosystems are
  `unknown`; their coverage semantics are not documented here.
- `version_precision` is `exact` for lockfiles and for direct `==`/`===` pins
  without wildcards; `imprecise` for any other constraint; and `unknown` when
  the package is not declared directly in the reported manifest (for example via
  `-r`), declared inconsistently, or the manifest could not be inspected.

Only `assessed` with `exact` precision counts as **confidently assessed**.
Everything else carries a reason. A supported manifest the scanner did not
report is `not_reported` with reason `no_dependency_entries` (the inventory
found none), `possibly_ignored` (a `.gitignore` is in scope), or
`not_reported_by_scanner`. Repository `.gitignore` rules are still honored by
the scanner, but every exclusion is observable and blocks a coverage claim.

The overall `coverage.status` is:

- `no_known_gaps`: the scan succeeded, the inventory finished, at least one
  manifest was assessed, and every inventoried manifest and package was
  confidently assessed. It is bounded by the inventory scope above and the
  advisory basis; it is **not** a claim of complete repository coverage.
- `incomplete`: any limitation exists. Each one is listed in `limitations` with a
  machine-readable `reason`, a path, and a detail.
- `unknown`: the scan was partial or failed, or its output was unusable.
  Observations are kept as diagnostics only, and packages are `unknown`.

Scanner sources outside the target keep their findings (they are still
evidence) but never count toward coverage.

## Provenance

`provenance` records evidence about how the report was produced. Each fact
states its origin: `scanner` facts were reported by the scanner itself, and
`adapter` facts were configured, observed, or computed by this adapter. A value
that could not be obtained is null with a `detail` explaining why; nothing is
inferred.

| Field | Origin | Contents |
|---|---|---|
| `scanner.version`, facts `scanner_version`, `scalibr_version`, `scanner_commit`, `scanner_build_date` | scanner | Parsed from `--version`. Missing or unparseable output stays unavailable. A non-2.x version makes the scan fail |
| `command`, `started_at`, `finished_at`, `exit_code` | adapter | The exact argument list and the observed execution window and exit status |
| `executable`, `executable_sha256` | adapter | The resolved executable and its digest (of a wrapper, if one is used) |
| `configuration`, `configuration_sha256` | adapter | The adapter-owned override configuration |
| `timeout_seconds`, `max_output_bytes` | adapter | Execution bounds |
| `inherited_osv_environment` | adapter | Names (never values) of inherited `OSV_*` variables, which can influence the scanner |
| `advisory_source` | adapter | See below |
| `artifacts` | adapter | URIs of retained `stdout.json`, `stderr.txt`, and `version.txt` |

`advisory_source.kind` is `online_service` by default: OSV-Scanner queried the
live OSV API, which is time-bound and **never reproducible**. With
`--offline-database DIR`, the scanner runs with `--offline` against
`DIR/osv-scanner/<ecosystem>/all.zip` and never downloads. The adapter records
SHA-256 digests of the archives before and after the scan. It is `reproducible`
only if archives exist and are unchanged; a change during the scan is an error.
OSV-Scanner does not report which archives it loaded, so all present archives
are fingerprinted. The directory must be outside the target, because
repository-controlled advisory data would undermine verification.
`--local-db-path` is a hidden OSV-Scanner flag; if a later version drops it,
the scan fails rather than silently going online.

Coverage status and advisory reproducibility are independent: an online scan
can have `no_known_gaps` coverage while its advisory basis is not reproducible.

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
metadata are retained in the separate raw artifact. With `--all-packages`,
package records without advisories produce coverage entries, not findings or
errors. FastAPI behavior is unchanged.

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

Three opt-in tests use the real checksum-verified v2.3.0 executable:

```sh
# No network: generate a temporary OSV cache containing the one public advisory.
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner_offline -v
# No network: real coverage behavior for clean, nested, ignored, empty, symlinked cases.
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner_coverage -v
# Live API: database/network availability required; advisory data can drift.
RUN_OSV_INTEGRATION=1 OSV_SCANNER=/path/to/osv-scanner uv run pytest tests/test_osv.py::test_real_scanner -v
```

The offline integration test selects the cached advisory with
`offline_database`, so the recorded advisory source is exact. For both advisory
and package ignore rules it first proves that a normal scan is suppressed, then
proves that the adapter reports the known advisory from a nested Django 2.1.0
manifest despite root and nested configurations, and that the database is
recorded as a reproducible, fingerprinted source. `test_real_scanner_coverage`
scans fully offline: a clean repository must reach `no_known_gaps`, and a
repository combining nested, empty, ignored, unsupported, imprecise, unversioned,
and symlinked manifests must report each case with its reason. The live test scans
nested Django 2.2.0 with attempted repository suppression.
Never install these deliberately vulnerable fixture dependencies.

`all-packages-clean.json` and `all-packages-mixed.json` are real OSV-Scanner
v2.3.0 `--all-packages` output from synthetic repositories, trimmed to one public
advisory per package with paths rebased to `/repo`. Coverage tests rebuild the
matching files and run the real inventory, covering clean packages, nested
manifests, imprecise and unversioned constraints, `-r` includes, empty, ignored,
unsupported, and symlinked manifests, other ecosystems, and failed and partial
scans. Each scenario asserts that nothing unassessed is counted as confidently
assessed.
