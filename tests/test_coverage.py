"""Coverage evidence must never overstate what was assessed.

Fixtures named ``all-packages-*`` are trimmed OSV-Scanner v2.3.0
``--all-packages`` output from synthetic repositories (public advisory data).
"""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from test_osv import fake_scanner

from remediator.domain import (
    AdvisorySourceKind,
    CoverageReason,
    CoverageStatus,
    DiscoveryMethod,
    ManifestCoverage,
    ManifestStatus,
    PackageAssessment,
    ProvenanceOrigin,
    ScanResult,
    ScanStatus,
    VersionPrecision,
)
from remediator.scanners.osv import OSVScanner, normalize
from remediator.scanners.python_manifests import inventory

FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def write(root: Path, relative: str, text: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def scan_output(name: str, target: Path) -> bytes:
    """A captured fixture whose source paths are rebased onto ``target``."""
    return (FIXTURES / name).read_text().replace('"/repo/', f'"{target}/').encode()


def normalized(raw: bytes, target: Path, *, use_inventory: bool = True) -> ScanResult:
    result = normalize(
        raw,
        target=target,
        artifact_reference="test:raw",
        inventory=inventory(target) if use_inventory else None,
    )
    # Every report must survive a serialization round trip with its invariants.
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    return result


def reasons(result: ScanResult) -> set[CoverageReason]:
    assert result.coverage is not None
    return {note.reason for note in result.coverage.limitations}


def manifest(result: ScanResult, path: str) -> ManifestCoverage:
    assert result.coverage is not None
    [found] = [m for m in result.coverage.manifests if m.path == path]
    return found


def mixed_repository(target: Path) -> None:
    write(target, "requirements.txt", "six==1.16.0\nrequests>=2.0\nidna>=2,<3\n")
    write(target, "services/api/requirements.txt", "-r base.in\nDjango==2.2.0\n")
    write(target, "services/api/base.in", "flask===0.12\n")


def test_clean_scan_records_positive_package_evidence(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.status == ScanStatus.SUCCESS and not result.findings
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.NO_KNOWN_GAPS
    found = manifest(result, "requirements.txt")
    assert found.status == ManifestStatus.ASSESSED
    assert found.discovered_by == [DiscoveryMethod.INVENTORY, DiscoveryMethod.SCANNER]
    [package] = found.packages
    assert (package.name, package.version, package.advisory_count) == (
        "six",
        "1.16.0",
        0,
    )
    assert package.confidently_assessed


def test_zero_findings_alone_is_not_coverage(tmp_path: Path) -> None:
    """Exit 0 with no package records (e.g. without --all-packages) proves nothing."""
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    result = normalized(b'{"results": []}', tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    assert manifest(result, "requirements.txt").status == ManifestStatus.NOT_REPORTED
    assert CoverageReason.NO_MANIFESTS_ASSESSED in reasons(result)
    without_inventory = normalized(
        scan_output("all-packages-clean.json", tmp_path), tmp_path, use_inventory=False
    )
    assert without_inventory.coverage is not None
    assert without_inventory.coverage.status == CoverageStatus.INCOMPLETE
    assert CoverageReason.INVENTORY_UNAVAILABLE in reasons(without_inventory)


def test_mixed_precision_and_nested_manifests(tmp_path: Path) -> None:
    mixed_repository(tmp_path)
    result = normalized(scan_output("all-packages-mixed.json", tmp_path), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    root = {p.name: p for p in manifest(result, "requirements.txt").packages}
    nested = {
        p.name: p for p in manifest(result, "services/api/requirements.txt").packages
    }
    assert root["six"].confidently_assessed
    # requests>=2.0 is reported as 2.0 by OSV-Scanner; it is not an exact pin.
    assert root["requests"].version == "2.0"
    assert root["requests"].assessment == PackageAssessment.ASSESSED
    assert root["requests"].version_precision == VersionPrecision.IMPRECISE
    assert not root["requests"].confidently_assessed
    # idna>=2,<3 has no extracted version, so it was never matched.
    assert root["idna"].assessment == PackageAssessment.NOT_ASSESSED
    assert root["idna"].version is None
    assert nested["django"].confidently_assessed
    # flask arrives through "-r base.in", so this manifest does not pin it.
    assert nested["flask"].version_precision == VersionPrecision.UNKNOWN
    assert reasons(result) >= {
        CoverageReason.IMPRECISE_CONSTRAINT,
        CoverageReason.MISSING_VERSION,
        CoverageReason.NOT_DECLARED_IN_MANIFEST,
    }
    # Findings are unaffected by coverage classification.
    assert {f.component.name for f in result.findings} == {
        "requests",
        "flask",
        "django",
    }


@pytest.mark.parametrize(
    ("setup", "path", "status", "reason"),
    [
        (
            lambda root: write(root, "empty/requirements.txt", "# none\n"),
            "empty/requirements.txt",
            ManifestStatus.NOT_REPORTED,
            CoverageReason.NO_DEPENDENCY_ENTRIES,
        ),
        (
            lambda root: (
                write(root, ".gitignore", "vendor/\n"),
                write(root, "vendor/requirements.txt", "Django==2.2.0\n"),
            ),
            "vendor/requirements.txt",
            ManifestStatus.NOT_REPORTED,
            CoverageReason.POSSIBLY_IGNORED,
        ),
        (
            lambda root: write(root, "lost/requirements.txt", "Django==2.2.0\n"),
            "lost/requirements.txt",
            ManifestStatus.NOT_REPORTED,
            CoverageReason.NOT_REPORTED_BY_SCANNER,
        ),
        (
            lambda root: write(root, "setup.py", "setup()\n"),
            "setup.py",
            ManifestStatus.UNSUPPORTED,
            CoverageReason.UNSUPPORTED_FORMAT,
        ),
        (
            lambda root: write(root, "requirements/base.txt", "Django==2.2.0\n"),
            "requirements/base.txt",
            ManifestStatus.UNSUPPORTED,
            CoverageReason.UNSUPPORTED_FORMAT,
        ),
        (
            lambda root: (root / "linked-requirements.txt").symlink_to(
                root / "requirements.txt"
            ),
            "linked-requirements.txt",
            ManifestStatus.EXCLUDED,
            CoverageReason.SYMLINK_NOT_FOLLOWED,
        ),
        (
            # Unsupported manifest names must not vanish when symlinked.
            lambda root: (root / "Pipfile").symlink_to(root / "requirements.txt"),
            "Pipfile",
            ManifestStatus.EXCLUDED,
            CoverageReason.SYMLINK_NOT_FOLLOWED,
        ),
        (
            lambda root: (root / "requirements.in").symlink_to(
                root / "requirements.txt"
            ),
            "requirements.in",
            ManifestStatus.EXCLUDED,
            CoverageReason.SYMLINK_NOT_FOLLOWED,
        ),
    ],
)
def test_unassessed_manifests_block_coverage_claims(
    tmp_path: Path,
    setup: Callable[[Path], object],
    path: str,
    status: ManifestStatus,
    reason: CoverageReason,
) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    setup(tmp_path)
    # The scanner reports only the root manifest, exactly as in a clean scan.
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    found = manifest(result, path)
    assert found.status == status and not found.packages
    assert [n.reason for n in found.notes] == [reason]
    assert reason in reasons(result)
    assert manifest(result, "requirements.txt").packages[0].confidently_assessed


def test_any_other_symlink_blocks_coverage(tmp_path: Path) -> None:
    """A link's target type is never inspected, so even a file link is a gap."""
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    write(tmp_path.parent / "elsewhere", "notes.md")
    (tmp_path / "docs").symlink_to(tmp_path.parent / "elsewhere")
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    assert [(n.reason, n.path) for n in result.coverage.limitations] == [
        (CoverageReason.SYMLINK_NOT_FOLLOWED, "docs")
    ]


def test_declarations_the_scanner_skipped_are_not_assessed(tmp_path: Path) -> None:
    """OSV-Scanner v2.3.0 silently drops dotted and one-character names."""
    write(tmp_path, "requirements.txt", "six==1.16.0\nzope.interface==5.0\nx==1.0\n")
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    packages = {p.name: p for p in manifest(result, "requirements.txt").packages}
    assert packages["six"].confidently_assessed
    for name in ("zope-interface", "x"):
        assert packages[name].assessment == PackageAssessment.NOT_ASSESSED
        assert packages[name].version is None
        assert [n.reason for n in packages[name].notes] == [
            CoverageReason.NOT_REPORTED_BY_SCANNER
        ]


@pytest.mark.parametrize("include", ["-r base.in", "--requirement=base.in"])
def test_requirement_includes_block_coverage(tmp_path: Path, include: str) -> None:
    """Included declarations may be skipped (or, for --requirement, never read)."""
    write(tmp_path, "requirements.txt", f"six==1.16.0\n{include}\n")
    write(tmp_path, "base.in", "zope.interface==5.0\n")
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    found = manifest(result, "requirements.txt")
    assert found.status == ManifestStatus.ASSESSED
    assert [n.reason for n in found.notes] == [CoverageReason.UNINSPECTED_INCLUDE]
    assert found.notes[0].detail is not None and include in found.notes[0].detail
    assert found.packages[0].confidently_assessed


@pytest.mark.parametrize(
    "line", ["-e ./localpkg", "./localpkg", "https://example.invalid/x.whl"]
)
def test_unattributable_declarations_block_coverage(tmp_path: Path, line: str) -> None:
    write(tmp_path, "requirements.txt", f"six==1.16.0\n{line}\n")
    result = normalized(scan_output("all-packages-clean.json", tmp_path), tmp_path)
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    found = manifest(result, "requirements.txt")
    assert [n.reason for n in found.notes] == [CoverageReason.UNRECOGNIZED_DECLARATION]
    # No bogus package (such as "https") is invented from the line.
    assert [p.name for p in found.packages] == ["six"]


@pytest.mark.parametrize(
    "package",
    [
        {"name": "", "version": "1.0", "ecosystem": "PyPI"},
        {"name": "  ", "version": "1.0", "ecosystem": "PyPI"},
        {"name": "six", "version": " ", "ecosystem": "PyPI"},
        {"name": "six", "version": "1.0", "ecosystem": "\t"},
    ],
)
def test_blank_package_strings_keep_sibling_findings(
    tmp_path: Path, package: dict[str, str]
) -> None:
    mixed_repository(tmp_path)
    document = json.loads(scan_output("all-packages-mixed.json", tmp_path))
    document["results"][0]["packages"].append({"package": package})
    result = normalized(json.dumps(document).encode(), tmp_path)
    # The malformed record is a diagnostic; valid findings survive.
    assert result.status == ScanStatus.PARTIAL
    assert any("malformed package" in error for error in result.errors)
    assert {f.component.name for f in result.findings} == {
        "requests",
        "flask",
        "django",
    }
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.UNKNOWN
    assert CoverageReason.MALFORMED_RECORD in reasons(result)


def test_lockfile_versions_are_exact(tmp_path: Path) -> None:
    write(tmp_path, "poetry.lock", '[[package]]\nname = "six"\nversion = "1.16.0"\n')
    document = json.loads(scan_output("all-packages-clean.json", tmp_path))
    document["results"][0]["source"]["path"] = str(tmp_path / "poetry.lock")
    result = normalized(json.dumps(document).encode(), tmp_path)
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.NO_KNOWN_GAPS


def test_other_ecosystems_are_not_vouched_for(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    document = json.loads(scan_output("all-packages-clean.json", tmp_path))
    document["results"].append(
        {
            "source": {"path": str(tmp_path / "package-lock.json"), "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "left-pad",
                        "version": "1.0.0",
                        "ecosystem": "npm",
                    }
                }
            ],
        }
    )
    result = normalized(json.dumps(document).encode(), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    [package] = manifest(result, "package-lock.json").packages
    assert package.assessment == PackageAssessment.UNKNOWN
    assert CoverageReason.ECOSYSTEM_OUTSIDE_SCOPE in reasons(result)
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.INCOMPLETE


def broken_source(document: dict[str, object]) -> None:
    results = document["results"]
    assert isinstance(results, list)
    results.append({"source": {"path": "/elsewhere", "type": "os"}, "packages": []})


@pytest.mark.parametrize("failure", ["invalid-json", "malformed-source", "errors"])
def test_unsuccessful_scans_never_claim_coverage(tmp_path: Path, failure: str) -> None:
    mixed_repository(tmp_path)
    raw = scan_output("all-packages-mixed.json", tmp_path)
    errors: list[str] = []
    if failure == "invalid-json":
        raw = raw[: len(raw) // 2]
    elif failure == "malformed-source":
        document = json.loads(raw)
        broken_source(document)
        raw = json.dumps(document).encode()
    else:
        errors = ["OSV-Scanner timed out"]
    result = normalize(
        raw,
        target=tmp_path,
        artifact_reference="test:raw",
        inventory=inventory(tmp_path),
        execution_errors=errors,
    )
    assert result.status != ScanStatus.SUCCESS
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.UNKNOWN
    assert CoverageReason.SCAN_NOT_SUCCESSFUL in reasons(result)
    for found in result.coverage.manifests:
        assert found.status != ManifestStatus.ASSESSED
        assert not any(p.confidently_assessed for p in found.packages)
        assert all(p.assessment == PackageAssessment.UNKNOWN for p in found.packages)


def test_sources_outside_target_keep_findings_but_not_coverage(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    document = json.loads((FIXTURES / "single.json").read_text())
    result = normalized(json.dumps(document).encode(), tmp_path)
    assert result.status == ScanStatus.SUCCESS
    assert [f.vulnerability.primary_id for f in result.findings] == ["GHSA-example"]
    assert CoverageReason.OUTSIDE_TARGET in reasons(result)
    assert manifest(result, "requirements.txt").status == ManifestStatus.NOT_REPORTED


def test_duplicate_package_records_are_collapsed(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    document = json.loads(scan_output("all-packages-clean.json", tmp_path))
    document["results"] *= 2
    result = normalized(json.dumps(document).encode(), tmp_path)
    assert len(manifest(result, "requirements.txt").packages) == 1
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.NO_KNOWN_GAPS


def clean_scanner(tmp_path: Path, version: str | None = None) -> str:
    output = (FIXTURES / "all-packages-clean.json").read_text()
    body = f"""
import sys
target = sys.argv[-1]
sys.stdout.write({output!r}.replace('"/repo/', '"' + target + '/'))
"""
    if version is None:
        return fake_scanner(tmp_path, body)
    return fake_scanner(tmp_path, body, version=version)


def test_adapter_records_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    monkeypatch.setenv("OSV_TEST_SECRET", "never-recorded")
    executable = clean_scanner(tmp_path)
    result = OSVScanner(executable).scan(
        target, artifact_directory=tmp_path / "raw", asset_key="example/demo"
    )
    assert result.status == ScanStatus.SUCCESS
    assert result.schema_version == 2
    assert result.asset.key == "example/demo"
    assert result.scanner.version == "2.3.0"
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.NO_KNOWN_GAPS
    provenance = result.provenance
    assert provenance is not None
    assert provenance.exit_code == 0
    assert provenance.started_at is not None and provenance.finished_at is not None
    assert provenance.started_at <= provenance.finished_at
    assert provenance.started_at.utcoffset() is not None
    assert provenance.command[0] == executable
    assert "--all-packages" in provenance.command
    source = provenance.advisory_source
    assert source is not None
    assert source.kind == AdvisorySourceKind.ONLINE_SERVICE
    assert not source.reproducible and not source.fingerprints
    facts = {fact.name: fact for fact in provenance.facts}
    assert facts["scanner_commit"].origin == ProvenanceOrigin.SCANNER
    assert facts["scanner_commit"].value == "b0b6027aa7b2b50fd3fe5fe185d609f481f02a44"
    assert facts["configuration_sha256"].origin == ProvenanceOrigin.ADAPTER
    config_text = b"# Adapter-owned: no exclusions or package overrides.\n"
    assert (
        facts["configuration_sha256"].value == hashlib.sha256(config_text).hexdigest()
    )
    assert (
        facts["executable_sha256"].value
        == hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    )
    assert facts["inherited_osv_environment"].value == "OSV_TEST_SECRET"
    assert "never-recorded" not in result.model_dump_json()
    names = sorted(uri.rsplit("/", 1)[1] for uri in provenance.artifacts)
    assert names == ["stderr.txt", "stdout.json", "version.txt"]
    [run] = (tmp_path / "raw").iterdir()
    assert (run / "version.txt").read_text().startswith("osv-scanner version: 2.3.0")
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in run.iterdir())


@pytest.mark.parametrize(
    "version",
    ["", "garbage\n", "osv-scanner version: \n"],
    ids=["empty", "junk", "blank"],
)
def test_missing_version_stays_unavailable(tmp_path: Path, version: str) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    result = OSVScanner(clean_scanner(tmp_path, version)).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    # Missing provenance is recorded as unavailable, not guessed or fatal.
    assert result.status == ScanStatus.SUCCESS
    assert result.scanner.version is None
    assert result.provenance is not None
    for fact in result.provenance.facts:
        if fact.origin == ProvenanceOrigin.SCANNER:
            assert fact.value is None and fact.detail


def test_version_command_failure_is_unavailable(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    output = (FIXTURES / "all-packages-clean.json").read_text()
    executable = fake_scanner(
        tmp_path,
        f"""
import sys
if sys.argv[1:] == ['--version']:
    sys.exit(3)
sys.stdout.write({output!r}.replace('"/repo/', '"' + sys.argv[-1] + '/'))
""",
        version=None,
    )
    result = OSVScanner(executable).scan(target, artifact_directory=tmp_path / "raw")
    assert result.scanner.version is None
    assert result.provenance is not None
    version = next(f for f in result.provenance.facts if f.name == "scanner_version")
    assert version.value is None and version.detail and "exit 3" in version.detail


def test_unsupported_major_version_is_not_clean(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    executable = clean_scanner(tmp_path, "osv-scanner version: 1.9.2\n")
    result = OSVScanner(executable).scan(target, artifact_directory=tmp_path / "raw")
    assert result.status == ScanStatus.FAILED
    assert "targets v2" in result.errors[0]
    assert result.coverage is not None
    assert result.coverage.status == CoverageStatus.UNKNOWN


def offline_database(root: Path) -> Path:
    archive = root / "osv-scanner" / "PyPI" / "all.zip"
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic archive")
    return root


def test_offline_database_is_fingerprinted(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    database = offline_database(tmp_path / "db")
    result = OSVScanner(clean_scanner(tmp_path), offline_database=database).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.provenance is not None
    assert "--offline" in result.provenance.command
    assert f"--local-db-path={database}" in result.provenance.command
    source = result.provenance.advisory_source
    assert source is not None
    assert source.kind == AdvisorySourceKind.LOCAL_DATABASE and source.reproducible
    [fingerprint] = source.fingerprints
    assert fingerprint.subject == "osv-scanner/PyPI/all.zip"
    assert fingerprint.value == hashlib.sha256(b"synthetic archive").hexdigest()


def test_changed_offline_database_is_not_reproducible(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    database = offline_database(tmp_path / "db")
    archive = database / "osv-scanner" / "PyPI" / "all.zip"
    output = (FIXTURES / "all-packages-clean.json").read_text()
    executable = fake_scanner(
        tmp_path,
        f"""
import sys
from pathlib import Path
Path({str(archive)!r}).write_bytes(b'refreshed during scan')
sys.stdout.write({output!r}.replace('"/repo/', '"' + sys.argv[-1] + '/'))
""",
    )
    result = OSVScanner(executable, offline_database=database).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.status == ScanStatus.FAILED
    assert "changed during the scan" in result.errors[0]
    assert result.provenance is not None
    source = result.provenance.advisory_source
    assert source is not None and not source.reproducible


def test_empty_offline_database_is_not_reproducible(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    (tmp_path / "db").mkdir()
    result = OSVScanner(clean_scanner(tmp_path), offline_database=tmp_path / "db").scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.provenance is not None
    source = result.provenance.advisory_source
    assert source is not None and not source.reproducible and not source.fingerprints


def test_offline_database_inside_target_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    database = offline_database(target / "db")
    with pytest.raises(ValueError, match="outside the scanned target"):
        OSVScanner(offline_database=database).scan(
            target, artifact_directory=tmp_path / "raw"
        )


@pytest.mark.parametrize("component", ["root", "ecosystem", "archive"])
def test_symlinked_offline_database_is_rejected(tmp_path: Path, component: str) -> None:
    """Advisory bytes must not be reachable from the target through symlinks."""
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    planted = offline_database(target / "planted")  # repository-controlled
    database = tmp_path / "db"
    if component == "root":
        database.mkdir()
        (database / "osv-scanner").symlink_to(planted / "osv-scanner")
    elif component == "ecosystem":
        (database / "osv-scanner").mkdir(parents=True)
        (database / "osv-scanner" / "PyPI").symlink_to(planted / "osv-scanner" / "PyPI")
    else:
        (database / "osv-scanner" / "PyPI").mkdir(parents=True)
        (database / "osv-scanner" / "PyPI" / "all.zip").symlink_to(
            planted / "osv-scanner" / "PyPI" / "all.zip"
        )
    marker = tmp_path / "scanner-ran"
    executable = fake_scanner(
        tmp_path, f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    with pytest.raises(ValueError, match="symlink"):
        OSVScanner(executable, offline_database=database).scan(
            target, artifact_directory=tmp_path / "raw"
        )
    assert not marker.exists() and not (tmp_path / "raw").exists()


def test_symlink_planted_during_scan_is_not_reproducible(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    database = offline_database(tmp_path / "db")
    archive = database / "osv-scanner" / "PyPI" / "all.zip"
    output = (FIXTURES / "all-packages-clean.json").read_text()
    executable = fake_scanner(
        tmp_path,
        f"""
import os, sys
os.replace({str(archive)!r}, {str(target / "copy.zip")!r})
os.symlink({str(target / "copy.zip")!r}, {str(archive)!r})
sys.stdout.write({output!r}.replace('"/repo/', '"' + sys.argv[-1] + '/'))
""",
    )
    result = OSVScanner(executable, offline_database=database).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.status == ScanStatus.FAILED
    assert "became unsafe" in result.errors[0]
    assert result.provenance is not None
    source = result.provenance.advisory_source
    assert source is not None and not source.reproducible and not source.fingerprints


def test_inventory_limits_reach_coverage(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    write(target, "requirements.txt", "six==1.16.0\n")
    write(target, "a/b/notes.txt")
    result = OSVScanner(clean_scanner(tmp_path), inventory_max_depth=1).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.coverage is not None
    assert result.coverage.inventory is not None
    assert result.coverage.inventory.truncated
    assert result.coverage.status == CoverageStatus.INCOMPLETE
    assert CoverageReason.INVENTORY_TRUNCATED in reasons(result)


def test_cli_passes_asset_key_and_database(tmp_path: Path) -> None:
    from unittest.mock import patch

    from remediator.cli import main

    target = tmp_path / "repo"
    target.mkdir()
    database = offline_database(tmp_path / "db")
    argv = [
        "remediator",
        str(target),
        "--artifacts",
        str(tmp_path / "raw"),
        "--executable",
        clean_scanner(tmp_path),
        "--asset-key",
        "example/demo",
        "--offline-database",
        str(database),
        "--output",
        str(tmp_path / "out.json"),
    ]
    with patch("sys.argv", argv):
        main()
    result = ScanResult.model_validate_json((tmp_path / "out.json").read_text())
    assert result.asset.key == "example/demo"
    assert result.provenance is not None
    source = result.provenance.advisory_source
    assert source is not None and source.kind == AdvisorySourceKind.LOCAL_DATABASE
