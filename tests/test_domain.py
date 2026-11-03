"""Offline contract tests; all scanner data is synthetic."""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from remediator.domain import (
    AdvisorySource,
    Asset,
    AssetType,
    Component,
    CoverageReason,
    CoverageStatus,
    Evidence,
    Finding,
    FixInformation,
    FixStatus,
    ManifestCoverage,
    PackageCoverage,
    ProvenanceFact,
    ScanCoverage,
    Scanner,
    ScanProvenance,
    ScanResult,
    ScanStatus,
    Vulnerability,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(params=["repository_scan.json", "container_image_scan.json"])
def scan_payload(request: pytest.FixtureRequest) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / request.param).read_text())
    return payload


@pytest.fixture
def scan(scan_payload: dict[str, Any]) -> ScanResult:
    return ScanResult.model_validate(scan_payload)


def test_synthetic_scan_round_trip(scan: ScanResult) -> None:
    encoded = scan.model_dump_json()
    restored = ScanResult.model_validate_json(encoded)
    assert restored == scan
    assert restored.model_dump_json() == encoded
    finding = restored.findings[0]
    assert finding.vulnerability.primary_id == "SYNTHETIC-2026-0001"
    assert finding.vulnerability.aliases == ["SYNTHETIC-ALIAS-001"]
    assert finding.vulnerability.severity is None
    assert finding.component.installed_version == "1.0+vendor:revision"
    assert finding.evidence.observed_at.utcoffset() == timedelta(hours=-7)
    assert "2026-10-27T09:30:00-07:00" in encoded
    assert finding.evidence.artifact_reference.startswith("artifact:synthetic/")
    if scan.asset.type == AssetType.REPOSITORY:
        assert scan.scanner.version == "0.0.0-test"
        assert finding.fix.status == FixStatus.AVAILABLE
    else:
        assert scan.scanner.version is None
        assert finding.fix.status == FixStatus.NO_FIX


def test_absent_optional_metadata(scan_payload: dict[str, Any]) -> None:
    data = scan_payload["findings"][0]
    data.pop("fix")
    data["component"].pop("location")
    data["vulnerability"] = {"primary_id": "SOURCE-ID"}
    finding = Finding.model_validate(data)
    assert finding.fix.status == FixStatus.UNKNOWN
    assert finding.component.location is None
    assert finding.vulnerability.aliases == []
    assert finding.vulnerability.title is None
    assert finding.vulnerability.description is None
    assert finding.vulnerability.severity is None
    assert finding.vulnerability.references == []
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


@pytest.mark.parametrize("status", list(ScanStatus))
@pytest.mark.parametrize("has_errors", [False, True])
@pytest.mark.parametrize("has_findings", [False, True])
def test_scan_status_invariants(
    scan_payload: dict[str, Any],
    status: ScanStatus,
    has_errors: bool,
    has_findings: bool,
) -> None:
    scan_payload.update(
        status=status, errors=["synthetic read failure"] if has_errors else []
    )
    if not has_findings:
        scan_payload["findings"] = []
    valid = (
        (status == ScanStatus.SUCCESS and not has_errors)
        or (status == ScanStatus.PARTIAL and has_errors)
        or (status == ScanStatus.FAILED and has_errors and not has_findings)
    )
    if valid:
        result = ScanResult.model_validate(scan_payload)
        assert ScanResult.model_validate_json(result.model_dump_json()) == result
    else:
        with pytest.raises(ValidationError):
            ScanResult.model_validate(scan_payload)


def test_successful_empty_scan_defaults(scan_payload: dict[str, Any]) -> None:
    scan_payload.pop("findings")
    result = ScanResult.model_validate(scan_payload)
    assert result.status == ScanStatus.SUCCESS
    assert result.findings == []
    assert result.errors == []


@pytest.mark.parametrize("status", list(FixStatus))
@pytest.mark.parametrize("versions", [[], ["vendor:2.0~rc1", "other-format"]])
def test_fix_information(status: FixStatus, versions: list[str]) -> None:
    payload = {"status": status, "fixed_versions": versions}
    if (status == FixStatus.AVAILABLE) == bool(versions):
        fix = FixInformation.model_validate(payload)
        assert FixInformation.model_validate_json(fix.model_dump_json()) == fix
    else:
        with pytest.raises(ValidationError):
            FixInformation.model_validate(payload)


def test_unknown_is_distinct_from_no_fix() -> None:
    unknown = FixInformation()
    no_fix = FixInformation(status=FixStatus.NO_FIX)
    assert unknown.fixed_versions == no_fix.fixed_versions == []
    assert unknown != no_fix
    assert unknown.model_dump_json() != no_fix.model_dump_json()


@pytest.mark.parametrize(
    ("model", "payload", "required_fields", "optional_fields"),
    [
        (Asset, {"type": "repository", "locator": "repo"}, ["locator"], []),
        (
            Component,
            {"name": "pkg", "ecosystem": "custom", "installed_version": "opaque"},
            ["name", "ecosystem", "installed_version"],
            ["location"],
        ),
        (
            Vulnerability,
            {"primary_id": "source"},
            ["primary_id"],
            ["title", "description", "severity"],
        ),
        (Scanner, {"name": "scanner"}, ["name"], ["version"]),
        (
            Evidence,
            {
                "scanner": {"name": "scanner"},
                "observed_at": "2026-10-27T10:00:00Z",
                "target": ".",
                "artifact_reference": "opaque:report",
            },
            ["target", "artifact_reference"],
            [],
        ),
    ],
)
def test_required_and_optional_text(
    model: type[BaseModel],
    payload: dict[str, Any],
    required_fields: list[str],
    optional_fields: list[str],
) -> None:
    for field in required_fields:
        missing = payload.copy()
        del missing[field]
        with pytest.raises(ValidationError):
            model.model_validate(missing)
    invalid_values: tuple[object, ...] = ("", " \t\n", 123, False, [], {})
    for field in required_fields + optional_fields:
        for invalid in invalid_values:
            with pytest.raises(ValidationError):
                model.model_validate({**payload, field: invalid})


def test_unknown_fields_rejected_at_every_boundary(scan: ScanResult) -> None:
    finding = scan.findings[0]
    models: list[BaseModel] = [
        scan,
        scan.asset,
        scan.scanner,
        finding,
        finding.component,
        finding.vulnerability,
        finding.evidence,
        finding.fix,
    ]
    for model in models:
        with pytest.raises(ValidationError, match="extra_forbidden"):
            type(model).model_validate({**model.model_dump(), "raw_report": {}})


@pytest.mark.parametrize("field", ["aliases", "references"])
@pytest.mark.parametrize("invalid", [[" "], [123], "not-a-list"])
def test_invalid_advisory_lists(field: str, invalid: object) -> None:
    with pytest.raises(ValidationError):
        Vulnerability.model_validate({"primary_id": "source", field: invalid})


@pytest.mark.parametrize("invalid", [" ", 123, None])
def test_invalid_fixed_versions(invalid: object) -> None:
    with pytest.raises(ValidationError):
        FixInformation.model_validate(
            {"status": "available", "fixed_versions": [invalid]}
        )


@pytest.mark.parametrize(
    "invalid", ["2026-10-27T10:00:00", datetime(2026, 10, 27, 10), "not-a-date"]
)
def test_invalid_observation_timestamp(
    scan_payload: dict[str, Any], invalid: object
) -> None:
    scan_payload["findings"][0]["evidence"]["observed_at"] = invalid
    with pytest.raises(ValidationError):
        ScanResult.model_validate(scan_payload)


@pytest.mark.parametrize("field", ["execution_id", "status", "asset", "scanner"])
def test_missing_scan_fields(scan_payload: dict[str, Any], field: str) -> None:
    del scan_payload[field]
    with pytest.raises(ValidationError):
        ScanResult.model_validate(scan_payload)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("execution_id", " \t"),
        ("execution_id", 123),
        ("status", "clean"),
        ("findings", {}),
        ("errors", [" "]),
        ("errors", [123]),
    ],
)
def test_invalid_scan_fields(
    scan_payload: dict[str, Any], field: str, invalid: object
) -> None:
    scan_payload[field] = invalid
    with pytest.raises(ValidationError):
        ScanResult.model_validate(scan_payload)


@pytest.mark.parametrize("field", ["asset", "component", "vulnerability", "evidence"])
def test_missing_finding_fields(scan_payload: dict[str, Any], field: str) -> None:
    del scan_payload["findings"][0][field]
    with pytest.raises(ValidationError):
        ScanResult.model_validate(scan_payload)


@pytest.mark.parametrize("field", ["asset", "scanner"])
def test_mismatched_provenance(scan_payload: dict[str, Any], field: str) -> None:
    if field == "asset":
        scan_payload["asset"]["locator"] = "another-repo"
    else:
        scan_payload["scanner"]["version"] = "another-version"
    with pytest.raises(ValidationError, match="must match scan"):
        ScanResult.model_validate(scan_payload)


def test_multiple_findings_and_independent_defaults(
    scan_payload: dict[str, Any],
) -> None:
    scan_payload["findings"].append(scan_payload["findings"][0])
    result = ScanResult.model_validate(scan_payload)
    assert len(result.findings) == 2
    assert ScanResult.model_validate_json(result.model_dump_json()) == result
    first = Vulnerability(primary_id="  source:opaque  ")
    second = Vulnerability(primary_id="second")
    first.aliases.append("alias")
    assert second.aliases == []
    assert first.primary_id == "  source:opaque  "


def test_invalid_enums() -> None:
    with pytest.raises(ValidationError):
        Asset.model_validate({"type": "package", "locator": "pkg"})
    with pytest.raises(ValidationError):
        FixInformation.model_validate({"status": "verified"})


@pytest.mark.parametrize(
    "timestamp", ["2026-10-27T10:00:00+05:30", "2026-10-27T10:00:00Z"]
)
def test_offsets_and_supplied_advisory_metadata(
    scan_payload: dict[str, Any], timestamp: str
) -> None:
    data = scan_payload["findings"][0]
    data["evidence"]["observed_at"] = timestamp
    data["vulnerability"].update(
        title="Synthetic advisory",
        description="Synthetic description",
        severity="SOURCE:HIGH",
    )
    finding = Finding.model_validate(data)
    restored = Finding.model_validate_json(finding.model_dump_json())
    assert restored == finding
    assert restored.vulnerability.severity == "SOURCE:HIGH"
    assert (
        restored.evidence.observed_at.utcoffset()
        == datetime.fromisoformat(timestamp).utcoffset()
    )


@pytest.mark.parametrize(
    "field", ["scanner", "observed_at", "target", "artifact_reference"]
)
def test_missing_evidence_fields(scan_payload: dict[str, Any], field: str) -> None:
    del scan_payload["findings"][0]["evidence"][field]
    with pytest.raises(ValidationError):
        ScanResult.model_validate(scan_payload)


def coverage_payload() -> dict[str, Any]:
    payload: dict[str, Any] = json.loads(
        (FIXTURES / "repository_coverage_scan.json").read_text()
    )
    return payload


def no_gaps_coverage() -> dict[str, Any]:
    return {
        "status": "no_known_gaps",
        "inventory": {
            "ecosystems": ["PyPI"],
            "supported_patterns": ["requirements.txt"],
            "max_depth": 1,
            "max_entries": 10,
            "entries_examined": 1,
            "truncated": False,
        },
        "manifests": [
            {
                "path": "requirements.txt",
                "status": "assessed",
                "discovered_by": ["inventory", "scanner"],
                "packages": [
                    {
                        "name": "six",
                        "ecosystem": "PyPI",
                        "version": "1.16.0",
                        "assessment": "assessed",
                        "version_precision": "exact",
                    }
                ],
            }
        ],
    }


def test_version_one_reports_still_load(scan_payload: dict[str, Any]) -> None:
    assert "schema_version" not in scan_payload
    scan = ScanResult.model_validate(scan_payload)
    assert scan.schema_version == 1
    assert scan.coverage is None and scan.provenance is None
    assert scan.asset.key is None


def test_version_one_cannot_carry_new_evidence(scan_payload: dict[str, Any]) -> None:
    scan_payload["coverage"] = no_gaps_coverage()
    with pytest.raises(ValidationError, match="schema 2"):
        ScanResult.model_validate(scan_payload)
    scan_payload["schema_version"] = 2
    assert ScanResult.model_validate(scan_payload).coverage is not None


def test_coverage_example_round_trip() -> None:
    scan = ScanResult.model_validate(coverage_payload())
    assert scan.schema_version == 2
    assert scan.asset.key == "example.invalid/synthetic/demo"
    assert scan.coverage is not None and scan.provenance is not None
    assert scan.coverage.status == CoverageStatus.INCOMPLETE
    assert {n.reason for n in scan.coverage.limitations} == {
        CoverageReason.IMPRECISE_CONSTRAINT,
        CoverageReason.UNSUPPORTED_FORMAT,
    }
    assert ScanResult.model_validate_json(scan.model_dump_json()) == scan


def test_new_reports_are_rejected_by_version_one_models() -> None:
    # Documented incompatibility: older code forbids the new fields.
    class VersionOne(BaseModel):
        model_config = ScanResult.model_config

        execution_id: str

    with pytest.raises(ValidationError):
        VersionOne.model_validate({"execution_id": "x", "schema_version": 2})


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda c: c["manifests"][0]["packages"][0].update(
                version_precision="imprecise",
                notes=[{"reason": "imprecise_constraint"}],
            ),
            "unassessed packages",
        ),
        (lambda c: c["inventory"].update(truncated=True), "full inventory"),
        (lambda c: c.update(inventory=None), "full inventory"),
        (lambda c: c.update(manifests=[]), "requires a manifest"),
        (
            lambda c: c.update(limitations=[{"reason": "possibly_ignored"}]),
            "cannot have limitations",
        ),
        (
            lambda c: c["manifests"][0].update(
                notes=[{"reason": "no_dependency_entries"}]
            ),
            "unassessed manifests",
        ),
    ],
)
def test_no_known_gaps_is_self_consistent(mutate: Any, message: str) -> None:
    coverage = no_gaps_coverage()
    ScanCoverage.model_validate(coverage)
    mutate(coverage)
    with pytest.raises(ValidationError, match=message):
        ScanCoverage.model_validate(coverage)


@pytest.mark.parametrize("status", ["incomplete", "unknown"])
def test_gaps_require_reasons(status: str) -> None:
    coverage = no_gaps_coverage() | {"status": status}
    with pytest.raises(ValidationError, match="requires limitations"):
        ScanCoverage.model_validate(coverage)


@pytest.mark.parametrize("status", ["partial", "failed"])
def test_unsuccessful_scans_cannot_claim_coverage(status: str) -> None:
    payload = coverage_payload()
    payload.update(
        status=status, errors=["synthetic failure"], coverage=no_gaps_coverage()
    )
    if status == "failed":
        payload["findings"] = []
    with pytest.raises(ValidationError, match="cannot claim coverage"):
        ScanResult.model_validate(payload)


@pytest.mark.parametrize(
    ("package", "message"),
    [
        (
            {
                "name": "x",
                "ecosystem": "PyPI",
                "assessment": "assessed",
                "version_precision": "exact",
            },
            "ecosystem and version",
        ),
        (
            {"name": "x", "assessment": "not_assessed"},
            "require a note",
        ),
        (
            {
                "name": "x",
                "ecosystem": "PyPI",
                "version": "1",
                "assessment": "assessed",
                "version_precision": "exact",
                "advisory_count": -1,
            },
            "greater than or equal",
        ),
    ],
)
def test_package_coverage_invariants(package: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        PackageCoverage.model_validate(package)


def test_unassessed_manifests_cannot_list_packages() -> None:
    package = no_gaps_coverage()["manifests"][0]["packages"][0]
    with pytest.raises(ValidationError, match="list packages"):
        ManifestCoverage.model_validate(
            {
                "path": "requirements.txt",
                "status": "not_reported",
                "discovered_by": ["inventory"],
                "packages": [package],
                "notes": [{"reason": "possibly_ignored"}],
            }
        )


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ({"kind": "online_service", "reproducible": True}, "reproducible"),
        ({"kind": "local_database", "reproducible": True}, "reproducible"),
    ],
)
def test_only_fingerprinted_databases_are_reproducible(
    source: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        AdvisorySource.model_validate(source)


def test_provenance_invariants() -> None:
    with pytest.raises(ValidationError, match="requires a detail"):
        ProvenanceFact.model_validate({"name": "scanner_version", "origin": "scanner"})
    with pytest.raises(ValidationError, match="finish before it starts"):
        ScanProvenance.model_validate(
            {
                "started_at": "2026-11-03T12:00:01Z",
                "finished_at": "2026-11-03T12:00:00Z",
            }
        )
    with pytest.raises(ValidationError):
        ScanProvenance.model_validate({"started_at": "2026-11-03T12:00:00"})
