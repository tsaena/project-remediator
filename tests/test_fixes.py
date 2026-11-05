"""Fixed-version candidates: PEP 440 range evaluation that never overclaims."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from remediator.correlation import group_advisories
from remediator.domain import (
    AffectedPackage,
    FixApplicability,
    FixEvidence,
    FixInformation,
    FixReason,
    FixStatus,
    RangeEvent,
    ScanResult,
)
from remediator.fixes import (
    GroupFixStatus,
    evaluate_fix,
    group_fix,
    listed_in_versions,
)
from remediator.scanners.osv import normalize
from remediator.scanners.python_manifests import inventory

sys.path.insert(0, str(Path(__file__).parent))
from test_correlation import scan as correlation_scan  # noqa: E402
from test_coverage import mixed_repository, scan_output, write  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def package(
    *ranges: list[dict[str, str]],
    name: str = "django",
    ecosystem: str = "PyPI",
    range_type: str = "ECOSYSTEM",
) -> AffectedPackage:
    return AffectedPackage.model_validate(
        {
            "ecosystem": ecosystem,
            "name": name,
            "ranges": [{"type": range_type, "events": events} for events in ranges],
        }
    )


def evaluate(
    affected: list[AffectedPackage],
    version: str,
    *,
    confirmed: bool = True,
    listed: bool | None = None,
    name: str = "Django",
    ecosystem: str = "PyPI",
) -> FixInformation:
    result = evaluate_fix(
        affected,
        ecosystem=ecosystem,
        name=name,
        installed_version=version,
        version_confirmed=confirmed,
        listed_in_versions=listed,
    )
    # Advisory ranges never establish that no fix exists.
    assert result.status != FixStatus.NO_FIX
    return result


def reason(result: FixInformation) -> FixReason:
    assert result.evidence is not None
    return result.evidence.reason


# PYSEC-2019-10 for Django, in the scrambled order OSV-Scanner emits.
DJANGO = package(
    [
        {"introduced": "2.1"},
        {"fixed": "2.1.10"},
        {"introduced": "2.2"},
        {"fixed": "2.2.3"},
        {"introduced": "1.11"},
        {"fixed": "1.11.22"},
    ]
)


@pytest.mark.parametrize(
    ("version", "fixed"),
    [
        ("2.2.0", "2.2.3"),
        ("2.2", "2.2.3"),
        ("2.2.2", "2.2.3"),
        ("2.1.0", "2.1.10"),
        ("2.1.9", "2.1.10"),
        ("1.11", "1.11.22"),
    ],
)
def test_candidate_is_the_fix_closing_the_containing_interval(
    version: str, fixed: str
) -> None:
    result = evaluate([DJANGO], version)
    assert result.status == FixStatus.AVAILABLE and result.fixed_versions == [fixed]
    assert result.evidence is not None
    assert result.evidence.applicability == FixApplicability.AFFECTED
    assert result.evidence.fixed == fixed and result.evidence.introduced


@pytest.mark.parametrize("version", ["2.2.3", "2.2.4", "2.1.10", "2.0", "1.10", "3.0"])
def test_versions_outside_every_interval_are_not_affected(version: str) -> None:
    result = evaluate([DJANGO], version)
    assert result.status == FixStatus.UNKNOWN
    assert reason(result) == FixReason.NOT_AFFECTED_BY_RANGES
    assert result.evidence is not None
    assert result.evidence.applicability == FixApplicability.NOT_AFFECTED


@pytest.mark.parametrize(
    ("events", "version", "expected"),
    [
        # Boundaries: introduced is inclusive, fixed is exclusive.
        ([{"introduced": "0"}, {"fixed": "2.3.0"}], "0.1", FixReason.FIXED_EVENT),
        ([{"introduced": "1.0"}, {"fixed": "2.0"}], "1.0", FixReason.FIXED_EVENT),
        (
            [{"introduced": "1.0"}, {"fixed": "2.0"}],
            "2.0",
            FixReason.NOT_AFFECTED_BY_RANGES,
        ),
        (
            [{"introduced": "1.0"}, {"fixed": "2.0"}],
            "2.0.0",
            FixReason.NOT_AFFECTED_BY_RANGES,
        ),
        (
            [{"introduced": "1.0"}, {"fixed": "2.0"}],
            "0.9",
            FixReason.NOT_AFFECTED_BY_RANGES,
        ),
        # last_affected is inclusive and names no fixed version.
        (
            [{"introduced": "1.0"}, {"last_affected": "2.0"}],
            "2.0",
            FixReason.LAST_AFFECTED_ONLY,
        ),
        (
            [{"introduced": "1.0"}, {"last_affected": "2.0"}],
            "2.0.1",
            FixReason.NOT_AFFECTED_BY_RANGES,
        ),
        ([{"introduced": "1.0"}], "9.0", FixReason.OPEN_ENDED),
        # PEP 440, not lexical order: 1.10 > 1.9 and pre-releases sort first.
        ([{"introduced": "1.9"}, {"fixed": "1.10"}], "1.9.5", FixReason.FIXED_EVENT),
        ([{"introduced": "2.0a1"}, {"fixed": "2.1.9"}], "2.0", FixReason.FIXED_EVENT),
        (
            [{"introduced": "2.0a1"}, {"fixed": "2.1.9"}],
            "2.0.dev1",
            FixReason.NOT_AFFECTED_BY_RANGES,
        ),
        # Malformed or unsupported ranges stay unknown.
        ([{"introduced": "1.0"}, {"limit": "2.0"}], "1.5", FixReason.UNSUPPORTED_EVENT),
        ([{"fixed": "2.0"}], "1.0", FixReason.INVALID_RANGE),
        ([{"introduced": "1.0"}, {"fixed": "1.0"}], "1.0", FixReason.INVALID_RANGE),
        (
            [{"introduced": "1.0"}, {"fixed": "not a version"}],
            "1.5",
            FixReason.INVALID_VERSION,
        ),
    ],
)
def test_range_semantics(
    events: list[dict[str, str]], version: str, expected: FixReason
) -> None:
    result = evaluate([package(events)], version)
    assert reason(result) == expected
    assert (result.status == FixStatus.AVAILABLE) == (expected == FixReason.FIXED_EVENT)


def test_overlapping_intervals_report_conflicts_conservatively() -> None:
    same = evaluate(
        [
            package([{"introduced": "1.0"}, {"fixed": "2.0"}]),
            package([{"introduced": "1.5"}, {"fixed": "2.0"}]),
        ],
        "1.6",
    )
    assert same.fixed_versions == ["2.0"]
    different = evaluate(
        [
            package([{"introduced": "1.0"}, {"fixed": "2.0"}]),
            package([{"introduced": "1.5"}, {"fixed": "3.0"}]),
        ],
        "1.6",
    )
    assert reason(different) == FixReason.CONFLICTING_RANGES
    mixed = evaluate(
        [
            package([{"introduced": "1.0"}, {"fixed": "2.0"}]),
            package([{"introduced": "1.5"}]),
        ],
        "1.6",
    )
    assert reason(mixed) == FixReason.OPEN_ENDED


@pytest.mark.parametrize(
    ("affected", "name", "expected"),
    [
        (
            [package([{"introduced": "0"}, {"fixed": "1"}], name="flask")],
            "Django",
            FixReason.NO_MATCHING_PACKAGE,
        ),
        (
            [package([{"introduced": "0"}, {"fixed": "1"}], ecosystem="npm")],
            "Django",
            FixReason.NO_MATCHING_PACKAGE,
        ),
        (
            [package([{"introduced": "0"}, {"fixed": "1"}], range_type="GIT")],
            "Django",
            FixReason.NO_SUPPORTED_RANGE,
        ),
        (
            [package([{"introduced": "0"}, {"fixed": "1"}], name="zope_interface")],
            "zope.interface",
            FixReason.FIXED_EVENT,
        ),
    ],
)
def test_only_the_findings_own_package_and_ecosystem_ranges_count(
    affected: list[AffectedPackage], name: str, expected: FixReason
) -> None:
    assert reason(evaluate(affected, "0.5", name=name)) == expected


def test_unconfirmed_or_invalid_installed_versions_stay_unknown() -> None:
    assert reason(evaluate([DJANGO], "2.2.0", confirmed=False)) == (
        FixReason.INSTALLED_VERSION_UNCONFIRMED
    )
    assert reason(evaluate([DJANGO], "2.2.0-not!valid")) == FixReason.INVALID_VERSION
    # Other ecosystems are not evaluated at all.
    assert evaluate([DJANGO], "2.2.0", ecosystem="npm") == FixInformation()


@pytest.mark.parametrize(
    ("version", "listed", "expected"),
    [
        # A range contains it, but the explicit versions list does not.
        ("2.2.0", False, FixReason.VERSIONS_LIST_DISAGREES),
        # Listed as affected, but no range contains it (as with PYSEC-2015-17).
        ("2.0", True, FixReason.VERSIONS_LIST_DISAGREES),
        ("2.2.0", True, FixReason.FIXED_EVENT),
        ("2.2.0", None, FixReason.FIXED_EVENT),
    ],
)
def test_versions_list_disagreement_is_unknown(
    version: str, listed: bool | None, expected: FixReason
) -> None:
    result = evaluate([DJANGO], version, listed=listed)
    assert reason(result) == expected
    assert result.evidence is not None and result.evidence.listed_in_versions == listed


def test_listed_in_versions_uses_pep440_equality() -> None:
    assert listed_in_versions(["2.1", "2.2"], "2.2.0") is True
    assert listed_in_versions(["2.1"], "2.2.0") is False
    assert listed_in_versions([], "2.2.0") is None
    assert listed_in_versions(["weird-tag"], "weird-tag") is True


def test_fix_models_reject_unsupported_claims() -> None:
    candidate = FixEvidence(
        applicability=FixApplicability.AFFECTED,
        reason=FixReason.FIXED_EVENT,
        fixed="2.2.3",
    )
    with pytest.raises(ValidationError, match="only a fixed_event"):
        FixInformation(evidence=candidate)
    with pytest.raises(ValidationError, match="evidenced fixed event"):
        FixInformation(
            status=FixStatus.AVAILABLE, fixed_versions=["9.9"], evidence=candidate
        )
    unknown = FixEvidence(
        applicability=FixApplicability.UNKNOWN, reason=FixReason.OPEN_ENDED
    )
    with pytest.raises(ValidationError, match="never establish no_fix"):
        FixInformation(status=FixStatus.NO_FIX, evidence=unknown)
    with pytest.raises(ValidationError, match="only a fixed_event"):
        FixInformation(
            status=FixStatus.AVAILABLE, fixed_versions=["1"], evidence=unknown
        )
    with pytest.raises(ValidationError, match="needs an affected interval"):
        FixEvidence(
            applicability=FixApplicability.NOT_AFFECTED,
            reason=FixReason.FIXED_EVENT,
            fixed="1",
        )
    with pytest.raises(ValidationError, match="exactly one field"):
        RangeEvent(introduced="1", fixed="2")


def test_schema_two_reports_cannot_carry_fix_evidence() -> None:
    payload: dict[str, Any] = json.loads(
        (FIXTURES / "repository_coverage_scan.json").read_text()
    )
    assert ScanResult.model_validate(payload).schema_version == 2
    payload["findings"][0]["fix"] = {
        "evidence": {"applicability": "unknown", "reason": "open_ended"}
    }
    with pytest.raises(ValidationError, match="need schema 3"):
        ScanResult.model_validate(payload)
    payload["schema_version"] = 3
    assert ScanResult.model_validate(payload).findings[0].fix.evidence is not None


def test_adapter_evaluates_only_confirmed_exact_pins(tmp_path: Path) -> None:
    mixed_repository(tmp_path)
    result = normalize(
        scan_output("all-packages-mixed.json", tmp_path),
        target=tmp_path,
        artifact_reference="test:raw",
        inventory=inventory(tmp_path),
    )
    fixes = {f.component.name: f.fix for f in result.findings}
    # Django==2.2.0 is an exact pin; PYSEC-2019-10 names 2.2.3 for 2.2.x.
    assert fixes["django"].status == FixStatus.AVAILABLE
    assert fixes["django"].fixed_versions == ["2.2.3"]
    evidence = fixes["django"].evidence
    assert evidence is not None
    assert (evidence.introduced, evidence.fixed, evidence.listed_in_versions) == (
        "2.2",
        "2.2.3",
        True,
    )
    # requests>=2.0 is a bound and flask arrives via -r: neither is confirmed.
    for name in ("requests", "flask"):
        assert reason(fixes[name]) == FixReason.INSTALLED_VERSION_UNCONFIRMED
    django = next(f for f in result.findings if f.component.name == "django")
    assert [a.name for a in django.vulnerability.affected] == ["django"]
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


def advisory_output(target: Path, affected: list[Any], version: str = "2.0") -> bytes:
    document = {
        "results": [
            {
                "source": {
                    "path": str(target / "requirements.txt"),
                    "type": "lockfile",
                },
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": version,
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [
                            {"id": "PYSEC-2015-17", "affected": affected}
                        ],
                    }
                ],
            }
        ]
    }
    return json.dumps(document).encode()


def test_scanner_match_contradicted_by_ranges_stays_unknown(tmp_path: Path) -> None:
    """PYSEC-2015-17 lists 2.0 explicitly although its range starts at 2.1.0."""
    write(tmp_path, "requirements.txt", "requests==2.0\n")
    affected = [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "3bd8afb"}]},
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "2.1.0"}, {"fixed": "2.6.0"}],
                },
            ],
            "versions": ["2.0", "2.1.0"],
        }
    ]
    result = normalize(
        advisory_output(tmp_path, affected),
        target=tmp_path,
        artifact_reference="test:raw",
        inventory=inventory(tmp_path),
    )
    [finding] = result.findings
    assert reason(finding.fix) == FixReason.VERSIONS_LIST_DISAGREES
    assert finding.fix.status == FixStatus.UNKNOWN


@pytest.mark.parametrize(
    "affected",
    [
        ["not an object"],
        [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [{"events": []}],
            }
        ],
        [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0", "fixed": "1"}]}
                ],
            }
        ],
    ],
)
def test_malformed_affected_data_keeps_the_finding(
    tmp_path: Path, affected: list[Any]
) -> None:
    write(tmp_path, "requirements.txt", "requests==2.0\n")
    result = normalize(
        advisory_output(tmp_path, affected),
        target=tmp_path,
        artifact_reference="test:raw",
        inventory=inventory(tmp_path),
    )
    assert result.status == "success"
    [finding] = result.findings
    assert reason(finding.fix) == FixReason.MALFORMED_AFFECTED


def fix_finding(
    primary: str, fixed: str | None, version: str = "2.2.0", *aliases: str
) -> dict[str, Any]:
    from test_correlation import finding

    data = finding(primary, *aliases, version=version)
    if fixed is None:
        data["fix"] = {
            "evidence": {"applicability": "affected", "reason": "open_ended"}
        }
    else:
        data["fix"] = {
            "status": "available",
            "fixed_versions": [fixed],
            "evidence": {
                "applicability": "affected",
                "reason": "fixed_event",
                "fixed": fixed,
            },
        }
    return data


@pytest.mark.parametrize(
    ("advisories", "status", "fixed"),
    [
        (
            [("PYSEC-1", "2.2.3"), ("GHSA-1", "2.2.3.0")],
            GroupFixStatus.CANDIDATE,
            "2.2.3",
        ),
        ([("PYSEC-1", "2.2.3"), ("GHSA-1", "2.2.4")], GroupFixStatus.CONFLICT, None),
        ([("PYSEC-1", "2.2.3"), ("GHSA-1", None)], GroupFixStatus.CONFLICT, None),
        ([("PYSEC-1", None), ("GHSA-1", None)], GroupFixStatus.UNKNOWN, None),
    ],
)
def test_group_candidate_needs_every_advisory_to_agree(
    advisories: list[tuple[str, str | None]], status: GroupFixStatus, fixed: str | None
) -> None:
    findings = [
        fix_finding(primary, fix, "2.2.0", "CVE-1") for primary, fix in advisories
    ]
    scan = correlation_scan(findings, schema_version=3)
    [group] = group_advisories(scan, "example/app")
    result = group_fix(group, scan)
    assert (result.status, result.fixed_version) == (status, fixed)
    assert len(result.advisories) == 2


def test_group_with_several_installed_versions_is_unknown() -> None:
    findings = [
        fix_finding("PYSEC-1", "2.2.3", "2.2.0", "CVE-1"),
        fix_finding("GHSA-1", "2.2.3", "2.2.1", "CVE-1"),
    ]
    scan = correlation_scan(findings, schema_version=3)
    [group] = group_advisories(scan, "example/app")
    assert group_fix(group, scan).status == GroupFixStatus.UNKNOWN
    other = correlation_scan([fix_finding("OTHER-1", "1.0")], schema_version=3)
    with pytest.raises(ValueError, match="does not belong"):
        group_fix(group, other)
