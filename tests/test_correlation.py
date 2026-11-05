"""Correlation must never turn uncertainty into a match (or a verdict)."""

import itertools
import json
import random
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from remediator.correlation import (
    ComparabilityReason,
    ComparabilityStatus,
    ComponentSlot,
    Correlation,
    CorrelationEntry,
    CorrelationKind,
    CorrelationReason,
    GroupRisk,
    correlate,
    group_advisories,
    manifest_path,
)
from remediator.domain import ScanResult
from remediator.scanners.osv import normalize

FIXTURES = Path(__file__).parent / "fixtures"
KEY = "example/app"
SCANNER = {"name": "OSV-Scanner", "version": "2.3.0"}
COVERAGE: dict[str, Any] = {
    "status": "no_known_gaps",
    "inventory": {
        "ecosystems": ["PyPI"],
        "supported_patterns": ["requirements.txt"],
        "max_depth": 32,
        "max_entries": 100,
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


UNKNOWN_COVERAGE: dict[str, Any] = {
    "status": "unknown",
    "limitations": [{"reason": "scan_not_successful"}],
}


def provenance(fingerprint: str = "a" * 64) -> dict[str, Any]:
    return {
        "advisory_source": {
            "kind": "local_database",
            "reproducible": True,
            "fingerprints": [
                {
                    "subject": "osv-scanner/PyPI/all.zip",
                    "algorithm": "sha256",
                    "value": fingerprint,
                }
            ],
        }
    }


def finding(
    primary: str,
    *aliases: str,
    name: str = "Django",
    version: str = "2.2.0",
    manifest: str | None = "requirements.txt",
    root: str = "/repo",
    key: str | None = KEY,
    ecosystem: str = "PyPI",
) -> dict[str, Any]:
    return {
        "asset": {"type": "repository", "locator": root, "key": key},
        "component": {
            "name": name,
            "ecosystem": ecosystem,
            "installed_version": version,
            "location": None if manifest is None else f"{root}/{manifest}",
        },
        "vulnerability": {"primary_id": primary, "aliases": list(aliases)},
        "evidence": {
            "scanner": SCANNER,
            "observed_at": "2026-11-05T12:00:00Z",
            "target": f"{root}/{manifest}",
            "artifact_reference": "test:raw",
        },
    }


def scan(
    findings: list[dict[str, Any]],
    *,
    root: str = "/repo",
    key: str | None = KEY,
    **overrides: Any,
) -> ScanResult:
    payload: dict[str, Any] = {
        "schema_version": 2,
        "execution_id": "exec",
        "asset": {"type": "repository", "locator": root, "key": key},
        "scanner": SCANNER,
        "status": "success",
        "findings": findings,
        "coverage": COVERAGE,
        "provenance": provenance(),
    }
    payload.update(overrides)
    return ScanResult.model_validate(payload)


def kinds(result: Correlation) -> list[tuple[CorrelationKind, list[CorrelationReason]]]:
    return [(e.kind, e.reasons) for e in result.entries]


def test_same_repository_at_different_checkout_paths() -> None:
    before = scan([finding("GHSA-1", "CVE-1", root="/a/checkout")], root="/a/checkout")
    after = scan([finding("GHSA-1", "CVE-1", root="/srv/b")], root="/srv/b")
    result = correlate(before, after)
    assert result.status == ComparabilityStatus.COMPARABLE
    [entry] = result.entries
    assert entry.kind == CorrelationKind.MATCHED and entry.reasons == []
    assert entry.slot == ComponentSlot(
        asset_key=KEY, ecosystem="PyPI", name="django", manifest_path="requirements.txt"
    )


def test_upgrade_keeps_slot_identity() -> None:
    before = scan([finding("GHSA-1", version="2.2.0")])
    after = scan([finding("GHSA-1", version="2.2.28", name="django")])
    [entry] = correlate(before, after).entries
    assert entry.kind == CorrelationKind.MATCHED
    assert entry.reasons == [CorrelationReason.VERSION_CHANGED]
    assert entry.slot is not None and entry.slot.name == "django"


def test_disappearance_is_only_before_never_a_verdict() -> None:
    result = correlate(scan([finding("GHSA-1")]), scan([]))
    [entry] = result.entries
    assert entry.kind == CorrelationKind.ONLY_BEFORE
    values = {k.value for k in CorrelationKind} | {r.value for r in CorrelationReason}
    assert not values & {"fixed", "verified", "resolved", "remediated"}
    appeared = correlate(scan([]), scan([finding("GHSA-2")])).entries
    assert [e.kind for e in appeared] == [CorrelationKind.ONLY_AFTER]


def test_moved_manifest_is_never_matched() -> None:
    before = scan([finding("GHSA-1", "CVE-1", manifest="requirements.txt")])
    after = scan(
        [finding("GHSA-1", "CVE-1", manifest="requirements/base-requirements.txt")]
    )
    result = correlate(before, after)
    assert sorted(kinds(result)) == [
        (CorrelationKind.ONLY_AFTER, [CorrelationReason.POSSIBLE_MANIFEST_MOVE]),
        (CorrelationKind.ONLY_BEFORE, [CorrelationReason.POSSIBLE_MANIFEST_MOVE]),
    ]
    # A different package in a different manifest is not a possible move.
    other = scan(
        [finding("GHSA-1", "CVE-1", name="flask", manifest="api/requirements.txt")]
    )
    assert all(r == [] for _, r in kinds(correlate(before, other)))


@pytest.mark.parametrize("side", ["before", "after"])
def test_duplicate_slots_are_ambiguous(side: str) -> None:
    two = [finding("GHSA-1", version="2.2.0"), finding("GHSA-1", version="5.0.0")]
    one = [finding("GHSA-1", version="2.2.0")]
    result = correlate(
        *((scan(two), scan(one)) if side == "before" else (scan(one), scan(two)))
    )
    [entry] = result.entries
    assert entry.kind == CorrelationKind.AMBIGUOUS
    assert entry.reasons == [CorrelationReason.DUPLICATE_SLOT]


def test_grouping_is_permutation_independent_for_alias_chains() -> None:
    # A-C share X, B-D share Y, C-D share Z: one connected component. OSV-Scanner
    # v2.3.0's own grouper splits this as [A, C, D] + [B] in this input order.
    chain = [("A", "X"), ("B", "Y"), ("C", "X", "Z"), ("D", "Y", "Z")]
    results = set()
    for order in itertools.permutations(chain):
        groups = group_advisories(scan([finding(*ids) for ids in order]), KEY)
        results.add(tuple(tuple(g.advisory_ids) for g in groups))
    assert results == {(("A", "B", "C", "D"),)}


def test_groups_never_cross_packages_or_manifests() -> None:
    findings = [
        finding("GHSA-1", "CVE-1", name="django"),
        finding("GHSA-2", "CVE-1", name="flask"),
        finding("GHSA-3", "CVE-1", name="django", manifest="api/requirements.txt"),
    ]
    groups = group_advisories(scan(findings), KEY)
    assert sorted(g.advisory_ids for g in groups) == [
        ["GHSA-1"],
        ["GHSA-2"],
        ["GHSA-3"],
    ]


def test_groups_preserve_every_observation() -> None:
    [group] = group_advisories(
        scan([finding("PYSEC-1", "CVE-1"), finding("GHSA-1", "CVE-1")]), KEY
    )
    assert group.advisory_ids == ["GHSA-1", "PYSEC-1"]
    assert group.identifiers == ["CVE-1", "GHSA-1", "PYSEC-1"]
    assert [(o.primary_id, o.finding_index) for o in group.observations] == [
        ("GHSA-1", 1),
        ("PYSEC-1", 0),
    ]


def test_multi_cve_groups_are_flagged() -> None:
    findings = [finding("GHSA-1", "CVE-1", "CVE-2")]
    [group] = group_advisories(scan(findings), KEY)
    assert group.risks == [GroupRisk.MULTIPLE_CVES]
    [entry] = correlate(scan(findings), scan(findings)).entries
    assert entry.kind == CorrelationKind.MATCHED
    assert entry.reasons == [CorrelationReason.MULTIPLE_CVES]


@pytest.mark.parametrize(
    ("before", "after", "reason"),
    [
        # One group {A, B} linked by X splits into A and B.
        ([("A", "X"), ("B", "X")], [("A",), ("B",)], CorrelationReason.ALIAS_SPLIT),
        ([("A",), ("B",)], [("A", "X"), ("B", "X")], CorrelationReason.ALIAS_MERGE),
        # Two groups on each side, overlapping crosswise.
        (
            [("A", "X"), ("B", "Y")],
            [("A", "Y"), ("B", "X")],
            CorrelationReason.OVERLAPPING_GROUPS,
        ),
    ],
)
def test_alias_changes_are_ambiguous(
    before: list[tuple[str, ...]],
    after: list[tuple[str, ...]],
    reason: CorrelationReason,
) -> None:
    result = correlate(
        scan([finding(*ids) for ids in before]), scan([finding(*ids) for ids in after])
    )
    assert kinds(result) == [(CorrelationKind.AMBIGUOUS, [reason])]


def test_one_to_one_identifier_change_still_matches() -> None:
    before = scan([finding("PYSEC-1", "CVE-1")])
    after = scan([finding("GHSA-1", "CVE-1")])
    assert kinds(correlate(before, after)) == [
        (CorrelationKind.MATCHED, [CorrelationReason.IDENTIFIERS_CHANGED])
    ]


@pytest.mark.parametrize(
    "location", [None, "/elsewhere/requirements.txt", "../requirements.txt"]
)
def test_unplaceable_findings_are_ambiguous(location: str | None) -> None:
    data = finding("GHSA-1")
    data["component"]["location"] = location
    result = correlate(scan([data]), scan([data]))
    assert [(e.kind, e.reasons, e.slot) for e in result.entries] == [
        (CorrelationKind.AMBIGUOUS, [CorrelationReason.SLOT_UNAVAILABLE], None),
        (CorrelationKind.AMBIGUOUS, [CorrelationReason.SLOT_UNAVAILABLE], None),
    ]


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("/repo/a/requirements.txt", "a/requirements.txt"),
        ("/repo/a/../b/requirements.txt", "b/requirements.txt"),
        ("a/requirements.txt", "a/requirements.txt"),
        ("/repository/requirements.txt", None),
        ("/repo", None),
        ("/repo/../x", None),
    ],
)
def test_manifest_paths_are_lexical_and_contained(
    location: str, expected: str | None
) -> None:
    assert manifest_path(location, "/repo") == expected


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"before_key": None}, ComparabilityReason.MISSING_ASSET_KEY),
        ({"after_key": "example/other"}, ComparabilityReason.ASSET_KEY_MISMATCH),
        (
            {
                "after": {
                    "status": "failed",
                    "errors": ["x"],
                    "findings": [],
                    "coverage": UNKNOWN_COVERAGE,
                }
            },
            ComparabilityReason.SCAN_FAILED,
        ),
    ],
)
def test_blocking_restrictions_make_correlation_unavailable(
    change: dict[str, Any], reason: ComparabilityReason
) -> None:
    before_key = change.get("before_key", KEY)
    after_key = change.get("after_key", KEY)
    before = scan([finding("GHSA-1", key=before_key)], key=before_key)
    overrides = dict(change.get("after", {}))
    findings = overrides.pop("findings", [finding("GHSA-1", key=after_key)])
    after = scan(findings, key=after_key, **overrides)
    result = correlate(before, after)
    assert result.status == ComparabilityStatus.UNAVAILABLE
    assert result.entries == []
    assert reason in {n.reason for n in result.restrictions}


def incomplete_coverage() -> dict[str, Any]:
    return {
        **COVERAGE,
        "status": "incomplete",
        "limitations": [{"reason": "possibly_ignored"}],
    }


@pytest.mark.parametrize(
    ("after", "reason"),
    [
        (
            {"status": "partial", "errors": ["x"], "coverage": UNKNOWN_COVERAGE},
            ComparabilityReason.SCAN_PARTIAL,
        ),
        ({"coverage": None}, ComparabilityReason.COVERAGE_MISSING),
        ({"coverage": "incomplete"}, ComparabilityReason.COVERAGE_INCOMPLETE),
        ({"provenance": None}, ComparabilityReason.PROVENANCE_MISSING),
        ({"scanner": {"name": "Other"}}, ComparabilityReason.SCANNER_CHANGED),
        (
            {"scanner": {"name": "OSV-Scanner"}},
            ComparabilityReason.SCANNER_VERSION_UNKNOWN,
        ),
        (
            {"scanner": {"name": "OSV-Scanner", "version": "2.3.1"}},
            ComparabilityReason.SCANNER_VERSION_CHANGED,
        ),
        (
            {"provenance": {"advisory_source": {"kind": "online_service"}}},
            ComparabilityReason.ADVISORY_SOURCE_NOT_REPRODUCIBLE,
        ),
        (
            {"provenance": {"advisory_source": {"kind": "online_service"}}},
            ComparabilityReason.ADVISORY_SOURCE_CHANGED,
        ),
        (
            {"provenance": provenance("b" * 64)},
            ComparabilityReason.ADVISORY_DATA_CHANGED,
        ),
        ({"provenance": {}}, ComparabilityReason.ADVISORY_SOURCE_UNKNOWN),
    ],
)
def test_restrictions_are_reported_not_hidden(
    after: dict[str, Any], reason: ComparabilityReason
) -> None:
    if after.get("coverage") == "incomplete":
        after = {**after, "coverage": incomplete_coverage()}
    data = finding("GHSA-1")
    if "scanner" in after:
        data["evidence"]["scanner"] = after["scanner"]
    result = correlate(scan([finding("GHSA-1")]), scan([data], **after))
    assert result.status == ComparabilityStatus.RESTRICTED
    assert reason in {n.reason for n in result.restrictions}
    assert [e.kind for e in result.entries] == [CorrelationKind.MATCHED]


def test_version_one_reports_cannot_be_correlated() -> None:
    old = ScanResult.model_validate_json(
        (FIXTURES / "repository_scan.json").read_text()
    )
    result = correlate(old, old)
    assert result.status == ComparabilityStatus.UNAVAILABLE
    assert ComparabilityReason.MISSING_ASSET_KEY in {
        n.reason for n in result.restrictions
    }


def test_output_is_independent_of_finding_order() -> None:
    findings = [
        finding("GHSA-1", "CVE-1"),
        finding("PYSEC-1", "CVE-1"),
        finding("GHSA-2", name="flask"),
        finding("GHSA-3", name="six", manifest="api/requirements.txt"),
    ]

    def shape(result: Correlation) -> list[Any]:
        return [
            (e.kind, e.slot, [g.advisory_ids for g in e.before + e.after], e.reasons)
            for e in result.entries
        ]

    expected = shape(correlate(scan(findings), scan(findings)))
    rng = random.Random(7)
    for _ in range(20):
        shuffled = rng.sample(findings, len(findings))
        assert shape(correlate(scan(shuffled), scan(findings))) == expected


def test_real_shaped_reports_correlate_across_checkouts() -> None:
    raw = (FIXTURES / "osv" / "all-packages-mixed.json").read_text()
    reports = [
        normalize(
            raw.replace('"/repo/', f'"{root}/').encode(),
            target=Path(root),
            artifact_reference="test:raw",
            asset_key=KEY,
        )
        for root in ("/checkouts/a", "/srv/other/b")
    ]
    result = correlate(*reports)
    # Normalized without inventory or provenance: correlated, but restricted.
    assert result.status == ComparabilityStatus.RESTRICTED
    assert {(e.kind, e.slot.name) for e in result.entries if e.slot} == {
        (CorrelationKind.MATCHED, "django"),
        (CorrelationKind.MATCHED, "flask"),
        (CorrelationKind.MATCHED, "requests"),
    }
    assert Correlation.model_validate_json(result.model_dump_json()) == result


def test_correlation_models_reject_inconsistent_claims() -> None:
    [group] = group_advisories(scan([finding("GHSA-1")]), KEY)
    with pytest.raises(ValidationError, match="exactly one group"):
        CorrelationEntry(kind=CorrelationKind.MATCHED, slot=group.slot, before=[group])
    with pytest.raises(ValidationError, match="ambiguity reason"):
        CorrelationEntry(kind=CorrelationKind.AMBIGUOUS, before=[group])
    with pytest.raises(ValidationError, match="status unavailable"):
        Correlation.model_validate(
            {"status": "restricted", "restrictions": [{"reason": "missing_asset_key"}]}
        )
    with pytest.raises(ValidationError, match="status comparable"):
        Correlation.model_validate({"status": "restricted"})
    with pytest.raises(ValidationError):
        ComponentSlot.model_validate(json.loads(json.dumps({"asset_key": KEY})))
