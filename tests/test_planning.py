"""Remediation plans: specific proposals with evidence, explicit refusals otherwise."""

import builtins
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from remediator import planning
from remediator.domain import ScanResult, ScanStatus
from remediator.planning import (
    PlanDecision,
    PlanEntry,
    PlanLimitationReason,
    PlanUnknown,
    RefusalReason,
    RemediationPlan,
    plan,
)
from remediator.scanners.osv import OSVScanner, normalize
from remediator.scanners.python_manifests import inventory

sys.path.insert(0, str(Path(__file__).parent))
from test_coverage import mixed_repository, scan_output, write  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def advisory(
    identifier: str,
    *ranges: list[dict[str, str]],
    name: str = "django",
    versions: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "package": {"ecosystem": "PyPI", "name": name},
        "ranges": [{"type": "ECOSYSTEM", "events": e} for e in ranges],
    }
    if versions is not None:
        entry["versions"] = versions
    return {"id": identifier, "affected": [entry], **extra}


def scan(
    root: Path,
    manifest: str,
    text: str,
    packages: list[tuple[str, str, list[dict[str, Any]]]],
    *,
    ecosystem: str = "PyPI",
    source: Path | None = None,
) -> ScanResult:
    """Normalize synthetic OSV-Scanner output for a real file tree."""
    write(root, manifest, text)
    document = {
        "results": [
            {
                "source": {"path": str(source or root / manifest), "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": name,
                            "version": version,
                            "ecosystem": ecosystem,
                        },
                        "vulnerabilities": vulns,
                    }
                    for name, version, vulns in packages
                ],
            }
        ]
    }
    return _keyed(
        normalize(
            json.dumps(document).encode(),
            target=root,
            artifact_reference="test:raw",
            inventory=inventory(root),
        )
    )


def _keyed(result: ScanResult, key: str = "example/repo") -> ScanResult:
    data = result.model_dump(mode="json")
    data["asset"]["key"] = key
    for finding in data["findings"]:
        finding["asset"]["key"] = key
    return ScanResult.model_validate(data)


def only(result: ScanResult) -> PlanEntry:
    planned = plan(result)
    assert RemediationPlan.model_validate_json(planned.model_dump_json()) == planned
    [entry] = planned.entries
    return entry


DJANGO_22 = advisory("PYSEC-1", [{"introduced": "2.2"}, {"fixed": "2.2.3"}])


def test_mixed_repository_proposes_only_the_exact_pin(tmp_path: Path) -> None:
    mixed_repository(tmp_path)
    result = _keyed(
        normalize(
            scan_output("all-packages-mixed.json", tmp_path),
            target=tmp_path,
            artifact_reference="test:raw",
            inventory=inventory(tmp_path),
        )
    )
    planned = plan(result)
    decisions = {e.package: (e.decision, e.refusal) for e in planned.entries}
    assert decisions == {
        "django": (PlanDecision.PROPOSED, None),
        # requests>=2.0 is a bound and flask arrives through -r.
        "flask": (PlanDecision.REFUSED, RefusalReason.VERSION_UNCONFIRMED),
        "requests": (PlanDecision.REFUSED, RefusalReason.VERSION_UNCONFIRMED),
    }
    django = next(e for e in planned.entries if e.package == "django")
    assert django.change is not None
    assert django.change.model_dump() == {
        "manifest_path": "services/api/requirements.txt",
        "package": "django",
        "current_version": "2.2.0",
        "proposed_version": "2.2.3",
        "requirement": "django==2.2.3",
        "crosses_major_version": False,
    }
    assert set(django.unknowns) == set(PlanUnknown)
    assert [g.fix.status for g in django.groups] == ["candidate"]
    reasons = {n.reason for n in planned.limitations}
    assert reasons == {PlanLimitationReason.COVERAGE_INCOMPLETE}
    assert planned.source.execution_id == result.execution_id


def test_highest_candidate_is_proposed_only_when_it_escapes_every_range(
    tmp_path: Path,
) -> None:
    advisories = [
        DJANGO_22,
        advisory("PYSEC-2", [{"introduced": "2.2"}, {"fixed": "2.2.10"}]),
    ]
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", advisories)],
        )
    )
    assert entry.decision == PlanDecision.PROPOSED
    assert entry.change is not None and entry.change.proposed_version == "2.2.10"
    assert entry.change.requirement == "Django==2.2.10"


def test_highest_candidate_inside_another_advisory_is_refused(tmp_path: Path) -> None:
    # PYSEC-2 is fixed for 2.2.0 at 2.2.3, but reintroduced at 2.2.5, which is
    # exactly PYSEC-1's fix. A planner picking the highest fix proposes 2.2.5.
    advisories = [
        advisory("PYSEC-1", [{"introduced": "2.2"}, {"fixed": "2.2.5"}]),
        advisory(
            "PYSEC-2",
            [{"introduced": "2.2"}, {"fixed": "2.2.3"}],
            [{"introduced": "2.2.5"}, {"fixed": "2.2.9"}],
        ),
    ]
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", advisories)],
        )
    )
    assert entry.refusal == RefusalReason.TARGET_STILL_AFFECTED
    assert entry.change is None and "PYSEC-2" in entry.detail


def listed_conflict(tmp_path: Path) -> ScanResult:
    # PYSEC-1's range ends at 2.0, but it explicitly lists 3.0 as affected;
    # PYSEC-2's fix is 3.0. Ranges alone would clear 3.0.
    advisories = [
        advisory(
            "PYSEC-1",
            [{"introduced": "0"}, {"fixed": "2.0"}],
            versions=["1.0", "3.0"],
        ),
        advisory("PYSEC-2", [{"introduced": "0"}, {"fixed": "3.0"}], versions=["1.0"]),
    ]
    return scan(
        tmp_path, "requirements.txt", "Django==1.0\n", [("Django", "1.0", advisories)]
    )


def test_target_explicitly_listed_as_affected_is_refused(tmp_path: Path) -> None:
    result = listed_conflict(tmp_path)
    assert [f.fix.fixed_versions for f in result.findings] == [["2.0"], ["3.0"]]
    entry = only(result)
    assert entry.refusal == RefusalReason.TARGET_STILL_AFFECTED
    assert "PYSEC-1 explicitly lists 3.0" in entry.detail


def test_reports_without_listed_versions_cannot_clear_a_target(tmp_path: Path) -> None:
    """Schema 3 kept only the count of listed versions."""
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [
            (
                "Django",
                "2.2.0",
                [
                    {
                        **DJANGO_22,
                        "affected": [
                            {**DJANGO_22["affected"][0], "versions": ["2.2.0"]}
                        ],
                    }
                ],
            )
        ],
    )

    def schema_three(data: dict[str, Any]) -> None:
        data["schema_version"] = 3
        for finding in data["findings"]:
            for affected in finding["vulnerability"]["affected"]:
                affected.pop("versions")

    old = tampered(result, schema_three)
    assert old.findings[0].vulnerability.affected[0].listed_versions == 1
    assert only(result).decision == PlanDecision.PROPOSED
    entry = only(old)
    assert entry.refusal == RefusalReason.TARGET_UNVERIFIABLE


def test_listed_versions_need_schema_four_and_a_matching_count(
    tmp_path: Path,
) -> None:
    payload = listed_conflict(tmp_path).model_dump(mode="json")
    assert payload["schema_version"] == 4
    payload["schema_version"] = 3
    with pytest.raises(ValidationError, match="schema 4"):
        ScanResult.model_validate(payload)
    payload["schema_version"] = 4
    payload["findings"][0]["vulnerability"]["affected"][0]["listed_versions"] = 1
    with pytest.raises(ValidationError, match="count"):
        ScanResult.model_validate(payload)


def test_any_group_without_a_candidate_refuses_the_package(tmp_path: Path) -> None:
    advisories = [DJANGO_22, advisory("PYSEC-2", [{"introduced": "2.2"}])]
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", advisories)],
        )
    )
    assert entry.refusal == RefusalReason.NO_FIX_CANDIDATE
    assert sorted(g.fix.status for g in entry.groups) == ["candidate", "unknown"]


def test_aliases_that_disagree_are_a_conflict(tmp_path: Path) -> None:
    advisories = [
        advisory(
            "PYSEC-1",
            [{"introduced": "2.2"}, {"fixed": "2.2.3"}],
            aliases=["CVE-2019-0001"],
        ),
        advisory(
            "GHSA-x",
            [{"introduced": "2.2"}, {"fixed": "2.2.4"}],
            aliases=["CVE-2019-0001"],
        ),
    ]
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", advisories)],
        )
    )
    assert entry.refusal == RefusalReason.CONFLICTING_ADVISORIES
    [group] = entry.groups
    assert group.fix.status == "conflict" and group.fix.fixed_version is None


@pytest.mark.parametrize(
    ("manifest", "text"),
    [
        ("requirements.txt", "Django>=2.2\n"),
        ("requirements.txt", "-r base.in\n"),
    ],
)
def test_unconfirmed_versions_are_refused(
    tmp_path: Path, manifest: str, text: str
) -> None:
    write(tmp_path, "base.in", "Django==2.2.0\n")
    entry = only(scan(tmp_path, manifest, text, [("Django", "2.2.0", [DJANGO_22])]))
    assert entry.refusal == RefusalReason.VERSION_UNCONFIRMED


@pytest.mark.parametrize("manifest", ["poetry.lock", "uv.lock", "Pipfile.lock"])
def test_lockfiles_are_not_planned(tmp_path: Path, manifest: str) -> None:
    entry = only(scan(tmp_path, manifest, "", [("Django", "2.2.0", [DJANGO_22])]))
    assert entry.refusal == RefusalReason.UNSUPPORTED_MANIFEST


def test_several_versions_in_one_manifest_are_refused(tmp_path: Path) -> None:
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\nDjango==2.2.1\n",
            [("Django", "2.2.0", [DJANGO_22]), ("Django", "2.2.1", [])],
        )
    )
    assert entry.refusal == RefusalReason.MULTIPLE_INSTALLED_VERSIONS


def test_other_ecosystems_are_refused(tmp_path: Path) -> None:
    vulns = [advisory("GHSA-npm", [{"introduced": "0"}, {"fixed": "2.0.0"}])]
    entry = only(
        scan(
            tmp_path,
            "package-lock.json",
            "{}",
            [("lodash", "1.0.0", vulns)],
            ecosystem="npm",
        )
    )
    assert entry.refusal == RefusalReason.UNSUPPORTED_ECOSYSTEM


def test_findings_outside_the_asset_are_refused(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    entry = only(
        scan(
            root,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", [DJANGO_22])],
            source=tmp_path / "elsewhere" / "requirements.txt",
        )
    )
    assert entry.refusal == RefusalReason.SLOT_UNAVAILABLE
    assert entry.slot is None


def tampered(result: ScanResult, change: Any) -> ScanResult:
    data = result.model_dump(mode="json")
    change(data)
    return ScanResult.model_validate(data)


def test_edited_fix_evidence_is_not_trusted(tmp_path: Path) -> None:
    """A report claiming a fix at or below the installed version is refused."""
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", [DJANGO_22])],
    )

    def lower(data: dict[str, Any]) -> None:
        fix = data["findings"][0]["fix"]
        fix["fixed_versions"] = ["2.1"]
        fix["evidence"]["fixed"] = "2.1"

    entry = only(tampered(result, lower))
    assert entry.refusal == RefusalReason.INCONSISTENT_EVIDENCE


@pytest.mark.parametrize("status", [ScanStatus.PARTIAL, ScanStatus.FAILED])
def test_unsuccessful_scans_never_propose(tmp_path: Path, status: ScanStatus) -> None:
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", [DJANGO_22])],
    )

    def fail(data: dict[str, Any]) -> None:
        data["status"] = status.value
        data["errors"] = ["scanner exited early"]
        data["coverage"]["status"] = "unknown"
        data["coverage"]["limitations"] = [
            {"reason": "scan_not_successful", "detail": "scanner exited early"}
        ]
        if status == ScanStatus.FAILED:
            data["findings"] = []

    planned = plan(tampered(result, fail))
    reasons = {n.reason for n in planned.limitations}
    assert PlanLimitationReason.SCAN_NOT_SUCCESSFUL in reasons
    assert all(e.decision == PlanDecision.REFUSED for e in planned.entries)
    if status == ScanStatus.PARTIAL:
        [entry] = planned.entries
        assert entry.refusal == RefusalReason.SCAN_NOT_SUCCESSFUL
    else:
        # No entries, but the plan does not look clean.
        assert planned.entries == []


def test_missing_asset_key_is_a_limitation(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", [DJANGO_22])],
    )

    def unkey(data: dict[str, Any]) -> None:
        data["asset"]["key"] = None
        for finding in data["findings"]:
            finding["asset"]["key"] = None

    planned = plan(tampered(result, unkey))
    assert PlanLimitationReason.MISSING_ASSET_KEY in {
        n.reason for n in planned.limitations
    }


def test_major_version_jumps_are_flagged(tmp_path: Path) -> None:
    vulns = [advisory("PYSEC-1", [{"introduced": "0"}, {"fixed": "5.2.16"}])]
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", vulns)],
        )
    )
    assert entry.change is not None
    assert entry.change.proposed_version == "5.2.16"
    assert entry.change.crosses_major_version


def test_plans_are_deterministic_under_finding_order(tmp_path: Path) -> None:
    advisories = [
        advisory(f"PYSEC-{i}", [{"introduced": "2.2"}, {"fixed": f"2.2.{i + 3}"}])
        for i in range(6)
    ]
    write(tmp_path, "sub/requirements.txt", "Flask==0.12\n")
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", advisories)],
    )
    expected = plan(result).model_dump_json()
    for seed in range(5):

        def shuffle(data: dict[str, Any], seed: int = seed) -> None:
            random.Random(seed).shuffle(data["findings"])

        assert plan(tampered(result, shuffle)).model_dump_json() == expected


def test_planning_performs_no_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = scan(
        tmp_path,
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", [DJANGO_22])],
    )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("planning must not perform I/O")

    for module, name in [
        (builtins, "open"),
        (os, "open"),
        (subprocess, "Popen"),
    ]:
        monkeypatch.setattr(module, name, forbidden)
    assert plan(result).entries[0].decision == PlanDecision.PROPOSED


def test_models_reject_unsupported_proposals(tmp_path: Path) -> None:
    entry = only(
        scan(
            tmp_path,
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", [DJANGO_22])],
        )
    )
    data = entry.model_dump(mode="json")
    bad: list[dict[str, Any]] = []
    for path, value in [
        (("change", "proposed_version"), "2.2.9"),
        (("change", "current_version"), "2.2.4"),
        (("change", "crosses_major_version"), True),
        (("unknowns",), []),
        (("refusal",), "no_fix_candidate"),
        (("change",), None),
    ]:
        copy = json.loads(json.dumps(data))
        target = copy
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        bad.append(copy)
    unknown_group = json.loads(json.dumps(data))
    unknown_group["groups"][0]["fix"].update(status="unknown", fixed_version=None)
    bad.append(unknown_group)
    refused_with_change = json.loads(json.dumps(data))
    refused_with_change.update(decision="refused", refusal="no_fix_candidate")
    bad.append(refused_with_change)
    for payload in bad:
        with pytest.raises(ValidationError):
            PlanEntry.model_validate(payload)
    planned = plan(
        scan(
            tmp_path / "b",
            "requirements.txt",
            "Django==2.2.0\n",
            [("Django", "2.2.0", [DJANGO_22])],
        )
    )
    payload = planned.model_dump(mode="json")
    payload["source"]["status"] = "partial"
    with pytest.raises(ValidationError, match="unsuccessful"):
        RemediationPlan.model_validate(payload)


def test_cli_writes_a_private_plan(tmp_path: Path) -> None:
    result = scan(
        tmp_path / "repo",
        "requirements.txt",
        "Django==2.2.0\n",
        [("Django", "2.2.0", [DJANGO_22])],
    )
    report = tmp_path / "report.json"
    report.write_text(result.model_dump_json())
    output = tmp_path / "plan.json"
    assert planning.main([str(report), "--output", str(output)]) == 0
    assert output.stat().st_mode & 0o777 == 0o600
    written = RemediationPlan.model_validate_json(output.read_text())
    assert written.entries[0].decision == PlanDecision.PROPOSED
    # Existing outputs, symlinked reports and the report itself are refused.
    link = tmp_path / "link.json"
    link.symlink_to(report)
    for argv in (
        [str(report), "--output", str(output)],
        [str(link)],
        [str(report), "--output", str(report)],
    ):
        with pytest.raises(SystemExit):
            planning.main(argv)


def test_cli_bounds_the_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = tmp_path / "report.json"
    report.write_text(" " * 100)
    monkeypatch.setattr(planning, "MAX_REPORT_BYTES", 10)
    with pytest.raises(SystemExit):
        planning.main([str(report)])


@pytest.mark.skipif(
    os.getenv("RUN_OSV_INTEGRATION") != "1", reason="opt-in real scanner"
)
def test_real_scanner_plan_for_the_vulnerable_fixture(tmp_path: Path) -> None:
    result = OSVScanner(os.environ.get("OSV_SCANNER", "osv-scanner"), timeout=300).scan(
        FIXTURES / "vulnerable-python",
        artifact_directory=tmp_path / "raw",
        asset_key="example/vulnerable-python",
    )
    planned = plan(result)
    [entry] = planned.entries
    assert entry.package.lower() == "django"
    assert entry.decision == PlanDecision.PROPOSED, entry.detail
    assert entry.change is not None
    assert entry.change.current_version == "2.2.0"
    assert len(entry.groups) >= 1
