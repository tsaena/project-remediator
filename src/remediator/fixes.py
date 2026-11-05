"""Conservative fixed-version candidates for exactly versioned PyPI packages.

A candidate is the ``fixed`` event that closes the advisory range interval
containing the installed version. It is reported evidence, not proof that a
release exists, installs, or is compatible. Anything uncertain stays unknown;
advisory ranges never establish ``no_fix``.
"""

from dataclasses import dataclass
from enum import StrEnum

from packaging.version import InvalidVersion, Version
from pydantic import Field

from remediator.correlation import AdvisoryGroup
from remediator.domain import (
    AffectedPackage,
    AffectedRange,
    FixApplicability,
    FixEvidence,
    FixInformation,
    FixReason,
    FixStatus,
    ScanResult,
)
from remediator.domain.models import DomainModel, NonBlank
from remediator.naming import canonical_pypi_name

ECOSYSTEM = "PyPI"


def _unknown(
    reason: FixReason,
    detail: str,
    applicability: FixApplicability = FixApplicability.UNKNOWN,
    listed: bool | None = None,
    **bounds: str | None,
) -> FixInformation:
    return FixInformation(
        evidence=FixEvidence(
            applicability=applicability,
            reason=reason,
            detail=detail,
            listed_in_versions=listed,
            **bounds,
        )
    )


@dataclass(frozen=True)
class _Interval:
    """The interval of one range that contains the installed version."""

    introduced: str
    fixed: str | None = None
    last_affected: str | None = None


class _Invalid(Exception):
    def __init__(self, reason: FixReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _version(text: str) -> Version:
    try:
        return Version(text)
    except InvalidVersion:
        raise _Invalid(
            FixReason.INVALID_VERSION, f"not a PEP 440 version: {text!r}"
        ) from None


def _containing(affected_range: AffectedRange, installed: Version) -> _Interval | None:
    """Evaluate one ECOSYSTEM range per the OSV schema, with PEP 440 order."""
    events: list[tuple[Version, int, str, str]] = []
    for event in affected_range.events:
        if event.limit is not None:
            raise _Invalid(
                FixReason.UNSUPPORTED_EVENT, "limit events are not supported"
            )
        if event.introduced is not None:
            raw, kind = event.introduced, "introduced"
            key = Version("0") if raw == "0" else _version(raw)
        elif event.fixed is not None:
            raw, kind, key = event.fixed, "fixed", _version(event.fixed)
        else:
            assert event.last_affected is not None
            raw, kind = event.last_affected, "last_affected"
            key = _version(raw)
        events.append((key, 0 if kind == "introduced" else 1, kind, raw))
    if not any(kind == "introduced" for _, _, kind, _ in events):
        raise _Invalid(FixReason.INVALID_RANGE, "range has no introduced event")
    versions = [key for key, _, _, _ in events]
    if len(set(versions)) != len(versions):
        raise _Invalid(FixReason.INVALID_RANGE, "range has events at the same version")
    start: str | None = None
    for key, _, kind, raw in sorted(events):
        if kind == "introduced":
            if key <= installed and start is None:
                start = raw
        elif start is not None:
            # The first closing event after an applicable introduction ends
            # the interval: either before the installed version, or above it.
            closes_below = key <= installed if kind == "fixed" else key < installed
            if closes_below:
                start = None
                continue
            if kind == "fixed":
                return _Interval(introduced=start, fixed=raw)
            return _Interval(introduced=start, last_affected=raw)
    return None if start is None else _Interval(introduced=start)


def evaluate_fix(
    affected: list[AffectedPackage],
    *,
    ecosystem: str,
    name: str,
    installed_version: str,
    version_confirmed: bool,
    listed_in_versions: bool | None,
) -> FixInformation:
    """Fix information for one advisory and one exactly versioned package."""
    listed = listed_in_versions
    if ecosystem != ECOSYSTEM:
        return FixInformation()
    if not version_confirmed:
        return _unknown(
            FixReason.INSTALLED_VERSION_UNCONFIRMED,
            "installed version is not a confirmed exact pin",
            listed=listed,
        )
    relevant = [
        a
        for a in affected
        if a.ecosystem == ECOSYSTEM
        and canonical_pypi_name(a.name) == canonical_pypi_name(name)
    ]
    if not relevant:
        return _unknown(
            FixReason.NO_MATCHING_PACKAGE,
            "advisory has no affected entry for this package",
            listed=listed,
        )
    ranges = [r for a in relevant for r in a.ranges if r.type == "ECOSYSTEM"]
    if not ranges:
        return _unknown(
            FixReason.NO_SUPPORTED_RANGE,
            "advisory has no ECOSYSTEM range for this package",
            listed=listed,
        )
    try:
        installed = _version(installed_version)
        intervals = [i for r in ranges if (i := _containing(r, installed)) is not None]
    except _Invalid as invalid:
        return _unknown(invalid.reason, invalid.detail, listed=listed)
    if not intervals:
        if listed:
            return _unknown(
                FixReason.VERSIONS_LIST_DISAGREES,
                "listed as affected, but no range contains the installed version",
                listed=listed,
            )
        return _unknown(
            FixReason.NOT_AFFECTED_BY_RANGES,
            "no range contains the installed version",
            FixApplicability.NOT_AFFECTED,
            listed=listed,
        )
    if listed is False:
        return _unknown(
            FixReason.VERSIONS_LIST_DISAGREES,
            "a range contains the installed version, but the explicit versions "
            "list does not",
            listed=listed,
        )
    interval = intervals[0]
    bounds = {
        "introduced": interval.introduced,
        "fixed": interval.fixed,
        "last_affected": interval.last_affected,
    }
    if any(i.fixed is None and i.last_affected is None for i in intervals):
        return _unknown(
            FixReason.OPEN_ENDED,
            "the affected interval has no closing event",
            FixApplicability.AFFECTED,
            listed,
            **bounds,
        )
    if any(i.last_affected is not None for i in intervals):
        return _unknown(
            FixReason.LAST_AFFECTED_ONLY,
            "the interval ends at last_affected, which names no fixed version",
            FixApplicability.AFFECTED,
            listed,
            **bounds,
        )
    fixes = {Version(i.fixed) for i in intervals if i.fixed is not None}
    if len(fixes) > 1:
        return _unknown(
            FixReason.CONFLICTING_RANGES,
            "ranges containing the installed version name different fixes",
            FixApplicability.AFFECTED,
            listed,
            **bounds,
        )
    assert interval.fixed is not None
    return FixInformation(
        status=FixStatus.AVAILABLE,
        fixed_versions=[interval.fixed],
        evidence=FixEvidence(
            applicability=FixApplicability.AFFECTED,
            reason=FixReason.FIXED_EVENT,
            detail="reported by the advisory; not proof that a release exists, "
            "installs, or is compatible",
            listed_in_versions=listed,
            **bounds,
        ),
    )


def listed_in_versions(versions: list[str], installed_version: str) -> bool | None:
    """Whether an explicit versions list contains the installed version."""
    if not versions:
        return None
    try:
        installed: Version | str = Version(installed_version)
    except InvalidVersion:
        installed = installed_version
    for listed in versions:
        try:
            if Version(listed) == installed:
                return True
        except InvalidVersion:
            if listed == installed_version:
                return True
    return False


class GroupFixStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class AdvisoryFix(DomainModel):
    advisory_id: NonBlank
    installed_version: NonBlank
    fix: FixInformation


class GroupFix(DomainModel):
    """A group-level candidate only when every advisory agrees."""

    status: GroupFixStatus
    fixed_version: NonBlank | None = None
    detail: NonBlank
    advisories: list[AdvisoryFix] = Field(min_length=1)


def group_fix(group: AdvisoryGroup, scan: ScanResult) -> GroupFix:
    """Combine per-advisory results without choosing among disagreeing ones."""
    advisories = []
    for observation in group.observations:
        index = observation.finding_index
        if (
            index >= len(scan.findings)
            or scan.findings[index].vulnerability.primary_id != observation.primary_id
        ):
            raise ValueError("the group does not belong to this scan")
        finding = scan.findings[index]
        advisories.append(
            AdvisoryFix(
                advisory_id=observation.primary_id,
                installed_version=observation.installed_version,
                fix=finding.fix,
            )
        )
    versions = {a.installed_version for a in advisories}
    available = [a for a in advisories if a.fix.status == FixStatus.AVAILABLE]
    fixes = {Version(a.fix.fixed_versions[0]) for a in available}
    if len(versions) > 1:
        status, fixed, detail = (
            GroupFixStatus.UNKNOWN,
            None,
            "the group spans several installed versions",
        )
    elif not available:
        status, fixed, detail = (
            GroupFixStatus.UNKNOWN,
            None,
            "no advisory supports a fixed version",
        )
    elif len(available) < len(advisories) or len(fixes) > 1:
        status, fixed, detail = (
            GroupFixStatus.CONFLICT,
            None,
            "advisories disagree; no single version is selected",
        )
    else:
        status, fixed, detail = (
            GroupFixStatus.CANDIDATE,
            # Equal under PEP 440; report one spelling deterministically.
            min(a.fix.fixed_versions[0] for a in available),
            "every advisory in the group reports this fixed version",
        )
    return GroupFix(
        status=status, fixed_version=fixed, detail=detail, advisories=advisories
    )
