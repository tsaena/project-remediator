"""Conservative correlation of findings across two scans of the same asset.

Correlation answers "which observation in one scan corresponds to which in the
other". It is not verification: an advisory that appears only in the earlier
scan has not been shown to be fixed. Every uncertain relationship is reported
as ambiguous rather than resolved by guessing.
"""

import posixpath
from collections import defaultdict
from enum import StrEnum
from typing import Literal, Self

from pydantic import ConfigDict, Field, model_validator

from remediator.domain import (
    CoverageStatus,
    Finding,
    ScanResult,
    ScanStatus,
)
from remediator.domain.models import DomainModel, NonBlank
from remediator.naming import canonical_pypi_name


class ComponentSlot(DomainModel):
    """Where a dependency is declared, independent of its version or checkout."""

    # Immutable and hashable: a slot is a value identity.
    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_key: NonBlank
    ecosystem: NonBlank
    # Normalized: PEP 503 for PyPI, otherwise exactly as reported.
    name: NonBlank
    # Relative to the asset root, with "/" separators.
    manifest_path: NonBlank


class GroupRisk(StrEnum):
    # Shared aliases linked more than one CVE: possibly distinct vulnerabilities.
    MULTIPLE_CVES = "multiple_cves"


class AdvisoryObservation(DomainModel):
    """One finding: a single advisory reported for one installed version."""

    finding_index: int = Field(ge=0)
    primary_id: NonBlank
    aliases: list[NonBlank] = Field(default_factory=list)
    installed_version: NonBlank


class AdvisoryGroup(DomainModel):
    """Advisories of one slot in one scan, connected through shared identifiers."""

    slot: ComponentSlot | None = None
    advisory_ids: list[NonBlank] = Field(min_length=1)
    identifiers: list[NonBlank] = Field(min_length=1)
    observations: list[AdvisoryObservation] = Field(min_length=1)
    risks: list[GroupRisk] = Field(default_factory=list)


class CorrelationKind(StrEnum):
    MATCHED = "matched"
    ONLY_BEFORE = "only_before"
    ONLY_AFTER = "only_after"
    AMBIGUOUS = "ambiguous"


class CorrelationReason(StrEnum):
    # Informational on matches.
    IDENTIFIERS_CHANGED = "identifiers_changed"
    VERSION_CHANGED = "version_changed"
    MULTIPLE_CVES = "multiple_cves"
    # Why a relationship is ambiguous.
    ALIAS_SPLIT = "alias_split"
    ALIAS_MERGE = "alias_merge"
    OVERLAPPING_GROUPS = "overlapping_groups"
    DUPLICATE_SLOT = "duplicate_slot"
    SLOT_UNAVAILABLE = "slot_unavailable"
    # A hint only: never turns two entries into a match.
    POSSIBLE_MANIFEST_MOVE = "possible_manifest_move"


_AMBIGUITY = {
    CorrelationReason.ALIAS_SPLIT,
    CorrelationReason.ALIAS_MERGE,
    CorrelationReason.OVERLAPPING_GROUPS,
    CorrelationReason.DUPLICATE_SLOT,
    CorrelationReason.SLOT_UNAVAILABLE,
}


class CorrelationEntry(DomainModel):
    kind: CorrelationKind
    slot: ComponentSlot | None = None
    before: list[AdvisoryGroup] = Field(default_factory=list)
    after: list[AdvisoryGroup] = Field(default_factory=list)
    reasons: list[CorrelationReason] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        sides = (len(self.before), len(self.after))
        ambiguous = bool(_AMBIGUITY & set(self.reasons))
        if self.kind == CorrelationKind.MATCHED:
            if sides != (1, 1) or ambiguous or self.slot is None:
                raise ValueError("a match pairs exactly one group per side in a slot")
        elif self.kind == CorrelationKind.ONLY_BEFORE:
            if sides != (1, 0):
                raise ValueError("only_before has one earlier group and no later one")
        elif self.kind == CorrelationKind.ONLY_AFTER:
            if sides != (0, 1):
                raise ValueError("only_after has one later group and no earlier one")
        elif not ambiguous or not any(sides):
            raise ValueError("ambiguous entries need groups and an ambiguity reason")
        return self


class ComparabilityStatus(StrEnum):
    COMPARABLE = "comparable"
    # Correlated, but known differences limit what the result can support.
    RESTRICTED = "restricted"
    # Not correlated at all.
    UNAVAILABLE = "unavailable"


class ComparabilityReason(StrEnum):
    MISSING_ASSET_KEY = "missing_asset_key"
    ASSET_KEY_MISMATCH = "asset_key_mismatch"
    ASSET_TYPE_MISMATCH = "asset_type_mismatch"
    SCAN_FAILED = "scan_failed"
    SCAN_PARTIAL = "scan_partial"
    COVERAGE_MISSING = "coverage_missing"
    COVERAGE_INCOMPLETE = "coverage_incomplete"
    PROVENANCE_MISSING = "provenance_missing"
    SCANNER_CHANGED = "scanner_changed"
    SCANNER_VERSION_UNKNOWN = "scanner_version_unknown"
    SCANNER_VERSION_CHANGED = "scanner_version_changed"
    ADVISORY_SOURCE_UNKNOWN = "advisory_source_unknown"
    ADVISORY_SOURCE_CHANGED = "advisory_source_changed"
    ADVISORY_SOURCE_NOT_REPRODUCIBLE = "advisory_source_not_reproducible"
    ADVISORY_DATA_CHANGED = "advisory_data_changed"


BLOCKING_REASONS = frozenset(
    {
        ComparabilityReason.MISSING_ASSET_KEY,
        ComparabilityReason.ASSET_KEY_MISMATCH,
        ComparabilityReason.ASSET_TYPE_MISMATCH,
        # A failed scan has no findings, so everything would look removed.
        ComparabilityReason.SCAN_FAILED,
    }
)


class ComparabilityNote(DomainModel):
    reason: ComparabilityReason
    scan: Literal["before", "after"] | None = None
    detail: NonBlank | None = None


class Correlation(DomainModel):
    status: ComparabilityStatus
    restrictions: list[ComparabilityNote] = Field(default_factory=list)
    entries: list[CorrelationEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        blocking = any(n.reason in BLOCKING_REASONS for n in self.restrictions)
        expected = (
            ComparabilityStatus.UNAVAILABLE
            if blocking
            else ComparabilityStatus.RESTRICTED
            if self.restrictions
            else ComparabilityStatus.COMPARABLE
        )
        if self.status != expected:
            raise ValueError(f"restrictions require status {expected.value}")
        if blocking and self.entries:
            raise ValueError("unavailable correlations cannot contain entries")
        return self


def manifest_path(location: str | None, locator: str) -> str | None:
    """Lexically relate a component location to the asset root, if possible."""
    if location is None:
        return None
    path = posixpath.normpath(location)
    if posixpath.isabs(path):
        root = posixpath.normpath(locator)
        if not posixpath.isabs(root):
            return None
        path = posixpath.relpath(path, root)
    if path == "." or path == ".." or path.startswith("../"):
        return None
    return path


def normalized_name(ecosystem: str, name: str) -> str:
    return canonical_pypi_name(name) if ecosystem == "PyPI" else name


def component_slot(finding: Finding, asset_key: str) -> ComponentSlot | None:
    path = manifest_path(finding.component.location, finding.asset.locator)
    if path is None:
        return None
    return ComponentSlot(
        asset_key=asset_key,
        ecosystem=finding.component.ecosystem,
        name=normalized_name(finding.component.ecosystem, finding.component.name),
        manifest_path=path,
    )


def _observation(index: int, finding: Finding) -> AdvisoryObservation:
    return AdvisoryObservation(
        finding_index=index,
        primary_id=finding.vulnerability.primary_id,
        aliases=finding.vulnerability.aliases,
        installed_version=finding.component.installed_version,
    )


def _identifiers(observation: AdvisoryObservation) -> set[str]:
    return {observation.primary_id, *observation.aliases}


def _components(items: list[set[str]]) -> list[list[int]]:
    """Indices of items connected through shared identifiers (union-find)."""
    parent = list(range(len(items)))

    def find(node: int) -> int:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    owner: dict[str, int] = {}
    for index, identifiers in enumerate(items):
        for identifier in identifiers:
            if identifier in owner:
                parent[find(index)] = find(owner[identifier])
            else:
                owner[identifier] = index
    groups: dict[int, list[int]] = defaultdict(list)
    for index in range(len(items)):
        groups[find(index)].append(index)
    return list(groups.values())


def _group(
    slot: ComponentSlot | None, observations: list[AdvisoryObservation]
) -> list[AdvisoryGroup]:
    """Order-independent groups: connected components, never across slots."""
    groups = []
    for members in _components([_identifiers(o) for o in observations]):
        chosen = [observations[i] for i in members]
        identifiers = sorted(set().union(*(_identifiers(o) for o in chosen)))
        cves = [i for i in identifiers if i.upper().startswith("CVE-")]
        groups.append(
            AdvisoryGroup(
                slot=slot,
                advisory_ids=sorted({o.primary_id for o in chosen}),
                identifiers=identifiers,
                observations=sorted(
                    chosen,
                    key=lambda o: (o.primary_id, o.installed_version, o.finding_index),
                ),
                risks=[GroupRisk.MULTIPLE_CVES] if len(cves) > 1 else [],
            )
        )
    return sorted(groups, key=lambda g: g.advisory_ids)


class _ScanGroups:
    """One scan's findings, grouped per slot."""

    def __init__(self, scan: ScanResult, asset_key: str) -> None:
        by_slot: dict[ComponentSlot, list[AdvisoryObservation]] = defaultdict(list)
        unplaced: dict[tuple[str, str, str], list[AdvisoryObservation]] = defaultdict(
            list
        )
        for index, finding in enumerate(scan.findings):
            observation = _observation(index, finding)
            slot = component_slot(finding, asset_key)
            if slot is None:
                component = finding.component
                key = (
                    component.ecosystem,
                    normalized_name(component.ecosystem, component.name),
                    component.location or "",
                )
                unplaced[key].append(observation)
            else:
                by_slot[slot].append(observation)
        self.groups = {slot: _group(slot, obs) for slot, obs in by_slot.items()}
        # Several installed versions in one slot cannot be told apart later.
        # Versions without advisories have no findings, only coverage records.
        versions: dict[ComponentSlot, set[str]] = defaultdict(set)
        for slot, obs in by_slot.items():
            versions[slot].update(o.installed_version for o in obs)
        for manifest in scan.coverage.manifests if scan.coverage else []:
            path = manifest_path(manifest.path, scan.asset.locator)
            for package in manifest.packages:
                if path is None or not package.ecosystem or not package.version:
                    continue
                slot = ComponentSlot(
                    asset_key=asset_key,
                    ecosystem=package.ecosystem,
                    name=normalized_name(package.ecosystem, package.name),
                    manifest_path=path,
                )
                versions[slot].add(package.version)
        self.duplicates = {slot for slot, seen in versions.items() if len(seen) > 1}
        self.unplaced = [
            group for key in sorted(unplaced) for group in _group(None, unplaced[key])
        ]


def group_advisories(scan: ScanResult, asset_key: str) -> list[AdvisoryGroup]:
    """All advisory groups of one scan, ordered by slot and advisory IDs."""
    groups = _ScanGroups(scan, asset_key)
    ordered = [
        g for slot in sorted(groups.groups, key=_slot_key) for g in groups.groups[slot]
    ]
    return ordered + groups.unplaced


def _slot_key(slot: ComponentSlot) -> tuple[str, str, str, str]:
    return (slot.asset_key, slot.ecosystem, slot.name, slot.manifest_path)


def _risk_reasons(groups: list[AdvisoryGroup]) -> list[CorrelationReason]:
    if any(GroupRisk.MULTIPLE_CVES in g.risks for g in groups):
        return [CorrelationReason.MULTIPLE_CVES]
    return []


def _match_slot(
    slot: ComponentSlot, before: list[AdvisoryGroup], after: list[AdvisoryGroup]
) -> list[CorrelationEntry]:
    items = [set(g.identifiers) for g in before] + [set(g.identifiers) for g in after]
    entries = []
    for members in _components(items):
        left = [before[i] for i in members if i < len(before)]
        right = [after[i - len(before)] for i in members if i >= len(before)]
        risks = _risk_reasons(left + right)
        if left and right and len(left) == len(right) == 1:
            reasons = []
            if left[0].identifiers != right[0].identifiers:
                reasons.append(CorrelationReason.IDENTIFIERS_CHANGED)
            versions = {o.installed_version for o in left[0].observations}
            if versions != {o.installed_version for o in right[0].observations}:
                reasons.append(CorrelationReason.VERSION_CHANGED)
            kind = CorrelationKind.MATCHED
        elif left and right:
            reasons = [
                CorrelationReason.ALIAS_SPLIT
                if len(left) == 1
                else CorrelationReason.ALIAS_MERGE
                if len(right) == 1
                else CorrelationReason.OVERLAPPING_GROUPS
            ]
            kind = CorrelationKind.AMBIGUOUS
        else:
            reasons = []
            kind = CorrelationKind.ONLY_BEFORE if left else CorrelationKind.ONLY_AFTER
        entries.append(
            CorrelationEntry(
                kind=kind, slot=slot, before=left, after=right, reasons=reasons + risks
            )
        )
    return entries


def _comparability(before: ScanResult, after: ScanResult) -> list[ComparabilityNote]:
    notes: list[ComparabilityNote] = []
    side: Literal["before", "after"]
    for side, scan in (("before", before), ("after", after)):

        def note(
            reason: ComparabilityReason,
            detail: str | None = None,
            side: Literal["before", "after"] = side,
        ) -> None:
            notes.append(ComparabilityNote(reason=reason, scan=side, detail=detail))

        if scan.asset.key is None:
            note(
                ComparabilityReason.MISSING_ASSET_KEY, "a caller asset key is required"
            )
        if scan.status == ScanStatus.FAILED:
            note(ComparabilityReason.SCAN_FAILED)
        elif scan.status == ScanStatus.PARTIAL:
            note(ComparabilityReason.SCAN_PARTIAL)
        if scan.coverage is None:
            note(ComparabilityReason.COVERAGE_MISSING)
        elif scan.coverage.status != CoverageStatus.NO_KNOWN_GAPS:
            note(ComparabilityReason.COVERAGE_INCOMPLETE, scan.coverage.status.value)
        if scan.provenance is None:
            note(ComparabilityReason.PROVENANCE_MISSING)
        if scan.scanner.version is None:
            note(ComparabilityReason.SCANNER_VERSION_UNKNOWN)
        source = scan.provenance.advisory_source if scan.provenance else None
        if source is None:
            note(ComparabilityReason.ADVISORY_SOURCE_UNKNOWN)
        elif not source.reproducible:
            note(
                ComparabilityReason.ADVISORY_SOURCE_NOT_REPRODUCIBLE, source.kind.value
            )

    def pair(reason: ComparabilityReason, detail: str) -> None:
        notes.append(ComparabilityNote(reason=reason, detail=detail))

    if before.asset.key and after.asset.key and before.asset.key != after.asset.key:
        pair(ComparabilityReason.ASSET_KEY_MISMATCH, "different caller asset keys")
    if before.asset.type != after.asset.type:
        pair(ComparabilityReason.ASSET_TYPE_MISMATCH, "different asset types")
    if before.scanner.name != after.scanner.name:
        pair(ComparabilityReason.SCANNER_CHANGED, "different scanners")
    if (
        before.scanner.version
        and after.scanner.version
        and before.scanner.version != after.scanner.version
    ):
        pair(
            ComparabilityReason.SCANNER_VERSION_CHANGED,
            f"{before.scanner.version} -> {after.scanner.version}",
        )
    sources = [
        s.provenance.advisory_source if s.provenance else None for s in (before, after)
    ]
    if sources[0] and sources[1]:
        if sources[0].kind != sources[1].kind:
            pair(ComparabilityReason.ADVISORY_SOURCE_CHANGED, "different source kinds")
        elif sources[0].fingerprints != sources[1].fingerprints:
            pair(ComparabilityReason.ADVISORY_DATA_CHANGED, "different fingerprints")
    return notes


def correlate(before: ScanResult, after: ScanResult) -> Correlation:
    """Relate findings of two scans; never a verdict about remediation."""
    restrictions = _comparability(before, after)
    if any(n.reason in BLOCKING_REASONS for n in restrictions):
        return Correlation(
            status=ComparabilityStatus.UNAVAILABLE, restrictions=restrictions
        )
    assert before.asset.key is not None
    earlier = _ScanGroups(before, before.asset.key)
    later = _ScanGroups(after, before.asset.key)
    entries: list[CorrelationEntry] = []
    for slot in sorted(set(earlier.groups) | set(later.groups), key=_slot_key):
        left = earlier.groups.get(slot, [])
        right = later.groups.get(slot, [])
        if slot in earlier.duplicates or slot in later.duplicates:
            entries.append(
                CorrelationEntry(
                    kind=CorrelationKind.AMBIGUOUS,
                    slot=slot,
                    before=left,
                    after=right,
                    reasons=[
                        CorrelationReason.DUPLICATE_SLOT,
                        *_risk_reasons(left + right),
                    ],
                )
            )
        else:
            entries.extend(_match_slot(slot, left, right))
    entries = _mark_possible_moves(entries)
    for side, groups in (("before", earlier.unplaced), ("after", later.unplaced)):
        for group in groups:
            entries.append(
                CorrelationEntry(
                    kind=CorrelationKind.AMBIGUOUS,
                    before=[group] if side == "before" else [],
                    after=[group] if side == "after" else [],
                    reasons=[
                        CorrelationReason.SLOT_UNAVAILABLE,
                        *_risk_reasons([group]),
                    ],
                )
            )
    status = (
        ComparabilityStatus.RESTRICTED
        if restrictions
        else ComparabilityStatus.COMPARABLE
    )
    return Correlation(status=status, restrictions=restrictions, entries=entries)


def _mark_possible_moves(entries: list[CorrelationEntry]) -> list[CorrelationEntry]:
    """Flag unmatched entries that may be the same advisory in a moved manifest."""
    gone = [e for e in entries if e.kind == CorrelationKind.ONLY_BEFORE]
    new = [e for e in entries if e.kind == CorrelationKind.ONLY_AFTER]
    moved: set[int] = set()
    for old in gone:
        for fresh in new:
            assert old.slot is not None and fresh.slot is not None
            same_package = (old.slot.ecosystem, old.slot.name) == (
                fresh.slot.ecosystem,
                fresh.slot.name,
            )
            shared = set(old.before[0].identifiers) & set(fresh.after[0].identifiers)
            if (
                same_package
                and shared
                and old.slot.manifest_path != fresh.slot.manifest_path
            ):
                moved.update((id(old), id(fresh)))
    return [
        CorrelationEntry(
            kind=e.kind,
            slot=e.slot,
            before=e.before,
            after=e.after,
            reasons=[*e.reasons, CorrelationReason.POSSIBLE_MANIFEST_MOVE],
        )
        if id(e) in moved
        else e
        for e in entries
    ]
