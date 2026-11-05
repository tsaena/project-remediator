"""Scanner-independent observations, without execution or remediation behavior."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

# Preserve source spelling and whitespace; only reject empty/whitespace-only values.
NonBlank = Annotated[str, StringConstraints(strict=True, pattern=r"\S")]


class DomainModel(BaseModel):
    """Reject accidental raw scanner fields at every normalized boundary."""

    model_config = ConfigDict(extra="forbid")


class AssetType(StrEnum):
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"


class Asset(DomainModel):
    type: AssetType
    locator: NonBlank
    # Caller-supplied stable identity. Locators such as checkout paths are not.
    key: NonBlank | None = None


class Component(DomainModel):
    name: NonBlank
    ecosystem: NonBlank
    installed_version: NonBlank
    location: NonBlank | None = None


class RangeEvent(DomainModel):
    """One advisory range event, as reported; exactly one field is set."""

    introduced: NonBlank | None = None
    fixed: NonBlank | None = None
    last_affected: NonBlank | None = None
    limit: NonBlank | None = None

    @model_validator(mode="after")
    def validate_single(self) -> Self:
        values = (self.introduced, self.fixed, self.last_affected, self.limit)
        if sum(v is not None for v in values) != 1:
            raise ValueError("a range event sets exactly one field")
        return self


class AffectedRange(DomainModel):
    # As reported, for example ECOSYSTEM, SEMVER, or GIT.
    type: NonBlank
    events: list[RangeEvent] = Field(default_factory=list)


class AffectedPackage(DomainModel):
    """An advisory's affected entry for the finding's own package, as reported."""

    ecosystem: NonBlank
    name: NonBlank
    ranges: list[AffectedRange] = Field(default_factory=list)
    # How many versions the advisory lists explicitly; the list itself stays
    # in the raw scanner artifact.
    listed_versions: int = Field(default=0, ge=0)


class Vulnerability(DomainModel):
    primary_id: NonBlank
    aliases: list[NonBlank] = Field(default_factory=list)
    title: NonBlank | None = None
    description: NonBlank | None = None
    severity: NonBlank | None = None
    references: list[NonBlank] = Field(default_factory=list)
    affected: list[AffectedPackage] = Field(default_factory=list)


class Scanner(DomainModel):
    name: NonBlank
    version: NonBlank | None = None


class Evidence(DomainModel):
    scanner: Scanner
    observed_at: AwareDatetime
    target: NonBlank
    artifact_reference: NonBlank


class FixStatus(StrEnum):
    UNKNOWN = "unknown"
    NO_FIX = "no_fix"
    AVAILABLE = "available"


class FixApplicability(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


class FixReason(StrEnum):
    # The only reason that supports an available candidate.
    FIXED_EVENT = "fixed_event"
    INSTALLED_VERSION_UNCONFIRMED = "installed_version_unconfirmed"
    INVALID_VERSION = "invalid_version"
    NO_MATCHING_PACKAGE = "no_matching_package"
    NO_SUPPORTED_RANGE = "no_supported_range"
    UNSUPPORTED_EVENT = "unsupported_event"
    INVALID_RANGE = "invalid_range"
    MALFORMED_AFFECTED = "malformed_affected"
    OPEN_ENDED = "open_ended"
    LAST_AFFECTED_ONLY = "last_affected_only"
    CONFLICTING_RANGES = "conflicting_ranges"
    CANDIDATE_STILL_AFFECTED = "candidate_still_affected"
    NOT_AFFECTED_BY_RANGES = "not_affected_by_ranges"
    VERSIONS_LIST_DISAGREES = "versions_list_disagrees"


class FixEvidence(DomainModel):
    """Why a fix status was assigned, from one advisory's affected ranges."""

    applicability: FixApplicability
    reason: FixReason
    detail: NonBlank | None = None
    # Bounds of the range interval that contains the installed version.
    introduced: NonBlank | None = None
    fixed: NonBlank | None = None
    last_affected: NonBlank | None = None
    # Whether the advisory's explicit versions list contains the installed
    # version; None when it lists no versions.
    listed_in_versions: bool | None = None

    @model_validator(mode="after")
    def validate_candidate(self) -> Self:
        if self.reason == FixReason.FIXED_EVENT and (
            self.applicability != FixApplicability.AFFECTED or self.fixed is None
        ):
            raise ValueError("a fixed_event candidate needs an affected interval")
        return self


class FixInformation(DomainModel):
    status: FixStatus = FixStatus.UNKNOWN
    fixed_versions: list[NonBlank] = Field(default_factory=list)
    evidence: FixEvidence | None = None

    @model_validator(mode="after")
    def validate_versions(self) -> Self:
        if self.status == FixStatus.AVAILABLE:
            if not self.fixed_versions:
                raise ValueError("available fix information requires fixed_versions")
        elif self.fixed_versions:
            raise ValueError("fixed_versions require available fix status")
        if self.evidence is not None:
            if self.status == FixStatus.NO_FIX:
                raise ValueError("advisory ranges never establish no_fix")
            candidate = self.evidence.reason == FixReason.FIXED_EVENT
            if candidate != (self.status == FixStatus.AVAILABLE):
                raise ValueError("only a fixed_event makes a fix available")
            if candidate and self.fixed_versions != [self.evidence.fixed]:
                raise ValueError("fixed_versions must be the evidenced fixed event")
        return self


class Finding(DomainModel):
    asset: Asset
    component: Component
    vulnerability: Vulnerability
    evidence: Evidence
    fix: FixInformation = Field(default_factory=FixInformation)


class ScanStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class CoverageStatus(StrEnum):
    # Every inventoried in-scope manifest and package was confidently assessed.
    # This is bounded by the documented inventory scope, never "complete".
    NO_KNOWN_GAPS = "no_known_gaps"
    INCOMPLETE = "incomplete"
    UNKNOWN = "unknown"


class ManifestStatus(StrEnum):
    ASSESSED = "assessed"
    NOT_REPORTED = "not_reported"
    EXCLUDED = "excluded"
    UNSUPPORTED = "unsupported"
    # Reported by a scan that did not succeed; packages are diagnostic only.
    UNKNOWN = "unknown"


class PackageAssessment(StrEnum):
    ASSESSED = "assessed"
    NOT_ASSESSED = "not_assessed"
    UNKNOWN = "unknown"


class VersionPrecision(StrEnum):
    EXACT = "exact"
    IMPRECISE = "imprecise"
    UNKNOWN = "unknown"


class DiscoveryMethod(StrEnum):
    INVENTORY = "inventory"
    SCANNER = "scanner"


class CoverageReason(StrEnum):
    SCAN_NOT_SUCCESSFUL = "scan_not_successful"
    SCANNER_OUTPUT_UNUSABLE = "scanner_output_unusable"
    INVENTORY_UNAVAILABLE = "inventory_unavailable"
    INVENTORY_TRUNCATED = "inventory_truncated"
    UNREADABLE_PATH = "unreadable_path"
    SYMLINK_NOT_FOLLOWED = "symlink_not_followed"
    NO_DEPENDENCY_ENTRIES = "no_dependency_entries"
    POSSIBLY_IGNORED = "possibly_ignored"
    NOT_REPORTED_BY_SCANNER = "not_reported_by_scanner"
    UNSUPPORTED_FORMAT = "unsupported_format"
    UNSUPPORTED_SOURCE = "unsupported_source"
    OUTSIDE_TARGET = "outside_target"
    NO_MANIFESTS_ASSESSED = "no_manifests_assessed"
    MISSING_VERSION = "missing_version"
    IMPRECISE_CONSTRAINT = "imprecise_constraint"
    NOT_DECLARED_IN_MANIFEST = "not_declared_in_manifest"
    UNINSPECTED_INCLUDE = "uninspected_include"
    UNRECOGNIZED_DECLARATION = "unrecognized_declaration"
    PRECISION_UNDETERMINED = "precision_undetermined"
    ECOSYSTEM_OUTSIDE_SCOPE = "ecosystem_outside_scope"
    MALFORMED_RECORD = "malformed_record"


class CoverageNote(DomainModel):
    """A reason why something cannot count as confidently assessed."""

    reason: CoverageReason
    path: NonBlank | None = None
    detail: NonBlank | None = None


class PackageCoverage(DomainModel):
    name: NonBlank
    ecosystem: NonBlank | None = None
    version: NonBlank | None = None
    assessment: PackageAssessment
    version_precision: VersionPrecision = VersionPrecision.UNKNOWN
    advisory_count: int = Field(default=0, ge=0)
    notes: list[CoverageNote] = Field(default_factory=list)

    @property
    def confidently_assessed(self) -> bool:
        return (
            self.assessment == PackageAssessment.ASSESSED
            and self.version_precision == VersionPrecision.EXACT
        )

    @model_validator(mode="after")
    def validate_assessment(self) -> Self:
        if self.assessment == PackageAssessment.ASSESSED and (
            self.ecosystem is None or self.version is None
        ):
            raise ValueError("assessed packages require an ecosystem and version")
        if not self.confidently_assessed and not self.notes:
            raise ValueError("packages not confidently assessed require a note")
        return self


class ManifestCoverage(DomainModel):
    # Relative to the asset root, with "/" separators.
    path: NonBlank
    status: ManifestStatus
    discovered_by: list[DiscoveryMethod] = Field(min_length=1)
    packages: list[PackageCoverage] = Field(default_factory=list)
    notes: list[CoverageNote] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.status != ManifestStatus.ASSESSED:
            if self.packages and self.status != ManifestStatus.UNKNOWN:
                raise ValueError("only assessed or unknown manifests list packages")
            if not self.notes:
                raise ValueError("unassessed manifests require a note")
        return self


class ManifestInventory(DomainModel):
    """What the independent inventory looked for and whether it finished."""

    ecosystems: list[NonBlank] = Field(min_length=1)
    supported_patterns: list[NonBlank] = Field(min_length=1)
    unsupported_patterns: list[NonBlank] = Field(default_factory=list)
    skipped_directories: list[NonBlank] = Field(default_factory=list)
    max_depth: int = Field(ge=0)
    max_entries: int = Field(ge=1)
    entries_examined: int = Field(ge=0)
    truncated: bool


class ScanCoverage(DomainModel):
    status: CoverageStatus
    inventory: ManifestInventory | None = None
    manifests: list[ManifestCoverage] = Field(default_factory=list)
    limitations: list[CoverageNote] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_claim(self) -> Self:
        if self.status != CoverageStatus.NO_KNOWN_GAPS:
            if not self.limitations:
                raise ValueError("incomplete or unknown coverage requires limitations")
            return self
        if self.limitations:
            raise ValueError("coverage without known gaps cannot have limitations")
        if self.inventory is None or self.inventory.truncated:
            raise ValueError("coverage without known gaps requires a full inventory")
        if not self.manifests:
            raise ValueError("coverage without known gaps requires a manifest")
        for manifest in self.manifests:
            if manifest.status != ManifestStatus.ASSESSED or manifest.notes:
                raise ValueError("coverage without known gaps has unassessed manifests")
            if not all(p.confidently_assessed for p in manifest.packages):
                raise ValueError("coverage without known gaps has unassessed packages")
        return self


class ProvenanceOrigin(StrEnum):
    SCANNER = "scanner"  # Reported by the scanner itself.
    ADAPTER = "adapter"  # Configured, observed, or computed by our adapter.


class ProvenanceFact(DomainModel):
    name: NonBlank
    origin: ProvenanceOrigin
    value: NonBlank | None = None
    detail: NonBlank | None = None

    @model_validator(mode="after")
    def validate_unavailable(self) -> Self:
        if self.value is None and self.detail is None:
            raise ValueError("unavailable provenance requires a detail")
        return self


class AdvisorySourceKind(StrEnum):
    ONLINE_SERVICE = "online_service"
    LOCAL_DATABASE = "local_database"
    UNKNOWN = "unknown"


class Fingerprint(DomainModel):
    subject: NonBlank
    algorithm: NonBlank
    value: NonBlank


class AdvisorySource(DomainModel):
    kind: AdvisorySourceKind
    origin: ProvenanceOrigin = ProvenanceOrigin.ADAPTER
    reproducible: bool = False
    fingerprints: list[Fingerprint] = Field(default_factory=list)
    detail: NonBlank | None = None

    @model_validator(mode="after")
    def validate_reproducible(self) -> Self:
        if self.reproducible and (
            self.kind != AdvisorySourceKind.LOCAL_DATABASE or not self.fingerprints
        ):
            raise ValueError("only fingerprinted local databases are reproducible")
        return self


class ScanProvenance(DomainModel):
    started_at: AwareDatetime | None = None
    finished_at: AwareDatetime | None = None
    exit_code: int | None = None
    command: list[NonBlank] = Field(default_factory=list)
    advisory_source: AdvisorySource | None = None
    artifacts: list[NonBlank] = Field(default_factory=list)
    facts: list[ProvenanceFact] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        if (
            self.started_at is not None
            and self.finished_at is not None
            and self.finished_at < self.started_at
        ):
            raise ValueError("scan cannot finish before it starts")
        return self


CURRENT_SCHEMA_VERSION: Literal[3] = 3


class ScanResult(DomainModel):
    # Reports without this field predate coverage and provenance (version 1).
    schema_version: Literal[1, 2, 3] = 1
    execution_id: NonBlank
    asset: Asset
    scanner: Scanner
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    errors: list[NonBlank] = Field(default_factory=list)
    coverage: ScanCoverage | None = None
    provenance: ScanProvenance | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> Self:
        if self.status == ScanStatus.SUCCESS and self.errors:
            raise ValueError("successful scans cannot contain errors")
        if self.status != ScanStatus.SUCCESS and not self.errors:
            raise ValueError("failed and partial scans require errors")
        if self.status == ScanStatus.FAILED and self.findings:
            raise ValueError("failed scans cannot contain findings; use partial")
        for finding in self.findings:
            if finding.asset != self.asset:
                raise ValueError("finding asset must match scan asset")
            if finding.evidence.scanner != self.scanner:
                raise ValueError("finding scanner must match scan scanner")
        if self.schema_version < 2 and (
            self.coverage or self.provenance or self.asset.key
        ):
            raise ValueError("coverage, provenance, and asset keys need schema 2")
        if self.schema_version < 3 and any(
            f.vulnerability.affected or f.fix.evidence for f in self.findings
        ):
            raise ValueError("affected ranges and fix evidence need schema 3")
        if (
            self.coverage is not None
            and self.status != ScanStatus.SUCCESS
            and self.coverage.status == CoverageStatus.NO_KNOWN_GAPS
        ):
            raise ValueError("unsuccessful scans cannot claim coverage")
        return self
