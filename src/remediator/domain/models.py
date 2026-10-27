"""Scanner-independent observations, without execution or remediation behavior."""

from enum import StrEnum
from typing import Annotated, Self

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


class Component(DomainModel):
    name: NonBlank
    ecosystem: NonBlank
    installed_version: NonBlank
    location: NonBlank | None = None


class Vulnerability(DomainModel):
    primary_id: NonBlank
    aliases: list[NonBlank] = Field(default_factory=list)
    title: NonBlank | None = None
    description: NonBlank | None = None
    severity: NonBlank | None = None
    references: list[NonBlank] = Field(default_factory=list)


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


class FixInformation(DomainModel):
    status: FixStatus = FixStatus.UNKNOWN
    fixed_versions: list[NonBlank] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_versions(self) -> Self:
        if self.status == FixStatus.AVAILABLE:
            if not self.fixed_versions:
                raise ValueError("available fix information requires fixed_versions")
        elif self.fixed_versions:
            raise ValueError("fixed_versions require available fix status")
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


class ScanResult(DomainModel):
    execution_id: NonBlank
    asset: Asset
    scanner: Scanner
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    errors: list[NonBlank] = Field(default_factory=list)

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
        return self
