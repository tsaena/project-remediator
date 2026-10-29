"""OSV-Scanner v2 source JSON adapter and controlled local invocation."""

import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, ValidationError

from remediator.domain import (
    Asset,
    AssetType,
    Component,
    Evidence,
    Finding,
    FixInformation,
    Scanner,
    ScanResult,
    ScanStatus,
    Vulnerability,
)


class Wire(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)


class Reference(Wire):
    url: str


class Advisory(Wire):
    id: str
    aliases: list[str] = []
    summary: str | None = None
    details: str | None = None
    references: list[Reference] = []


class Package(Wire):
    name: str
    ecosystem: str
    version: str


class PackageRecord(Wire):
    package: Package
    vulnerabilities: list[dict[str, object]] = []


class Source(Wire):
    path: str
    type: str


class SourceRecord(Wire):
    source: Source
    packages: list[dict[str, object]]


def normalize(
    raw: bytes,
    *,
    target: Path,
    artifact_reference: str,
    scanner: Scanner | None = None,
    execution_id: str | None = None,
    execution_errors: list[str] | None = None,
) -> ScanResult:
    """Normalize conservatively; rejected records always produce diagnostics."""
    asset = Asset(type=AssetType.REPOSITORY, locator=str(target))
    identity = scanner or Scanner(name="OSV-Scanner")
    errors = list(execution_errors or [])
    findings: list[Finding] = []
    observed = datetime.now(UTC)
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) or not isinstance(
            document.get("results"), list
        ):
            raise ValueError("expected an object with a results array")
        if document.get("experimental_generic_findings") or document.get(
            "image_metadata"
        ):
            errors.append("unsupported non-package or image results")
        for index, source_raw in enumerate(document["results"]):
            try:
                source = SourceRecord.model_validate(source_raw)
                if source.source.type not in {"lockfile", "sbom"}:
                    raise ValueError("unsupported source type")
                if not source.source.path.strip():
                    raise ValueError("missing source path")
                for package_index, package_raw in enumerate(source.packages):
                    try:
                        package = PackageRecord.model_validate(package_raw)
                        component = Component(
                            name=package.package.name,
                            ecosystem=package.package.ecosystem,
                            installed_version=package.package.version,
                            location=source.source.path,
                        )
                        for advisory_index, advisory_raw in enumerate(
                            package.vulnerabilities
                        ):
                            try:
                                advisory = Advisory.model_validate(advisory_raw)
                                findings.append(
                                    Finding(
                                        asset=asset,
                                        component=component,
                                        vulnerability=Vulnerability(
                                            primary_id=advisory.id,
                                            aliases=advisory.aliases,
                                            title=advisory.summary,
                                            description=advisory.details,
                                            references=[
                                                r.url for r in advisory.references
                                            ],
                                        ),
                                        evidence=Evidence(
                                            scanner=identity,
                                            observed_at=observed,
                                            target=source.source.path,
                                            artifact_reference=artifact_reference,
                                        ),
                                        fix=FixInformation(),
                                    )
                                )
                            except (ValueError, ValidationError):
                                errors.append(
                                    f"source {index} package {package_index} "
                                    f"advisory {advisory_index}: malformed advisory"
                                )
                    except (ValueError, ValidationError):
                        errors.append(
                            f"source {index} package {package_index}: malformed package"
                        )
            except (ValueError, ValidationError):
                errors.append(f"source {index}: unsupported or malformed source")
    except (ValueError, UnicodeDecodeError) as exc:
        errors.append(f"invalid OSV JSON: {exc}")
    # Preserve manifests and advisory IDs; collapse identical observations only.
    unique = {finding.model_dump_json(): finding for finding in findings}
    findings = list(unique.values())
    status = ScanStatus.SUCCESS
    if errors:
        status = ScanStatus.PARTIAL if findings else ScanStatus.FAILED
    return ScanResult(
        execution_id=execution_id or str(uuid4()),
        asset=asset,
        scanner=identity,
        status=status,
        findings=findings,
        errors=errors,
    )


class OSVScanner:
    """Read-only source scan, with time and output limits, not an OS sandbox."""

    def __init__(
        self,
        executable: str = "osv-scanner",
        *,
        timeout: float = 120,
        max_output_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        if timeout <= 0 or max_output_bytes <= 0:
            raise ValueError("timeout and output bound must be positive")
        self.executable = executable
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def scan(self, target: Path, *, artifact_directory: Path) -> ScanResult:
        target = target.resolve(strict=True)
        if not target.is_dir():
            raise ValueError("target must be a local directory")
        artifact_directory = artifact_directory.resolve()
        if artifact_directory == target or target in artifact_directory.parents:
            raise ValueError("artifacts must be outside the scanned target")
        artifact_directory.mkdir(parents=True, exist_ok=True)
        execution_id = str(uuid4())
        artifact = artifact_directory / execution_id
        artifact.mkdir(mode=0o700)
        errors: list[str] = []
        raw = b""
        # Files avoid unbounded PIPE buffering. Retained artifacts are capped; temporary
        # spools can overshoot between polls, so this is not a disk quota/sandbox.
        with TemporaryDirectory() as spool:
            stdout_path, stderr_path = Path(spool) / "stdout", Path(spool) / "stderr"
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    with subprocess.Popen(
                        [
                            self.executable,
                            "scan",
                            "source",
                            "--format=json",
                            "--no-resolve",
                            str(target),
                        ],
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                    ) as process:
                        deadline = time.monotonic() + self.timeout
                        while process.poll() is None:
                            if time.monotonic() >= deadline:
                                errors.append("OSV-Scanner timed out")
                                process.kill()
                                break
                            if (
                                stdout_path.stat().st_size + stderr_path.stat().st_size
                                > self.max_output_bytes
                            ):
                                errors.append("OSV-Scanner output limit exceeded")
                                process.kill()
                                break
                            time.sleep(0.02)
                        code = process.wait()
                        if code not in (0, 1):
                            errors.append(f"OSV-Scanner execution failed (exit {code})")
                except OSError as exc:
                    errors.append(f"cannot execute OSV-Scanner: {exc}")
            remaining = self.max_output_bytes
            for name, path in (
                ("stdout.json", stdout_path),
                ("stderr.txt", stderr_path),
            ):
                with path.open("rb") as handle:
                    data = handle.read(remaining)
                (artifact / name).write_bytes(data)
                remaining -= len(data)
                if path.stat().st_size > len(data):
                    errors.append(f"{name} truncated at output limit")
                if name == "stdout.json":
                    raw = data
        result = normalize(
            raw,
            target=target,
            artifact_reference=artifact.as_uri(),
            execution_id=execution_id,
            execution_errors=errors,
        )
        if not errors and code == 1 and not result.findings:
            result = normalize(
                raw,
                target=target,
                artifact_reference=artifact.as_uri(),
                execution_id=execution_id,
                execution_errors=["exit 1 without supported vulnerability findings"],
            )
        return result
