"""OSV-Scanner v2 source JSON adapter and controlled local invocation."""

import json
import math
import os
import selectors
import signal
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
from remediator.output import directory, private_output


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
        if not math.isfinite(timeout) or timeout <= 0 or max_output_bytes <= 0:
            raise ValueError(
                "timeout must be finite and positive; output bound must be positive"
            )
        self.executable = (
            str(Path(executable).resolve()) if os.sep in executable else executable
        )
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def scan(self, target: Path, *, artifact_directory: Path) -> ScanResult:
        target = target.resolve(strict=True)
        if not target.is_dir():
            raise ValueError("target must be a local directory")
        if os.name != "posix":
            raise ValueError("scanner process-group cleanup requires POSIX")
        # Validate every path component before resolving, including parent symlinks.
        artifact_directory = Path(os.path.abspath(artifact_directory))
        resolved_artifacts = artifact_directory.resolve()
        if resolved_artifacts == target or target in resolved_artifacts.parents:
            raise ValueError("artifacts must be outside the scanned target")
        with directory(artifact_directory, create=True):
            pass
        execution_id = str(uuid4())
        artifact = artifact_directory / execution_id
        artifact.mkdir(mode=0o700)
        errors: list[str] = []
        code: int | None = None
        streams = [bytearray(), bytearray()]
        # --config is a global override in v2.3.0, not a default/fallback config.
        with TemporaryDirectory(prefix="remediator-osv-") as controlled:
            config = Path(controlled) / "osv-scanner.toml"
            with private_output(config) as handle:
                handle.write(b"# Adapter-owned: no exclusions or package overrides.\n")
            try:
                process = subprocess.Popen(
                    [
                        self.executable,
                        "scan",
                        "source",
                        "--format=json",
                        "--no-resolve",
                        "--recursive",
                        "--config",
                        str(config),
                        str(target),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    start_new_session=True,
                    cwd=controlled,
                )
                try:
                    assert process.stdout is not None and process.stderr is not None
                    with selectors.DefaultSelector() as selector:
                        for index, pipe in enumerate((process.stdout, process.stderr)):
                            os.set_blocking(pipe.fileno(), False)
                            selector.register(pipe, selectors.EVENT_READ, index)
                        deadline = time.monotonic() + self.timeout
                        while selector.get_map() or process.poll() is None:
                            remaining_time = deadline - time.monotonic()
                            if remaining_time <= 0:
                                errors.append("OSV-Scanner timed out")
                                break
                            overflow = False
                            for key, _ in selector.select(min(remaining_time, 0.05)):
                                data = os.read(key.fd, 65536)
                                if not data:
                                    selector.unregister(key.fileobj)
                                    continue
                                remaining = self.max_output_bytes - sum(
                                    map(len, streams)
                                )
                                streams[key.data].extend(data[:remaining])
                                if len(data) > remaining:
                                    errors.append("OSV-Scanner output limit exceeded")
                                    overflow = True
                                    break
                            if overflow:
                                break
                finally:
                    # Kill the session's process group even if its leader has exited.
                    # Descendants holding inherited pipes must not outlive a scan.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    code = process.wait()
                    if process.stdout is not None:
                        process.stdout.close()
                    if process.stderr is not None:
                        process.stderr.close()
                if code not in (0, 1):
                    errors.append(f"OSV-Scanner execution failed (exit {code})")
            except OSError as exc:
                errors.append(f"cannot execute OSV-Scanner: {exc}")
        for name, captured in zip(("stdout.json", "stderr.txt"), streams, strict=True):
            with private_output(artifact / name) as handle:
                handle.write(captured)
        raw = bytes(streams[0])
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
