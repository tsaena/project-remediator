"""OSV-Scanner v2 source JSON adapter and controlled local invocation."""

import hashlib
import json
import math
import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, ValidationError

from remediator.domain import (
    CURRENT_SCHEMA_VERSION,
    AdvisorySource,
    AdvisorySourceKind,
    Asset,
    AssetType,
    Component,
    CoverageNote,
    CoverageReason,
    CoverageStatus,
    DiscoveryMethod,
    Evidence,
    Finding,
    Fingerprint,
    FixInformation,
    ManifestCoverage,
    ManifestStatus,
    PackageAssessment,
    PackageCoverage,
    ProvenanceFact,
    ProvenanceOrigin,
    ScanCoverage,
    Scanner,
    ScanProvenance,
    ScanResult,
    ScanStatus,
    VersionPrecision,
    Vulnerability,
)
from remediator.output import directory, private_output
from remediator.scanners import python_manifests
from remediator.scanners.python_manifests import (
    LOCKFILES,
    DiscoveredManifest,
    Inventory,
    canonical_name,
)

SCANNER_NAME = "OSV-Scanner"
SCAN_ARGUMENTS = [
    "scan",
    "source",
    "--format=json",
    "--no-resolve",
    "--recursive",
    "--all-packages",
]
CONFIGURATION = b"# Adapter-owned: no exclusions or package overrides.\n"
VERSION_OUTPUT_LIMIT = 64 * 1024
VERSION_TIMEOUT = 30.0
# Package coverage semantics are documented only for this ecosystem.
COVERED_ECOSYSTEM = "PyPI"
_VERSION_LINES = {
    "osv-scanner version": "scanner_version",
    "osv-scalibr version": "scalibr_version",
    "commit": "scanner_commit",
    "built at": "scanner_build_date",
}


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


@dataclass
class _Observation:
    """One scanner package record, classified once the scan status is known."""

    name: str
    ecosystem: str
    version: str
    advisory_count: int
    malformed_advisories: bool = False


@dataclass
class _Source:
    packages: list[_Observation] = field(default_factory=list)
    notes: list[CoverageNote] = field(default_factory=list)


def normalize(
    raw: bytes,
    *,
    target: Path,
    artifact_reference: str,
    scanner: Scanner | None = None,
    execution_id: str | None = None,
    execution_errors: list[str] | None = None,
    inventory: Inventory | None = None,
    asset_key: str | None = None,
    provenance: ScanProvenance | None = None,
) -> ScanResult:
    """Normalize conservatively; rejected records always produce diagnostics.

    Coverage is derived from the scanner's package records and, when supplied,
    an independent manifest inventory. Without an inventory, coverage is never
    better than incomplete.
    """
    asset = Asset(type=AssetType.REPOSITORY, locator=str(target), key=asset_key)
    identity = scanner or Scanner(name=SCANNER_NAME)
    errors = list(execution_errors or [])
    findings: list[Finding] = []
    sources: dict[str, _Source] = {}
    limitations: list[CoverageNote] = []
    output_usable = False
    observed = datetime.now(UTC)
    try:
        document = json.loads(raw)
        if not isinstance(document, dict) or not isinstance(
            document.get("results"), list
        ):
            raise ValueError("expected an object with a results array")
        output_usable = True
        if document.get("experimental_generic_findings") or document.get(
            "image_metadata"
        ):
            errors.append("unsupported non-package or image results")
            limitations.append(
                CoverageNote(
                    reason=CoverageReason.UNSUPPORTED_SOURCE,
                    detail="non-package or image results are not normalized",
                )
            )
        for index, source_raw in enumerate(document["results"]):
            try:
                source = SourceRecord.model_validate(source_raw)
                if not source.source.path.strip():
                    raise ValueError("missing source path")
                relative = _relative(source.source.path, target)
                if source.source.type not in {"lockfile", "sbom"}:
                    limitations.append(
                        CoverageNote(
                            reason=CoverageReason.UNSUPPORTED_SOURCE,
                            path=relative,
                            detail=f"source type {source.source.type!r}",
                        )
                    )
                    raise ValueError("unsupported source type")
                if relative is None:
                    # Findings are still evidence; only coverage cannot use them.
                    limitations.append(
                        CoverageNote(
                            reason=CoverageReason.OUTSIDE_TARGET,
                            detail="scanner reported a source outside the target",
                        )
                    )
                    observations = _Source()
                else:
                    observations = sources.setdefault(relative, _Source())
                for package_index, package_raw in enumerate(source.packages):
                    try:
                        package = PackageRecord.model_validate(package_raw)
                    except ValidationError:
                        errors.append(
                            f"source {index} package {package_index}: malformed package"
                        )
                        observations.notes.append(
                            CoverageNote(
                                reason=CoverageReason.MALFORMED_RECORD,
                                path=relative,
                                detail=f"package record {package_index} is malformed",
                            )
                        )
                        continue
                    reported = package.package
                    if not reported.name.strip() or any(
                        value and not value.strip()
                        for value in (reported.ecosystem, reported.version)
                    ):
                        # Blank strings cannot be normalized; keep the rest.
                        errors.append(
                            f"source {index} package {package_index}: malformed package"
                        )
                        observations.notes.append(
                            CoverageNote(
                                reason=CoverageReason.MALFORMED_RECORD,
                                path=relative,
                                detail=f"package record {package_index} has a blank "
                                "name, ecosystem, or version",
                            )
                        )
                        continue
                    observation = _Observation(
                        package.package.name,
                        package.package.ecosystem,
                        package.package.version,
                        len(package.vulnerabilities),
                    )
                    observations.packages.append(observation)
                    if not package.vulnerabilities:
                        continue
                    try:
                        component = Component(
                            name=package.package.name,
                            ecosystem=package.package.ecosystem,
                            installed_version=package.package.version,
                            location=source.source.path,
                        )
                    except ValidationError:
                        errors.append(
                            f"source {index} package {package_index}: malformed package"
                        )
                        observation.malformed_advisories = True
                        continue
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
                                        references=[r.url for r in advisory.references],
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
                            observation.malformed_advisories = True
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
    coverage = _coverage(
        status=status,
        output_usable=output_usable,
        sources=sources,
        inventory=inventory,
        limitations=limitations,
    )
    return ScanResult(
        schema_version=CURRENT_SCHEMA_VERSION,
        execution_id=execution_id or str(uuid4()),
        asset=asset,
        scanner=identity,
        status=status,
        findings=findings,
        errors=errors,
        coverage=coverage,
        provenance=provenance,
    )


def _relative(path: str, target: Path) -> str | None:
    """Lexically relate a scanner path to the target; never touches the disk."""
    candidate = Path(os.path.normpath(target / path))
    try:
        relative = candidate.relative_to(target)
    except ValueError:
        return None
    return PurePosixPath(*relative.parts).as_posix() if relative.parts else None


def _coverage(
    *,
    status: ScanStatus,
    output_usable: bool,
    sources: dict[str, _Source],
    inventory: Inventory | None,
    limitations: list[CoverageNote],
) -> ScanCoverage:
    succeeded = status == ScanStatus.SUCCESS
    limitations = list(limitations)
    if not succeeded:
        limitations.append(
            CoverageNote(
                reason=CoverageReason.SCAN_NOT_SUCCESSFUL,
                detail="partial or failed scan; observations are diagnostic only",
            )
        )
    if not output_usable:
        limitations.append(
            CoverageNote(
                reason=CoverageReason.SCANNER_OUTPUT_UNUSABLE,
                detail="scanner output could not be parsed",
            )
        )
    discovered = inventory.manifests if inventory else {}
    if inventory is None:
        limitations.append(
            CoverageNote(
                reason=CoverageReason.INVENTORY_UNAVAILABLE,
                detail="no independent manifest inventory was performed",
            )
        )
    else:
        limitations.extend(inventory.limitations)
    manifests: list[ManifestCoverage] = []
    for path in sorted(set(sources) | set(discovered)):
        found = discovered.get(path)
        if path in sources:
            manifest = _reported(path, sources[path], found, succeeded)
        else:
            assert found is not None
            manifest = _unreported(found)
        manifests.append(manifest)
        limitations.extend(manifest.notes)
        for package in manifest.packages:
            limitations.extend(
                CoverageNote(
                    reason=note.reason,
                    path=path,
                    detail=f"package {package.name}: {note.detail}",
                )
                for note in package.notes
            )
    if not any(m.status == ManifestStatus.ASSESSED for m in manifests):
        limitations.append(
            CoverageNote(
                reason=CoverageReason.NO_MANIFESTS_ASSESSED,
                detail="no manifest has positive evidence of assessment",
            )
        )
    if not succeeded or not output_usable:
        coverage_status = CoverageStatus.UNKNOWN
    elif limitations:
        coverage_status = CoverageStatus.INCOMPLETE
    else:
        coverage_status = CoverageStatus.NO_KNOWN_GAPS
    return ScanCoverage(
        status=coverage_status,
        inventory=inventory.record if inventory else None,
        manifests=manifests,
        limitations=limitations,
    )


def _reported(
    path: str,
    source: _Source,
    found: DiscoveredManifest | None,
    succeeded: bool,
) -> ManifestCoverage:
    discovered_by = [DiscoveryMethod.SCANNER]
    if found is not None:
        discovered_by.insert(0, DiscoveryMethod.INVENTORY)
    notes = list(source.notes)
    if not succeeded:
        notes.append(
            CoverageNote(
                reason=CoverageReason.SCAN_NOT_SUCCESSFUL,
                path=path,
                detail="reported by a scan that did not succeed",
            )
        )
    elif not source.packages:
        notes.append(
            CoverageNote(
                reason=CoverageReason.NO_DEPENDENCY_ENTRIES,
                path=path,
                detail="scanner reported this manifest without packages",
            )
        )
    unique: dict[tuple[str, str, str], _Observation] = {}
    for observation in source.packages:
        key = (observation.name, observation.ecosystem, observation.version)
        previous = unique.get(key)
        if previous is None or observation.malformed_advisories:
            unique[key] = observation
    packages = [
        _package(observation, path, found, succeeded) for observation in unique.values()
    ]
    if succeeded and found is not None and found.requirements is not None:
        # Included files can hold declarations the scanner skips (or, for
        # "--requirement", never reads), which nothing here can reconcile.
        notes.extend(
            CoverageNote(
                reason=CoverageReason.UNINSPECTED_INCLUDE,
                path=path,
                detail=f"{include!r}: included declarations are not "
                "independently inventoried",
            )
            for include in found.requirements.includes
        )
        notes.extend(
            CoverageNote(
                reason=CoverageReason.UNRECOGNIZED_DECLARATION,
                path=path,
                detail=f"{line[:200]!r}: not attributable to a named package, "
                "so the scanner cannot assess it",
            )
            for line in found.requirements.unrecognized
        )
        # The scanner silently skips some declarations (for example dotted or
        # one-character names), so every direct declaration must be accounted for.
        reported = {canonical_name(o.name) for o in source.packages}
        packages.extend(
            PackageCoverage(
                name=name,
                ecosystem=COVERED_ECOSYSTEM,
                assessment=PackageAssessment.NOT_ASSESSED,
                notes=[
                    CoverageNote(
                        reason=CoverageReason.NOT_REPORTED_BY_SCANNER,
                        detail="declared in this manifest but the scanner reported "
                        "no package record for it",
                    )
                ],
            )
            for name in sorted(set(found.requirements.precision) - reported)
        )
    return ManifestCoverage(
        path=path,
        status=ManifestStatus.ASSESSED if succeeded else ManifestStatus.UNKNOWN,
        discovered_by=discovered_by,
        packages=packages,
        notes=notes,
    )


def _package(
    observation: _Observation,
    path: str,
    found: DiscoveredManifest | None,
    succeeded: bool,
) -> PackageCoverage:
    notes: list[CoverageNote] = []
    if not succeeded:
        assessment = PackageAssessment.UNKNOWN
        notes.append(
            CoverageNote(
                reason=CoverageReason.SCAN_NOT_SUCCESSFUL,
                detail="reported by a scan that did not succeed",
            )
        )
    elif observation.ecosystem != COVERED_ECOSYSTEM:
        assessment = PackageAssessment.UNKNOWN
        notes.append(
            CoverageNote(
                reason=CoverageReason.ECOSYSTEM_OUTSIDE_SCOPE,
                detail=f"coverage semantics are documented only for "
                f"{COVERED_ECOSYSTEM}, not {observation.ecosystem or 'empty'}",
            )
        )
    elif not observation.version:
        assessment = PackageAssessment.NOT_ASSESSED
        notes.append(
            CoverageNote(
                reason=CoverageReason.MISSING_VERSION,
                detail="no version was extracted, so it was not matched",
            )
        )
    elif observation.malformed_advisories:
        assessment = PackageAssessment.UNKNOWN
        notes.append(
            CoverageNote(
                reason=CoverageReason.MALFORMED_RECORD,
                detail="some reported advisories could not be normalized",
            )
        )
    else:
        assessment = PackageAssessment.ASSESSED
    precision = VersionPrecision.UNKNOWN
    if assessment == PackageAssessment.ASSESSED:
        precision, note = _precision(observation, path, found)
        if note is not None:
            notes.append(note)
    return PackageCoverage(
        name=observation.name,
        ecosystem=observation.ecosystem or None,
        version=observation.version or None,
        assessment=assessment,
        version_precision=precision,
        advisory_count=observation.advisory_count,
        notes=notes,
    )


def _precision(
    observation: _Observation, path: str, found: DiscoveredManifest | None
) -> tuple[VersionPrecision, CoverageNote | None]:
    """Whether the assessed version is exactly what the manifest pins."""
    if PurePosixPath(path).name in LOCKFILES:
        return VersionPrecision.EXACT, None
    if found is None or found.requirements is None:
        return VersionPrecision.UNKNOWN, CoverageNote(
            reason=CoverageReason.PRECISION_UNDETERMINED,
            detail="the manifest was not inspected, so version precision is unknown",
        )
    precision = found.requirements.precision.get(canonical_name(observation.name))
    if precision is None:
        return VersionPrecision.UNKNOWN, CoverageNote(
            reason=CoverageReason.NOT_DECLARED_IN_MANIFEST,
            detail="not declared directly in this manifest (for example via -r)",
        )
    if precision == VersionPrecision.IMPRECISE:
        return precision, CoverageNote(
            reason=CoverageReason.IMPRECISE_CONSTRAINT,
            detail=f"version {observation.version} was derived from a non-exact "
            "constraint, not an exact pin",
        )
    if precision == VersionPrecision.UNKNOWN:
        return precision, CoverageNote(
            reason=CoverageReason.PRECISION_UNDETERMINED,
            detail="conflicting declarations in this manifest",
        )
    return precision, None


def _unreported(found: DiscoveredManifest) -> ManifestCoverage:
    if found.notes:
        symlink = any(
            n.reason == CoverageReason.SYMLINK_NOT_FOLLOWED for n in found.notes
        )
        status = ManifestStatus.EXCLUDED if symlink else ManifestStatus.UNSUPPORTED
        notes = found.notes
    elif found.has_entries is False:
        status = ManifestStatus.NOT_REPORTED
        notes = [
            CoverageNote(
                reason=CoverageReason.NO_DEPENDENCY_ENTRIES,
                path=found.path,
                detail="the manifest declares no dependencies",
            )
        ]
    elif found.ignore_files:
        status = ManifestStatus.NOT_REPORTED
        notes = [
            CoverageNote(
                reason=CoverageReason.POSSIBLY_IGNORED,
                path=found.path,
                detail="not reported by the scanner; ignore rules in scope: "
                + ", ".join(found.ignore_files),
            )
        ]
    else:
        status = ManifestStatus.NOT_REPORTED
        notes = [
            CoverageNote(
                reason=CoverageReason.NOT_REPORTED_BY_SCANNER,
                path=found.path,
                detail="supported manifest without scanner package records",
            )
        ]
    return ManifestCoverage(
        path=found.path,
        status=status,
        discovered_by=[DiscoveryMethod.INVENTORY],
        notes=notes,
    )


@dataclass
class _Execution:
    code: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    errors: list[str] = field(default_factory=list)


def _execute(
    argv: list[str], *, cwd: str, timeout: float, limit: int, label: str
) -> _Execution:
    """Run without a shell, bounded in time and retained output; kill the group."""
    result = _Execution()
    streams = [bytearray(), bytearray()]
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
            cwd=cwd,
        )
        try:
            assert process.stdout is not None and process.stderr is not None
            with selectors.DefaultSelector() as selector:
                for index, pipe in enumerate((process.stdout, process.stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, index)
                deadline = time.monotonic() + timeout
                while selector.get_map() or process.poll() is None:
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        result.errors.append(f"{label} timed out")
                        break
                    overflow = False
                    for key, _ in selector.select(min(remaining_time, 0.05)):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        remaining = limit - sum(map(len, streams))
                        streams[key.data].extend(data[:remaining])
                        if len(data) > remaining:
                            result.errors.append(f"{label} output limit exceeded")
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
            result.code = process.wait()
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if result.code not in (0, 1):
            result.errors.append(f"{label} execution failed (exit {result.code})")
    except OSError as exc:
        result.errors.append(f"cannot execute {label}: {exc}")
    result.stdout, result.stderr = bytes(streams[0]), bytes(streams[1])
    return result


def _version_facts(execution: _Execution) -> tuple[str | None, list[ProvenanceFact]]:
    """Scanner-reported build identity; anything not reported stays unavailable."""
    reported: dict[str, str] = {}
    if execution.code == 0 and not execution.errors:
        text = execution.stdout.decode("utf-8", errors="replace")
        for line in text.splitlines():
            key, _, value = line.partition(":")
            name = _VERSION_LINES.get(key.strip())
            if name and value.strip() and name not in reported:
                reported[name] = value.strip()
    why = "; ".join(execution.errors) or "not present in --version output"
    facts = [
        ProvenanceFact(
            name=name,
            origin=ProvenanceOrigin.SCANNER,
            value=reported.get(name),
            detail=None if name in reported else why,
        )
        for name in _VERSION_LINES.values()
    ]
    return reported.get("scanner_version"), facts


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _database_fingerprints(database: Path) -> list[Fingerprint]:
    """Fingerprint OSV-Scanner's offline archives: <dir>/osv-scanner/*/all.zip.

    Symlinks below the database root are rejected: the scanner would follow
    them, and one could point at repository-controlled bytes. Every component
    is opened relative to its parent with ``O_NOFOLLOW``, so the check and the
    bytes hashed cannot diverge.
    """

    def child(parent: int, name: str, *, directory: bool) -> int | None:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"offline database contains a symlink: {name}")
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode):
            return None
        flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0)
        return os.open(name, flags, dir_fd=parent)

    fingerprints: list[Fingerprint] = []
    root = os.open(database, os.O_RDONLY | os.O_DIRECTORY)
    try:
        base = child(root, "osv-scanner", directory=True)
        if base is None:
            return []
        try:
            for ecosystem in sorted(os.listdir(base)):
                folder = child(base, ecosystem, directory=True)
                if folder is None:
                    continue
                try:
                    archive = child(folder, "all.zip", directory=False)
                    if archive is None:
                        continue
                    digest = hashlib.sha256()
                    with os.fdopen(archive, "rb") as handle:
                        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                            digest.update(chunk)
                finally:
                    os.close(folder)
                fingerprints.append(
                    Fingerprint(
                        subject=f"osv-scanner/{ecosystem}/all.zip",
                        algorithm="sha256",
                        value=digest.hexdigest(),
                    )
                )
        finally:
            os.close(base)
    finally:
        os.close(root)
    return fingerprints


class OSVScanner:
    """Read-only source scan, with time and output limits, not an OS sandbox."""

    def __init__(
        self,
        executable: str = "osv-scanner",
        *,
        timeout: float = 120,
        max_output_bytes: int = 10 * 1024 * 1024,
        offline_database: Path | None = None,
        inventory_max_depth: int = python_manifests.MAX_DEPTH,
        inventory_max_entries: int = python_manifests.MAX_ENTRIES,
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0 or max_output_bytes <= 0:
            raise ValueError(
                "timeout must be finite and positive; output bound must be positive"
            )
        if inventory_max_depth < 0 or inventory_max_entries < 1:
            raise ValueError("inventory limits must be positive")
        self.executable = (
            str(Path(executable).resolve()) if os.sep in executable else executable
        )
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes
        self.offline_database = (
            offline_database.resolve(strict=True) if offline_database else None
        )
        if self.offline_database is not None and not self.offline_database.is_dir():
            raise ValueError("offline database must be a directory")
        self.inventory_max_depth = inventory_max_depth
        self.inventory_max_entries = inventory_max_entries

    def scan(
        self,
        target: Path,
        *,
        artifact_directory: Path,
        asset_key: str | None = None,
    ) -> ScanResult:
        target = target.resolve(strict=True)
        if not target.is_dir():
            raise ValueError("target must be a local directory")
        if os.name != "posix":
            raise ValueError("scanner process-group cleanup requires POSIX")
        database = self.offline_database
        if database is not None and (database == target or target in database.parents):
            raise ValueError("offline database must be outside the scanned target")
        # Raises on symlinked archives before anything is created or executed.
        before = _database_fingerprints(database) if database else []
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
        # The inventory runs first and only reads; nothing from the target executes.
        manifests = python_manifests.inventory(
            target,
            max_depth=self.inventory_max_depth,
            max_entries=self.inventory_max_entries,
        )
        database_flags = (
            ["--offline", f"--local-db-path={database}"] if database else []
        )
        # --config is a global override in v2.3.0, not a default/fallback config.
        with TemporaryDirectory(prefix="remediator-osv-") as controlled:
            config = Path(controlled) / "osv-scanner.toml"
            with private_output(config) as handle:
                handle.write(CONFIGURATION)
            version = _execute(
                [self.executable, "--version"],
                cwd=controlled,
                timeout=min(self.timeout, VERSION_TIMEOUT),
                limit=VERSION_OUTPUT_LIMIT,
                label=f"{SCANNER_NAME} --version",
            )
            command = [
                self.executable,
                *SCAN_ARGUMENTS,
                *database_flags,
                "--config",
                str(config),
                str(target),
            ]
            started = datetime.now(UTC)
            execution = _execute(
                command,
                cwd=controlled,
                timeout=self.timeout,
                limit=self.max_output_bytes,
                label=SCANNER_NAME,
            )
            finished = datetime.now(UTC)
        errors = list(execution.errors)
        scanner_version, facts = _version_facts(version)
        if scanner_version is not None and not scanner_version.startswith("2."):
            errors.append(
                f"unsupported {SCANNER_NAME} version {scanner_version}; "
                "this adapter targets v2"
            )
        advisory_source = self._advisory_source(before, errors)
        files = {
            "stdout.json": execution.stdout,
            "stderr.txt": execution.stderr,
            "version.txt": version.stdout + version.stderr,
        }
        for name, captured in files.items():
            with private_output(artifact / name) as handle:
                handle.write(captured)
        provenance = ScanProvenance(
            started_at=started,
            finished_at=finished,
            exit_code=execution.code,
            command=command,
            advisory_source=advisory_source,
            artifacts=[(artifact / name).as_uri() for name in files],
            facts=[*facts, *self._adapter_facts()],
        )
        run = partial(
            normalize,
            execution.stdout,
            target=target,
            artifact_reference=artifact.as_uri(),
            scanner=Scanner(name=SCANNER_NAME, version=scanner_version),
            execution_id=execution_id,
            inventory=manifests,
            asset_key=asset_key,
            provenance=provenance,
        )
        result = run(execution_errors=errors)
        if not errors and execution.code == 1 and not result.findings:
            result = run(
                execution_errors=["exit 1 without supported vulnerability findings"]
            )
        return result

    def _advisory_source(
        self, before: list[Fingerprint], errors: list[str]
    ) -> AdvisorySource:
        if self.offline_database is None:
            return AdvisorySource(
                kind=AdvisorySourceKind.ONLINE_SERVICE,
                detail="no local database was selected, so OSV-Scanner v2 queried "
                "the online OSV service; results are time-bound, not a snapshot",
            )
        try:
            after = _database_fingerprints(self.offline_database)
        except ValueError as exc:
            errors.append(f"offline advisory database became unsafe: {exc}")
            return AdvisorySource(
                kind=AdvisorySourceKind.LOCAL_DATABASE,
                detail="database archives became unsafe during the scan",
            )
        if before != after:
            errors.append("offline advisory database changed during the scan")
            return AdvisorySource(
                kind=AdvisorySourceKind.LOCAL_DATABASE,
                detail="database archives changed during the scan",
            )
        return AdvisorySource(
            kind=AdvisorySourceKind.LOCAL_DATABASE,
            reproducible=bool(after),
            fingerprints=after,
            detail="adapter-computed digests of the archives present before and "
            "after the scan; which archives the scanner loaded is not reported"
            if after
            else "no database archives were found",
        )

    def _adapter_facts(self) -> list[ProvenanceFact]:
        executable = shutil.which(self.executable)
        digest: str | None = None
        why = "executable not found on PATH"
        if executable is not None:
            try:
                digest = _sha256(Path(executable))
            except OSError as exc:
                why = f"executable could not be read: {exc.strerror}"
        inherited = sorted(name for name in os.environ if name.startswith("OSV_"))
        adapter = ProvenanceOrigin.ADAPTER
        return [
            ProvenanceFact(
                name="executable", origin=adapter, value=executable or self.executable
            ),
            ProvenanceFact(
                name="executable_sha256",
                origin=adapter,
                value=digest,
                detail=None if digest else why,
            ),
            ProvenanceFact(
                name="configuration",
                origin=adapter,
                value="adapter-owned override with no exclusions or package overrides",
            ),
            ProvenanceFact(
                name="configuration_sha256",
                origin=adapter,
                value=hashlib.sha256(CONFIGURATION).hexdigest(),
            ),
            ProvenanceFact(
                name="timeout_seconds", origin=adapter, value=str(self.timeout)
            ),
            ProvenanceFact(
                name="max_output_bytes",
                origin=adapter,
                value=str(self.max_output_bytes),
            ),
            ProvenanceFact(
                name="inherited_osv_environment",
                origin=adapter,
                value=", ".join(inherited) or "none",
                detail="names only; values are not recorded",
            ),
        ]
