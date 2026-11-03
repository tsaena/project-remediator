"""Bounded, read-only inventory of Python dependency manifests.

Supported patterns mirror the OSV-Scanner v2.3.0 (osv-scalibr v0.4.0) source
extractors, so a supported manifest that the scanner does not report is
observable. Nothing here executes, imports, or builds repository content.
"""

import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

from remediator.domain import (
    CoverageNote,
    CoverageReason,
    ManifestInventory,
    VersionPrecision,
)

LOCKFILES = frozenset({"Pipfile.lock", "pdm.lock", "poetry.lock", "uv.lock"})
SUPPORTED_PATTERNS = [
    "*requirements*.txt (case-sensitive, as OSV-Scanner matches)",
    *sorted(LOCKFILES),
]
UNSUPPORTED_PATTERNS = [
    "setup.py",
    "setup.cfg (with install_requires or extras_require)",
    "pyproject.toml (with dependency declarations)",
    "Pipfile",
    "pylock.toml and pylock.*.toml",
    "*requirements*.in",
    "case variants of *requirements*.txt",
    "*.txt inside a directory named requirements",
]
SKIPPED_DIRECTORIES = [".git"]
MAX_DEPTH = 32
MAX_ENTRIES = 100_000
MAX_INSPECTED_BYTES = 1024 * 1024
# Individually reported unclassified symlinks; the rest are summarized.
MAX_SYMLINK_NOTES = 100
# Read by content to decide whether they declare dependencies.
CONTENT_CHECKED = frozenset({"setup.cfg", "pyproject.toml"})

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_EXACT = re.compile(r"===?\s*([^\s;,*]+)\s*(?:;.*)?")
_OPTION = re.compile(r"\s+--?[A-Za-z]")
# What may follow a PEP 508 name: extras, a version specifier, markers, or "@".
_AFTER_NAME = re.compile(r"$|[\s\[;=<>!~@]")
_COMMENT = re.compile(r"(^|\s)#.*$")


def canonical_name(name: str) -> str:
    """PEP 503 normalization, used only to match declarations to packages."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class Requirements:
    """Direct declarations in one requirements file; includes are not followed."""

    precision: dict[str, VersionPrecision]
    has_entries: bool
    # Raw "-r"/"--requirement" lines, whose declarations are not inventoried.
    includes: list[str] = field(default_factory=list)
    # Lines that declare something not attributable to a named package, such
    # as editable installs, paths, and bare URLs; OSV-Scanner skips them.
    unrecognized: list[str] = field(default_factory=list)
    # Exact pins per canonical name; markers can pin one name to several.
    pins: dict[str, set[str]] = field(default_factory=dict)


def parse_requirements(text: str) -> Requirements:
    precision: dict[str, VersionPrecision] = {}
    includes: list[str] = []
    unrecognized: list[str] = []
    pins: dict[str, set[str]] = {}
    has_entries = False
    for line in text.replace("\\\n", " ").splitlines():
        line = _COMMENT.sub("", line).strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement")):
            has_entries = True
            includes.append(line)
            continue
        if line.startswith(("-e", "--editable")):
            has_entries = True
            unrecognized.append(line)
            continue
        if line.startswith("-"):
            # Other options (index URLs, hashes, constraints) declare nothing.
            continue
        line = _OPTION.split(line, maxsplit=1)[0]
        has_entries = True
        match = _NAME.match(line)
        rest = line[match.end() :] if match else line
        if match is None or not _AFTER_NAME.match(rest):
            unrecognized.append(line)
            continue
        rest = re.sub(r"^\s*\[[^\]]*\]", "", rest).strip()
        exact = _EXACT.fullmatch(rest)
        found = VersionPrecision.EXACT if exact else VersionPrecision.IMPRECISE
        name = canonical_name(match.group())
        if exact:
            pins.setdefault(name, set()).add(exact.group(1))
        if precision.get(name, found) != found:
            found = VersionPrecision.UNKNOWN
        precision[name] = found
    return Requirements(precision, has_entries, includes, unrecognized, pins)


def is_supported(name: str) -> bool:
    return name in LOCKFILES or (name.endswith(".txt") and "requirements" in name)


def _unsupported_name(name: str, parent: str) -> str | None:
    """Why a file is an unsupported manifest, judged by its name alone."""
    lower = name.lower()
    if name == "setup.py":
        return "setup.py is not extracted and cannot be inspected without executing"
    if name == "Pipfile":
        return "Pipfile declarations are not extracted; only Pipfile.lock is"
    if lower == "pylock.toml" or (
        lower.startswith("pylock.") and lower.endswith(".toml")
    ):
        return "PEP 751 lockfiles are not extracted by OSV-Scanner v2.3.0"
    if lower.endswith(".in") and "requirements" in lower:
        return "pip-tools input files are not extracted"
    if lower.endswith(".txt") and "requirements" in lower:
        return "OSV-Scanner matches *requirements*.txt case-sensitively"
    if lower.endswith(".txt") and Path(parent).name.lower() == "requirements":
        return "file name lacks 'requirements', so OSV-Scanner does not extract it"
    return None


def _unsupported(name: str, parent: str, read: "_Reader") -> str | None:
    """Return why a known Python manifest is not assessed, if it declares deps."""
    why = _unsupported_name(name, parent)
    if why is not None:
        return why
    if name == "setup.cfg":
        text = read()
        if text is None:
            return "setup.cfg could not be inspected"
        if "install_requires" in text or "extras_require" in text:
            return "setup.cfg dependency declarations are not extracted"
        return None
    if name == "pyproject.toml":
        text = read()
        if text is None:
            return "pyproject.toml could not be inspected"
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError):
            return "pyproject.toml could not be parsed"
        if _declares_dependencies(data):
            return "pyproject.toml dependency declarations are not extracted"
    return None


def _declares_dependencies(data: dict[str, object]) -> bool:
    """Err toward "declares": a missed table would hide unassessed dependencies.

    Standard fields are checked exactly. Under ``[tool]``, any non-empty key
    mentioning "depend" counts (Poetry, PDM, uv, Hatch, and tools not yet
    known), except a Poetry table that only constrains the Python version.
    """
    project = data.get("project")
    if isinstance(project, dict):
        if project.get("dependencies") or project.get("optional-dependencies"):
            return True
        dynamic = project.get("dynamic")
        if isinstance(dynamic, list) and {
            "dependencies",
            "optional-dependencies",
        } & {str(item) for item in dynamic}:
            return True
    if data.get("dependency-groups"):
        return True
    pending: list[object] = [data.get("tool")]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                python_only = isinstance(child, dict) and set(child) <= {"python"}
                if "depend" in str(key).lower() and child and not python_only:
                    return True
                pending.append(child)
        elif isinstance(value, list):
            pending.extend(value)
    return False


class _Reader:
    """Lazily read one regular file without following symlinks, bounded."""

    def __init__(self, directory_fd: int, name: str) -> None:
        self.directory_fd = directory_fd
        self.name = name

    def __call__(self) -> str | None:
        try:
            fd = os.open(
                self.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=self.directory_fd,
            )
        except OSError:
            return None
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None
            data = handle.read(MAX_INSPECTED_BYTES + 1)
        if len(data) > MAX_INSPECTED_BYTES:
            return None
        return data.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class DiscoveredManifest:
    path: str
    supported: bool
    notes: list[CoverageNote] = field(default_factory=list)
    requirements: Requirements | None = None
    has_entries: bool | None = None
    ignore_files: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Inventory:
    record: ManifestInventory
    manifests: dict[str, DiscoveredManifest]
    limitations: list[CoverageNote]


def inventory(
    root: Path, *, max_depth: int = MAX_DEPTH, max_entries: int = MAX_ENTRIES
) -> Inventory:
    """Walk ``root`` via directory descriptors; symlinks are never followed."""
    manifests: dict[str, DiscoveredManifest] = {}
    limitations: list[CoverageNote] = []
    examined = 0
    symlinks = 0
    truncated = False
    # Each entry: (descriptor path relative to root, depth, ignore files in scope).
    pending: list[tuple[str, int, list[str]]] = [("", 0, [])]
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        while pending and not truncated:
            relative, depth, ignores = pending.pop()
            try:
                fd = _open_directory(root_fd, relative)
            except OSError as exc:
                limitations.append(
                    CoverageNote(
                        reason=CoverageReason.UNREADABLE_PATH,
                        path=relative,
                        detail=f"directory could not be opened: {exc.strerror}",
                    )
                )
                continue
            try:
                # Never read more than the remaining budget (plus one, to
                # detect truncation) from a directory, however large it is.
                budget = max_entries - examined
                with os.scandir(fd) as scan:
                    entries = sorted(islice(scan, budget + 1), key=lambda e: e.name)
                names = {e.name for e in entries}
                if ".gitignore" in names:
                    ignores = [*ignores, _join(relative, ".gitignore")]
                subdirectories: list[str] = []
                for entry in entries:
                    if examined >= max_entries:
                        truncated = True
                        limitations.append(
                            CoverageNote(
                                reason=CoverageReason.INVENTORY_TRUNCATED,
                                path=relative or None,
                                detail=f"entry limit {max_entries} reached",
                            )
                        )
                        break
                    examined += 1
                    path = _join(relative, entry.name)
                    if entry.is_symlink():
                        symlinks += _symlink(
                            entry.name, relative, path, manifests, limitations, symlinks
                        )
                    elif entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIPPED_DIRECTORIES:
                            continue
                        if depth + 1 > max_depth:
                            truncated = True
                            limitations.append(
                                CoverageNote(
                                    reason=CoverageReason.INVENTORY_TRUNCATED,
                                    path=path,
                                    detail=f"depth limit {max_depth} reached",
                                )
                            )
                            continue
                        subdirectories.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        found = _file(entry.name, relative, path, fd, ignores)
                        if found is not None:
                            manifests[path] = found
                pending.extend(
                    (path, depth + 1, ignores) for path in reversed(subdirectories)
                )
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)
    if symlinks > MAX_SYMLINK_NOTES:
        limitations.append(
            CoverageNote(
                reason=CoverageReason.SYMLINK_NOT_FOLLOWED,
                detail=f"{symlinks - MAX_SYMLINK_NOTES} more symlinks were not "
                "followed and are not listed individually",
            )
        )
    record = ManifestInventory(
        ecosystems=["PyPI"],
        supported_patterns=SUPPORTED_PATTERNS,
        unsupported_patterns=UNSUPPORTED_PATTERNS,
        skipped_directories=SKIPPED_DIRECTORIES,
        max_depth=max_depth,
        max_entries=max_entries,
        entries_examined=examined,
        truncated=truncated,
    )
    return Inventory(record, manifests, limitations)


def _join(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _open_directory(root_fd: int, relative: str) -> int:
    """Open one component at a time so no path component can be a symlink."""
    fd = os.dup(root_fd)
    for part in relative.split("/") if relative else []:
        try:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
        finally:
            os.close(fd)
        fd = child
    return fd


def _symlink(
    name: str,
    parent: str,
    path: str,
    manifests: dict[str, DiscoveredManifest],
    limitations: list[CoverageNote],
    unclassified: int,
) -> int:
    """Classify a symlink by its own name; its target is never examined.

    Returns 1 for a symlink that is not a manifest name. Its target might be a
    directory of manifests, so it is always a limitation, never ignored.
    """
    note = CoverageNote(
        reason=CoverageReason.SYMLINK_NOT_FOLLOWED,
        path=path,
        detail="symlinks are not followed by the inventory or OSV-Scanner",
    )
    supported = is_supported(name)
    if supported or name in CONTENT_CHECKED or _unsupported_name(name, parent):
        manifests[path] = DiscoveredManifest(path, supported, [note])
        return 0
    if unclassified < MAX_SYMLINK_NOTES:
        limitations.append(
            CoverageNote(
                reason=CoverageReason.SYMLINK_NOT_FOLLOWED,
                path=path,
                detail="symlink not followed; its target may contain manifests",
            )
        )
    return 1


def _file(
    name: str, parent: str, path: str, directory_fd: int, ignores: list[str]
) -> DiscoveredManifest | None:
    read = _Reader(directory_fd, name)
    if is_supported(name):
        if name in LOCKFILES:
            # Lockfile contents are not parsed: only emptiness is known.
            text = read()
            has_entries = False if text is not None and not text.strip() else None
            return DiscoveredManifest(
                path, True, has_entries=has_entries, ignore_files=ignores
            )
        text = read()
        requirements = None if text is None else parse_requirements(text)
        return DiscoveredManifest(
            path,
            True,
            requirements=requirements,
            has_entries=None if requirements is None else requirements.has_entries,
            ignore_files=ignores,
        )
    why = _unsupported(name, parent, read)
    if why is None:
        return None
    note = CoverageNote(reason=CoverageReason.UNSUPPORTED_FORMAT, path=path, detail=why)
    return DiscoveredManifest(path, False, [note], ignore_files=ignores)
