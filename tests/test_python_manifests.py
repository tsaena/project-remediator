"""Independent Python manifest inventory: patterns, bounds, and symlinks."""

import os
from pathlib import Path

import pytest

from remediator.domain import CoverageReason, VersionPrecision
from remediator.scanners.python_manifests import (
    MAX_INSPECTED_BYTES,
    inventory,
    is_supported,
    parse_requirements,
)

EXACT = VersionPrecision.EXACT
IMPRECISE = VersionPrecision.IMPRECISE


def write(root: Path, relative: str, text: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


@pytest.mark.parametrize(
    ("name", "supported"),
    [
        ("requirements.txt", True),
        ("dev-requirements.txt", True),
        ("requirements-test.txt", True),
        ("Pipfile.lock", True),
        ("pdm.lock", True),
        ("poetry.lock", True),
        ("uv.lock", True),
        # OSV-Scanner v2.3.0 matches these names case-sensitively.
        ("Requirements.txt", False),
        ("requirements.TXT", False),
        ("requirements.in", False),
        ("base.txt", False),
        ("Pipfile", False),
        ("package-lock.json", False),
    ],
)
def test_supported_patterns(name: str, supported: bool) -> None:
    assert is_supported(name) is supported


@pytest.mark.parametrize(
    ("line", "precision"),
    [
        ("Django==2.2.0", EXACT),
        ("Django == 2.2.0", EXACT),
        ("flask===0.12", EXACT),
        ("Django[bcrypt]==2.2.0 ; python_version >= '3'", EXACT),
        ("six==1.16.0 --hash=sha256:abc", EXACT),
        ("requests>=2.0", IMPRECISE),
        ("requests~=2.0", IMPRECISE),
        ("requests<=2.0", IMPRECISE),
        ("urllib3==1.24.*", IMPRECISE),
        ("idna>=2,<3", IMPRECISE),
        ("idna==2.0,!=2.1", IMPRECISE),
        ("Django", IMPRECISE),
        ("pkg @ https://example.invalid/pkg.whl", IMPRECISE),
    ],
)
def test_requirement_precision(line: str, precision: VersionPrecision) -> None:
    parsed = parse_requirements(line + "\n")
    assert parsed.has_entries
    assert list(parsed.precision.values()) == [precision]


def test_requirement_file_grammar() -> None:
    parsed = parse_requirements(
        "# comment\n"
        "--index-url https://example.invalid/simple\n"
        "-e git+https://example.invalid/x.git#egg=x\n"
        "Django==\\\n2.2.0  # trailing comment\n"
        "Zope.Interface==5.0\n"
        "zope-interface>=5\n"
    )
    assert parsed.precision["django"] == EXACT
    # Conflicting declarations of one canonical name are not trusted as exact.
    assert parsed.precision["zope-interface"] == VersionPrecision.UNKNOWN
    assert set(parsed.precision) == {"django", "zope-interface"}


@pytest.mark.parametrize(
    ("text", "has_entries"),
    [
        ("", False),
        ("# only comments\n\n", False),
        ("--index-url https://example.invalid\n", False),
        ("-r base.txt\n", True),
        ("six==1.16.0\n", True),
    ],
)
def test_empty_manifest_detection(text: str, has_entries: bool) -> None:
    assert parse_requirements(text).has_entries is has_entries


def test_inventory_discovers_nested_hidden_and_unsupported(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    write(tmp_path, "services/api/dev-requirements.txt", "Django==2.2.0\n")
    write(tmp_path, ".hidden/requirements.txt", "six==1.16.0\n")
    write(tmp_path, "app/poetry.lock", "[[package]]\n")
    write(tmp_path, "requirements/base.txt", "Django==2.2.0\n")
    write(tmp_path, "Requirements.TXT", "Django==2.2.0\n")
    write(tmp_path, "setup.py", "raise SystemExit('never executed')\n")
    write(tmp_path, "pyproject.toml", '[project]\ndependencies = ["Django"]\n')
    write(tmp_path, "tools/pyproject.toml", "[tool.ruff]\nline-length = 88\n")
    write(tmp_path, "tools/setup.cfg", "[flake8]\nmax-line-length = 88\n")
    write(tmp_path, ".git/requirements.txt", "Django==2.2.0\n")
    write(tmp_path, "README.txt", "not a manifest\n")
    result = inventory(tmp_path)
    supported = {p for p, m in result.manifests.items() if m.supported}
    unsupported = {p for p, m in result.manifests.items() if not m.supported}
    assert supported == {
        "requirements.txt",
        "services/api/dev-requirements.txt",
        ".hidden/requirements.txt",
        "app/poetry.lock",
    }
    assert unsupported == {
        "requirements/base.txt",
        "Requirements.TXT",
        "setup.py",
        "pyproject.toml",
    }
    for path in unsupported:
        [note] = result.manifests[path].notes
        assert note.reason == CoverageReason.UNSUPPORTED_FORMAT
        assert note.detail
    assert not result.record.truncated
    assert result.record.skipped_directories == [".git"]
    assert not result.limitations


def test_inventory_never_follows_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    write(outside, "requirements.txt", "Django==2.2.0\n")
    write(outside, "nested/requirements.txt", "Django==2.2.0\n")
    root.mkdir()
    (root / "requirements.txt").symlink_to(outside / "requirements.txt")
    (root / "linked").symlink_to(outside / "nested", target_is_directory=True)
    (root / "dangling.txt").symlink_to(tmp_path / "missing")
    result = inventory(root)
    manifest = result.manifests["requirements.txt"]
    assert [n.reason for n in manifest.notes] == [CoverageReason.SYMLINK_NOT_FOLLOWED]
    # The link target is never read, so nothing about it is claimed.
    assert manifest.requirements is None and manifest.has_entries is None
    assert "linked/requirements.txt" not in result.manifests
    assert [(n.reason, n.path) for n in result.limitations] == [
        (CoverageReason.SYMLINK_NOT_FOLLOWED, "linked")
    ]


def test_inventory_bounds(tmp_path: Path) -> None:
    write(tmp_path, "a/b/c/requirements.txt", "six==1.16.0\n")
    shallow = inventory(tmp_path, max_depth=2)
    assert shallow.record.truncated
    assert "a/b/c/requirements.txt" not in shallow.manifests
    assert shallow.limitations[0].reason == CoverageReason.INVENTORY_TRUNCATED
    for index in range(5):
        write(tmp_path, f"file{index}.txt")
    few = inventory(tmp_path, max_entries=3)
    assert few.record.truncated and few.record.entries_examined == 3
    assert few.limitations[-1].reason == CoverageReason.INVENTORY_TRUNCATED
    full = inventory(tmp_path)
    assert not full.record.truncated
    assert "a/b/c/requirements.txt" in full.manifests


def test_inventory_does_not_block_or_overread(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / "requirements.txt")
    write(tmp_path, "big/requirements.txt", "#" * (MAX_INSPECTED_BYTES + 1))
    result = inventory(tmp_path)
    assert "requirements.txt" not in result.manifests
    big = result.manifests["big/requirements.txt"]
    assert big.supported and big.requirements is None and big.has_entries is None


def test_ignore_files_are_scoped(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    write(tmp_path, "vendor/.gitignore", "*\n")
    write(tmp_path, "vendor/lib/requirements.txt", "Django==2.2.0\n")
    result = inventory(tmp_path)
    assert result.manifests["requirements.txt"].ignore_files == []
    assert result.manifests["vendor/lib/requirements.txt"].ignore_files == [
        "vendor/.gitignore"
    ]


def test_inventory_is_read_only(tmp_path: Path) -> None:
    write(tmp_path, "requirements.txt", "six==1.16.0\n")
    write(tmp_path, "setup.py", "open('pwned', 'w')\n")
    before = sorted((p, p.stat().st_mtime_ns) for p in tmp_path.rglob("*"))
    inventory(tmp_path)
    assert sorted((p, p.stat().st_mtime_ns) for p in tmp_path.rglob("*")) == before
    assert not (tmp_path / "pwned").exists()
