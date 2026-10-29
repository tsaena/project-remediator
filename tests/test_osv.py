import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from remediator.domain import ScanResult, ScanStatus
from remediator.scanners.osv import OSVScanner, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def parse(name: str) -> ScanResult:
    return normalize(
        (FIXTURES / name).read_bytes(),
        target=Path("/repo"),
        artifact_reference="file:///artifacts/raw.json",
    )


def test_mapping() -> None:
    result = parse("single.json")
    assert result.status == ScanStatus.SUCCESS
    finding = result.findings[0]
    assert finding.component.name == "Django"
    assert finding.component.ecosystem == "PyPI"
    assert finding.component.installed_version == "2.2.0"
    assert finding.component.location == "/repo/requirements.txt"
    assert finding.vulnerability.primary_id == "GHSA-example"
    assert finding.vulnerability.aliases == ["CVE-2099-0001"]
    assert finding.vulnerability.references == ["https://example.org/advisory"]
    assert finding.evidence.scanner == result.scanner
    assert finding.evidence.observed_at.utcoffset() is not None
    assert finding.evidence.artifact_reference == "file:///artifacts/raw.json"
    assert finding.fix.status == "unknown"
    assert finding.fix.fixed_versions == []
    assert ScanResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    ("name", "status", "count"),
    [
        ("clean.json", "success", 0),
        ("multiple.json", "success", 3),
        ("minimal.json", "success", 1),
        ("partial.json", "partial", 1),
        ("failed.json", "failed", 0),
        ("malformed.json", "failed", 0),
    ],
)
def test_fixtures(name: str, status: str, count: int) -> None:
    result = parse(name)
    assert result.status == status
    assert len(result.findings) == count
    assert bool(result.errors) == (status != "success")


def test_duplicates() -> None:
    data = json.loads((FIXTURES / "single.json").read_bytes())
    data["results"] *= 2
    result = normalize(
        json.dumps(data).encode(),
        target=Path("/repo"),
        artifact_reference="artifact:raw",
    )
    assert len(result.findings) == 1


@pytest.mark.parametrize("code", [0, 1, 127, 128, 129, 130, -9])
def test_execution(tmp_path: Path, code: int) -> None:
    target = tmp_path / "repo with spaces"
    target.mkdir()
    process = MagicMock()
    process.__enter__.return_value = process
    process.poll.return_value = code
    process.wait.return_value = code

    def start(*args: object, **kwargs: object) -> MagicMock:
        output = kwargs["stdout"]
        assert hasattr(output, "write")
        output.write((FIXTURES / "single.json").read_bytes())
        return process

    with patch("remediator.scanners.osv.subprocess.Popen", side_effect=start) as mock:
        result = OSVScanner().scan(target, artifact_directory=tmp_path / "artifacts")
    assert result.status == ("success" if code in (0, 1) else "partial")
    assert mock.call_args.args[0][-1] == str(target)
    assert mock.call_args.kwargs["shell"] is False
    assert list((tmp_path / "artifacts").glob("*/stdout.json"))


def test_missing_binary(tmp_path: Path) -> None:
    with patch(
        "remediator.scanners.osv.subprocess.Popen", side_effect=FileNotFoundError
    ):
        result = OSVScanner().scan(
            tmp_path,
            artifact_directory=tmp_path.parent / tmp_path.name.join(["art-", ""]),
        )
    assert result.status == "failed"
    assert "cannot execute" in result.errors[0]


def test_timeout_and_limit(tmp_path: Path) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.poll.return_value = None
    process.wait.return_value = -9
    with patch("remediator.scanners.osv.subprocess.Popen", return_value=process):
        result = OSVScanner(timeout=0.001).scan(
            tmp_path,
            artifact_directory=tmp_path.parent / (tmp_path.name + "-artifacts"),
        )
    process.kill.assert_called_once()
    assert result.status == "failed"
    assert "timed out" in result.errors[0]


@pytest.mark.skipif(
    os.getenv("RUN_OSV_INTEGRATION") != "1", reason="opt-in real scanner"
)
def test_real_scanner(tmp_path: Path) -> None:
    target = Path(__file__).parent / "fixtures" / "vulnerable-python"
    result = OSVScanner(os.getenv("OSV_SCANNER", "osv-scanner")).scan(
        target,
        artifact_directory=tmp_path,
    )
    assert result.status == "success", result.errors
    assert any(f.component.name.lower() == "django" for f in result.findings)
    subprocess.run([os.getenv("OSV_SCANNER", "osv-scanner"), "--version"], check=True)


@pytest.mark.parametrize(("raw", "code"), [(b"{broken", 0), (b'{"results":[]}', 1)])
def test_invalid_execution(tmp_path: Path, raw: bytes, code: int) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.poll.return_value = code
    process.wait.return_value = code

    def start(*args: object, **kwargs: object) -> MagicMock:
        output = kwargs["stdout"]
        assert hasattr(output, "write")
        output.write(raw)
        return process

    with patch("remediator.scanners.osv.subprocess.Popen", side_effect=start):
        result = OSVScanner().scan(
            tmp_path,
            artifact_directory=tmp_path.parent / (tmp_path.name + "-raw"),
        )
    assert result.status == "failed"


def test_output_bound(tmp_path: Path) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.poll.return_value = None
    process.wait.return_value = -9

    def start(*args: object, **kwargs: object) -> MagicMock:
        output = kwargs["stdout"]
        assert hasattr(output, "write")
        output.write(b"x" * 100)
        assert hasattr(output, "flush")
        output.flush()
        return process

    artifacts = tmp_path.parent / (tmp_path.name + "-bounded")
    with patch("remediator.scanners.osv.subprocess.Popen", side_effect=start):
        result = OSVScanner(max_output_bytes=10).scan(
            tmp_path,
            artifact_directory=artifacts,
        )
    assert result.status == "failed"
    process.kill.assert_called_once()
    assert sum(p.stat().st_size for p in artifacts.glob("*/*")) <= 10


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from remediator.cli import main

    result = parse("single.json")
    with patch("sys.argv", ["remediator", str(tmp_path), "--artifacts", "/tmp/raw"]):
        with patch("remediator.cli.OSVScanner.scan", return_value=result):
            assert main() == 0
    assert ScanResult.model_validate_json(capsys.readouterr().out) == result
