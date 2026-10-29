import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

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


def fake_scanner(tmp_path: Path, body: str) -> str:
    import sys

    script = tmp_path / "fake scanner"
    script.write_text(f"#!{sys.executable}\n" + body)
    script.chmod(0o700)
    return str(script)


@pytest.mark.parametrize("code", [0, 1, 127, 128, 129, 130])
def test_execution(tmp_path: Path, code: int) -> None:
    target = tmp_path / "repo with spaces"
    target.mkdir()
    argv_file = tmp_path / "argv.json"
    executable = fake_scanner(
        tmp_path,
        f"""
import json, sys
from pathlib import Path
args = sys.argv[1:]
config = Path(args[args.index('--config') + 1])
assert config.is_absolute() and not config.is_relative_to(Path(args[-1]))
assert config.read_text() == '# Adapter-owned: no exclusions or package overrides.\\n'
assert sys.stdin.read() == ''
Path({str(argv_file)!r}).write_text(json.dumps(args))
sys.stdout.buffer.write({(FIXTURES / "single.json").read_bytes()!r})
sys.exit({code})
""",
    )
    with patch(
        "remediator.scanners.osv.subprocess.Popen", wraps=subprocess.Popen
    ) as start:
        result = OSVScanner(executable).scan(
            target, artifact_directory=tmp_path / "raw"
        )
    args = json.loads(argv_file.read_text())
    assert start.call_args.args[0] == [executable, *args]
    assert start.call_args.kwargs == {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "start_new_session": True,
        "cwd": str(Path(args[6]).parent),
    }
    assert args == [
        "scan",
        "source",
        "--format=json",
        "--no-resolve",
        "--recursive",
        "--config",
        args[6],
        str(target),
    ]
    assert not Path(args[6]).exists()
    assert result.status == ("success" if code in (0, 1) else "partial")


def test_missing_binary(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    result = OSVScanner(str(tmp_path / "missing")).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.status == "failed"
    assert "cannot execute" in result.errors[0]


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_timeout(timeout: float) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        OSVScanner(timeout=timeout)


@pytest.mark.parametrize("mode", ["timeout", "stdout", "stderr", "exited-parent"])
def test_cleanup_and_bounds(tmp_path: Path, mode: str) -> None:
    import time

    target = tmp_path / "repo"
    target.mkdir()
    child_pid = tmp_path / "child.pid"
    executable = fake_scanner(
        tmp_path,
        f"""
import os, subprocess, sys, time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
Path({str(child_pid)!r}).write_text(str(child.pid))
if {mode!r} == 'exited-parent':
    sys.exit(0)
if {mode!r} in ('stdout', 'stderr'):
    fd = 1 if {mode!r} == 'stdout' else 2
    while True:
        os.write(fd, b'x' * 65536)
time.sleep(60)
""",
    )
    started = time.monotonic()
    result = OSVScanner(executable, timeout=1, max_output_bytes=1000).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert time.monotonic() - started < 5
    assert result.status == "failed"
    expected = "output limit" if mode in ("stdout", "stderr") else "timed out"
    assert any(expected in error for error in result.errors)
    assert sum(p.stat().st_size for p in (tmp_path / "raw").glob("*/*")) <= 1000
    pid = int(child_pid.read_text())
    # A killed orphan can briefly remain as a zombie until the host reaps it.
    for _ in range(100):
        stat = Path(f"/proc/{pid}/stat")
        try:
            state = stat.read_text().split()[2]
        except FileNotFoundError:
            break
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        pytest.fail("scanner descendant is still running")


@pytest.mark.parametrize(("raw", "code"), [(b"{broken", 0), (b'{"results":[]}', 1)])
def test_invalid_execution(tmp_path: Path, raw: bytes, code: int) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    executable = fake_scanner(
        tmp_path,
        f"""
import sys
sys.stdout.buffer.write({raw!r})
sys.exit({code})
""",
    )
    result = OSVScanner(executable).scan(target, artifact_directory=tmp_path / "raw")
    assert result.status == "failed"


@pytest.mark.skipif(
    os.getenv("RUN_OSV_INTEGRATION") != "1", reason="opt-in real scanner"
)
def test_real_scanner(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    nested = target / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("Django==2.2.0\n")
    # Suppress all Django packages, both at root and alongside the manifest.
    suppression = (
        '[[PackageOverrides]]\nname = "django"\necosystem = "PyPI"\nignore = true\n'
    )
    for parent in (target, nested):
        (parent / "osv-scanner.toml").write_text(suppression)
    executable = os.getenv("OSV_SCANNER", "osv-scanner")
    version = subprocess.run([executable, "--version"], capture_output=True, check=True)
    assert b"2.3.0" in version.stdout
    result = OSVScanner(executable).scan(target, artifact_directory=tmp_path / "raw")
    assert result.status == "success", result.errors
    assert any(
        f.component.name.lower() == "django"
        and f.component.location == str(nested / "requirements.txt")
        for f in result.findings
    )


def test_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from remediator.cli import main

    result = parse("single.json")
    with patch("sys.argv", ["remediator", str(tmp_path), "--artifacts", "/tmp/raw"]):
        with patch("remediator.cli.OSVScanner.scan", return_value=result):
            assert main() == 0
    assert ScanResult.model_validate_json(capsys.readouterr().out) == result


@pytest.mark.parametrize(
    "unsafe", ["inside", "exists", "symlink", "parent-link", "artifact"]
)
def test_cli_rejects_unsafe_output(tmp_path: Path, unsafe: str) -> None:
    from remediator.cli import main

    target = tmp_path / "repo"
    target.mkdir()
    artifacts = tmp_path / "raw"
    existing = tmp_path / "existing"
    existing.write_text("preserve")
    output = tmp_path / "output"
    if unsafe == "inside":
        output = target / "output.json"
    elif unsafe == "exists":
        output = existing
    elif unsafe == "symlink":
        output.symlink_to(existing)
    elif unsafe == "parent-link":
        output.symlink_to(tmp_path, target_is_directory=True)
        output = output / "new.json"
    else:
        output = artifacts / "output.json"
    with (
        patch(
            "sys.argv",
            [
                "remediator",
                str(target),
                "--artifacts",
                str(artifacts),
                "--output",
                str(output),
            ],
        ),
        patch("remediator.cli.OSVScanner.scan") as scan,
    ):
        with pytest.raises(SystemExit) as error:
            main()
        assert error.value.code == 2
        scan.assert_not_called()
    assert existing.read_text() == "preserve"
    assert not (target / "output.json").exists()
    assert not (tmp_path / "new.json").exists()


def test_private_output_and_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from remediator.cli import main

    target = tmp_path / "repo"
    target.mkdir()
    output = tmp_path / "output.json"
    executable = fake_scanner(tmp_path, "print('{\"results\": []}')\n")
    argv = [
        "remediator",
        str(target),
        "--artifacts",
        str(tmp_path / "raw"),
        "--executable",
        executable,
        "--output",
        str(output),
        "--max-output-bytes",
        "1024",
    ]
    with patch("sys.argv", argv):
        assert main() == 0
    assert output.stat().st_mode & 0o777 == 0o600
    assert ScanResult.model_validate_json(output.read_text()).status == "success"
    for artifact in (tmp_path / "raw").glob("*/*"):
        assert artifact.stat().st_mode & 0o777 == 0o600
    with patch("sys.argv", argv):
        with pytest.raises(SystemExit):
            main()
    assert "scan/output failed" in capsys.readouterr().err


def test_artifact_safety(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    with pytest.raises(ValueError, match="outside"):
        OSVScanner().scan(target, artifact_directory=target / "new")
    assert not (target / "new").exists()
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(OSError):
        OSVScanner().scan(target, artifact_directory=link / "raw")


def test_recursive_and_config_contract_offline(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    nested = target / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("Django==2.2.0\n")
    for parent in (target, nested):
        (parent / "osv-scanner.toml").write_text(
            '[[IgnoredVulns]]\nid="GHSA-example"\n'
        )
    executable = fake_scanner(
        tmp_path,
        f"""
import json, sys, tomllib
from pathlib import Path
args = sys.argv[1:]
assert '--recursive' in args
config = tomllib.loads(Path(args[args.index('--config') + 1]).read_text())
assert not config.get('IgnoredVulns') and not config.get('PackageOverrides')
manifest = Path(args[-1]) / 'services/api/requirements.txt'
assert manifest.read_text() == 'Django==2.2.0\\n'
document = json.loads({(FIXTURES / "single.json").read_bytes()!r})
document['results'][0]['source']['path'] = str(manifest)
print(json.dumps(document))
sys.exit(1)
""",
    )
    result = OSVScanner(executable).scan(target, artifact_directory=tmp_path / "raw")
    assert result.status == "success"
    assert result.findings[0].vulnerability.primary_id == "GHSA-example"
    assert result.findings[0].component.location == str(nested / "requirements.txt")


@pytest.mark.skipif(
    os.getenv("RUN_OSV_INTEGRATION") != "1", reason="opt-in real scanner"
)
@pytest.mark.parametrize(
    "suppression",
    [
        '[[IgnoredVulns]]\nid="GHSA-6c3j-c64m-qhgq"\n',
        '[[PackageOverrides]]\nname="django"\necosystem="PyPI"\nignore=true\n',
    ],
)
def test_real_scanner_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suppression: str
) -> None:
    """Exercise v2.3.0 matching and config filtering with one cached advisory."""
    import shutil
    import zipfile

    executable = shutil.which(os.getenv("OSV_SCANNER", "osv-scanner"))
    assert executable is not None, "install OSV-Scanner v2.3.0"
    version = subprocess.run([executable, "--version"], capture_output=True, check=True)
    assert b"2.3.0" in version.stdout
    cache = tmp_path / "cache"
    db = cache / "osv-scanner" / "PyPI"
    db.mkdir(parents=True)
    with zipfile.ZipFile(db / "all.zip", "w") as archive:
        archive.write(FIXTURES / "django-advisory.json", "GHSA-6c3j-c64m-qhgq.json")
    monkeypatch.setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", str(cache))
    target = tmp_path / "repo"
    nested = target / "services" / "api"
    nested.mkdir(parents=True)
    (nested / "requirements.txt").write_text("Django==2.1.0\n")
    for parent in (target, nested):
        (parent / "osv-scanner.toml").write_text(suppression)
    control = subprocess.run(
        [
            executable,
            "scan",
            "source",
            "--format=json",
            "--no-resolve",
            "--recursive",
            "--offline",
            str(target),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert control.returncode == 0, control.stderr
    assert not normalize(
        control.stdout, target=target, artifact_reference="test:control"
    ).findings
    # A trusted test wrapper selects OSV's built-in offline matcher. Production
    # invocation and configuration remain unchanged; no service is mocked.
    wrapper = fake_scanner(
        tmp_path,
        f"""
import os, sys
os.execv({executable!r}, [{executable!r}, *sys.argv[1:], '--offline'])
""",
    )
    result = OSVScanner(wrapper).scan(target, artifact_directory=tmp_path / "raw")
    assert result.status == "success", result.errors
    assert any(
        f.vulnerability.primary_id == "GHSA-6c3j-c64m-qhgq"
        and f.component.location == str(nested / "requirements.txt")
        for f in result.findings
    )


@pytest.mark.parametrize("extra", [0, 1])
def test_output_at_limit(tmp_path: Path, extra: int) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    raw = b'{"results":[]}'
    executable = fake_scanner(
        tmp_path,
        f"""
import os
os.write(1, {raw!r} + b' ' * {extra})
""",
    )
    result = OSVScanner(executable, max_output_bytes=len(raw)).scan(
        target, artifact_directory=tmp_path / "raw"
    )
    assert result.status == ("success" if extra == 0 else "failed")
    assert bool(result.errors) == bool(extra)


def test_cli_write_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from remediator.cli import main

    target = tmp_path / "repo"
    target.mkdir()
    with (
        patch(
            "sys.argv",
            [
                "remediator",
                str(target),
                "--artifacts",
                str(tmp_path / "raw"),
                "--output",
                str(tmp_path / "output.json"),
            ],
        ),
        patch("remediator.cli.OSVScanner.scan", return_value=parse("clean.json")),
        patch("remediator.cli.private_output") as destination,
    ):
        destination.return_value.__enter__.return_value.write.side_effect = OSError(
            "disk full"
        )
        with pytest.raises(SystemExit) as error:
            main()
        assert error.value.code == 2
    assert "scan/output failed: disk full" in capsys.readouterr().err
