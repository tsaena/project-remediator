"""Developer CLI: python -m remediator.cli TARGET --artifacts DIRECTORY."""

import argparse
from pathlib import Path

from remediator.domain import ScanStatus
from remediator.scanners.osv import OSVScanner


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--executable", default="osv-scanner")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = OSVScanner(args.executable, timeout=args.timeout).scan(
            args.target,
            artifact_directory=args.artifacts,
        )
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    rendered = result.model_dump_json(indent=2)
    if args.output:
        args.output.write_text(rendered + "\n")
    else:
        print(rendered)
    return 0 if result.status == ScanStatus.SUCCESS else 2


if __name__ == "__main__":
    raise SystemExit(main())
