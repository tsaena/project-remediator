"""Developer CLI: python -m remediator.cli TARGET --artifacts DIRECTORY."""

import argparse
import os
from contextlib import ExitStack
from pathlib import Path

from remediator.domain import ScanStatus
from remediator.output import private_output
from remediator.scanners.osv import OSVScanner


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--executable", default="osv-scanner")
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--max-output-bytes", type=int, default=10 * 1024 * 1024)
    args = parser.parse_args()
    try:
        scanner = OSVScanner(
            args.executable,
            timeout=args.timeout,
            max_output_bytes=args.max_output_bytes,
        )
        target = args.target.resolve(strict=True)
        with ExitStack() as stack:
            output = None
            if args.output:
                args.output = Path(os.path.abspath(args.output))
                resolved = args.output.resolve()
                if resolved == target or target in resolved.parents:
                    raise ValueError("output must be outside the scanned target")
                artifacts = args.artifacts.resolve()
                if resolved == artifacts or artifacts in resolved.parents:
                    raise ValueError("output must be outside the artifact directory")
                output = stack.enter_context(private_output(args.output))
            result = scanner.scan(target, artifact_directory=args.artifacts)
            rendered = result.model_dump_json(indent=2) + "\n"
            if output is not None:
                output.write(rendered.encode())
            else:
                print(rendered, end="")
    except (OSError, ValueError) as exc:
        parser.error(f"scan/output failed: {exc}")
    return 0 if result.status == ScanStatus.SUCCESS else 2


if __name__ == "__main__":
    raise SystemExit(main())
