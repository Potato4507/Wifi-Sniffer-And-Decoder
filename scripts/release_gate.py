from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wifi_pipeline.release_gate import (
    DEFAULT_GATE_SUMMARY,
    DEFAULT_PI_REPORT,
    DEFAULT_UBUNTU_REPORT,
    DEFAULT_WINDOWS_REPORT,
    evaluate_release_gate,
    print_release_gate,
    write_release_gate_summary,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate the real validation matrix and sample analysis reports before calling a release fully validated."
    )
    parser.add_argument("--ubuntu-report", default=str(DEFAULT_UBUNTU_REPORT), help="Ubuntu standalone validation report path")
    parser.add_argument("--pi-report", default=str(DEFAULT_PI_REPORT), help="Raspberry Pi OS standalone validation report path")
    parser.add_argument("--windows-report", default=str(DEFAULT_WINDOWS_REPORT), help="Windows remote validation report path")
    parser.add_argument("--sample-report", action="append", default=None, help="Analysis report from a supported decode/replay sample set (repeatable)")
    parser.add_argument("--write-summary", default=str(DEFAULT_GATE_SUMMARY), help="Summary JSON output path")
    return parser


def _relative_or_full(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")
    except ValueError:
        return str(path)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result = evaluate_release_gate(
        ubuntu_report=Path(args.ubuntu_report).resolve(),
        pi_report=Path(args.pi_report).resolve(),
        windows_report=Path(args.windows_report).resolve(),
        sample_reports=[Path(path).resolve() for path in (args.sample_report or [])],
    )
    print_release_gate(result)
    if args.write_summary:
        summary_path = write_release_gate_summary(result, Path(args.write_summary).resolve())
        print(f"Summary written to {summary_path}")
    if not result.get("fully_validated"):
        print("Expected validation artifacts:")
        required = dict(result.get("required_reports") or {})
        for key in ("ubuntu_report", "pi_report", "windows_report"):
            if key in required:
                print(f"  - {_relative_or_full(Path(str(required[key])))}")
        for sample in list(required.get("sample_reports") or []):
            print(f"  - {_relative_or_full(Path(str(sample)))}")
    return 0 if result.get("fully_validated") else 1


if __name__ == "__main__":
    raise SystemExit(main())
