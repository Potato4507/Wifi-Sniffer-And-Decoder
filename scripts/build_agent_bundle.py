from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from wifi_pipeline.remote import build_capture_agent_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the self-contained remote capture-agent bundle.")
    parser.add_argument("--output-dir", default=str(PROJECT_ROOT / "dist"))
    parser.add_argument("--remote-root", default="/opt/wifi-pipeline")
    parser.add_argument("--capture-dir", default="")
    args = parser.parse_args()

    bundle_path = build_capture_agent_bundle(
        output_dir=Path(args.output_dir),
        remote_root=args.remote_root,
        capture_dir=args.capture_dir or None,
    )
    print(f"Built capture-agent bundle: {bundle_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
