#!/usr/bin/env python3
"""Generate the explicitly pinned Codex 0.160.0 synthetic wire contracts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from daimon_matrix import codex_body as body  # noqa: E402
from tools.generate_codex_0155_vectors import outputs  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = outputs(body.CURRENT_RELEASE)
    drift = [
        path
        for path, raw in expected.items()
        if not path.exists() or path.read_bytes() != raw
    ]
    if args.check:
        if drift:
            print(
                "Codex 0.160 artifact drift: "
                + ", ".join(str(path.relative_to(ROOT)) for path in drift),
                file=sys.stderr,
            )
        return int(bool(drift))
    for path in drift:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(expected[path])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
