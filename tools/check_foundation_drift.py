"""Report drift between the pinned foundation snapshot and its canonical original.

Advisory only. It edits nothing, commits nothing and never blocks a merge: a
reachable canonical document that differs produces a warning with both hashes, and
an unreachable document produces an explicit skip. Only an internal inconsistency
between the snapshot and its own provenance record is a failure, because that
means the pin itself is wrong.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Final

PROVENANCE: Final = Path("docs/foundation/PROVENANCE.json")
TIMEOUT_SECONDS: Final = 30.0


def strip_front_matter(raw: bytes) -> bytes:
    """Drop one leading HackMD YAML front-matter block, exactly as pinned."""
    if not raw.startswith(b"---\n"):
        return raw
    parts = raw.split(b"---\n", 2)
    if len(parts) != 3:
        return raw
    return parts[2].lstrip(b"\n")


def fail(message: str, *details: str) -> int:
    print(f"::error::{message}")
    for line in details:
        print(f"  {line}")
    return 1


def main() -> int:
    if not PROVENANCE.is_file():
        return fail("missing foundation provenance record", str(PROVENANCE))
    try:
        provenance = json.loads(PROVENANCE.read_text())
    except json.JSONDecodeError as exc:
        return fail("unreadable foundation provenance record", str(exc))
    snapshot_path = Path(str(provenance.get("snapshot", "")))
    expected = str(provenance.get("body_sha256", ""))
    if not snapshot_path.is_file() or len(expected) != 64:
        return fail("incomplete foundation provenance record")
    pinned = hashlib.sha256(strip_front_matter(snapshot_path.read_bytes())).hexdigest()
    if pinned != expected:
        return fail(
            "pinned snapshot does not match its own provenance record",
            f"snapshot body sha256: {pinned}",
            f"provenance body sha256: {expected}",
        )
    url = str(provenance.get("canonical_download", ""))
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            live = response.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"skipped: canonical document unreachable ({type(exc).__name__})")
        print(f"  pinned body sha256: {pinned}")
        return 0
    remote = hashlib.sha256(live).hexdigest()
    print(f"pinned body sha256: {pinned}")
    print(f"live body sha256:   {remote}")
    if remote != pinned:
        print("::warning::canonical foundation document drifted from the snapshot")
        print(
            "  reconcile explicitly: update the snapshot and its provenance "
            "record in one commit"
        )
        return 0
    print("match: pinned snapshot equals the canonical document")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
