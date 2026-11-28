"""Verify the Git reference used by a project link, without changing the checkout."""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from uuid import UUID


def verify_project_revision(
    directory: Path,
    commit: str,
    *,
    expected_origin: str | None = None,
    local_repository: UUID | None = None,
) -> dict[str, str | bool | None]:
    """Check an already authorized checkout and full commit object ID locally."""
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None:
        raise ValueError("Expected a full Git commit object ID.")
    if local_repository is not None and (
        not local_repository.int or expected_origin is not None
    ):
        raise ValueError("Select one local repository identity or a Git origin.")
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    env.update(
        GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0"
    )
    checkout = directory.resolve(strict=True)

    def git(*args: str, allow_missing: bool = False) -> str | None:
        result = subprocess.run(
            ["git", "-C", str(checkout), *args],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if allow_missing and result.returncode == 1:
            return None
        if result.returncode:
            raise ValueError("The selected Git checkout or commit is unavailable.")
        return result.stdout.rstrip("\n")

    def local_config(key: str) -> str | None:
        return git("config", "--local", "--get-all", key, allow_missing=True)

    root = git("rev-parse", "--show-toplevel")
    if root is None or Path(root).resolve() != checkout:
        raise ValueError("Select the exact project Git root.")
    if git("rev-parse", "--verify", f"{commit}^{{commit}}") != commit:
        raise ValueError("The reference does not identify the exact commit.")
    if expected_origin is not None and (
        not expected_origin
        or local_config("remote.origin.url") != expected_origin
    ):
        raise ValueError("The checkout has a different Git origin.")
    if local_repository is not None and (
        local_config("remote.origin.url") is not None
        or local_config("daimon.project-id") != str(local_repository)
    ):
        raise ValueError("The checkout has a different local repository identity.")
    head = git("rev-parse", "--verify", "--quiet", "HEAD^{commit}", allow_missing=True)
    return {
        "commit": commit,
        "object_format": git("rev-parse", "--show-object-format"),
        "checkout_head": head,
        "checkout_at_selected_commit": head == commit,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("commit")
    parser.add_argument("--local-repository", type=UUID)
    args = parser.parse_args()
    try:
        revision = verify_project_revision(
            args.directory, args.commit, local_repository=args.local_repository
        )
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(revision, sort_keys=True))


if __name__ == "__main__":
    main()
