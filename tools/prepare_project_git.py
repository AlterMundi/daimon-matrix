"""Prepare a project checkout and optional shared bare Git repository on an existing mount."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
from uuid import UUID


@contextmanager
def locked_directory(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def git(directory: Path, *args: str, absent_ok: bool = False) -> str | None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_ALLOW_PROTOCOL="file",
    )
    result = subprocess.run(
        ["git", "-C", str(directory), *args],
        env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False,
    )
    if absent_ok and result.returncode == 1:
        return None
    if result.returncode:
        raise ValueError(f"Git {args[0]} failed for the selected project directory.")
    return result.stdout.removesuffix("\n")


def require_directory(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Select an existing real directory.")
    return path.resolve(strict=True)


def checkout_binding(checkout: Path, repository: str, remote: Path | None) -> None:
    root = git(checkout, "rev-parse", "--show-toplevel")
    if root != str(checkout):
        raise ValueError("Select the exact project Git root.")
    origin = git(checkout, "config", "--local", "--get-all", "remote.origin.url", absent_ok=True)
    if remote is not None:
        if origin != str(remote):
            raise ValueError("The selected checkout has a different Git origin.")
    elif origin is not None or git(checkout, "config", "--local", "--get-all", "daimon.project-id",
                                   absent_ok=True) != repository:
        raise ValueError("The selected checkout has a different local repository identity.")


def prepare_project_git(
    workspace: Path, claim: str, checkout_name: str, repository: UUID, shared_root: Path | None = None,
) -> dict:
    """Use only a selected workspace and, optionally, its operator-approved existing shared mount."""
    if not checkout_name or checkout_name.startswith(".") or Path(checkout_name).name != checkout_name:
        raise ValueError("Select one project directory directly within the workspace.")
    if repository.int == 0 or not claim or len(claim.encode()) > 512:
        raise ValueError("Select the current workspace claim and a repository UUID.")

    workspace = require_directory(workspace)
    checkout = workspace / checkout_name
    repository_id = str(repository)
    remote = None
    with locked_directory(workspace):
        marker = workspace / ".daimon-topic"
        if (marker.is_symlink() or not marker.is_file()
                or marker.stat().st_size != len(claim.encode()) or marker.read_text() != claim):
            raise ValueError("The workspace claim changed.")
        exists = checkout.exists() or checkout.is_symlink()
        if exists:
            require_directory(checkout)
        if shared_root is not None:
            shared_root = require_directory(shared_root)
            if shared_root.is_relative_to(workspace):
                raise ValueError("Select a shared repository directory outside the workspace.")
            mode = shared_root.stat().st_mode
            if not mode & stat.S_ISGID or not mode & stat.S_IWGRP or mode & stat.S_IWOTH:
                raise ValueError("Select the existing private group-writable Git mount.")
            remote = shared_root / f"{repository_id}.git"
            if exists:
                checkout_binding(checkout, repository_id, remote)
            with locked_directory(shared_root):
                if remote.exists() or remote.is_symlink():
                    require_directory(remote)
                else:
                    remote.mkdir(mode=0o2770)
                    remote.chmod(0o2770)
                    git(remote, "init", "--bare", "--shared=group", "--initial-branch=main", "--template=")
                    git(remote, "config", "--local", "daimon.project-id", repository_id)
                trust = ("-c", f"safe.directory={remote}")
                if (git(remote, *trust, "rev-parse", "--is-bare-repository") != "true"
                        or git(remote, *trust, "config", "--local", "--get-all", "daimon.project-id",
                               absent_ok=True) != repository_id):
                    raise ValueError("The selected shared repository has a different identity.")
            if not exists:
                git(workspace, *trust, "clone", "--no-local", "--template=",
                    "--", str(remote), checkout_name)
        elif not exists:
            checkout.mkdir(mode=0o700)
            git(checkout, "init", "--initial-branch=main", "--template=")
            git(checkout, "config", "--local", "daimon.project-id", repository_id)

        checkout_binding(checkout, repository_id, remote)
        return {
            "checkout": checkout_name,
            "repository": repository_id,
            "locator": f"git:{remote}" if remote else f"git:local:{repository_id}",
            "created_checkout": not exists,
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("claim")
    parser.add_argument("checkout")
    parser.add_argument("repository", type=UUID)
    parser.add_argument("--shared-root", type=Path)
    args = parser.parse_args()
    try:
        result = prepare_project_git(args.workspace, args.claim, args.checkout, args.repository, args.shared_root)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
