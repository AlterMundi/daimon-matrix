"""Prepare or recover a Git checkout in an existing Gateway workspace."""

import argparse
import ctypes
import fcntl
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit
from uuid import UUID

if __package__:
    from .verify_project_git import verify_project_revision
else:
    from verify_project_git import verify_project_revision


@contextmanager
def locked_directory(directory: Path):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def publish_directory(staged: Path, destination: Path) -> None:
    """Publish a prepared directory without replacing a concurrent occupant."""
    libc = ctypes.CDLL(None, use_errno=True)
    source = os.fsencode(staged)
    target = os.fsencode(destination)
    if sys.platform == "linux" and hasattr(libc, "renameat2"):
        at_current_directory = -100
        rename_no_replace = 1
        rename = libc.renameat2
        rename.argtypes = (
            ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
        )
        result = rename(
            at_current_directory, source, at_current_directory, target, rename_no_replace
        )
    elif sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        rename_exclusive = 4
        rename = libc.renamex_np
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        result = rename(source, target, rename_exclusive)
    else:
        raise ValueError("Atomic project directory publication is unavailable.")
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def require_claim(workspace: Path, claim: str) -> None:
    marker = workspace / ".daimon-topic"
    if (marker.is_symlink() or not marker.is_file()
            or marker.stat().st_size != len(claim.encode()) or marker.read_text() != claim):
        raise ValueError("The workspace claim changed.")


def git(
    directory: Path, *args: str, absent_ok: bool = False, known_hosts: Path | None = None,
) -> str | None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_ALLOW_PROTOCOL="file",
    )
    if known_hosts is not None:
        host_file = str(known_hosts).replace("\\", "\\\\").replace('"', '\\"')
        env["GIT_ALLOW_PROTOCOL"] = "ssh"
        env["GIT_SSH_COMMAND"] = shlex.join([
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no", "-o", "KnownHostsCommand=none", "-o", "ConnectTimeout=8",
            "-o", f'UserKnownHostsFile="{host_file}"',
        ])
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


def bare_binding(remote: Path, repository: str) -> None:
    trust = ("-c", f"safe.directory={remote}")
    if (
        git(remote, *trust, "rev-parse", "--is-bare-repository") != "true"
        or git(remote, *trust, "config", "--local", "--get-all",
               "daimon.project-id", absent_ok=True) != repository
    ):
        raise ValueError("The selected shared repository has a different identity.")


def checkout_binding(checkout: Path, repository: str, remote: Path | str | None) -> None:
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


def validate_existing_origin(origin: str, known_hosts: Path | None) -> Path | None:
    if not origin or any(ord(char) < 32 or ord(char) == 127 for char in origin):
        raise ValueError("Select a valid Git origin.")
    if Path(origin).is_absolute() and known_hosts is None:
        return None
    url = urlsplit(origin)
    if (url.scheme != "ssh" or not url.hostname or not url.path.startswith("/")
            or url.password is not None or url.query or url.fragment or known_hosts is None):
        raise ValueError("Select an absolute Git origin or an SSH URL and pinned known-hosts file.")
    info = known_hosts.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
            or info.st_mode & 0o022 or not 0 < info.st_size <= 1024 * 1024):
        raise ValueError("Select a trusted known-hosts file.")
    return known_hosts.resolve(strict=True)


def prepare_project_git(
    workspace: Path, claim: str, checkout_name: str, repository: UUID, shared_root: Path | None = None,
    *, origin: str | None = None, commit: str | None = None, known_hosts: Path | None = None,
) -> dict:
    """Prepare the selected workspace without changing an existing checkout."""
    if not checkout_name or checkout_name.startswith(".") or Path(checkout_name).name != checkout_name:
        raise ValueError("Select one project directory directly within the workspace.")
    if repository.int == 0 or not claim or len(claim.encode()) > 512:
        raise ValueError("Select the current workspace claim and a repository UUID.")

    if origin is None:
        if commit is not None or known_hosts is not None:
            raise ValueError("Select the origin of the existing revision.")
    else:
        if shared_root is not None or commit is None or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
            raise ValueError("Select an existing origin and exact commit or a shared mount for a new project.")
        known_hosts = validate_existing_origin(origin, known_hosts)

    workspace = require_directory(workspace)
    checkout = workspace / checkout_name
    repository_id = str(repository)
    remote = origin
    with locked_directory(workspace):
        require_claim(workspace, claim)
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
                    with TemporaryDirectory(
                        prefix=".daimon-git-", dir=shared_root
                    ) as directory:
                        staged = Path(directory) / remote.name
                        staged.mkdir(mode=0o2770)
                        staged.chmod(0o2770)
                        git(staged, "init", "--bare", "--shared=group",
                            "--initial-branch=main", "--template=")
                        git(staged, "config", "--local", "daimon.project-id", repository_id)
                        bare_binding(staged, repository_id)
                        require_claim(workspace, claim)
                        publish_directory(staged, remote)
                bare_binding(remote, repository_id)
        if not exists:
            with TemporaryDirectory(prefix=".daimon-git-", dir=workspace) as directory:
                stage_root = Path(directory)
                staged = stage_root / checkout_name
                if remote is None:
                    staged.mkdir(mode=0o700)
                    git(staged, "init", "--initial-branch=main", "--template=")
                    git(staged, "config", "--local", "daimon.project-id", repository_id)
                elif origin is not None:
                    if known_hosts is None:
                        require_directory(Path(origin))
                    git(stage_root, "clone", "--no-local", "--no-checkout", "--template=",
                        "--", origin, checkout_name, known_hosts=known_hosts)
                    verify_project_revision(staged, commit, expected_origin=origin)
                    git(staged, "checkout", "--detach", commit)
                else:
                    git(stage_root, "-c", f"safe.directory={remote}",
                        "clone", "--no-local", "--template=",
                        "--", str(remote), checkout_name)
                checkout_binding(staged, repository_id, remote)
                require_claim(workspace, claim)
                publish_directory(staged, checkout)

        checkout_binding(checkout, repository_id, remote)
        revision = verify_project_revision(checkout, commit, expected_origin=origin) if origin is not None else {}
        return {
            **revision,
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
    parser.add_argument("--origin")
    parser.add_argument("--commit")
    parser.add_argument("--known-hosts", type=Path)
    args = parser.parse_args()
    try:
        result = prepare_project_git(
            args.workspace, args.claim, args.checkout, args.repository, args.shared_root,
            origin=args.origin, commit=args.commit, known_hosts=args.known_hosts,
        )
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
