"""Human-held signing ceremony for DM-033 review authority.

This process never connects to the hosted daemon.  It can create exactly one
reviewer key, accept an exact delegation, sign an exact decision draft, or
issue a short-lived disclosure proof.  Every signing operation requires a
real terminal confirmation and owner-only canonical input files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, Final

from .canonical import CanonicalError, canonical_bytes
from .human_review import (
    HumanReviewError,
    accept_authorization,
    create_access_proof,
    sign_review_decision,
    validate_authorization_core,
    validate_human_decision,
    validate_review_request,
    validate_reviewer_authorization,
)
from .identity import generate_ed25519_seed, signing_descriptor
from .keystore import EncryptedKeystore, KeystoreError

MAX_DOCUMENT_BYTES: Final = 512 * 1024
SIGNING_SLOT: Final = "reviewer-signing"
FORBIDDEN_SECRET_ENV: Final = frozenset(
    {"DAIMON_REVIEWER_PASSWORD", "DM_REVIEWER_PASSWORD"}
)


class ReviewerCliError(RuntimeError):
    """Stable ceremony refusal without path or secret disclosure."""


def _password_reader(descriptor: int) -> bytearray:
    if descriptor < 3:
        raise ReviewerCliError("reviewer_password_fd_refused")
    try:
        value = bytearray(os.read(descriptor, 4097))
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if not 12 <= len(value) <= 4096:
        value[:] = b"\x00" * len(value)
        raise ReviewerCliError("reviewer_password_refused")
    return value


def _owner_document(path: Path) -> Mapping[str, Any]:
    absolute = Path(os.path.abspath(path))
    try:
        before = absolute.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or not 1 <= before.st_size <= MAX_DOCUMENT_BYTES
        ):
            raise ReviewerCliError("reviewer_input_refused")
        descriptor = os.open(absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exception:
        raise ReviewerCliError("reviewer_input_unavailable") from exception
    try:
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise ReviewerCliError("reviewer_input_changed")
        raw = bytearray()
        while len(raw) < after.st_size:
            chunk = os.read(descriptor, after.st_size - len(raw))
            if not chunk:
                raise ReviewerCliError("reviewer_input_truncated")
            raw.extend(chunk)
    finally:
        os.close(descriptor)
    wire = bytes(raw[:-1] if raw.endswith(b"\n") else raw)
    raw[:] = b"\x00" * len(raw)
    try:
        value = json.loads(wire)
        if not isinstance(value, Mapping) or canonical_bytes(value) != wire:
            raise ReviewerCliError("reviewer_input_not_canonical")
    except (CanonicalError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ReviewerCliError("reviewer_input_invalid") from exception
    return value


def _owner_parent(path: Path) -> Path:
    parent = Path(os.path.abspath(path)).parent
    try:
        info = parent.lstat()
    except OSError as exception:
        raise ReviewerCliError("reviewer_output_parent_unavailable") from exception
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ReviewerCliError("reviewer_output_parent_refused")
    return parent


def _write_new(path: Path, value: Mapping[str, Any]) -> None:
    absolute = Path(os.path.abspath(path))
    _owner_parent(absolute)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            absolute,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        raw = canonical_bytes(value) + b"\n"
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except OSError as exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        with suppress(FileNotFoundError):
            absolute.unlink()
        raise ReviewerCliError("reviewer_output_refused") from exception
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _confirm(summary: Mapping[str, Any], identifier: str) -> None:
    if not sys.stdin.isatty():
        raise ReviewerCliError("reviewer_tty_required")
    token = identifier[-12:]
    sys.stderr.buffer.write(canonical_bytes(summary) + b"\n")
    sys.stderr.write(f"Type SIGN {token} to authorize this exact artifact: ")
    sys.stderr.flush()
    response = sys.stdin.readline(128)
    if response != f"SIGN {token}\n":
        raise ReviewerCliError("reviewer_confirmation_refused")


def _byte_diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Return one exact, inert, linear-time canonical-byte replacement hunk."""

    old = canonical_bytes(before)
    new = canonical_bytes(after)
    prefix = 0
    shared = min(len(old), len(new))
    while prefix < shared and old[prefix] == new[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < shared - prefix
        and old[len(old) - suffix - 1] == new[len(new) - suffix - 1]
    ):
        suffix += 1
    old_end = len(old) - suffix
    new_end = len(new) - suffix
    return {
        "schema": "dm.review.canonical-byte-diff/v1",
        "encoding": "hex",
        "offset": prefix,
        "removed": old[prefix:old_end].hex(),
        "inserted": new[prefix:new_end].hex(),
        "shared_suffix_bytes": suffix,
        "before_bytes": len(old),
        "before_sha256": hashlib.sha256(old).hexdigest(),
        "after_bytes": len(new),
        "after_sha256": hashlib.sha256(new).hexdigest(),
    }


def _seed(path: Path, descriptor: int) -> bytearray:
    contents = EncryptedKeystore(path).open(lambda: _password_reader(descriptor))
    if set(contents.secrets) != {SIGNING_SLOT}:
        raise ReviewerCliError("reviewer_keystore_slot_refused")
    seed = bytearray(contents.secrets[SIGNING_SLOT])
    if (
        len(seed) != 32
        or contents.control_head != signing_descriptor(bytes(seed))["key_id"]
    ):
        seed[:] = b"\x00" * len(seed)
        raise ReviewerCliError("reviewer_keystore_binding_mismatch")
    return seed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="daimon-reviewer", description=__doc__)
    result.add_argument("--keystore", type=Path, required=True)
    result.add_argument("--password-fd", type=int, required=True)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("key-create", help="create a fresh dedicated reviewer key")
    accept = commands.add_parser(
        "authorization-accept", help="accept an exact subject delegation"
    )
    accept.add_argument("--core", type=Path, required=True)
    accept.add_argument("--out", type=Path, required=True)
    decide = commands.add_parser(
        "decision-sign", help="sign one exact daemon-prepared decision draft"
    )
    decide.add_argument("--authorization", type=Path, required=True)
    decide.add_argument("--request", type=Path, required=True)
    decide.add_argument("--draft", type=Path, required=True)
    decide.add_argument("--out", type=Path, required=True)
    proof = commands.add_parser(
        "access-proof", help="sign a short-lived disclosure possession proof"
    )
    proof.add_argument("--authorization", type=Path, required=True)
    proof.add_argument("--rpc-request-id", required=True)
    proof.add_argument("--issued-at-ms", type=int, required=True)
    proof.add_argument("--expires-at-ms", type=int, required=True)
    proof.add_argument("--out", type=Path, required=True)
    return result


def _secret_channel_preflight(arguments: Sequence[str]) -> None:
    if FORBIDDEN_SECRET_ENV.intersection(os.environ):
        raise ReviewerCliError("reviewer_secret_channel_refused")
    for argument in arguments:
        if argument == "--password" or argument.startswith("--password="):
            raise ReviewerCliError("reviewer_secret_channel_refused")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    seed: bytearray | None = None
    password: bytearray | None = None
    try:
        _secret_channel_preflight(arguments)
        args = parser().parse_args(arguments)
        if not sys.stdin.isatty():
            raise ReviewerCliError("reviewer_tty_required")
        if args.command == "key-create":
            _owner_parent(args.keystore)
            password = _password_reader(args.password_fd)
            seed = bytearray(generate_ed25519_seed())
            descriptor = signing_descriptor(bytes(seed))
            _confirm(
                {
                    "schema": "dm.review.ceremony-preview/v1",
                    "operation": "create-reviewer-key",
                    "reviewer_key_id": descriptor["key_id"],
                },
                descriptor["key_id"],
            )
            EncryptedKeystore.create(
                args.keystore,
                lambda: password,
                control_head=descriptor["key_id"],
                secrets={SIGNING_SLOT: bytes(seed)},
            )
            sys.stdout.buffer.write(canonical_bytes(descriptor) + b"\n")
        elif args.command == "authorization-accept":
            seed = _seed(args.keystore, args.password_fd)
            core = validate_authorization_core(_owner_document(args.core))
            authorization = accept_authorization(core, bytes(seed))
            _confirm(
                {
                    "schema": "dm.review.ceremony-preview/v1",
                    "operation": "accept-authorization",
                    "authorization_id": authorization["authorization_id"],
                    "subject_me_id": authorization["subject_me_id"],
                    "policy_id": authorization["policy_id"],
                    "group": authorization["group"],
                    "scopes": authorization["scopes"],
                    "expires_at_ms": authorization["expires_at_ms"],
                    "max_outstanding_decisions": authorization[
                        "max_outstanding_decisions"
                    ],
                },
                authorization["authorization_id"],
            )
            _write_new(args.out, authorization)
        elif args.command == "decision-sign":
            seed = _seed(args.keystore, args.password_fd)
            authorization = validate_reviewer_authorization(
                _owner_document(args.authorization)
            )
            request = validate_review_request(_owner_document(args.request))
            draft = _owner_document(args.draft)
            decision = sign_review_decision(draft, bytes(seed))
            validate_human_decision(decision, authorization, request)
            original = {
                key: request[key] for key in ("policy", "candidate", "plan", "proposal")
            }
            _confirm(
                {
                    "schema": "dm.review.ceremony-preview/v1",
                    "operation": "sign-decision",
                    "decision_id": decision["decision_id"],
                    "review_request_id": decision["review_request_id"],
                    "action": decision["action"],
                    "reason_sha256": hashlib.sha256(
                        decision["reason"].encode("utf-8")
                    ).hexdigest(),
                    "replacement_sha256": None
                    if decision["replacement"] is None
                    else hashlib.sha256(
                        canonical_bytes(decision["replacement"])
                    ).hexdigest(),
                    "replacement_byte_diff": None
                    if decision["replacement"] is None
                    else _byte_diff(original, decision["replacement"]),
                },
                decision["decision_id"],
            )
            _write_new(args.out, decision)
        elif args.command == "access-proof":
            seed = _seed(args.keystore, args.password_fd)
            authorization = validate_reviewer_authorization(
                _owner_document(args.authorization)
            )
            proof = create_access_proof(
                authorization_id=authorization["authorization_id"],
                rpc_request_id=args.rpc_request_id,
                issued_at_ms=args.issued_at_ms,
                expires_at_ms=args.expires_at_ms,
                reviewer_seed=bytes(seed),
            )
            _confirm(
                {
                    "schema": "dm.review.ceremony-preview/v1",
                    "operation": "access-proof",
                    "proof_id": proof["proof_id"],
                    "authorization_id": proof["authorization_id"],
                    "expires_at_ms": proof["expires_at_ms"],
                },
                proof["proof_id"],
            )
            _write_new(args.out, proof)
        else:
            raise ReviewerCliError("reviewer_command_refused")
        return 0
    except (KeyboardInterrupt, EOFError):
        sys.stderr.buffer.write(
            canonical_bytes(
                {
                    "schema": "dm.review.ceremony-diagnostic/v1",
                    "code": "reviewer_confirmation_interrupted",
                }
            )
            + b"\n"
        )
        return 130
    except (ReviewerCliError, HumanReviewError, KeystoreError) as exception:
        sys.stderr.buffer.write(
            canonical_bytes(
                {"schema": "dm.review.ceremony-diagnostic/v1", "code": str(exception)}
            )
            + b"\n"
        )
        return 1
    except Exception:
        sys.stderr.buffer.write(
            canonical_bytes(
                {
                    "schema": "dm.review.ceremony-diagnostic/v1",
                    "code": "reviewer_ceremony_refused",
                }
            )
            + b"\n"
        )
        return 1
    finally:
        if seed is not None:
            seed[:] = b"\x00" * len(seed)
        if password is not None:
            password[:] = b"\x00" * len(password)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ReviewerCliError", "main", "parser"]
