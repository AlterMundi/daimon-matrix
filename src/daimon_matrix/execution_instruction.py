"""Closed, finite human execution requests; no message-origin authority.

Trust keys must belong to an isolated human-authentication frontend, NOT to
an agent/runtime client. This module deliberately has no signing API.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class ExecutionDenied(ValueError):
    """Fail-closed execution admission."""


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _name(value: object) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(r"[A-Za-z0-9:._/-]{1,200}", value)
    )


@dataclass(frozen=True)
class Scope:
    channel: str
    thread: str
    tool: str
    action: str

    def __post_init__(self) -> None:
        allowed = {
            ("messaging_inbox", "review"),
            ("messaging_send", "send"),
            ("messaging_reply", "reply"),
        }
        if (
            not all(_name(v) for v in asdict(self).values())
            or (self.tool, self.action) not in allowed
        ):
            raise ExecutionDenied("unsupported scope")


@dataclass(frozen=True)
class Instruction:
    schema: str
    instruction_id: str
    store_id: str
    revision: int
    predecessor: str | None
    principal: str
    being: str
    embodiment: str
    runner: str
    session: str
    mode: str
    start: int
    end: int
    interval: int | None
    max_cycle_seconds: int
    cleanup_seconds: int
    max_cycles: int
    max_effects: int
    max_input_tokens: int
    max_output_tokens: int
    provider: str
    model: str
    task_sha256: str
    scope: tuple[Scope, ...]

    def __post_init__(self) -> None:
        for name in (
            "revision",
            "start",
            "end",
            "max_cycle_seconds",
            "cleanup_seconds",
            "max_cycles",
            "max_effects",
            "max_input_tokens",
            "max_output_tokens",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= 2**53 - 1:
                raise ExecutionDenied(f"invalid {name}")
        for name in (
            "instruction_id",
            "store_id",
            "principal",
            "being",
            "embodiment",
            "runner",
            "session",
            "provider",
            "model",
        ):
            if not _name(getattr(self, name)):
                raise ExecutionDenied(f"invalid {name}")
        if self.schema != "execution/v1" or self.start >= self.end:
            raise ExecutionDenied("invalid schema/window")
        if not isinstance(self.task_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.task_sha256
        ):
            raise ExecutionDenied("invalid task digest")
        if (self.revision == 1 and self.predecessor is not None) or (
            self.revision > 1
            and (
                not isinstance(self.predecessor, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.predecessor)
            )
        ):
            raise ExecutionDenied("invalid predecessor")
        if self.mode == "manual":
            if self.interval is not None or self.max_cycles != 1:
                raise ExecutionDenied("manual means one cycle without interval")
        elif self.mode == "periodic":
            if type(self.interval) is not int or not 0 < self.interval <= 2**53 - 1:
                raise ExecutionDenied("positive interval required")
        else:
            raise ExecutionDenied("unsupported mode")
        if (
            not isinstance(self.scope, tuple)
            or not self.scope
            or not all(isinstance(s, Scope) for s in self.scope)
            or len(set(self.scope)) != len(self.scope)
        ):
            raise ExecutionDenied("invalid scope")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Instruction:
        try:
            if set(data) != {f.name for f in fields(cls)}:
                raise ExecutionDenied("instruction fields must be exact")
            copy = dict(data)
            if not isinstance(copy["scope"], list):
                raise ExecutionDenied("scope must be an array")
            copy["scope"] = tuple(Scope(**s) for s in copy["scope"])
            return cls(**copy)
        except (TypeError, KeyError) as exc:
            raise ExecutionDenied("invalid instruction") from exc

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["scope"] = [asdict(s) for s in self.scope]
        return result

    @property
    def sha256(self) -> str:
        return digest(self.to_dict())

    @property
    def binding(self) -> tuple[str, str, str, str]:
        return self.being, self.embodiment, self.runner, self.session


class ApprovalVerifier:
    """Explicit public trust binding supplied by the operator, never by the model."""

    def __init__(self, human_keys: Mapping[str, Ed25519PublicKey]):
        self._keys = dict(human_keys)

    def verify(
        self, action: str, payload: Mapping[str, Any], proof: Mapping[str, Any]
    ) -> tuple[str, str]:
        try:
            if set(proof) != {
                "purpose",
                "event_id",
                "principal",
                "payload_sha256",
                "signature",
            }:
                raise ExecutionDenied("closed approval required")
            if (
                action not in {"approve", "cancel"}
                or proof["purpose"] != ("execution/v1/" + action)
                or proof["payload_sha256"] != digest(payload)
            ):
                raise ExecutionDenied("approval purpose/payload mismatch")
            if (
                not _name(proof["event_id"])
                or proof["principal"] != payload["principal"]
            ):
                raise ExecutionDenied("approval principal/event mismatch")
            signature = proof["signature"]
            if not isinstance(signature, str) or not re.fullmatch(
                r"[0-9a-f]{128}", signature
            ):
                raise ExecutionDenied("invalid signature encoding")
            body = {k: v for k, v in proof.items() if k != "signature"}
            self._keys[proof["principal"]].verify(
                bytes.fromhex(signature), canonical(body)
            )
            return proof["principal"], proof["event_id"]
        except (InvalidSignature, KeyError, TypeError, ValueError) as exc:
            raise ExecutionDenied("unverified human approval") from exc
