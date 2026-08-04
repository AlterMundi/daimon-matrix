"""Plural being identity and authorization contracts for DM-021.

The builders in this module sign only typed ceremony artifacts.  They do not
expose a generic root-signing operation.  Root and recovery seeds are expected
to be opened by a custody ceremony and discarded immediately afterwards.
"""

from __future__ import annotations

import copy
import hashlib
import secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .canonical import b64url, canonical_bytes, digest, domain_bytes

Artifact = dict[str, Any]
SeedMap = Mapping[str, bytes]
HistoryVerifier = Callable[[Mapping[str, Any]], bool]

MAX_KEYS: Final = 32
MAX_SIGNATURES: Final = 128

DOMAINS: Final[dict[str, str]] = {
    "genesis": "dm.identity.genesis/v1",
    "root-rotation": "dm.identity.root-rotation/v1",
    "recovery-policy": "dm.identity.recovery-policy/v1",
    "recovery": "dm.identity.recovery/v1",
    "revocation": "dm.identity.revocation/v1",
    "embodiment-credential": "dm.identity.embodiment-credential/v1",
    "incarnation-authorization": "dm.identity.incarnation-authorization/v1",
    "history-binding": "dm.identity.history-binding/v1",
    "binding-activation": "dm.identity.binding-activation/v1",
}

ALLOWED_ROLES: Final[dict[str, frozenset[str]]] = {
    "genesis": frozenset({"root-authorization", "recovery-possession"}),
    "root-rotation": frozenset({"root-authorization", "new-root-possession"}),
    "recovery-policy": frozenset(
        {
            "root-authorization",
            "recovery-authorization",
            "new-recovery-possession",
        }
    ),
    "recovery": frozenset({"recovery-authorization", "new-root-possession"}),
    "revocation": frozenset({"root-authorization"}),
    "embodiment-credential": frozenset({"root-authorization", "embodiment-acceptance"}),
    "incarnation-authorization": frozenset({"incarnation-authorization"}),
    "history-binding": frozenset({"root-authorization"}),
    "binding-activation": frozenset({"root-authorization"}),
}


class IdentityError(ValueError):
    """Base class for identity contract failures."""


class VerificationError(IdentityError):
    """Raised when an identity artifact fails closed."""


class ControlForkError(VerificationError):
    """Raised when no unique control head exists."""


def generate_ed25519_seed() -> bytes:
    """Create a fresh Ed25519 seed for placement in a protected keystore."""

    return secrets.token_bytes(32)


def generate_x25519_private() -> bytes:
    """Create a fresh X25519 private value for an embodiment keystore."""

    return X25519PrivateKey.generate().private_bytes_raw()


def ed25519_public(seed: bytes) -> bytes:
    """Derive an Ed25519 public key from a 32-byte seed."""

    if len(seed) != 32:
        raise IdentityError("Ed25519 seed must be 32 bytes")
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def x25519_public(private: bytes) -> bytes:
    """Derive an X25519 public key from a 32-byte private value."""

    if len(private) != 32:
        raise IdentityError("X25519 private value must be 32 bytes")
    return (
        X25519PrivateKey.from_private_bytes(private)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def key_id(algorithm: Literal["Ed25519", "X25519"], public: bytes) -> str:
    if len(public) != 32:
        raise IdentityError("public keys must be 32 bytes")
    body = {"algorithm": algorithm, "public": b64url(public)}
    return "dm:key:v1:" + b64url(digest("dm.identity.key/v1", body))


def key_descriptor(
    algorithm: Literal["Ed25519", "X25519"], public: bytes
) -> dict[str, str]:
    return {
        "algorithm": algorithm,
        "key_id": key_id(algorithm, public),
        "public": b64url(public),
    }


def signing_descriptor(seed: bytes) -> dict[str, str]:
    return key_descriptor("Ed25519", ed25519_public(seed))


def encryption_descriptor(private: bytes) -> dict[str, str]:
    return key_descriptor("X25519", x25519_public(private))


def threshold_policy(seeds: Sequence[bytes], threshold: int) -> dict[str, Any]:
    descriptors = sorted(
        (signing_descriptor(seed) for seed in seeds), key=lambda item: item["key_id"]
    )
    _validate_threshold_policy({"keys": descriptors, "threshold": threshold})
    return {"keys": descriptors, "threshold": threshold}


def _closed(value: Mapping[str, Any], fields: set[str], what: str) -> None:
    if set(value) != fields:
        raise VerificationError(f"{what} fields mismatch")


def _public_map(policy: Mapping[str, Any]) -> dict[str, bytes]:
    _validate_threshold_policy(policy)
    return {
        descriptor["key_id"]: _descriptor_public(descriptor, "Ed25519")
        for descriptor in policy["keys"]
    }


def _descriptor_public(
    descriptor: Mapping[str, Any], expected: Literal["Ed25519", "X25519"]
) -> bytes:
    _closed(descriptor, {"algorithm", "key_id", "public"}, "key descriptor")
    if descriptor["algorithm"] != expected:
        raise VerificationError(f"expected {expected} key")
    from .canonical import unb64url

    public = unb64url(descriptor["public"], length=32)
    if descriptor["key_id"] != key_id(expected, public):
        raise VerificationError("derived key ID mismatch")
    if expected == "Ed25519":
        Ed25519PublicKey.from_public_bytes(public)
    return public


def _validate_threshold_policy(policy: Mapping[str, Any]) -> None:
    _closed(policy, {"keys", "threshold"}, "threshold policy")
    keys = policy["keys"]
    threshold = policy["threshold"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_KEYS:
        raise VerificationError("threshold key count is out of bounds")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise VerificationError("threshold must be an integer")
    if not 1 <= threshold <= len(keys):
        raise VerificationError("threshold is out of bounds")
    if keys != sorted(keys, key=lambda item: item.get("key_id", "")):
        raise VerificationError("threshold keys are not canonically sorted")
    seen_ids: set[str] = set()
    seen_public: set[bytes] = set()
    for descriptor in keys:
        public = _descriptor_public(descriptor, "Ed25519")
        if descriptor["key_id"] in seen_ids or public in seen_public:
            raise VerificationError("threshold policy contains an aliased key")
        seen_ids.add(descriptor["key_id"])
        seen_public.add(public)


def _policy_publics(policy: Mapping[str, Any]) -> set[bytes]:
    return set(_public_map(policy).values())


def _require_separate_policies(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> None:
    if _policy_publics(first) & _policy_publics(second):
        raise VerificationError("root and recovery key material must be distinct")


def _seed_map(seeds: Iterable[bytes]) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for seed in seeds:
        descriptor = signing_descriptor(seed)
        result[descriptor["key_id"]] = seed
    return result


def _signature(seed: bytes, role: str, preimage: bytes) -> dict[str, str]:
    descriptor = signing_descriptor(seed)
    return {
        "algorithm": "Ed25519",
        "key_id": descriptor["key_id"],
        "role": role,
        "value": b64url(Ed25519PrivateKey.from_private_bytes(seed).sign(preimage)),
    }


def _signatures(seeds: SeedMap, role: str, preimage: bytes) -> list[dict[str, str]]:
    return [_signature(seeds[key], role, preimage) for key in sorted(seeds)]


def _artifact(
    kind: str, body: Mapping[str, Any], signatures: list[dict[str, str]]
) -> Artifact:
    domain = DOMAINS[kind]
    artifact_hash = digest(domain, body)
    return {
        "schema": "dm.identity.artifact/v1",
        "kind": kind,
        "artifact_id": "dm:identity:v1:" + b64url(artifact_hash),
        "body": copy.deepcopy(dict(body)),
        "signatures": sorted(
            signatures, key=lambda item: (item["key_id"], item["role"])
        ),
    }


def _verify_wrapper(
    artifact: Mapping[str, Any], kind: str
) -> tuple[Mapping[str, Any], bytes]:
    _closed(
        artifact,
        {"schema", "kind", "artifact_id", "body", "signatures"},
        "identity artifact",
    )
    if artifact["schema"] != "dm.identity.artifact/v1" or artifact["kind"] != kind:
        raise VerificationError("identity artifact kind/schema mismatch")
    body = artifact["body"]
    if not isinstance(body, Mapping):
        raise VerificationError("artifact body must be an object")
    raw_hash = digest(DOMAINS[kind], body)
    if artifact["artifact_id"] != "dm:identity:v1:" + b64url(raw_hash):
        raise VerificationError("artifact ID mismatch")
    signatures = artifact["signatures"]
    if not isinstance(signatures, list) or len(signatures) > MAX_SIGNATURES:
        raise VerificationError("signature list is out of bounds")
    if signatures != sorted(
        signatures, key=lambda item: (item.get("key_id", ""), item.get("role", ""))
    ):
        raise VerificationError("signatures are not canonically sorted")
    seen: set[tuple[str, str]] = set()
    for signature in signatures:
        _closed(signature, {"algorithm", "key_id", "role", "value"}, "signature")
        if signature["algorithm"] != "Ed25519":
            raise VerificationError("signature algorithm mismatch")
        if signature["role"] not in ALLOWED_ROLES[kind]:
            raise VerificationError("signature role is invalid for artifact kind")
        marker = (signature["key_id"], signature["role"])
        if marker in seen:
            raise VerificationError("duplicate signature role/key")
        seen.add(marker)
    return body, raw_hash


def _verify_threshold(
    artifact: Mapping[str, Any],
    policy: Mapping[str, Any],
    role: str,
    preimage: bytes,
) -> None:
    public = _public_map(policy)
    valid: set[str] = set()
    from .canonical import unb64url

    for signature in artifact["signatures"]:
        if signature["role"] != role:
            continue
        key = signature["key_id"]
        if key not in public:
            raise VerificationError(f"unauthorized {role} signature")
        try:
            Ed25519PublicKey.from_public_bytes(public[key]).verify(
                unb64url(signature["value"], length=64), preimage
            )
        except InvalidSignature as error:
            raise VerificationError(f"invalid {role} signature") from error
        valid.add(key)
    if len(valid) < policy["threshold"]:
        raise VerificationError(f"{role} threshold not met")


def _sign_control(
    kind: str,
    body: Mapping[str, Any],
    authorizers: SeedMap,
    authorization_role: str,
    possessors: SeedMap | None = None,
) -> Artifact:
    signatures = _signatures(
        authorizers, authorization_role, domain_bytes(DOMAINS[kind], body)
    )
    if possessors is not None:
        raw_hash = digest(DOMAINS[kind], body)
        preimage = DOMAINS[kind].encode("ascii") + b"/possession\x00" + raw_hash
        signatures.extend(_signatures(possessors, "new-root-possession", preimage))
    return _artifact(kind, body, signatures)


@dataclass(frozen=True)
class ControlState:
    """Verified state at one unique control head."""

    being_ref: str
    head: str
    generation: int
    sequence: int
    root_policy: Mapping[str, Any]
    recovery_policy: Mapping[str, Any]
    revocations: Mapping[str, Mapping[str, int]]
    credential_authorities: Mapping[str, Mapping[str, Any]]
    carried_credential_authorities: Mapping[str, Mapping[str, Any]]
    activated_binding: str | None = None


def create_genesis(
    root_seeds: Sequence[bytes],
    root_threshold: int,
    recovery_seeds: Sequence[bytes],
    recovery_threshold: int,
    *,
    created_at_ms: int,
    nonce: bytes | None = None,
) -> Artifact:
    """Create a self-certifying being genesis with independent thresholds."""

    root = threshold_policy(root_seeds, root_threshold)
    recovery = threshold_policy(recovery_seeds, recovery_threshold)
    _require_separate_policies(root, recovery)
    core = {
        "nonce": b64url(nonce if nonce is not None else secrets.token_bytes(32)),
        "protocol": "daimon-matrix",
        "recovery": recovery,
        "root": root,
        "version": 1,
    }
    being_ref = "dm:being:v1:" + b64url(digest("dm.identity.being/v1", core))
    body = {
        "being_ref": being_ref,
        "control_generation": 0,
        "control_sequence": 0,
        "core": core,
        "created_at_ms": created_at_ms,
    }
    signatures = _signatures(
        _seed_map(root_seeds),
        "root-authorization",
        domain_bytes(DOMAINS["genesis"], body),
    )
    raw_hash = digest(DOMAINS["genesis"], body)
    signatures.extend(
        _signatures(
            _seed_map(recovery_seeds),
            "recovery-possession",
            DOMAINS["genesis"].encode("ascii") + b"/possession\x00" + raw_hash,
        )
    )
    return _artifact("genesis", body, signatures)


def verify_genesis(artifact: Mapping[str, Any]) -> ControlState:
    body, raw_hash = _verify_wrapper(artifact, "genesis")
    _closed(
        body,
        {
            "being_ref",
            "control_generation",
            "control_sequence",
            "core",
            "created_at_ms",
        },
        "genesis body",
    )
    if body["control_generation"] != 0 or body["control_sequence"] != 0:
        raise VerificationError("genesis control position must be (0, 0)")
    core = body["core"]
    _closed(core, {"nonce", "protocol", "recovery", "root", "version"}, "genesis core")
    if core["protocol"] != "daimon-matrix" or core["version"] != 1:
        raise VerificationError("genesis protocol/version mismatch")
    from .canonical import unb64url

    unb64url(core["nonce"], length=32)
    expected = "dm:being:v1:" + b64url(digest("dm.identity.being/v1", core))
    if body["being_ref"] != expected:
        raise VerificationError("self-certifying being reference mismatch")
    _verify_threshold(
        artifact,
        core["root"],
        "root-authorization",
        domain_bytes(DOMAINS["genesis"], body),
    )
    _verify_threshold(
        artifact,
        core["recovery"],
        "recovery-possession",
        DOMAINS["genesis"].encode("ascii") + b"/possession\x00" + raw_hash,
    )
    _require_separate_policies(core["root"], core["recovery"])
    state = ControlState(
        being_ref=body["being_ref"],
        head=artifact["artifact_id"],
        generation=0,
        sequence=0,
        root_policy=copy.deepcopy(core["root"]),
        recovery_policy=copy.deepcopy(core["recovery"]),
        revocations={},
        credential_authorities={},
        carried_credential_authorities={},
    )
    return replace(
        state,
        credential_authorities={state.head: copy.deepcopy(state.root_policy)},
    )


def _successor_body(state: ControlState, **changes: Any) -> dict[str, Any]:
    body = {
        "being_ref": state.being_ref,
        "control_generation": state.generation,
        "control_sequence": state.sequence + 1,
        "previous_control_head": state.head,
    }
    body.update(changes)
    return body


def create_root_rotation(
    state: ControlState,
    current_root_seeds: Sequence[bytes],
    replacement_root_seeds: Sequence[bytes],
    replacement_threshold: int,
    *,
    carry_forward_credentials: Sequence[str] = (),
) -> Artifact:
    replacement_policy = threshold_policy(replacement_root_seeds, replacement_threshold)
    _require_separate_policies(replacement_policy, state.recovery_policy)
    body = _successor_body(
        state,
        replacement_root=replacement_policy,
        carry_forward_credentials=sorted(set(carry_forward_credentials)),
    )
    return _sign_control(
        "root-rotation",
        body,
        _seed_map(current_root_seeds),
        "root-authorization",
        _seed_map(replacement_root_seeds),
    )


def create_recovery_policy_change(
    state: ControlState,
    current_root_seeds: Sequence[bytes],
    current_recovery_seeds: Sequence[bytes],
    replacement_recovery_seeds: Sequence[bytes],
    replacement_threshold: int,
) -> Artifact:
    replacement_policy = threshold_policy(
        replacement_recovery_seeds, replacement_threshold
    )
    _require_separate_policies(state.root_policy, replacement_policy)
    body = _successor_body(state, replacement_recovery=replacement_policy)
    preimage = domain_bytes(DOMAINS["recovery-policy"], body)
    signatures = _signatures(
        _seed_map(current_root_seeds), "root-authorization", preimage
    )
    signatures.extend(
        _signatures(
            _seed_map(current_recovery_seeds), "recovery-authorization", preimage
        )
    )
    raw_hash = digest(DOMAINS["recovery-policy"], body)
    signatures.extend(
        _signatures(
            _seed_map(replacement_recovery_seeds),
            "new-recovery-possession",
            DOMAINS["recovery-policy"].encode("ascii") + b"/possession\x00" + raw_hash,
        )
    )
    return _artifact("recovery-policy", body, signatures)


def create_revocation(
    state: ControlState,
    current_root_seeds: Sequence[bytes],
    *,
    embodiment_id: str,
    cutoff_incarnation_sequence: int,
    revocation_generation: int,
) -> Artifact:
    body = _successor_body(
        state,
        embodiment_id=embodiment_id,
        cutoff_incarnation_sequence=cutoff_incarnation_sequence,
        revocation_generation=revocation_generation,
    )
    return _sign_control(
        "revocation",
        body,
        _seed_map(current_root_seeds),
        "root-authorization",
    )


def create_recovery(
    states: Sequence[ControlState],
    current_recovery_seeds: Sequence[bytes],
    replacement_root_seeds: Sequence[bytes],
    replacement_threshold: int,
    *,
    revoke_embodiments: Sequence[str],
) -> Artifact:
    """Recover a unique head while naming every currently known branch head."""

    if not states:
        raise IdentityError("recovery needs at least one known control head")
    being_refs = {state.being_ref for state in states}
    recovery_policies = {canonical_bytes(state.recovery_policy) for state in states}
    if len(being_refs) != 1 or len(recovery_policies) != 1:
        raise IdentityError("recovery heads do not share being/recovery authority")
    replacement_policy = threshold_policy(replacement_root_seeds, replacement_threshold)
    _require_separate_policies(replacement_policy, states[0].recovery_policy)
    body = {
        "being_ref": states[0].being_ref,
        "competing_control_heads": sorted({state.head for state in states}),
        "control_generation": max(state.generation for state in states) + 1,
        "control_sequence": 0,
        "replacement_root": replacement_policy,
        "revoked_embodiments": sorted(set(revoke_embodiments)),
    }
    return _sign_control(
        "recovery",
        body,
        _seed_map(current_recovery_seeds),
        "recovery-authorization",
        _seed_map(replacement_root_seeds),
    )


def _verify_position(body: Mapping[str, Any], state: ControlState) -> None:
    if body["being_ref"] != state.being_ref:
        raise VerificationError("being reference mismatch")
    if body["previous_control_head"] != state.head:
        raise VerificationError("control predecessor mismatch")
    if body["control_generation"] != state.generation:
        raise VerificationError("control generation mismatch")
    if body["control_sequence"] != state.sequence + 1:
        raise VerificationError("control sequence must increment exactly once")


def verify_successor(artifact: Mapping[str, Any], state: ControlState) -> ControlState:
    kind = artifact.get("kind")
    if kind not in {"root-rotation", "recovery-policy", "revocation"}:
        raise VerificationError("artifact is not a normal control successor")
    body, raw_hash = _verify_wrapper(artifact, kind)
    common = {
        "being_ref",
        "control_generation",
        "control_sequence",
        "previous_control_head",
    }
    _verify_position(body, state)
    preimage = domain_bytes(DOMAINS[kind], body)
    _verify_threshold(artifact, state.root_policy, "root-authorization", preimage)
    root_policy = state.root_policy
    recovery_policy = state.recovery_policy
    revocations = copy.deepcopy(dict(state.revocations))
    credential_authorities = copy.deepcopy(dict(state.credential_authorities))
    carried_authorities = copy.deepcopy(dict(state.carried_credential_authorities))
    if kind == "root-rotation":
        _closed(
            body,
            common | {"replacement_root", "carry_forward_credentials"},
            "root rotation body",
        )
        replacement_policy = body["replacement_root"]
        _require_separate_policies(replacement_policy, state.recovery_policy)
        _verify_threshold(
            artifact,
            replacement_policy,
            "new-root-possession",
            DOMAINS[kind].encode("ascii") + b"/possession\x00" + raw_hash,
        )
        carried = body["carry_forward_credentials"]
        if carried != sorted(set(carried)):
            raise VerificationError("carry-forward IDs must be sorted and unique")
        root_policy = copy.deepcopy(replacement_policy)
        credential_authorities = {
            artifact["artifact_id"]: copy.deepcopy(replacement_policy)
        }
        carried_authorities = {
            credential_id: copy.deepcopy(state.root_policy) for credential_id in carried
        }
    elif kind == "recovery-policy":
        _closed(body, common | {"replacement_recovery"}, "recovery policy body")
        _verify_threshold(
            artifact,
            state.recovery_policy,
            "recovery-authorization",
            preimage,
        )
        replacement_policy = body["replacement_recovery"]
        _require_separate_policies(state.root_policy, replacement_policy)
        _verify_threshold(
            artifact,
            replacement_policy,
            "new-recovery-possession",
            DOMAINS[kind].encode("ascii") + b"/possession\x00" + raw_hash,
        )
        recovery_policy = copy.deepcopy(replacement_policy)
    else:
        _closed(
            body,
            common
            | {
                "embodiment_id",
                "cutoff_incarnation_sequence",
                "revocation_generation",
            },
            "revocation body",
        )
        if body["cutoff_incarnation_sequence"] < 0 or body["revocation_generation"] < 1:
            raise VerificationError("invalid revocation high-water")
        prior = revocations.get(body["embodiment_id"])
        expected_generation = 1 if prior is None else prior["revocation_generation"] + 1
        if body["revocation_generation"] != expected_generation:
            raise VerificationError("revocation generation must increment exactly once")
        if (
            prior is not None
            and body["cutoff_incarnation_sequence"]
            > prior["cutoff_incarnation_sequence"]
        ):
            raise VerificationError("revocation cutoff cannot become less restrictive")
        revocations[body["embodiment_id"]] = {
            "cutoff_incarnation_sequence": body["cutoff_incarnation_sequence"],
            "revocation_generation": body["revocation_generation"],
        }
    if kind != "root-rotation":
        credential_authorities[artifact["artifact_id"]] = copy.deepcopy(root_policy)
    return ControlState(
        being_ref=state.being_ref,
        head=artifact["artifact_id"],
        generation=state.generation,
        sequence=state.sequence + 1,
        root_policy=root_policy,
        recovery_policy=recovery_policy,
        revocations=revocations,
        credential_authorities=credential_authorities,
        carried_credential_authorities=carried_authorities,
        activated_binding=state.activated_binding,
    )


def verify_recovery(
    artifact: Mapping[str, Any], states: Sequence[ControlState]
) -> ControlState:
    if not states:
        raise VerificationError("recovery has no known heads")
    body, raw_hash = _verify_wrapper(artifact, "recovery")
    _closed(
        body,
        {
            "being_ref",
            "competing_control_heads",
            "control_generation",
            "control_sequence",
            "replacement_root",
            "revoked_embodiments",
        },
        "recovery body",
    )
    if body["being_ref"] != states[0].being_ref or any(
        state.being_ref != states[0].being_ref for state in states
    ):
        raise VerificationError("recovery being mismatch")
    known_heads = sorted({state.head for state in states})
    if body["competing_control_heads"] != known_heads:
        raise VerificationError("recovery must cite every known head exactly")
    if body["control_generation"] != max(state.generation for state in states) + 1:
        raise VerificationError("recovery generation mismatch")
    if body["control_sequence"] != 0:
        raise VerificationError("recovery sequence must reset to zero")
    revoked_embodiments = body["revoked_embodiments"]
    if revoked_embodiments != sorted(set(revoked_embodiments)):
        raise VerificationError("recovery revocations must be sorted and unique")
    policies = {canonical_bytes(state.recovery_policy) for state in states}
    if len(policies) != 1:
        raise VerificationError("fork branches disagree on recovery authority")
    _require_separate_policies(body["replacement_root"], states[0].recovery_policy)
    _verify_threshold(
        artifact,
        states[0].recovery_policy,
        "recovery-authorization",
        domain_bytes(DOMAINS["recovery"], body),
    )
    _verify_threshold(
        artifact,
        body["replacement_root"],
        "new-root-possession",
        DOMAINS["recovery"].encode("ascii") + b"/possession\x00" + raw_hash,
    )
    revoked = _merge_revocations(states)
    for embodiment_id in revoked_embodiments:
        previous = revoked.get(embodiment_id, {})
        revoked[embodiment_id] = {
            "cutoff_incarnation_sequence": previous.get(
                "cutoff_incarnation_sequence", 0
            ),
            "revocation_generation": previous.get("revocation_generation", 0) + 1,
        }
    return ControlState(
        being_ref=states[0].being_ref,
        head=artifact["artifact_id"],
        generation=body["control_generation"],
        sequence=0,
        root_policy=copy.deepcopy(body["replacement_root"]),
        recovery_policy=copy.deepcopy(states[0].recovery_policy),
        revocations=revoked,
        credential_authorities={
            artifact["artifact_id"]: copy.deepcopy(body["replacement_root"])
        },
        carried_credential_authorities={},
    )


def _merge_revocations(
    states: Sequence[ControlState],
) -> dict[str, dict[str, int]]:
    """Conservatively preserve every branch's revocation high-water."""

    merged: dict[str, dict[str, int]] = {}
    for state in states:
        for embodiment_id, revocation in state.revocations.items():
            previous = merged.get(embodiment_id)
            if previous is None:
                merged[embodiment_id] = copy.deepcopy(dict(revocation))
                continue
            previous["revocation_generation"] = max(
                previous["revocation_generation"],
                revocation["revocation_generation"],
            )
            previous["cutoff_incarnation_sequence"] = min(
                previous["cutoff_incarnation_sequence"],
                revocation["cutoff_incarnation_sequence"],
            )
    return merged


class ControlChain:
    """Append-only verifier that quarantines competing normal successors."""

    def __init__(self, genesis: Mapping[str, Any]) -> None:
        state = verify_genesis(genesis)
        self._states: dict[str, ControlState] = {state.head: state}
        self._heads: set[str] = {state.head}
        self._children: dict[str, set[str]] = {}

    @property
    def heads(self) -> tuple[str, ...]:
        return tuple(sorted(self._heads))

    @property
    def state(self) -> ControlState:
        if len(self._heads) != 1:
            raise ControlForkError("control successors are quarantined")
        return self._states[next(iter(self._heads))]

    def states(self) -> tuple[ControlState, ...]:
        return tuple(self._states[head] for head in sorted(self._heads))

    def add(self, artifact: Mapping[str, Any]) -> ControlState:
        artifact_id = artifact.get("artifact_id")
        if artifact_id in self._states:
            raise VerificationError("control artifact replay")
        kind = artifact.get("kind")
        if kind == "recovery":
            state = verify_recovery(artifact, self.states())
            self._states[state.head] = state
            self._heads = {state.head}
            return state
        body = artifact.get("body")
        if not isinstance(body, Mapping):
            raise VerificationError("control artifact body missing")
        predecessor = body.get("previous_control_head")
        if predecessor not in self._states:
            raise VerificationError("unknown control predecessor")
        state = verify_successor(artifact, self._states[predecessor])
        self._states[state.head] = state
        self._children.setdefault(predecessor, set()).add(state.head)
        self._heads.discard(predecessor)
        self._heads.add(state.head)
        return state


def create_embodiment_credential(
    state: ControlState,
    root_seeds: Sequence[bytes],
    embodiment_signing_seed: bytes,
    embodiment_encryption_public: bytes,
    *,
    embodiment_id: str,
    body_ref: str,
    purposes: Sequence[str],
    valid_from_ms: int,
    valid_until_ms: int,
    revocation_generation: int = 0,
    transport_principals: Sequence[Mapping[str, Any]] = (),
) -> Artifact:
    normalized_principals = sorted(
        (copy.deepcopy(dict(principal)) for principal in transport_principals),
        key=lambda principal: (principal["scheme"], principal["principal_id"]),
    )
    body = {
        "being_ref": state.being_ref,
        "body_ref": body_ref,
        "control_head": state.head,
        "embodiment_id": embodiment_id,
        "encryption_key": key_descriptor("X25519", embodiment_encryption_public),
        "purposes": sorted(set(purposes)),
        "revocation_generation": revocation_generation,
        "signing_key": signing_descriptor(embodiment_signing_seed),
        "transport_principals": normalized_principals,
        "valid_from_ms": valid_from_ms,
        "valid_until_ms": valid_until_ms,
    }
    preimage = domain_bytes(DOMAINS["embodiment-credential"], body)
    signatures = _signatures(_seed_map(root_seeds), "root-authorization", preimage)
    raw_hash = digest(DOMAINS["embodiment-credential"], body)
    signatures.append(
        _signature(
            embodiment_signing_seed,
            "embodiment-acceptance",
            DOMAINS["embodiment-credential"].encode("ascii")
            + b"/acceptance\x00"
            + raw_hash,
        )
    )
    return _artifact("embodiment-credential", body, signatures)


def verify_embodiment_credential(
    credential: Mapping[str, Any],
    state: ControlState,
    *,
    at_ms: int,
    allow_revoked_history: bool = False,
) -> Mapping[str, Any]:
    body, raw_hash = _verify_wrapper(credential, "embodiment-credential")
    _closed(
        body,
        {
            "being_ref",
            "body_ref",
            "control_head",
            "embodiment_id",
            "encryption_key",
            "purposes",
            "revocation_generation",
            "signing_key",
            "transport_principals",
            "valid_from_ms",
            "valid_until_ms",
        },
        "embodiment credential body",
    )
    if body["being_ref"] != state.being_ref:
        raise VerificationError("credential being does not match")
    authority_policy = state.credential_authorities.get(body["control_head"])
    if authority_policy is None:
        authority_policy = state.carried_credential_authorities.get(
            credential["artifact_id"]
        )
    if authority_policy is None:
        raise VerificationError("credential was not explicitly carried forward")
    if not body["valid_from_ms"] <= at_ms <= body["valid_until_ms"]:
        raise VerificationError("credential is outside its validity interval")
    if body["purposes"] != sorted(set(body["purposes"])) or not body["purposes"]:
        raise VerificationError("credential purposes must be sorted and non-empty")
    encryption_public = _descriptor_public(body["encryption_key"], "X25519")
    signing_public = _descriptor_public(body["signing_key"], "Ed25519")
    forbidden_publics = _policy_publics(authority_policy) | _policy_publics(
        state.recovery_policy
    )
    if (
        signing_public in forbidden_publics
        or encryption_public in forbidden_publics
        or encryption_public == signing_public
    ):
        raise VerificationError("embodiment key aliases another key purpose")
    principals = body["transport_principals"]
    if principals != sorted(
        principals,
        key=lambda principal: (principal["scheme"], principal["principal_id"]),
    ):
        raise VerificationError("transport principals are not canonically sorted")
    seen_principals: set[tuple[str, str]] = set()
    seen_transport_keys: set[bytes] = set()
    for principal in principals:
        _closed(principal, {"key", "principal_id", "scheme"}, "transport principal")
        marker = (principal["scheme"], principal["principal_id"])
        public = _descriptor_public(principal["key"], "Ed25519")
        if marker in seen_principals or public in seen_transport_keys:
            raise VerificationError("transport principal is duplicated or aliased")
        if public in (signing_public, encryption_public) or public in forbidden_publics:
            raise VerificationError("transport key aliases identity key material")
        seen_principals.add(marker)
        seen_transport_keys.add(public)
    _verify_threshold(
        credential,
        authority_policy,
        "root-authorization",
        domain_bytes(DOMAINS["embodiment-credential"], body),
    )
    from .canonical import unb64url

    acceptance = [
        signature
        for signature in credential["signatures"]
        if signature["role"] == "embodiment-acceptance"
    ]
    if len(acceptance) != 1 or acceptance[0]["key_id"] != body["signing_key"]["key_id"]:
        raise VerificationError("credential lacks exact embodiment acceptance")
    try:
        Ed25519PublicKey.from_public_bytes(signing_public).verify(
            unb64url(acceptance[0]["value"], length=64),
            DOMAINS["embodiment-credential"].encode("ascii")
            + b"/acceptance\x00"
            + raw_hash,
        )
    except InvalidSignature as error:
        raise VerificationError("invalid embodiment acceptance") from error
    revocation = state.revocations.get(body["embodiment_id"])
    if (
        revocation
        and not allow_revoked_history
        and body["revocation_generation"] < revocation["revocation_generation"]
    ):
        raise VerificationError("embodiment credential has been revoked")
    return body


def create_incarnation_authorization(
    credential: Mapping[str, Any],
    embodiment_signing_seed: bytes,
    *,
    incarnation_id: str,
    incarnation_sequence: int,
    started_at_ms: int,
) -> Artifact:
    credential_body = credential["body"]
    body = {
        "being_ref": credential_body["being_ref"],
        "embodiment_credential_id": credential["artifact_id"],
        "embodiment_id": credential_body["embodiment_id"],
        "incarnation_id": incarnation_id,
        "incarnation_sequence": incarnation_sequence,
        "started_at_ms": started_at_ms,
    }
    return _artifact(
        "incarnation-authorization",
        body,
        [
            _signature(
                embodiment_signing_seed,
                "incarnation-authorization",
                domain_bytes(DOMAINS["incarnation-authorization"], body),
            )
        ],
    )


def verify_incarnation_authorization(
    authorization: Mapping[str, Any],
    credential: Mapping[str, Any],
    state: ControlState,
    *,
    at_ms: int,
) -> Mapping[str, Any]:
    credential_body = verify_embodiment_credential(
        credential,
        state,
        at_ms=at_ms,
        allow_revoked_history=True,
    )
    body, _ = _verify_wrapper(authorization, "incarnation-authorization")
    _closed(
        body,
        {
            "being_ref",
            "embodiment_credential_id",
            "embodiment_id",
            "incarnation_id",
            "incarnation_sequence",
            "started_at_ms",
        },
        "incarnation authorization body",
    )
    if (
        body["being_ref"] != state.being_ref
        or body["embodiment_id"] != credential_body["embodiment_id"]
        or body["embodiment_credential_id"] != credential["artifact_id"]
    ):
        raise VerificationError("incarnation/credential binding mismatch")
    if body["incarnation_sequence"] < 0:
        raise VerificationError("incarnation sequence must be non-negative")
    if body["started_at_ms"] < 0 or body["started_at_ms"] > at_ms:
        raise VerificationError("incarnation start time is invalid")
    revocation = state.revocations.get(body["embodiment_id"])
    if (
        revocation
        and body["incarnation_sequence"] > revocation["cutoff_incarnation_sequence"]
    ):
        raise VerificationError("incarnation is later than the revocation cutoff")
    signatures = authorization["signatures"]
    if len(signatures) != 1 or signatures[0]["role"] != "incarnation-authorization":
        raise VerificationError("incarnation needs one embodiment signature")
    signing_public = _descriptor_public(credential_body["signing_key"], "Ed25519")
    from .canonical import unb64url

    try:
        Ed25519PublicKey.from_public_bytes(signing_public).verify(
            unb64url(signatures[0]["value"], length=64),
            domain_bytes(DOMAINS["incarnation-authorization"], body),
        )
    except InvalidSignature as error:
        raise VerificationError("invalid incarnation authorization") from error
    return body


def create_history_binding(
    state: ControlState,
    root_seeds: Sequence[bytes],
    *,
    provisional_being_ref: str,
    manifest_bytes: bytes,
    manifest_revision: int,
    accepted_heads: Sequence[Mapping[str, Any]],
) -> Artifact:
    heads = sorted(
        (copy.deepcopy(dict(head)) for head in accepted_heads),
        key=lambda head: canonical_bytes(head),
    )
    _validate_history_heads(heads)
    body = {
        "accepted_heads": heads,
        "being_ref": state.being_ref,
        "control_head": state.head,
        "manifest_hash": b64url(hashlib.sha256(manifest_bytes).digest()),
        "manifest_revision": manifest_revision,
        "provisional_being_ref": provisional_being_ref,
    }
    return _sign_control(
        "history-binding",
        body,
        _seed_map(root_seeds),
        "root-authorization",
    )


def verify_history_binding(
    binding: Mapping[str, Any],
    state: ControlState,
    *,
    manifest_bytes: bytes,
    manifest_revision: int,
    accepted_heads: Sequence[Mapping[str, Any]],
    verify_head: HistoryVerifier,
) -> Mapping[str, Any]:
    body, _ = _verify_wrapper(binding, "history-binding")
    _closed(
        body,
        {
            "accepted_heads",
            "being_ref",
            "control_head",
            "manifest_hash",
            "manifest_revision",
            "provisional_being_ref",
        },
        "history binding body",
    )
    if body["being_ref"] != state.being_ref or body["control_head"] != state.head:
        raise VerificationError("history binding control anchor mismatch")
    expected_heads = sorted(
        (copy.deepcopy(dict(head)) for head in accepted_heads),
        key=lambda head: canonical_bytes(head),
    )
    _validate_history_heads(body["accepted_heads"])
    _validate_history_heads(expected_heads)
    if body["accepted_heads"] != expected_heads:
        raise VerificationError("history binding head set mismatch")
    if body["manifest_revision"] != manifest_revision:
        raise VerificationError("history binding manifest revision mismatch")
    if body["manifest_hash"] != b64url(hashlib.sha256(manifest_bytes).digest()):
        raise VerificationError("history binding manifest bytes mismatch")
    if not all(verify_head(head) for head in body["accepted_heads"]):
        raise VerificationError("history binding contains an unverified head")
    _verify_threshold(
        binding,
        state.root_policy,
        "root-authorization",
        domain_bytes(DOMAINS["history-binding"], body),
    )
    return body


def _validate_history_heads(heads: Any) -> None:
    if not isinstance(heads, list) or not 1 <= len(heads) <= 1024:
        raise VerificationError("history binding head count is out of bounds")
    if heads != sorted(heads, key=canonical_bytes):
        raise VerificationError("history binding heads are not canonically sorted")
    seen: set[bytes] = set()
    fields = {
        "content_hash",
        "event_id",
        "incarnation_id",
        "origin_embodiment_id",
        "sequence",
        "signer_key_id",
    }
    for head in heads:
        if not isinstance(head, Mapping):
            raise VerificationError("history head must be an object")
        _closed(head, fields, "history head")
        canonical = canonical_bytes(head)
        if canonical in seen:
            raise VerificationError("history binding contains a duplicate head")
        seen.add(canonical)
        content_hash = head["content_hash"]
        if (
            not isinstance(content_hash, str)
            or len(content_hash) != 64
            or any(character not in "0123456789abcdef" for character in content_hash)
        ):
            raise VerificationError("history head content hash is invalid")
        for field in fields - {"content_hash", "sequence"}:
            if not isinstance(head[field], str) or not head[field]:
                raise VerificationError(f"history head {field} is invalid")
        if (
            not isinstance(head["sequence"], int)
            or isinstance(head["sequence"], bool)
            or head["sequence"] < 0
        ):
            raise VerificationError("history head sequence is invalid")


def create_binding_activation(
    state: ControlState, root_seeds: Sequence[bytes], binding: Mapping[str, Any]
) -> Artifact:
    body = {
        "being_ref": state.being_ref,
        "binding_id": binding["artifact_id"],
        "control_head": state.head,
        "mode": "root-bound",
    }
    return _sign_control(
        "binding-activation",
        body,
        _seed_map(root_seeds),
        "root-authorization",
    )


def verify_binding_activation(
    activation: Mapping[str, Any], binding: Mapping[str, Any], state: ControlState
) -> ControlState:
    body, _ = _verify_wrapper(activation, "binding-activation")
    _closed(
        body, {"being_ref", "binding_id", "control_head", "mode"}, "activation body"
    )
    if body != {
        "being_ref": state.being_ref,
        "binding_id": binding["artifact_id"],
        "control_head": state.head,
        "mode": "root-bound",
    }:
        raise VerificationError("binding activation mismatch")
    _verify_threshold(
        activation,
        state.root_policy,
        "root-authorization",
        domain_bytes(DOMAINS["binding-activation"], body),
    )
    return replace(state, activated_binding=binding["artifact_id"])


def require_trust_mode(state: ControlState, requested: str) -> None:
    """Reject provisional downgrade after a root binding is activated."""

    expected = "root-bound" if state.activated_binding else "provisional"
    if requested != expected:
        raise VerificationError(f"trust mode mismatch: expected {expected}")


__all__ = [
    "ControlChain",
    "ControlForkError",
    "ControlState",
    "IdentityError",
    "VerificationError",
    "create_binding_activation",
    "create_embodiment_credential",
    "create_genesis",
    "create_history_binding",
    "create_incarnation_authorization",
    "create_recovery",
    "create_recovery_policy_change",
    "create_revocation",
    "create_root_rotation",
    "ed25519_public",
    "encryption_descriptor",
    "generate_ed25519_seed",
    "generate_x25519_private",
    "key_descriptor",
    "key_id",
    "require_trust_mode",
    "signing_descriptor",
    "threshold_policy",
    "verify_binding_activation",
    "verify_embodiment_credential",
    "verify_genesis",
    "verify_history_binding",
    "verify_incarnation_authorization",
    "verify_recovery",
    "verify_successor",
    "x25519_public",
]
