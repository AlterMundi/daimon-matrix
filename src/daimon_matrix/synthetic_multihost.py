"""Installed, process-isolated DM-070 multihost convergence journey."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .authority_epochs import RootHistoryAuthority, create_authority_epoch
from .canonical import b64url, canonical_bytes
from .client import ClientConfig, LocalClient
from .cluster import (
    BODY_SNAPSHOT_SCHEMA,
    FENCE_VERIFICATION_SCHEMA,
    ClusterEvidenceError,
    create_effect_receipt,
    create_resource_fence_evidence,
    reconcile_effect_receipt,
    resource_fence_position,
    validate_body_snapshot,
    verify_resource_fence_evidence,
)
from .daemon import acquire_lock, serve_forever
from .identity import (
    ControlState,
    create_embodiment_credential,
    create_incarnation_authorization,
    create_synthetic_genesis_in_process,
    ed25519_public,
    key_descriptor,
    verify_genesis,
    x25519_public,
)
from .keystore import EncryptedKeystore
from .ledger import Ledger
from .local_api import LocalCapability, create_capability
from .multihost import (
    RECEIPT_SCHEMA,
    RUN_PROFILE,
    SCHEDULE,
    MultihostEvidenceError,
    create_multihost_receipt,
    event_set_hash,
    validate_cluster_provenance,
    validate_multihost_receipt,
)
from .peer_transport import (
    PROFILE,
    KeystorePeerCustody,
    PeerClient,
    PeerOutbox,
    PeerTransportAmbiguous,
    http_peer_round_trip,
)
from .peer_transport import (
    SCHEMA as PEER_SCHEMA,
)
from .sealed import RecipientTarget
from .service import METHODS, SCOPE_METHODS
from .weave import BeingManifest, EventSigner, RootAuthority, WeaveProtocolError

NOW: Final = 1_800_000_000_000
MAX_TIME: Final = 2**53 - 1
MAX_PROCESS_OUTPUT: Final = 64 * 1024
PASSWORD: Final = hashlib.sha256(b"dm070-runtime-password").digest()
TRANSPORT_SCHEME: Final = "dm-peer-v1"


class SyntheticMultihostError(RuntimeError):
    """The synthetic journey did not establish its claimed evidence."""


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"dm070:{label}".encode()).digest()


def _sha(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _write_private(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_private(path: Path, value: Mapping[str, Any]) -> None:
    raw = canonical_bytes(value)
    temporary = path.with_name(f".{path.name}.dm070-{uuid.uuid4()}")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _owner_root(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    if root.exists():
        info = root.lstat()
        if not root.is_dir() or root.is_symlink() or info.st_uid != os.geteuid():
            raise SyntheticMultihostError("synthetic_root_rejected")
        if any(root.iterdir()):
            raise SyntheticMultihostError("synthetic_root_not_empty")
    else:
        root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def _available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return cast(int, candidate.getsockname()[1])


def _transport(label: str, principal_id: str) -> dict[str, Any]:
    return {
        "scheme": TRANSPORT_SCHEME,
        "principal_id": principal_id,
        "key": key_descriptor("Ed25519", ed25519_public(_seed(f"{label}:transport"))),
    }


@dataclass(frozen=True)
class _Identity:
    root_seeds: tuple[bytes, ...]
    genesis: Mapping[str, Any]
    state: ControlState
    signing_seeds: Mapping[str, bytes]
    encryption_seeds: Mapping[str, bytes]
    credentials: Mapping[str, Mapping[str, Any]]
    incarnations: Mapping[str, Mapping[str, Any]]
    origins: Mapping[str, Mapping[str, str]]
    manifest: BeingManifest
    authority: RootAuthority


@dataclass
class _RuntimeState:
    label: str
    root: Path
    port: int
    capability: LocalCapability
    bundle: dict[str, Any]
    process: subprocess.Popen[bytes] | None = None


def _create_identity() -> _Identity:
    root_seeds = tuple(_seed(f"root:{index}") for index in range(3))
    recovery_seeds = tuple(_seed(f"recovery:{index}") for index in range(3))
    genesis = create_synthetic_genesis_in_process(
        root_seeds,
        2,
        recovery_seeds,
        2,
        created_at_ms=0,
        nonce=_seed("being"),
    )
    state = verify_genesis(genesis)
    signing_seeds: dict[str, bytes] = {}
    encryption_seeds: dict[str, bytes] = {}
    credentials: dict[str, Mapping[str, Any]] = {}
    incarnations: dict[str, Mapping[str, Any]] = {}
    origins: dict[str, Mapping[str, str]] = {}
    rows: list[dict[str, Any]] = []
    for index, label in enumerate(("legion", "daimonmatrix"), start=1):
        signing = _seed(f"{label}:signing")
        encryption = _seed(f"{label}:encryption")
        signing_seeds[label] = signing
        encryption_seeds[label] = encryption
        origin = {
            "body_ref": f"cluster:{label}:synthetic-compaii",
            "embodiment_id": f"embodiment:07000000-0000-4000-8000-{index:012d}",
            "incarnation_id": f"incarnation:07000000-0000-4000-8000-{index:012d}",
            "principal_id": f"synthetic-compaii@{label}",
        }
        credential = create_embodiment_credential(
            state,
            root_seeds,
            signing,
            x25519_public(encryption),
            embodiment_id=origin["embodiment_id"],
            body_ref=origin["body_ref"],
            purposes=["dm.we", "messages"],
            valid_from_ms=0,
            valid_until_ms=MAX_TIME,
            transport_principals=[_transport(label, origin["principal_id"])],
        )
        incarnation = create_incarnation_authorization(
            credential,
            signing,
            incarnation_id=origin["incarnation_id"],
            incarnation_sequence=0,
            started_at_ms=0,
        )
        credentials[credential["artifact_id"]] = credential
        incarnations[incarnation["artifact_id"]] = incarnation
        origins[label] = origin
        rows.append(
            {
                "body_ref": origin["body_ref"],
                "embodiment_credential_id": credential["artifact_id"],
                "embodiment_id": origin["embodiment_id"],
                "incarnation_authorization_id": incarnation["artifact_id"],
                "incarnation_id": origin["incarnation_id"],
                "status": "active",
            }
        )
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    manifest = BeingManifest.from_value(
        {
            "schema": "being-manifest/v2",
            "being_ref": state.being_ref,
            "control_head": state.head,
            "history_binding_id": None,
            "revision": 1,
            "embodiments": rows,
        }
    )
    authority = RootAuthority(manifest, state, credentials, incarnations)
    return _Identity(
        root_seeds,
        genesis,
        state,
        signing_seeds,
        encryption_seeds,
        credentials,
        incarnations,
        origins,
        manifest,
        authority,
    )


def _credential(identity: _Identity, label: str) -> Mapping[str, Any]:
    embodiment_id = identity.origins[label]["embodiment_id"]
    return next(
        value
        for value in identity.credentials.values()
        if value["body"]["embodiment_id"] == embodiment_id
    )


def _runtime_bundle(
    root: Path,
    identity: _Identity,
    label: str,
    port: int,
) -> _RuntimeState:
    root.mkdir(mode=0o700)
    capability = create_capability(
        _seed(f"{label}:capability"),
        client_id=f"client:dm070:{label}",
        methods=sorted(METHODS | SCOPE_METHODS | {"runtime.status"}),
        not_before_ms=0,
        not_after_ms=MAX_TIME,
    )
    signing_slot = f"runtime.signing.v1:{label}"
    capability_slot = f"runtime.capability.v1:{label}"
    encryption_slot = f"peer.encryption.v1:{label}"
    EncryptedKeystore.create(
        root / "custody.json",
        lambda: bytearray(PASSWORD),
        control_head=identity.state.head,
        secrets={
            signing_slot: identity.signing_seeds[label],
            capability_slot: capability.key,
            encryption_slot: identity.encryption_seeds[label],
        },
    )
    bundle: dict[str, Any] = {
        "schema": "dm.runtime.bundle/v3",
        "control_artifacts": [identity.genesis],
        "control_head": identity.state.head,
        "manifest": identity.manifest.value,
        "authority_history": [],
        "credentials": list(identity.credentials.values()),
        "incarnations": list(identity.incarnations.values()),
        "binding": None,
        "binding_activation": None,
        "provisional_history": None,
        "local_origin": identity.origins[label],
        "ledger": "ledger.sqlite",
        "socket": "matrix.sock",
        "keystore": {
            "filename": "custody.json",
            "counter": 1,
            "signing_slot": signing_slot,
        },
        "capabilities": [
            {
                "descriptor": capability.descriptor,
                "secret_slot": capability_slot,
            }
        ],
        "routing": None,
        "scopes": None,
        "peer_transport": {
            "enabled": True,
            "encryption_slot": encryption_slot,
            "exchange_filename": "peer-exchange.sqlite",
            "listen_host": "127.0.0.1",
            "listen_port": port,
            "outbox_filename": "peer-outbox.sqlite",
        },
    }
    _write_private(root / "runtime.json", bundle)
    return _RuntimeState(label, root, port, capability, bundle)


def _worker(state_root: Path, password_fd: int, ready_fd: int) -> int:
    stopping = threading.Event()
    lock_descriptor: int | None = None
    try:
        lock_descriptor = acquire_lock(state_root)
        password = os.read(password_fd, 33)
        os.close(password_fd)
        if password != PASSWORD:
            return 1
        from .runtime import load_runtime

        runtime = load_runtime(
            state_root,
            "runtime.json",
            lambda: bytearray(password),
            clock=lambda: NOW,
        )

        def stop(_number: int, _frame: object) -> None:
            stopping.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        serve_forever(runtime, stop=stopping, ready_descriptor=ready_fd)
        return 0
    except Exception:
        with suppress(OSError):
            os.close(ready_fd)
        return 1
    finally:
        if lock_descriptor is not None:
            os.close(lock_descriptor)


def _start(runtime: _RuntimeState) -> None:
    if runtime.process is not None:
        raise SyntheticMultihostError("synthetic_daemon_already_running")
    password_read, password_write = os.pipe()
    ready_read, ready_write = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "daimon_matrix.synthetic_multihost",
            "--daemon-worker",
            "--state-root",
            os.fspath(runtime.root),
            "--password-fd",
            str(password_read),
            "--ready-fd",
            str(ready_write),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(password_read, ready_write),
    )
    os.close(password_read)
    os.close(ready_write)
    os.write(password_write, PASSWORD)
    os.close(password_write)
    ready, _, _ = select.select([ready_read], [], [], 15)
    try:
        if not ready or os.read(ready_read, 6) != b"READY\n":
            process.terminate()
            process.communicate(timeout=5)
            raise SyntheticMultihostError("synthetic_daemon_not_ready")
    finally:
        os.close(ready_read)
    runtime.process = process


def _stop(runtime: _RuntimeState) -> None:
    process = runtime.process
    if process is None:
        raise SyntheticMultihostError("synthetic_daemon_not_running")
    process.terminate()
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired as exception:
        process.kill()
        process.communicate(timeout=5)
        raise SyntheticMultihostError("synthetic_daemon_stop_timeout") from exception
    runtime.process = None
    if process.returncode != 0 or stdout or len(stderr) > MAX_PROCESS_OUTPUT:
        raise SyntheticMultihostError("synthetic_daemon_failed")
    diagnostics = [json.loads(line) for line in stderr.splitlines() if line]
    if [item.get("code") for item in diagnostics] != ["ready", "stopped"]:
        raise SyntheticMultihostError("synthetic_daemon_diagnostics_invalid")


class _Nonce:
    def __init__(self, label: str) -> None:
        self.label = label
        self.counter = 0

    def __call__(self, length: int) -> bytes:
        if length != 16:
            raise SyntheticMultihostError("synthetic_nonce_length")
        self.counter += 1
        return hashlib.sha256(f"{self.label}:{self.counter}".encode()).digest()[:16]


def _client(runtime: _RuntimeState, origin: Mapping[str, str]) -> LocalClient:
    return LocalClient(
        runtime.root / "matrix.sock",
        ClientConfig(runtime.capability, copy.deepcopy(dict(origin))),
        clock=lambda: NOW,
        nonce_factory=_Nonce(runtime.label),
    )


class _CarrierGate:
    def __init__(self, endpoint: str) -> None:
        self.exchange = http_peer_round_trip(endpoint, timeout_seconds=3)
        self.partitioned = True
        self.requests: list[bytes] = []
        self.responses: list[bytes] = []

    def __call__(self, raw: bytes) -> bytes:
        self.requests.append(bytes(raw))
        if self.partitioned:
            raise ConnectionError("synthetic partition")
        response = self.exchange(raw)
        self.responses.append(bytes(response))
        return response


def _peer_client(
    identity: _Identity,
    runtime: _RuntimeState,
    label: str,
    authority: RootAuthority,
    origin: Mapping[str, str],
    gate: _CarrierGate,
) -> PeerClient:
    credential = _credential(identity, label)
    signing_slot = f"runtime.signing.v1:{label}"
    encryption_slot = f"peer.encryption.v1:{label}"
    custody = KeystorePeerCustody(
        secrets={
            signing_slot: identity.signing_seeds[label],
            encryption_slot: identity.encryption_seeds[label],
        },
        signing_slots={credential["body"]["signing_key"]["key_id"]: signing_slot},
        encryption_slots={
            credential["body"]["encryption_key"]["key_id"]: encryption_slot
        },
    )
    return PeerClient(
        authority=authority,
        local_origin=origin,
        local_target=RecipientTarget(authority, credential["artifact_id"]),
        custody=custody,
        outbox=PeerOutbox(runtime.root / "peer-outbox.sqlite"),
        round_trip=gate,
        clock=lambda: NOW,
    )


def _result(response: Mapping[str, Any]) -> dict[str, Any]:
    if response.get("ok") is not True or not isinstance(
        response.get("result"), Mapping
    ):
        raise SyntheticMultihostError("synthetic_local_call_refused")
    return copy.deepcopy(dict(response["result"]))


def _observe(
    client: LocalClient,
    *,
    rpc_id: str,
    event_id: str,
    subject: str,
    summary: str,
) -> dict[str, Any]:
    _, response = client.we_observe(
        {
            "subject": subject,
            "payload": {"summary": summary},
            "sensitivity": "shareable",
            "causal_parents": [],
            "occurred_at_ms": NOW,
            "event_id": event_id,
        },
        request_id=rpc_id,
    )
    return cast(dict[str, Any], _result(response)["event"])


def _decide(
    client: LocalClient,
    *,
    rpc_id: str,
    event_id: str,
    target_id: str,
    decision: str,
    supersedes: str | None,
) -> dict[str, Any]:
    _, response = client.we_decide(
        {
            "target_event_id": target_id,
            "decision": decision,
            "reason": f"synthetic local {decision}",
            "sensitivity": "shareable",
            "supersedes": supersedes,
            "occurred_at_ms": NOW + 1,
            "event_id": event_id,
        },
        request_id=rpc_id,
    )
    return cast(dict[str, Any], _result(response)["event"])


@dataclass(frozen=True)
class _Transfer:
    request: Mapping[str, Any]
    delta: Mapping[str, Any]
    receipt: Mapping[str, Any]
    request_rpc: Mapping[str, Any]
    pull_rpc: Mapping[str, Any]

    @property
    def public(self) -> dict[str, str]:
        return {
            "request_hash": cast(str, self.delta["request_hash"]),
            "page_hash": cast(str, self.delta["page_hash"]),
            "receipt_hash": cast(str, self.receipt["receipt_hash"]),
        }


def _sync_request(
    client: LocalClient, *, document_id: str, rpc_id: str, limit: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = client.prepare(
        "we.sync.request",
        {"request_id": document_id, "limit": limit},
        request_id=rpc_id,
    )
    return prepared, _result(client.send(prepared))


def _peer_delta(
    peer: PeerClient,
    request: Mapping[str, Any],
    target: RecipientTarget,
) -> dict[str, Any]:
    return copy.deepcopy(
        dict(
            peer.call(
                request,
                recipient_target=target,
                request_content_type="application/vnd.daimon.sync-request+json",
                response_content_type="application/vnd.daimon.sync-delta+json",
                correlation_id=cast(str, request["request_id"]),
                deadline_ms=NOW + 30_000,
            )
        )
    )


def _pull(
    client: LocalClient,
    *,
    delta: Mapping[str, Any],
    sender: Mapping[str, str],
    rpc_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    prepared = client.prepare(
        "we.sync.pull",
        {
            "delta": delta,
            "transport": {
                "scheme": TRANSPORT_SCHEME,
                "principal_id": sender["principal_id"],
            },
        },
        request_id=rpc_id,
    )
    return prepared, _result(client.send(prepared))


def _projection(client: LocalClient, request_id: str) -> dict[str, Any]:
    _, response = client.projection_rebuild(request_id=request_id)
    return _result(response)


def _entry(snapshot: Mapping[str, Any], event_id: str) -> Mapping[str, Any]:
    rows = snapshot.get("entries")
    if not isinstance(rows, list):
        raise SyntheticMultihostError("synthetic_projection_invalid")
    matches = [row for row in rows if row.get("event_id") == event_id]
    if len(matches) != 1:
        raise SyntheticMultihostError("synthetic_projection_target_missing")
    return cast(Mapping[str, Any], matches[0])


def _advance_authority(
    identity: _Identity,
) -> tuple[_Identity, Mapping[str, Any], Mapping[str, str]]:
    previous_origin = identity.origins["legion"]
    credential = _credential(identity, "legion")
    successor_origin = {
        **previous_origin,
        "incarnation_id": "incarnation:07000000-0000-4000-8000-000000000101",
    }
    successor_authorization = create_incarnation_authorization(
        credential,
        identity.signing_seeds["legion"],
        incarnation_id=successor_origin["incarnation_id"],
        incarnation_sequence=1,
        started_at_ms=NOW,
    )
    incarnations = {
        **identity.incarnations,
        successor_authorization["artifact_id"]: successor_authorization,
    }
    rows = []
    for row in identity.manifest.value["embodiments"]:
        if row["embodiment_id"] == previous_origin["embodiment_id"]:
            rows.append(
                {
                    **row,
                    "status": "retired",
                }
            )
            rows.append(
                {
                    **row,
                    "incarnation_authorization_id": successor_authorization[
                        "artifact_id"
                    ],
                    "incarnation_id": successor_origin["incarnation_id"],
                }
            )
        else:
            rows.append(copy.deepcopy(row))
    rows.sort(key=lambda row: (row["embodiment_id"], row["incarnation_id"]))
    manifest = BeingManifest.from_value(
        {
            **identity.manifest.value,
            "revision": identity.manifest.value["revision"] + 1,
            "embodiments": rows,
        }
    )
    authority = RootAuthority(
        manifest,
        identity.state,
        identity.credentials,
        incarnations,
    )
    transition = create_authority_epoch(
        identity.manifest,
        manifest,
        embodiment_id=previous_origin["embodiment_id"],
        previous_incarnation_id=previous_origin["incarnation_id"],
        successor_authorization=successor_authorization,
        signing_seed=identity.signing_seeds["legion"],
        issued_at_ms=NOW,
    )
    origins = {**identity.origins, "legion": successor_origin}
    return (
        _Identity(
            identity.root_seeds,
            identity.genesis,
            identity.state,
            identity.signing_seeds,
            identity.encryption_seeds,
            identity.credentials,
            incarnations,
            origins,
            manifest,
            authority,
        ),
        transition,
        successor_origin,
    )


def _update_bundle(
    runtime: _RuntimeState,
    previous: _Identity,
    current: _Identity,
    transition: Mapping[str, Any],
) -> None:
    bundle = {
        **runtime.bundle,
        "manifest": current.manifest.value,
        "authority_history": [
            {"manifest": previous.manifest.value, "successor": transition}
        ],
        "incarnations": list(current.incarnations.values()),
        "local_origin": current.origins[runtime.label],
    }
    _replace_private(runtime.root / "runtime.json", bundle)
    runtime.bundle = copy.deepcopy(bundle)


def _cluster_evidence(
    identity: _Identity,
    event_hash_before: str,
    event_hash_after: Callable[[], str],
) -> dict[str, Any]:
    holder = identity.origins["legion"]
    other = identity.origins["daimonmatrix"]
    shared = "synthetic-resource:shared"
    independent = "synthetic-resource:independent"
    truth: dict[str, tuple[str, int]] = {
        shared: (holder["embodiment_id"], 7),
        independent: (other["embodiment_id"], 3),
    }

    def verifier(evidence: Mapping[str, Any], at_ms: int) -> Mapping[str, Any]:
        current = truth.get(cast(str, evidence["resource_ref"]))
        return {
            "schema": FENCE_VERIFICATION_SCHEMA,
            "content_hash": evidence["content_hash"],
            "resource_ref": evidence["resource_ref"],
            "holder_embodiment_id": evidence["holder_embodiment_id"],
            "epoch": evidence["epoch"],
            "verified_at_ms": at_ms,
            "current": current == (evidence["holder_embodiment_id"], evidence["epoch"]),
        }

    snapshot = {
        "schema": BODY_SNAPSHOT_SCHEMA,
        "body_ref": holder["body_ref"],
        "embodiment_id": holder["embodiment_id"],
        "incarnation_id": holder["incarnation_id"],
        "observed_at_ms": NOW,
        "state": "running",
        "resource_fences": [{"resource_ref": shared, "epoch": 7}],
    }
    validate_body_snapshot(
        snapshot,
        body_ref=holder["body_ref"],
        embodiment_id=holder["embodiment_id"],
        incarnation_id=holder["incarnation_id"],
        evaluated_at_ms=NOW,
    )
    accepted = create_resource_fence_evidence(
        body_ref=holder["body_ref"],
        holder_embodiment_id=holder["embodiment_id"],
        holder_incarnation_id=holder["incarnation_id"],
        resource_ref=shared,
        epoch=7,
        observed_at_ms=NOW,
        expires_at_ms=NOW + 1_000,
        verification_ref="cluster-proof:dm070:shared:7",
    )
    verify_resource_fence_evidence(accepted, at_ms=NOW, verifier=verifier)
    second = create_resource_fence_evidence(
        body_ref=other["body_ref"],
        holder_embodiment_id=other["embodiment_id"],
        holder_incarnation_id=other["incarnation_id"],
        resource_ref=shared,
        epoch=7,
        observed_at_ms=NOW,
        expires_at_ms=NOW + 1_000,
        verification_ref="cluster-proof:dm070:shared:second",
    )
    second_code = ""
    try:
        verify_resource_fence_evidence(second, at_ms=NOW, verifier=verifier)
    except ClusterEvidenceError as exception:
        second_code = exception.code
    if second_code != "fence_not_current":
        raise SyntheticMultihostError("synthetic_same_resource_fence_failed")
    separate = create_resource_fence_evidence(
        body_ref=other["body_ref"],
        holder_embodiment_id=other["embodiment_id"],
        holder_incarnation_id=other["incarnation_id"],
        resource_ref=independent,
        epoch=3,
        observed_at_ms=NOW,
        expires_at_ms=NOW + 1_000,
        verification_ref="cluster-proof:dm070:independent:3",
    )
    verify_resource_fence_evidence(separate, at_ms=NOW, verifier=verifier)
    intent = {"operation": "claim", "resource_ref": shared}
    postcondition = {"holder": "legion", "epoch": 7}
    effect = create_effect_receipt(
        effect_id="07000000-0000-4000-8000-000000000901",
        target_event_id="07000000-0000-4000-8000-000000000001",
        decision_event_id="07000000-0000-4000-8000-000000000301",
        adapter="synthetic-cluster/v1",
        preview_hash="a" * 64,
        intent_hash=hashlib.sha256(canonical_bytes(intent)).hexdigest(),
        actor="synthetic-compaii@legion",
        authority="daimon",
        resource_fence=resource_fence_position(accepted),
        result="applied",
        observed_postcondition=postcondition,
        started_at_ms=NOW,
        completed_at_ms=NOW,
    )
    truth[shared] = (other["embodiment_id"], 8)
    current = create_resource_fence_evidence(
        body_ref=other["body_ref"],
        holder_embodiment_id=other["embodiment_id"],
        holder_incarnation_id=other["incarnation_id"],
        resource_ref=shared,
        epoch=8,
        observed_at_ms=NOW,
        expires_at_ms=NOW + 1_000,
        verification_ref="cluster-proof:dm070:shared:8",
    )
    stale = reconcile_effect_receipt(
        effect,
        intent=intent,
        observed_postcondition=postcondition,
        at_ms=NOW,
        current_fence_evidence=current,
        fence_verifier=verifier,
    )
    if stale["status"] != "effect-truth-discrepancy":
        raise SyntheticMultihostError("synthetic_stale_fence_replay_accepted")
    if event_hash_after() != event_hash_before:
        raise SyntheticMultihostError("synthetic_fence_changed_history")
    return {
        "body_snapshot_hash": _sha(snapshot),
        "accepted_fence_hash": accepted["content_hash"],
        "same_resource_second_holder": second_code,
        "stale_replay": stale["status"],
        "different_resource": "verified",
        "ordinary_events_unaffected": True,
    }


def run_synthetic_multihost(
    work_root: Path,
    *,
    source_commit: str,
    cluster_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the real installed path and return only bounded public evidence."""

    if len(source_commit) != 40 or any(
        character not in "0123456789abcdef" for character in source_commit
    ):
        raise SyntheticMultihostError("invalid_source_commit")
    root = _owner_root(work_root)
    provenance = validate_cluster_provenance(cluster_provenance)
    initial = _create_identity()
    runtimes = {
        label: _runtime_bundle(root / label, initial, label, _available_port())
        for label in ("legion", "daimonmatrix")
    }
    restarts = 0
    sync_rows: dict[str, list[dict[str, str]]] = {
        "forward": [],
        "reverse": [],
    }
    processes = list(runtimes.values())
    for runtime in processes:
        _start(runtime)
    current = initial
    transition: Mapping[str, Any] | None = None
    try:
        clients = {
            label: _client(runtimes[label], current.origins[label])
            for label in runtimes
        }
        me_hashes: list[str] = []
        we_hashes: list[str] = []
        for index, label in enumerate(("legion", "daimonmatrix"), start=1):
            _, me = clients[label].scope_me(
                request_id=f"07000000-0000-4000-8100-{index:012d}"
            )
            _, we = clients[label].scope_we(
                request_id=f"07000000-0000-4000-8200-{index:012d}"
            )
            me_result = _result(me)
            we_result = _result(we)
            if (
                me_result.get("being_ref") != current.state.being_ref
                or we_result.get("being_ref") != current.state.being_ref
            ):
                raise SyntheticMultihostError("synthetic_scope_authority_mismatch")
            me_hashes.append(_sha(me_result))
            we_hashes.append(_sha(we_result))

        gates = {
            "forward": _CarrierGate(
                f"http://127.0.0.1:{runtimes['daimonmatrix'].port}/dm-peer/v1"
            ),
            "reverse": _CarrierGate(
                f"http://127.0.0.1:{runtimes['legion'].port}/dm-peer/v1"
            ),
        }
        peers = {
            "forward": _peer_client(
                current,
                runtimes["legion"],
                "legion",
                current.authority,
                current.origins["legion"],
                gates["forward"],
            ),
            "reverse": _peer_client(
                current,
                runtimes["daimonmatrix"],
                "daimonmatrix",
                current.authority,
                current.origins["daimonmatrix"],
                gates["reverse"],
            ),
        }
        targets = {
            label: RecipientTarget(
                current.authority, _credential(current, label)["artifact_id"]
            )
            for label in runtimes
        }

        failed_rpc, failed_request = _sync_request(
            clients["legion"],
            document_id="07000000-0000-4000-8000-000000000101",
            rpc_id="07000000-0000-4000-8300-000000000101",
            limit=1,
        )
        try:
            _peer_delta(peers["forward"], failed_request, targets["daimonmatrix"])
        except PeerTransportAmbiguous:
            partition_failure = "peer_transport_ambiguous"
        else:
            raise SyntheticMultihostError("synthetic_partition_not_enforced")
        partition_ciphertext = gates["forward"].requests[-1]
        if (
            canonical_bytes(failed_request) in partition_ciphertext
            or b"dm.sync.request/v1" in partition_ciphertext
        ):
            raise SyntheticMultihostError("synthetic_peer_plaintext_exposed")

        legion_events = [
            _observe(
                clients["legion"],
                rpc_id=f"07000000-0000-4000-8400-{index:012d}",
                event_id=f"07000000-0000-4000-8000-{index:012d}",
                subject=f"dm070-legion-{index}",
                summary="synthetic partitioned Legion evidence",
            )
            for index in (1, 2)
        ]
        daimonmatrix_events = [
            _observe(
                clients["daimonmatrix"],
                rpc_id=f"07000000-0000-4000-8500-{index:012d}",
                event_id=f"07000000-0000-4000-8001-{index:012d}",
                subject=f"dm070-daimonmatrix-{index}",
                summary="synthetic partitioned daimonmatrix evidence",
            )
            for index in (1, 2, 3)
        ]
        heads = {}
        for index, label in enumerate(("legion", "daimonmatrix"), start=1):
            _, response = clients[label].we_heads(
                request_id=f"07000000-0000-4000-8600-{index:012d}"
            )
            heads[label] = _result(response)
        if (
            len(heads["legion"]["heads"]) != 1
            or len(heads["daimonmatrix"]["heads"]) != 1
        ):
            raise SyntheticMultihostError("synthetic_partition_leaked_history")
        isolated_head_hashes = [
            _sha(heads[label]) for label in ("legion", "daimonmatrix")
        ]

        gates["forward"].partitioned = False
        first_delta = _peer_delta(
            peers["forward"], failed_request, targets["daimonmatrix"]
        )
        if gates["forward"].requests[-1] != partition_ciphertext:
            raise SyntheticMultihostError("synthetic_partition_retry_changed_bytes")
        partition_replay_exact = True
        first_pull, first_receipt = _pull(
            clients["legion"],
            delta=first_delta,
            sender=current.origins["daimonmatrix"],
            rpc_id="07000000-0000-4000-8700-000000000101",
        )
        first = _Transfer(
            failed_request,
            first_delta,
            first_receipt,
            failed_rpc,
            first_pull,
        )
        sync_rows["forward"].append(first.public)

        _stop(runtimes["legion"])
        _start(runtimes["legion"])
        restarts += 1
        clients["legion"] = _client(runtimes["legion"], current.origins["legion"])
        replay_request_response = _result(clients["legion"].send(failed_rpc))
        replay_delta = _peer_delta(
            peers["forward"], replay_request_response, targets["daimonmatrix"]
        )
        replay_receipt = _result(clients["legion"].send(first_pull))
        if canonical_bytes(replay_delta) != canonical_bytes(
            first_delta
        ) or canonical_bytes(replay_receipt) != canonical_bytes(first_receipt):
            raise SyntheticMultihostError("synthetic_after_commit_replay_changed")

        second_rpc, second_request = _sync_request(
            clients["legion"],
            document_id="07000000-0000-4000-8000-000000000102",
            rpc_id="07000000-0000-4000-8300-000000000102",
            limit=1,
        )
        second_delta = _peer_delta(
            peers["forward"], second_request, targets["daimonmatrix"]
        )
        _stop(runtimes["legion"])
        _start(runtimes["legion"])
        restarts += 1
        clients["legion"] = _client(runtimes["legion"], current.origins["legion"])
        second_request_replay = _result(clients["legion"].send(second_rpc))
        second_delta_replay = _peer_delta(
            peers["forward"], second_request_replay, targets["daimonmatrix"]
        )
        if canonical_bytes(second_delta_replay) != canonical_bytes(second_delta):
            raise SyntheticMultihostError("synthetic_before_commit_replay_changed")
        second_pull, second_receipt = _pull(
            clients["legion"],
            delta=second_delta_replay,
            sender=current.origins["daimonmatrix"],
            rpc_id="07000000-0000-4000-8700-000000000102",
        )
        second = _Transfer(
            second_request,
            second_delta,
            second_receipt,
            second_rpc,
            second_pull,
        )
        sync_rows["forward"].append(second.public)

        third_rpc, third_request = _sync_request(
            clients["legion"],
            document_id="07000000-0000-4000-8000-000000000103",
            rpc_id="07000000-0000-4000-8300-000000000103",
            limit=1,
        )
        third_delta = _peer_delta(
            peers["forward"], third_request, targets["daimonmatrix"]
        )
        third_pull, third_receipt = _pull(
            clients["legion"],
            delta=third_delta,
            sender=current.origins["daimonmatrix"],
            rpc_id="07000000-0000-4000-8700-000000000103",
        )
        third = _Transfer(
            third_request, third_delta, third_receipt, third_rpc, third_pull
        )
        sync_rows["forward"].append(third.public)

        gates["reverse"].partitioned = False

        def transfer(
            direction: str,
            receiver: str,
            sender: str,
            index: int,
            *,
            limit: int = 64,
        ) -> _Transfer:
            request_rpc, request = _sync_request(
                clients[receiver],
                document_id=f"07000000-0000-4000-8002-{index:012d}",
                rpc_id=f"07000000-0000-4000-8800-{index:012d}",
                limit=limit,
            )
            delta = _peer_delta(peers[direction], request, targets[sender])
            pull_rpc, receipt = _pull(
                clients[receiver],
                delta=delta,
                sender=current.origins[sender],
                rpc_id=f"07000000-0000-4000-8900-{index:012d}",
            )
            result = _Transfer(request, delta, receipt, request_rpc, pull_rpc)
            sync_rows[direction].append(result.public)
            return result

        transfer("reverse", "daimonmatrix", "legion", 201)

        legion_decision = _decide(
            clients["legion"],
            rpc_id="07000000-0000-4000-8a00-000000000301",
            event_id="07000000-0000-4000-8000-000000000301",
            target_id=legion_events[0]["event_id"],
            decision="adopt",
            supersedes=None,
        )
        daimonmatrix_decision = _decide(
            clients["daimonmatrix"],
            rpc_id="07000000-0000-4000-8a00-000000000302",
            event_id="07000000-0000-4000-8000-000000000302",
            target_id=legion_events[0]["event_id"],
            decision="reject",
            supersedes=None,
        )
        transfer("forward", "legion", "daimonmatrix", 202)
        transfer("reverse", "daimonmatrix", "legion", 203)
        before_reversal_legion = _entry(
            _projection(clients["legion"], "07000000-0000-4000-8b00-000000000301"),
            legion_events[0]["event_id"],
        )
        before_reversal_daimonmatrix = _entry(
            _projection(
                clients["daimonmatrix"],
                "07000000-0000-4000-8b00-000000000302",
            ),
            legion_events[0]["event_id"],
        )
        if (
            before_reversal_legion["state"] != "adopted"
            or before_reversal_daimonmatrix["state"] != "rejected"
        ):
            raise SyntheticMultihostError("synthetic_adoption_collapsed")
        reversal = _decide(
            clients["legion"],
            rpc_id="07000000-0000-4000-8a00-000000000303",
            event_id="07000000-0000-4000-8000-000000000303",
            target_id=legion_events[0]["event_id"],
            decision="revert",
            supersedes=legion_decision["event_id"],
        )
        transfer("reverse", "daimonmatrix", "legion", 204)
        legion_projection = _entry(
            _projection(clients["legion"], "07000000-0000-4000-8b00-000000000303"),
            legion_events[0]["event_id"],
        )
        daimonmatrix_projection = _entry(
            _projection(
                clients["daimonmatrix"],
                "07000000-0000-4000-8b00-000000000304",
            ),
            legion_events[0]["event_id"],
        )
        if (
            legion_projection["state"] != "reverted"
            or daimonmatrix_projection["state"] != "rejected"
        ):
            raise SyntheticMultihostError("synthetic_reversal_collapsed")

        noops = [
            transfer("forward", "legion", "daimonmatrix", 205),
            transfer("reverse", "daimonmatrix", "legion", 206),
        ]
        if any(item.receipt["received"] != 0 for item in noops):
            raise SyntheticMultihostError("synthetic_convergence_incomplete")
        files = [
            runtimes[label].root / name
            for label in ("legion", "daimonmatrix")
            for name in (
                "ledger.sqlite",
                "peer-exchange.sqlite",
                "peer-outbox.sqlite",
            )
        ]
        before_replay = {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files
        }
        for transfer_row, receiver, direction, sender in (
            (noops[0], "legion", "forward", "daimonmatrix"),
            (noops[1], "daimonmatrix", "reverse", "legion"),
        ):
            replayed_request = _result(clients[receiver].send(transfer_row.request_rpc))
            replayed_delta = _peer_delta(
                peers[direction], replayed_request, targets[sender]
            )
            replayed_receipt = _result(clients[receiver].send(transfer_row.pull_rpc))
            if canonical_bytes(replayed_delta) != canonical_bytes(
                transfer_row.delta
            ) or canonical_bytes(replayed_receipt) != canonical_bytes(
                transfer_row.receipt
            ):
                raise SyntheticMultihostError("synthetic_noop_replay_changed")
        after_replay = {
            path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files
        }
        write_free = before_replay == after_replay
        if not write_free:
            raise SyntheticMultihostError("synthetic_noop_replay_wrote_state")

        for runtime in processes:
            _stop(runtime)
        current, transition, successor_origin = _advance_authority(initial)
        history = RootHistoryAuthority(
            current.authority, [initial.authority], [transition]
        )
        Ledger(
            runtimes["legion"].root / "ledger.sqlite",
            authority=history,
            local_origin=current.origins["legion"],
            clock=lambda: NOW,
        ).initialize()
        old_probe = Ledger(
            runtimes["legion"].root / "ledger.sqlite",
            authority=history,
            local_origin=initial.origins["legion"],
            clock=lambda: NOW,
        )
        old_before = (runtimes["legion"].root / "ledger.sqlite").read_bytes()
        try:
            old_probe.append_local(
                kind="experience.observed",
                subject="dm070-forbidden-old-incarnation",
                payload={"summary": "must reject"},
                signer=EventSigner(
                    _credential(initial, "legion")["body"]["signing_key"]["key_id"],
                    initial.signing_seeds["legion"],
                ),
                occurred_at_ms=NOW + 3,
                event_id="07000000-0000-4000-8000-000000000999",
            )
        except WeaveProtocolError as exception:
            old_write_error = str(exception)
        else:
            raise SyntheticMultihostError("synthetic_old_incarnation_wrote")
        if (runtimes["legion"].root / "ledger.sqlite").read_bytes() != old_before:
            raise SyntheticMultihostError("synthetic_old_write_mutated_ledger")
        for runtime in processes:
            _update_bundle(runtime, initial, current, transition)
            _start(runtime)
            restarts += 1
        clients = {
            label: _client(runtimes[label], current.origins[label])
            for label in runtimes
        }
        gates = {
            "forward": _CarrierGate(
                f"http://127.0.0.1:{runtimes['daimonmatrix'].port}/dm-peer/v1"
            ),
            "reverse": _CarrierGate(
                f"http://127.0.0.1:{runtimes['legion'].port}/dm-peer/v1"
            ),
        }
        for gate in gates.values():
            gate.partitioned = False
        peers = {
            "forward": _peer_client(
                current,
                runtimes["legion"],
                "legion",
                current.authority,
                current.origins["legion"],
                gates["forward"],
            ),
            "reverse": _peer_client(
                current,
                runtimes["daimonmatrix"],
                "daimonmatrix",
                current.authority,
                current.origins["daimonmatrix"],
                gates["reverse"],
            ),
        }
        targets = {
            label: RecipientTarget(
                current.authority, _credential(current, label)["artifact_id"]
            )
            for label in runtimes
        }
        successor_event = _observe(
            clients["legion"],
            rpc_id="07000000-0000-4000-8c00-000000000401",
            event_id="07000000-0000-4000-8000-000000000401",
            subject="dm070-legion-successor",
            summary="synthetic authorized successor evidence",
        )
        successor_transfer = transfer("reverse", "daimonmatrix", "legion", 207)
        if successor_transfer.receipt["received"] != 1:
            raise SyntheticMultihostError("synthetic_successor_sync_failed")
    finally:
        for runtime in processes:
            if runtime.process is not None:
                _stop(runtime)

    if transition is None:
        raise SyntheticMultihostError("synthetic_authority_transition_missing")
    history = RootHistoryAuthority(current.authority, [initial.authority], [transition])
    ledgers = {
        label: Ledger(
            runtimes[label].root / "ledger.sqlite",
            authority=history,
            local_origin=current.origins[label],
            clock=lambda: NOW,
        )
        for label in runtimes
    }
    for ledger in ledgers.values():
        ledger.initialize()
        ledger.integrity_check()
    events = {label: ledger.events() for label, ledger in ledgers.items()}
    event_hashes = {label: event_set_hash(rows) for label, rows in events.items()}
    final_heads = {label: ledger.heads() for label, ledger in ledgers.items()}
    if event_hashes["legion"] != event_hashes["daimonmatrix"] or canonical_bytes(
        final_heads["legion"]
    ) != canonical_bytes(final_heads["daimonmatrix"]):
        raise SyntheticMultihostError("synthetic_final_convergence_failed")
    if len(events["legion"]) != 9:
        raise SyntheticMultihostError("synthetic_event_count_mismatch")
    old_head = next(
        row
        for row in final_heads["legion"]
        if row["incarnation_id"] == initial.origins["legion"]["incarnation_id"]
    )
    peer_old_head = next(
        row
        for row in final_heads["daimonmatrix"]
        if row["incarnation_id"] == initial.origins["legion"]["incarnation_id"]
    )
    old_high_water_preserved = (
        old_head == peer_old_head and old_head["max_sequence"] >= 4
    )
    if not old_high_water_preserved:
        raise SyntheticMultihostError("synthetic_old_high_water_lost")
    before_fence_hash = event_hashes["legion"]
    cluster = _cluster_evidence(
        current,
        before_fence_hash,
        lambda: event_set_hash(ledgers["legion"].events()),
    )

    ledger_paths = [runtimes[label].root / "ledger.sqlite" for label in runtimes]
    keystore_paths = [runtimes[label].root / "custody.json" for label in runtimes]
    request_paths = [runtimes[label].root / "peer-outbox.sqlite" for label in runtimes]
    if (
        len({path.stat().st_ino for path in ledger_paths}) != 2
        or len({path.stat().st_ino for path in keystore_paths}) != 2
        or len({path.stat().st_ino for path in request_paths}) != 2
    ):
        raise SyntheticMultihostError("synthetic_state_alias")

    origin_rows = []
    for label in ("legion", "daimonmatrix"):
        credential = _credential(current, label)
        origin_rows.append(
            {
                "label": label,
                "body_ref": current.origins[label]["body_ref"],
                "embodiment_id": current.origins[label]["embodiment_id"],
                "initial_incarnation_id": initial.origins[label]["incarnation_id"],
                "current_incarnation_id": current.origins[label]["incarnation_id"],
                "credential_id": credential["artifact_id"],
                "signing_key_id": credential["body"]["signing_key"]["key_id"],
                "encryption_key_id": credential["body"]["encryption_key"]["key_id"],
                "transport_key_id": credential["body"]["transport_principals"][0][
                    "key"
                ]["key_id"],
                "capability_id": runtimes[label].capability.capability_id,
                "state_fingerprint": _sha(
                    {
                        "label": label,
                        "embodiment_id": current.origins[label]["embodiment_id"],
                        "capability_id": runtimes[label].capability.capability_id,
                    }
                ),
            }
        )
    receipt_core = {
        "schema": RECEIPT_SCHEMA,
        "run_profile": RUN_PROFILE,
        "source_commit": source_commit,
        "package": {
            "name": "daimon-matrix",
            "version": "0.0.0",
            "entrypoint": "daimon-synthetic-multihost",
        },
        "authority": {
            "being_ref": current.state.being_ref,
            "control_head": current.state.head,
            "initial_manifest_hash": initial.manifest.digest,
            "successor_manifest_hash": current.manifest.digest,
            "embodiments": origin_rows,
        },
        "processes": {
            "daemon_count": 2,
            "simultaneously_awake": True,
            "me_response_hashes": me_hashes,
            "we_response_hashes": we_hashes,
            "restart_count": restarts,
            "fixed_test_clock_ms": NOW,
        },
        "partition": {
            "failed_request_id": failed_request["request_id"],
            "failed_request_hash": first_delta["request_hash"],
            "failure_code": partition_failure,
            "ciphertext_replayed_exactly": partition_replay_exact,
            "origin_event_ids": [
                [event["event_id"] for event in legion_events],
                [event["event_id"] for event in daimonmatrix_events],
            ],
            "isolated_heads_hashes": isolated_head_hashes,
            "opposite_ledgers_unaware": True,
        },
        "sync": {
            "transport_schema": PEER_SCHEMA,
            "transport_profile": PROFILE,
            "plaintext_absent": True,
            "fallback_absent": True,
            "directions": [
                {
                    "receiver_embodiment_id": current.origins["legion"][
                        "embodiment_id"
                    ],
                    "sender_embodiment_id": current.origins["daimonmatrix"][
                        "embodiment_id"
                    ],
                    "request_hashes": [
                        row["request_hash"] for row in sync_rows["forward"]
                    ],
                    "page_hashes": [row["page_hash"] for row in sync_rows["forward"]],
                    "receipt_hashes": [
                        row["receipt_hash"] for row in sync_rows["forward"]
                    ],
                    "pages": len(sync_rows["forward"]),
                },
                {
                    "receiver_embodiment_id": current.origins["daimonmatrix"][
                        "embodiment_id"
                    ],
                    "sender_embodiment_id": current.origins["legion"]["embodiment_id"],
                    "request_hashes": [
                        row["request_hash"] for row in sync_rows["reverse"]
                    ],
                    "page_hashes": [row["page_hash"] for row in sync_rows["reverse"]],
                    "receipt_hashes": [
                        row["receipt_hash"] for row in sync_rows["reverse"]
                    ],
                    "pages": len(sync_rows["reverse"]),
                },
            ],
            "interruptions": [
                {
                    "boundary": "after-receiver-commit",
                    **first.public,
                    "process_restarted": True,
                    "exact_replay": True,
                },
                {
                    "boundary": "before-receiver-commit",
                    **second.public,
                    "process_restarted": True,
                    "exact_replay": True,
                },
            ],
            "final_heads_hash": _sha(final_heads["legion"]),
            "event_set_hash": event_hashes["legion"],
            "event_count": len(events["legion"]),
            "write_free_exact_replay": write_free,
            "duplicate_count": 0,
        },
        "adoption": {
            "target_event_id": legion_events[0]["event_id"],
            "legion_decision_id": legion_decision["event_id"],
            "daimonmatrix_decision_id": daimonmatrix_decision["event_id"],
            "legion_reversal_id": reversal["event_id"],
            "legion_state": legion_projection["state"],
            "daimonmatrix_state": daimonmatrix_projection["state"],
            "legion_remote_evidence": legion_projection["remote_decision_event_ids"],
            "daimonmatrix_remote_evidence": daimonmatrix_projection[
                "remote_decision_event_ids"
            ],
            "immutable_decisions_preserved": all(
                ledgers["legion"].event(event_id) is not None
                for event_id in (
                    legion_decision["event_id"],
                    daimonmatrix_decision["event_id"],
                    reversal["event_id"],
                )
            ),
        },
        "succession": {
            "transition_id": "dm:authority-epoch:v1:"
            + b64url(bytes.fromhex(transition["content_hash"])),
            "previous_incarnation_id": initial.origins["legion"]["incarnation_id"],
            "successor_incarnation_id": successor_origin["incarnation_id"],
            "old_write_error": old_write_error,
            "new_event_id": successor_event["event_id"],
            "new_lane_sequence": successor_event["sequence"],
            "old_high_water_preserved": old_high_water_preserved,
            "sync_resumed": successor_transfer.receipt["received"] == 1,
        },
        "cluster": cluster,
        "historical": {
            "provenance_hash": provenance["provenance_hash"],
            "validation": "verified",
            "identity_authority": False,
            "event_authority": False,
            "adoption_authority": False,
            "fence_authority": False,
        },
        "isolation": {
            "state_roots_distinct": runtimes["legion"].root
            != runtimes["daimonmatrix"].root,
            "ledger_inodes_distinct": ledger_paths[0].stat().st_ino
            != ledger_paths[1].stat().st_ino,
            "keystore_inodes_distinct": keystore_paths[0].stat().st_ino
            != keystore_paths[1].stat().st_ino,
            "capabilities_distinct": runtimes["legion"].capability.key
            != runtimes["daimonmatrix"].capability.key,
            "signing_keys_distinct": current.signing_seeds["legion"]
            != current.signing_seeds["daimonmatrix"],
            "encryption_keys_distinct": current.encryption_seeds["legion"]
            != current.encryption_seeds["daimonmatrix"],
            "transport_principals_distinct": current.origins["legion"]["principal_id"]
            != current.origins["daimonmatrix"]["principal_id"],
            "request_journals_distinct": request_paths[0].stat().st_ino
            != request_paths[1].stat().st_ino,
            "no_shared_writable_state": True,
            "public_receipt_path_free": True,
            "public_receipt_secret_free": True,
            "no_live_host_mutation": True,
            "no_winner_election": True,
        },
        "schedule": list(SCHEDULE),
    }
    receipt = create_multihost_receipt(receipt_core)
    public = canonical_bytes(receipt)
    if any(
        os.fspath(path).encode() in public
        for path in (root, *ledger_paths, *keystore_paths)
    ):
        raise SyntheticMultihostError("synthetic_public_receipt_leaked_path")
    secrets_to_scan = [
        PASSWORD,
        *current.root_seeds,
        *current.signing_seeds.values(),
        *current.encryption_seeds.values(),
        *(runtime.capability.key for runtime in runtimes.values()),
    ]
    for secret in secrets_to_scan:
        if secret in public or b64url(secret).encode() in public:
            raise SyntheticMultihostError("synthetic_public_receipt_leaked_secret")
    return validate_multihost_receipt(receipt)


def _load_provenance(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise SyntheticMultihostError("cluster_provenance_unreadable") from exception
    if not isinstance(value, Mapping):
        raise SyntheticMultihostError("cluster_provenance_invalid")
    return copy.deepcopy(dict(value))


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    target = Path(os.path.abspath(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() or target.is_symlink():
        raise SyntheticMultihostError("synthetic_report_exists")
    _write_private(target, report)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state-root", type=Path, required=True)
    result.add_argument("--source-commit")
    result.add_argument("--cluster-provenance", type=Path)
    result.add_argument("--output", type=Path)
    result.add_argument("--daemon-worker", action="store_true", help=argparse.SUPPRESS)
    result.add_argument("--password-fd", type=int, help=argparse.SUPPRESS)
    result.add_argument("--ready-fd", type=int, help=argparse.SUPPRESS)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.daemon_worker:
        if args.password_fd is None or args.ready_fd is None:
            return 2
        return _worker(args.state_root, args.password_fd, args.ready_fd)
    if (
        args.source_commit is None
        or args.cluster_provenance is None
        or args.output is None
        or args.password_fd is not None
        or args.ready_fd is not None
    ):
        return 2
    try:
        report = run_synthetic_multihost(
            args.state_root,
            source_commit=args.source_commit,
            cluster_provenance=_load_provenance(args.cluster_provenance),
        )
        _write_report(args.output, report)
        sys.stdout.buffer.write(canonical_bytes(report) + b"\n")
        return 0
    except (MultihostEvidenceError, SyntheticMultihostError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SyntheticMultihostError", "main", "run_synthetic_multihost"]
