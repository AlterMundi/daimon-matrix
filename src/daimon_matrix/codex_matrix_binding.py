"""Public, current Matrix authority checks for explicit Codex admission.

This module never opens custody, a ledger, an inbox or a provider account.
Historical event validity alone is insufficient for starting a native body.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import os
import stat
import sys
import time
import types
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .canonical import b64url, canonical_bytes
from .client import (
    ClientConfig,
    ClientError,
    LocalClient,
    load_prepared_request,
    store_prepared_request,
)
from .cluster import ClusterEvidenceError, validate_body_snapshot
from .codex_body import (
    ATTESTED_BOOTSTRAP_SCHEMA,
    AppServerProcess,
    CodexBodyAdapter,
    CodexBodyError,
    CodexBodyPlan,
    RuntimeHandleJournal,
    _fsync_directory,
    _json_load,
    _read_secure_file,
    _secure_directory,
    _write_new_file,
    create_profile,
    validate_bootstrap,
    validate_native_provider_token,
)
from .identity import (
    VerificationError,
    verify_embodiment_credential,
    verify_incarnation_authorization,
)
from .local_api import CAPABILITY_DOMAIN, CAPABILITY_SCHEMA
from .operator_capabilities import (
    OperatorCapabilityError,
    verify_operator_capability_binding,
)
from .scopes import BodyReader
from .service import SERVICE_METHODS
from .weave import RootAuthority, WeaveProtocolError, verify_event

# Consumed source bytes from daimon-cluster:
# 676495e852e6772a60de8221271ee9fc976f77ce.
CLUSTER_READER_SOURCE_HASHES = {
    "__init__": "7944f2570561ec3f3e7e3b2e4bb225e763b2aed2c2268649ac3dc3e62de55898",
    "embodiments": "1aeace11f79e136da51485c81fae98aff0f55cc0504ca43911c5b1fe86451b80",
    "fences": "5273d04e3e5abb596d772591892973f3676b5615f80809e7af30e6d533393f64",
    "matrix_host": "b539a366ca19bc30fdfbcb4a3704bbea5e2bea59a2c2e9d17a10d76e5115df01",
}


def pinned_cluster_body_reader(
    checkout: Path, state_root: Path, embodiment_id: str
) -> BodyReader:
    """Load only the verified Cluster reader; never import ambient clusterctl.

    All consumed bytes are checked before any code executes. Private module
    names isolate the reader from workspace/PYTHONPATH modules. Cluster state
    remains owned by its host: this function registers, starts and stops nothing.
    """
    _secure_directory(state_root, "owner_cluster_state_unsafe")
    sources = {}
    for name, expected in CLUSTER_READER_SOURCE_HASHES.items():
        path = checkout / "clusterctl" / f"{name}.py"
        raw = _read_secure_file(path, "owner_cluster_source_unsafe", owner_only=False)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise CodexBodyError("owner_cluster_source_mismatch")
        sources[name] = (path, raw)
    namespace = "_dm_codex_cluster_" + uuid.uuid4().hex
    names = []
    try:
        for name, (path, raw) in sources.items():
            module_name = namespace if name == "__init__" else namespace + "." + name
            module = types.ModuleType(module_name)
            module.__file__ = str(path)
            module.__package__ = namespace
            if name == "__init__":
                module.__path__ = []
            sys.modules[module_name] = module
            names.append(module_name)
            exec(compile(raw, str(path), "exec"), module.__dict__)
        host = sys.modules[namespace + ".matrix_host"].MatrixHostAdapter(
            state_root, embodiment_id
        )
        return cast(BodyReader, host.body_snapshot)
    finally:
        for name in names:
            sys.modules.pop(name, None)


def owner_cluster_body_reader(
    *,
    checkout: Path | None,
    state_root: Path | None,
    socket_path: Path | None,
    owner_uid: int | None,
    embodiment_id: str,
) -> BodyReader:
    """Select one explicit transport without a permission-bypass fallback."""
    if socket_path is not None or owner_uid is not None:
        if (
            socket_path is None
            or owner_uid is None
            or checkout is not None
            or state_root is not None
        ):
            raise CodexBodyError("owner_cluster_locations_required")
        from .cluster_owner_client import cluster_owner_socket_reader

        return cluster_owner_socket_reader(socket_path, owner_uid=owner_uid)
    if checkout is None or state_root is None:
        raise CodexBodyError("owner_cluster_locations_required")
    return pinned_cluster_body_reader(checkout, state_root, embodiment_id)


@dataclass(frozen=True)
class SessionContinuity:
    """Verified supplied session proof chain, not a current-head or fence claim."""

    event: Mapping[str, Any]
    witness_sequence: int
    matrix_session_id: str


class SessionProofJournal:
    """Owner-only durable append/CAS storage for one exact attested session.

    Signed proofs are verified before every append or accepted load. A torn
    file is preserved and refused; this class never truncates or repairs it.
    """

    def __init__(self, path: Path, *, bootstrap: Mapping[str, Any]) -> None:
        self.path = Path(os.path.abspath(path))
        self.bootstrap = validate_bootstrap(bootstrap)
        if self.bootstrap["schema"] != ATTESTED_BOOTSTRAP_SCHEMA:
            raise CodexBodyError("session_attested_bootstrap_required")
        self.bootstrap_hash = hashlib.sha256(
            canonical_bytes(self.bootstrap)
        ).hexdigest()

    def _read(self, descriptor: int) -> list[dict[str, Any]]:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise CodexBodyError("session_proof_file_unsafe")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, 64 * 1024):
            size += len(chunk)
            if size > 4 * 1024 * 1024:
                raise CodexBodyError("session_proof_file_too_large")
            chunks.append(chunk)
        raw = b"".join(chunks)
        if raw and not raw.endswith(b"\n"):
            raise CodexBodyError("session_proof_file_torn")
        proofs: list[dict[str, Any]] = []
        previous = None
        for generation, line in enumerate(raw.splitlines()):
            record = _json_load(line, "session_proof_record_invalid")
            if not isinstance(record, Mapping) or set(record) != {
                "schema",
                "bootstrap_hash",
                "generation",
                "previous_record_hash",
                "event",
                "record_hash",
            }:
                raise CodexBodyError("session_proof_record_invalid")
            core = {key: value for key, value in record.items() if key != "record_hash"}
            if line != canonical_bytes(record):
                raise CodexBodyError("session_proof_record_noncanonical")
            digest = hashlib.sha256(
                b"daimon/codex-session-proof/v1\x00" + canonical_bytes(core)
            ).hexdigest()
            if (
                record["schema"] != "dm.codex-body.session-proof-record/v1"
                or record["bootstrap_hash"] != self.bootstrap_hash
                or isinstance(record["generation"], bool)
                or record["generation"] != generation
                or record["previous_record_hash"] != previous
                or record["record_hash"] != digest
                or not isinstance(record["event"], Mapping)
            ):
                raise CodexBodyError("session_proof_record_invalid")
            proofs.append(copy.deepcopy(dict(record["event"])))
            previous = digest
        return proofs

    def _open(self, *, write: bool) -> tuple[int, int]:
        _secure_directory(self.path.parent, "session_proof_parent_unsafe")
        parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            info = os.fstat(parent)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise CodexBodyError("session_proof_parent_unsafe")
            flags = os.O_RDWR | os.O_APPEND | os.O_CREAT if write else os.O_RDONLY
            descriptor = os.open(
                self.path.name,
                flags | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=parent,
            )
            file_info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_info.st_mode)
                or file_info.st_uid != os.geteuid()
                or file_info.st_nlink != 1
                or stat.S_IMODE(file_info.st_mode) & 0o077
            ):
                raise CodexBodyError("session_proof_file_unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            return parent, descriptor
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            os.close(parent)
            raise

    def load(
        self,
        *,
        expected_high_water: str,
        verifier: Callable[[Sequence[Any], str], SessionContinuity],
    ) -> list[dict[str, Any]]:
        try:
            parent, descriptor = self._open(write=False)
        except FileNotFoundError:
            verifier([], expected_high_water)
            return []
        try:
            proofs = self._read(descriptor)
            verifier(proofs, expected_high_water)
            return proofs
        finally:
            os.close(descriptor)
            os.close(parent)

    def append(
        self,
        event: Mapping[str, Any],
        *,
        expected_high_water: str,
        verifier: Callable[[Sequence[Any], str], SessionContinuity],
    ) -> None:
        proof = copy.deepcopy(dict(event))
        parent, descriptor = self._open(write=True)
        try:
            proofs = self._read(descriptor)
            verifier(proofs, expected_high_water)
            tip = (
                proofs[-1]["content_hash"]
                if proofs
                else self.bootstrap["matrix_high_water"]
            )
            if tip != expected_high_water:
                raise CodexBodyError("session_proof_compare_and_swap_failed")
            verifier([*proofs, proof], proof.get("content_hash", ""))
            # Reconstruct the canonical record chain without replacing history.
            previous = None
            for generation, item in enumerate([*proofs, proof]):
                core = {
                    "schema": "dm.codex-body.session-proof-record/v1",
                    "bootstrap_hash": self.bootstrap_hash,
                    "generation": generation,
                    "previous_record_hash": previous,
                    "event": item,
                }
                previous = hashlib.sha256(
                    b"daimon/codex-session-proof/v1\x00" + canonical_bytes(core)
                ).hexdigest()
            raw = canonical_bytes({**core, "record_hash": previous}) + b"\n"
            if os.write(descriptor, raw) != len(raw):
                raise CodexBodyError("session_proof_write_incomplete")
            os.fsync(descriptor)
            os.fsync(parent)
        finally:
            os.close(descriptor)
            os.close(parent)


def session_witness_payload(
    bootstrap: Mapping[str, Any], previous: Mapping[str, Any], *, sequence: int
) -> dict[str, Any]:
    """Prepare public data; only the daemon may sign the resulting observation."""
    value = validate_bootstrap(bootstrap)
    if value["schema"] != ATTESTED_BOOTSTRAP_SCHEMA:
        raise CodexBodyError("session_attested_bootstrap_required")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise CodexBodyError("session_witness_sequence_invalid")
    try:
        return {
            "schema": "dm.codex-body.session-witness/v1",
            "matrix_session_id": value["matrix_session_id"],
            "bootstrap_event_hash": value["matrix_high_water"],
            "previous_event_id": previous["event_id"],
            "previous_event_hash": previous["content_hash"],
            "witness_sequence": sequence,
        }
    except KeyError as exception:
        raise CodexBodyError("session_witness_parent_invalid") from exception


def verify_session_continuity(
    bootstrap: Mapping[str, Any],
    witnesses: Sequence[Any],
    authority: RootAuthority,
    *,
    expected_high_water: str,
    **admission: Any,
) -> SessionContinuity:
    """Verify signed causal ancestry to an independently required saved tip.

    The caller owns durable proof storage and supplies the expected journal tip.
    This function never walks a ledger or inbox, fetches missing history,
    chooses between competing tips, or grants physical/resource authority.
    """
    verify_bootstrap_attestation(bootstrap, authority, **admission)
    if not isinstance(witnesses, Sequence) or isinstance(witnesses, (str, bytes)):
        raise CodexBodyError("session_witness_chain_invalid")
    value = validate_bootstrap(bootstrap)
    previous = value["attestation"]
    sequence = 0
    try:
        for sequence, proof in enumerate(witnesses, 1):
            event = verify_event(proof, authority)
            expected = session_witness_payload(value, previous, sequence=sequence)
            if (
                event["kind"] != "experience.observed"
                or event["subject"] != "codex-body/session-witness"
                or event["sensitivity"] != "private"
                or event["origin"] != admission["origin"]
                or event["manifest_hash"] != previous["manifest_hash"]
                or canonical_bytes(event["payload"]) != canonical_bytes(expected)
                or event["causal_parents"] != [previous["event_id"]]
                or event["sequence"] <= previous["sequence"]
                or not previous["occurred_at_ms"]
                <= event["occurred_at_ms"]
                <= admission["at_ms"]
            ):
                raise CodexBodyError("session_witness_chain_invalid")
            previous = event
        if previous["content_hash"] != expected_high_water:
            raise CodexBodyError("session_high_water_unproved")
        return SessionContinuity(
            copy.deepcopy(previous), sequence, value["matrix_session_id"]
        )
    except (WeaveProtocolError, KeyError, TypeError, ValueError) as exception:
        raise CodexBodyError("session_witness_chain_invalid") from exception


@dataclass(frozen=True)
class NativeBodyObservation:
    """Fresh Cluster observation; neither a Matrix lease nor a resource fence."""

    snapshot: Mapping[str, Any]
    fresh_until_ms: int


def observe_native_cluster_body(
    binding: CurrentMatrixBinding, reader: BodyReader, *, max_age_ms: int
) -> NativeBodyObservation:
    """Consume the trusted host's existing side-effect-free Cluster body reader.

    The freshness window is caller policy and grants no lifecycle authority.
    This helper never substitutes daemon health or manifest membership for
    Cluster observations, and never acquires or renews resource fences.
    """
    if (
        not isinstance(max_age_ms, int)
        or isinstance(max_age_ms, bool)
        or not 0 < max_age_ms < 2**53
    ):
        raise CodexBodyError("native_body_freshness_policy_invalid")
    try:
        snapshot = reader(
            binding.body_ref,
            binding.embodiment_id,
            binding.incarnation_id,
            binding.checked_at_ms,
        )
    except (OSError, RuntimeError, ValueError) as exception:
        raise CodexBodyError(
            "native_cluster_body_unavailable", retryable=True
        ) from exception
    try:
        value = validate_body_snapshot(
            snapshot,
            body_ref=binding.body_ref,
            embodiment_id=binding.embodiment_id,
            incarnation_id=binding.incarnation_id,
            evaluated_at_ms=binding.checked_at_ms,
        )
    except ClusterEvidenceError as exception:
        raise CodexBodyError("native_cluster_body_rejected") from exception
    until = min(value["observed_at_ms"] + max_age_ms, binding.capability_expires_at_ms)
    if value["state"] != "running" or until <= binding.checked_at_ms:
        raise CodexBodyError("native_cluster_body_not_current")
    return NativeBodyObservation(value, until)


def read_native_capability_key(descriptor: int) -> bytearray:
    """Read a protected seekable capability FD without changing its shared offset.

    Native App Server can start multiple MCP children sharing the inherited
    open-file description. Pipes are single-consumer and are refused here.
    The caller owns and closes this descriptor; key bytes never enter argv,
    environment, receipts or diagnostics.
    """
    if (
        not isinstance(descriptor, int)
        or isinstance(descriptor, bool)
        or descriptor < 3
    ):
        raise CodexBodyError("native_capability_descriptor_invalid")
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_nlink != 1
            or info.st_size != 32
        ):
            raise CodexBodyError("native_capability_descriptor_unsafe")
        key = os.pread(descriptor, 33, 0)
        if len(key) != 32:
            raise CodexBodyError("native_capability_descriptor_invalid")
        return bytearray(key)
    except OSError as exception:
        raise CodexBodyError("native_capability_descriptor_unavailable") from exception


def native_mcp_main(argv: list[str] | None = None) -> int:
    """Explicit native MCP entry point with one private key pipe per child."""
    from .mcp_server import main, parser

    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser().parse_args(arguments)
    if arguments.count("--capability-key-fd") != 1:
        print("native_capability_argument_invalid", file=sys.stderr)
        return 2
    position = arguments.index("--capability-key-fd") + 1
    source = args.capability_key_fd
    try:
        key = read_native_capability_key(source)
    except CodexBodyError as exception:
        print(exception.code, file=sys.stderr)
        return 2
    finally:
        with suppress(OSError):
            os.close(source)
    read_fd, write_fd = os.pipe()
    try:
        written = os.write(write_fd, key)
        if written != 32:
            raise CodexBodyError("native_capability_pipe_unavailable")
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
        key[:] = bytes(len(key))
    arguments[position] = str(read_fd)
    # The existing MCP entry point consumes and closes its private descriptor.
    return main(arguments)


def validate_current_runtime_status(status: Any, binding: CurrentMatrixBinding) -> None:
    """Match authenticated daemon metadata to the supplied root snapshot.

    This is a point-in-time epoch check, not a presence lease or resource fence.
    The caller must authenticate the response through the existing LocalClient.
    """
    expected_origin = {
        "body_ref": binding.body_ref,
        "embodiment_id": binding.embodiment_id,
        "incarnation_id": binding.incarnation_id,
        "principal_id": binding.principal_id,
    }
    try:
        if (
            not isinstance(status, Mapping)
            or status.get("schema") != "dm.runtime.status/v1"
            or status.get("integrity") != "ok"
            or status.get("being_ref") != binding.being_ref
            or status.get("local_origin") != expected_origin
            or status.get("manifest_hash") != binding.manifest_hash
        ):
            raise CodexBodyError("matrix_runtime_authority_mismatch")
        epoch = status["authority_epoch"]
        if not isinstance(epoch, Mapping) or set(epoch) != {
            "schema",
            "active_manifest_hash",
            "accepted_manifest_hashes",
            "epoch_count",
        }:
            raise CodexBodyError("matrix_runtime_authority_mismatch")
        accepted = epoch["accepted_manifest_hashes"]
        count = epoch["epoch_count"]
        if (
            epoch["schema"] != "dm.we.authority-epoch-status/v1"
            or epoch["active_manifest_hash"] != binding.manifest_hash
            or not isinstance(accepted, list)
            or any(not isinstance(item, str) for item in accepted)
            or not accepted
            or len(set(accepted)) != len(accepted)
            or binding.manifest_hash not in accepted
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count != len(accepted)
        ):
            raise CodexBodyError("matrix_runtime_authority_mismatch")
    except (KeyError, TypeError, ValueError) as exception:
        raise CodexBodyError("matrix_runtime_authority_mismatch") from exception


def check_current_runtime_authority(
    client: LocalClient, authority: RootAuthority, **admission: Any
) -> CurrentMatrixBinding:
    """Explicitly request authenticated metadata, never conversation contents."""
    binding = authenticate_matrix_binding(authority, **admission)
    selected = _admission_capability(
        admission["capability_rows"],
        capability_id=binding.capability_id,
        client_id=binding.client_id,
        runtime_id=binding.runtime_id,
        required_methods=frozenset({"runtime.status"}),
        at_ms=binding.checked_at_ms,
    )
    config = client.config
    if (
        config.capability.descriptor != selected
        or config.expected_server != admission["origin"]
        or config.runtime_id != binding.runtime_id
        or config.runtime_label != admission["runtime_label"]
    ):
        raise CodexBodyError("matrix_runtime_client_mismatch")
    try:
        response = client.send(client.prepare("runtime.status", {}))
    except ClientError as exception:
        raise CodexBodyError(
            "matrix_runtime_metadata_unavailable", retryable=True
        ) from exception
    if response.get("ok") is not True:
        raise CodexBodyError("matrix_runtime_metadata_rejected")
    validate_current_runtime_status(response.get("result"), binding)
    return binding


@dataclass(frozen=True)
class DaemonBootstrapVerifier:
    """Explicit startup verifier using the configured owner-local daemon."""

    client: LocalClient
    authority: RootAuthority
    admission: Mapping[str, Any]

    def __call__(self, bootstrap: Mapping[str, Any], at_ms: int) -> bool:
        arguments = {**copy.deepcopy(dict(self.admission)), "at_ms": at_ms}
        check_current_runtime_authority(self.client, self.authority, **arguments)
        verify_bootstrap_attestation(bootstrap, self.authority, **arguments)
        # Refuse an epoch change observed while the proof was being checked.
        check_current_runtime_authority(self.client, self.authority, **arguments)
        return True


def owner_local_admission(
    bundle: Mapping[str, Any], client: LocalClient, *, at_ms: int
) -> tuple[RootAuthority, dict[str, Any], CurrentMatrixBinding]:
    """Connect the public signed bundle to the daemon already serving it.

    This explicit operator preflight never loads a runtime or opens custody.
    A bundle is only a candidate authority snapshot: the authenticated socket
    must prove the same current epoch. There is no in-process fallback.
    """
    from .operator_rebirth import RebirthError, authority_from_runtime_bundle

    try:
        authority = authority_from_runtime_bundle(bundle)
        admission = {
            "origin": copy.deepcopy(bundle["local_origin"]),
            "runtime_id": bundle["runtime_id"],
            "runtime_label": bundle["runtime_label"],
            "capability_rows": copy.deepcopy(bundle["capabilities"]),
            "capability_binding": copy.deepcopy(bundle["operator_capability_binding"]),
            "capability_id": client.config.capability.capability_id,
            "client_id": client.config.capability.client_id,
            "required_methods": frozenset({"runtime.status", "we.heads", "we.observe"}),
            "at_ms": at_ms,
        }
        binding = check_current_runtime_authority(client, authority, **admission)
    except (RebirthError, KeyError, TypeError, ValueError) as exception:
        raise CodexBodyError("owner_local_admission_rejected") from exception
    return authority, admission, binding


def prepare_owner_bootstrap_request(
    bundle: Mapping[str, Any],
    client: LocalClient,
    request_path: Path,
    *,
    matrix_session_id: str,
    expires_at_ms: int,
    at_ms: int,
) -> dict[str, Any]:
    """Persist the bootstrap request after authenticated daemon authority queries.

    The saved we.observe request is not sent and no Matrix event is signed here.
    Authority queries do contact the live daemon and may update its request cache;
    this is not a pure offline preparation or a way around a live-operation gate.
    """
    _authority, _admission, binding = owner_local_admission(bundle, client, at_ms=at_ms)
    payload = bootstrap_attestation_payload(
        binding, matrix_session_id=matrix_session_id, expires_at_ms=expires_at_ms
    )
    request = client.prepare(
        "we.observe",
        {
            "subject": "codex-body/bootstrap",
            "payload": payload,
            "sensitivity": "private",
            "causal_parents": [],
            "occurred_at_ms": at_ms,
            "event_id": None,
        },
    )
    try:
        store_prepared_request(request_path, request)
    except ClientError as exception:
        raise CodexBodyError("owner_bootstrap_request_store_rejected") from exception
    return request


def attest_owner_bootstrap_request(
    bundle: Mapping[str, Any],
    client: LocalClient,
    request_path: Path,
    output_path: Path,
    *,
    matrix_session_id: str,
    expires_at_ms: int,
    at_ms: int,
) -> dict[str, Any]:
    """Send only the saved exact request and retain its verified public proof.

    Current authority is checked before sending. Response loss preserves the
    original request; an explicit retry uses its original ID/nonce/MAC/bytes.
    No fresh request is manufactured and no existing output is replaced.
    """
    authority, admission, _binding = owner_local_admission(bundle, client, at_ms=at_ms)
    raw = _json_load(
        _read_secure_file(request_path, "owner_bootstrap_request_rejected"),
        "owner_bootstrap_request_rejected",
    )
    try:
        issued_at_ms = raw["params"]["payload"]["bootstrap"]["issued_at_ms"]
        if not issued_at_ms <= at_ms < expires_at_ms:
            raise CodexBodyError("owner_bootstrap_interval_rejected")
        initial = authenticate_matrix_binding(
            authority, **{**admission, "at_ms": issued_at_ms}
        )
        params = {
            "subject": "codex-body/bootstrap",
            "payload": bootstrap_attestation_payload(
                initial,
                matrix_session_id=matrix_session_id,
                expires_at_ms=expires_at_ms,
            ),
            "sensitivity": "private",
            "causal_parents": [],
            "occurred_at_ms": issued_at_ms,
            "event_id": None,
        }
        request = load_prepared_request(
            request_path, client.config.capability, method="we.observe", params=params
        )
        if request != raw:
            raise CodexBodyError("owner_bootstrap_request_changed")
        # Validate output's parent before producing any Matrix effect.
        _secure_directory(output_path.parent, "owner_bootstrap_output_unsafe")
    except (ClientError, KeyError, TypeError, ValueError) as exception:
        raise CodexBodyError("owner_bootstrap_request_rejected") from exception
    try:
        response = client.send(request)
    except ClientError as exception:
        raise CodexBodyError(
            "owner_bootstrap_response_unavailable", retryable=True
        ) from exception
    if response.get("ok") is not True:
        raise CodexBodyError("owner_bootstrap_attestation_rejected")
    try:
        bootstrap = bootstrap_from_attestation(
            response["result"]["event"], authority, **admission
        )
    except (KeyError, TypeError) as exception:
        raise CodexBodyError("owner_bootstrap_attestation_rejected") from exception
    content = canonical_bytes(bootstrap)
    if output_path.exists() or output_path.is_symlink():
        if _read_secure_file(output_path, "owner_bootstrap_output_unsafe") != content:
            raise CodexBodyError("owner_bootstrap_output_conflict")
    else:
        _write_new_file(output_path, content, 0o600)
        _fsync_directory(output_path.parent)
    return bootstrap


@dataclass(frozen=True)
class NativeAdmissionVerifier:
    """Compose current daemon authority, durable ancestry and Cluster metadata.

    Called only for an explicitly requested lifecycle action. The returned
    legacy adapter shape conveys a freshness deadline, never a Matrix lease
    or authority to start/stop a physical body or acquire resource fences.
    """

    client: LocalClient
    authority: RootAuthority
    admission: Mapping[str, Any]
    journal: SessionProofJournal
    body_reader: BodyReader
    max_age_ms: int

    def __call__(self, requested: Mapping[str, Any], at_ms: int) -> dict[str, Any]:
        bootstrap = self.journal.bootstrap
        fields = {
            "being_ref",
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "matrix_session_id",
            "matrix_high_water",
        }
        if (
            not isinstance(requested, Mapping)
            or set(requested) != fields
            or any(
                requested[key] != bootstrap[key]
                for key in fields - {"matrix_high_water"}
            )
        ):
            raise CodexBodyError("native_admission_binding_mismatch")
        arguments = {**copy.deepcopy(dict(self.admission)), "at_ms": at_ms}
        binding = check_current_runtime_authority(
            self.client, self.authority, **arguments
        )

        def verify(proofs: Sequence[Any], tip: str) -> SessionContinuity:
            return verify_session_continuity(
                bootstrap,
                proofs,
                self.authority,
                expected_high_water=tip,
                **arguments,
            )

        self.journal.load(
            expected_high_water=requested["matrix_high_water"], verifier=verify
        )
        observation = observe_native_cluster_body(
            binding,
            self.body_reader,
            max_age_ms=self.max_age_ms,
        )
        check_current_runtime_authority(self.client, self.authority, **arguments)
        return {
            **{key: requested[key] for key in fields - {"being_ref"}},
            "state": "active",
            "expires_at_ms": min(
                observation.fresh_until_ms, bootstrap["expires_at_ms"]
            ),
        }


@dataclass(frozen=True)
class OwnerNativeSession:
    """One explicitly opened native process with owner-local admission.

    The host supplies its trusted, live Cluster reader; a cached JSON snapshot
    or daemon health is not a substitute. Opening initializes the protocol,
    but does not start a thread, submit input, read messages or sign events.
    The caller requests start/resume/recovery/park through ``adapter``.
    ``close`` releases the native transport without inventing a park receipt.
    """

    adapter: CodexBodyAdapter
    process: AppServerProcess

    def close(self) -> None:
        self.process.close()


def open_owner_native_session(
    plan: CodexBodyPlan,
    bundle: Mapping[str, Any],
    client: LocalClient,
    *,
    body_reader: BodyReader,
    proof_journal_path: Path,
    max_age_ms: int,
    create: bool = False,
    provider_token: str | None = None,
    clock: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
) -> OwnerNativeSession:
    """Compose the real socket, current Root, durable proofs and native body.

    Authority and physical observations are checked before any profile write
    or process spawn. The rendered MCP must use this exact client, socket and
    key descriptor. Failed initialization closes its child and preserves all
    profile/journal evidence; it never retries a launch or discovers a thread.
    """
    if provider_token is not None:
        validate_native_provider_token(provider_token)
    bootstrap = validate_bootstrap(plan.value["bootstrap"])
    if bootstrap["schema"] != ATTESTED_BOOTSTRAP_SCHEMA:
        raise CodexBodyError("owner_native_attested_bootstrap_required")
    key = read_native_capability_key(int(plan.mcp_args[5]))
    try:
        # ClientConfig.load consumes and wipes a mutable key buffer.
        key_matches = hmac.compare_digest(key, client.config.capability.key)
        mcp_config = ClientConfig.load(Path(plan.mcp_args[3]), key)
        if (
            mcp_config != client.config
            or Path(plan.mcp_args[1]) != client.socket_path
            or not key_matches
        ):
            raise CodexBodyError("owner_native_mcp_binding_mismatch")
    except ClientError as exception:
        raise CodexBodyError("owner_native_mcp_binding_rejected") from exception
    finally:
        key[:] = bytes(len(key))
    authority, admission, _binding = owner_local_admission(
        bundle, client, at_ms=clock()
    )
    verifier = DaemonBootstrapVerifier(client, authority, admission)
    verifier(bootstrap, clock())
    proofs = SessionProofJournal(proof_journal_path, bootstrap=bootstrap)
    presence = NativeAdmissionVerifier(
        client, authority, admission, proofs, body_reader, max_age_ms
    )
    handles = None
    expected_high_water = bootstrap["matrix_high_water"]
    if not create:
        # Authenticate ancestry against the independently saved, profile-bound
        # handle tip. The proof journal cannot choose its own expected tip.
        handles = RuntimeHandleJournal(
            plan.profile_root / "runtime-handles.jsonl", plan=plan
        )
        saved_handles = handles.load()
        if saved_handles:
            expected_high_water = saved_handles[-1]["matrix_high_water"]
    presence(
        {
            **{
                name: bootstrap[name]
                for name in (
                    "being_ref",
                    "body_ref",
                    "embodiment_id",
                    "incarnation_id",
                    "matrix_session_id",
                )
            },
            "matrix_high_water": expected_high_water,
        },
        clock(),
    )
    if create:
        create_profile(
            plan,
            bootstrap_verifier=lambda evidence, at_ms: verifier(evidence, at_ms),
            clock=clock,
        )
    if handles is None:
        handles = RuntimeHandleJournal(
            plan.profile_root / "runtime-handles.jsonl", plan=plan
        )
    process = AppServerProcess(
        plan,
        pass_fds=(int(plan.mcp_args[5]),),
        inherited_environment=(
            {"CODEX_ACCESS_TOKEN": provider_token}
            if provider_token is not None
            else None
        ),
    )
    try:
        adapter = CodexBodyAdapter(
            plan,
            process,
            lambda binding, at_ms: presence(binding, at_ms),
            handles,
            clock=clock,
        )
        adapter.initialize()
    except BaseException:
        process.close()
        raise
    return OwnerNativeSession(adapter, process)


def bootstrap_attestation_payload(
    binding: CurrentMatrixBinding, *, matrix_session_id: str, expires_at_ms: int
) -> dict[str, Any]:
    """Prepare public data for one explicitly requested local we.observe action.

    Preparing data neither signs nor sends it. The resulting observation must
    subsequently pass current root and capability verification.
    """
    if (
        not isinstance(expires_at_ms, int)
        or isinstance(expires_at_ms, bool)
        or not binding.checked_at_ms < expires_at_ms <= binding.capability_expires_at_ms
    ):
        raise CodexBodyError("matrix_bootstrap_interval_rejected")
    descriptor = {
        "schema": ATTESTED_BOOTSTRAP_SCHEMA,
        "being_ref": binding.being_ref,
        "body_ref": binding.body_ref,
        "embodiment_id": binding.embodiment_id,
        "incarnation_id": binding.incarnation_id,
        "matrix_session_id": matrix_session_id,
        "certificate_hash": binding.certificate_hash,
        "capability_set_hash": binding.capability_set_hash,
        "issued_at_ms": binding.checked_at_ms,
        "expires_at_ms": expires_at_ms,
    }
    return {
        "schema": "dm.codex-body.bootstrap-attestation/v1",
        "bootstrap": descriptor,
        "runtime_id": binding.runtime_id,
        "capability_id": binding.capability_id,
        "client_id": binding.client_id,
        "manifest_hash": binding.manifest_hash,
    }


def verify_bootstrap_attestation(
    bootstrap: Mapping[str, Any], authority: RootAuthority, **admission: Any
) -> bool:
    """Verify the complete event proof and recheck current admission authority."""
    try:
        value = validate_bootstrap(bootstrap)
        if value["schema"] != ATTESTED_BOOTSTRAP_SCHEMA:
            raise CodexBodyError("matrix_bootstrap_attestation_required")
        binding = authenticate_matrix_binding(authority, **admission)
        if (
            not {"runtime.status", "we.heads", "we.observe"}
            <= admission["required_methods"]
        ):
            raise CodexBodyError("matrix_bootstrap_permissions_missing")
        event = verify_event(value["attestation"], authority)
        if (
            event["origin"] != admission["origin"]
            or event["manifest_hash"] != binding.manifest_hash
            or not value["issued_at_ms"]
            <= binding.checked_at_ms
            < value["expires_at_ms"]
        ):
            raise CodexBodyError("matrix_bootstrap_attestation_rejected")
        expected = bootstrap_attestation_payload(
            binding,
            matrix_session_id=value["matrix_session_id"],
            expires_at_ms=value["expires_at_ms"],
        )
        # Issuance time belongs to the signed observation, not the later check.
        expected["bootstrap"]["issued_at_ms"] = value["issued_at_ms"]
        if event["payload"] != expected:
            raise CodexBodyError("matrix_bootstrap_attestation_rejected")
        member = authority.validate_origin(event["origin"], require_active=True)
        credential = authority.credentials[member["embodiment_credential_id"]]
        verify_embodiment_credential(
            credential, authority.state, at_ms=value["expires_at_ms"] - 1
        )
        return True
    except (
        VerificationError,
        WeaveProtocolError,
        KeyError,
        TypeError,
        ValueError,
    ) as exception:
        raise CodexBodyError("matrix_bootstrap_attestation_rejected") from exception


def bootstrap_from_attestation(
    event: Mapping[str, Any], authority: RootAuthority, **admission: Any
) -> dict[str, Any]:
    """Assemble a bootstrap only from a verified daemon-signed observation."""
    try:
        proof = copy.deepcopy(dict(event))
        value = {
            **proof["payload"]["bootstrap"],
            "attestation": proof,
            "signature": proof["signature"],
            "matrix_high_water": proof["content_hash"],
        }
        verify_bootstrap_attestation(value, authority, **admission)
        return validate_bootstrap(value)
    except (KeyError, TypeError, ValueError) as exception:
        raise CodexBodyError("matrix_bootstrap_attestation_rejected") from exception


@dataclass(frozen=True)
class CurrentMatrixBinding:
    """Authenticated public bindings; not a presence or bootstrap receipt."""

    being_ref: str
    body_ref: str
    embodiment_id: str
    incarnation_id: str
    principal_id: str
    runtime_id: str
    certificate_hash: str
    capability_set_hash: str
    manifest_hash: str
    checked_at_ms: int
    capability_id: str
    client_id: str
    capability_expires_at_ms: int


def _admission_capability(
    rows: Any,
    *,
    capability_id: str,
    client_id: str,
    runtime_id: str,
    required_methods: frozenset[str],
    at_ms: int,
) -> Mapping[str, Any]:
    """Check the selected signed finite capability without importing its key."""
    if not required_methods or not required_methods <= SERVICE_METHODS:
        raise CodexBodyError("matrix_capability_requirements_invalid")
    matches = [
        row for row in rows if row["descriptor"].get("capability_id") == capability_id
    ]
    if len(matches) != 1:
        raise CodexBodyError("matrix_capability_not_bound")
    selected_row = matches[0]
    if selected_row["runtime_id"] != runtime_id:
        raise CodexBodyError("matrix_capability_not_bound")
    descriptor = selected_row["descriptor"]
    if (
        set(descriptor)
        != {
            "capability_id",
            "client_id",
            "key_id",
            "methods",
            "not_after_ms",
            "not_before_ms",
            "schema",
            "status",
        }
        or descriptor["schema"] != CAPABILITY_SCHEMA
    ):
        raise CodexBodyError("matrix_capability_schema_unsupported")
    core = {key: value for key, value in descriptor.items() if key != "capability_id"}
    expected_id = "dm:local-capability:v1:" + b64url(
        hashlib.sha256(CAPABILITY_DOMAIN + canonical_bytes(core)).digest()
    )
    methods = descriptor["methods"]
    before, after = descriptor["not_before_ms"], descriptor["not_after_ms"]
    if (
        descriptor["capability_id"] != expected_id
        or descriptor["client_id"] != client_id
        or descriptor["status"] != "active"
        or not isinstance(before, int)
        or isinstance(before, bool)
        or not isinstance(after, int)
        or isinstance(after, bool)
        or not 0 <= before <= at_ms < after
        or not isinstance(methods, list)
        or any(not isinstance(method, str) for method in methods)
        or methods != sorted(set(methods))
        or not set(methods) <= SERVICE_METHODS
        or not required_methods <= set(methods)
    ):
        raise CodexBodyError("matrix_capability_not_authorized")
    return dict(descriptor)


def authenticate_matrix_binding(
    authority: RootAuthority,
    *,
    origin: Mapping[str, Any],
    runtime_id: str,
    runtime_label: str,
    capability_rows: Any,
    capability_binding: Any,
    capability_id: str,
    client_id: str,
    required_methods: frozenset[str],
    at_ms: int,
) -> CurrentMatrixBinding:
    """Authenticate a caller-supplied current root snapshot without private keys.

    The caller must obtain the current authority through its trusted runtime
    boundary. This function does not discover or refresh an authority epoch.
    Hashes are SHA-256 of the canonical complete credential/capability rows,
    distinct from the domain-separated operator capability-set identifier.
    """

    if not isinstance(at_ms, int) or isinstance(at_ms, bool) or at_ms < 0:
        raise CodexBodyError("matrix_binding_invalid_time")
    if not isinstance(authority, RootAuthority):
        raise CodexBodyError("matrix_binding_requires_current_root")
    try:
        bound_origin = copy.deepcopy(dict(origin))
        rows = copy.deepcopy(capability_rows)
        binding = copy.deepcopy(capability_binding)
        if set(bound_origin) != {
            "body_ref",
            "embodiment_id",
            "incarnation_id",
            "principal_id",
        }:
            raise CodexBodyError("matrix_binding_rejected")
        member = authority.validate_origin(bound_origin, require_active=True)
        credential = authority.credentials[member["embodiment_credential_id"]]
        incarnation = authority.incarnations[member["incarnation_authorization_id"]]
        # Unlike historical event verification, revocation is never waived.
        credential_body = verify_embodiment_credential(
            credential, authority.state, at_ms=at_ms
        )
        verify_incarnation_authorization(
            incarnation, credential, authority.state, at_ms=at_ms
        )
        verify_operator_capability_binding(
            binding,
            runtime_id=runtime_id,
            runtime_label=runtime_label,
            being_ref=authority.manifest.being_ref,
            origin=bound_origin,
            signing_key=credential_body["signing_key"],
            capability_rows=rows,
        )
        selected = _admission_capability(
            rows,
            capability_id=capability_id,
            client_id=client_id,
            runtime_id=runtime_id,
            required_methods=required_methods,
            at_ms=at_ms,
        )
        return CurrentMatrixBinding(
            being_ref=authority.manifest.being_ref,
            body_ref=bound_origin["body_ref"],
            embodiment_id=bound_origin["embodiment_id"],
            incarnation_id=bound_origin["incarnation_id"],
            principal_id=bound_origin["principal_id"],
            runtime_id=runtime_id,
            certificate_hash=hashlib.sha256(canonical_bytes(credential)).hexdigest(),
            capability_set_hash=hashlib.sha256(canonical_bytes(rows)).hexdigest(),
            manifest_hash=authority.manifest.digest,
            checked_at_ms=at_ms,
            capability_id=capability_id,
            client_id=client_id,
            capability_expires_at_ms=selected["not_after_ms"],
        )
    except (
        VerificationError,
        WeaveProtocolError,
        OperatorCapabilityError,
        KeyError,
        TypeError,
        ValueError,
    ) as exception:
        raise CodexBodyError("matrix_binding_rejected") from exception
