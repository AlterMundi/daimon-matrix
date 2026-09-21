"""Owner-invoked, file-based peer enrollment. Never reads a messaging inbox."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from daimon_matrix import relationships as rel
from daimon_matrix.authority_epochs import RootHistoryAuthority
from daimon_matrix.canonical import b64url, canonical_bytes, unb64url
from daimon_matrix.client import load_json_document
from daimon_matrix.messaging import GrantReference, MessagingPeerPolicy
from daimon_matrix.messaging_config import (
    _public_identity,
    config_digest,
    create_binding,
    verify_public_binding,
)
from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA, authority_from_document
from daimon_matrix.weave import (
    PROTOCOL,
    BeingManifest,
    RootAuthority,
    create_event,
    verify_event,
)

LINK_SCHEMA = "dm.onboarding.peer-link/v1"


def now() -> int:
    return time.time_ns() // 1_000_000


def read_public(path: Path, digest: str | None = None) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("chat_link_public_file_rejected")
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if digest is not None and hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("chat_link_public_digest_mismatch")
    return dict(load_json_document(raw))


def verify_identity(value: dict[str, Any]) -> RootHistoryAuthority:
    if set(value) != {"document", "binding"}:
        raise ValueError("chat_link_identity_shape")
    document = value["document"]
    if (
        set(document)
        != {
            "schema",
            "authority",
            "authority_history",
            "origin",
            "runtime_id",
            "runtime_label",
        }
        or document["schema"] != "dm.onboarding.prepared-chat-identity/v1"
    ):
        raise ValueError("chat_link_identity_shape")
    active = authority_from_document(document["authority"])
    entries = document["authority_history"]
    if not isinstance(entries, list) or len(entries) > 256:
        raise ValueError("chat_link_history_shape")
    historical = []
    next_authority = active
    for entry in reversed(entries):
        if set(entry) == {"manifest", "successor"}:
            previous = RootAuthority(
                BeingManifest.from_value(entry["manifest"]),
                next_authority.state,
                next_authority.credentials,
                next_authority.incarnations,
            )
        elif set(entry) == {
            "manifest",
            "successor",
            "control_artifacts",
            "control_head",
            "credentials",
            "incarnations",
        }:
            previous = authority_from_document(
                {
                    "schema": AUTHORITY_SCHEMA,
                    **{key: item for key, item in entry.items() if key != "successor"},
                }
            )
        else:
            raise ValueError("chat_link_history_shape")
        historical.append(previous)
        next_authority = previous
    authority = RootHistoryAuthority(
        active, list(reversed(historical)), [entry["successor"] for entry in entries]
    )
    selected = _public_identity(
        authority,
        document["origin"],
        document["runtime_id"],
        document["runtime_label"],
        now(),
    )
    key = active.credentials[selected["credential_id"]]["body"]["signing_key"]["public"]
    verify_public_binding(
        selected, unb64url(key, length=32), document, value["binding"]
    )
    return authority


def write(path: Path, value: Any) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def public_identity(runtime: Any, bundle: dict[str, Any]) -> dict[str, Any]:
    document = {
        "schema": "dm.onboarding.prepared-chat-identity/v1",
        "authority": {
            "schema": AUTHORITY_SCHEMA,
            **{
                key: bundle[key]
                for key in (
                    "control_artifacts",
                    "control_head",
                    "manifest",
                    "credentials",
                    "incarnations",
                )
            },
        },
        "authority_history": bundle["authority_history"],
        "origin": bundle["local_origin"],
        "runtime_id": bundle["runtime_id"],
        "runtime_label": bundle["runtime_label"],
    }
    return {"document": document, "binding": create_binding(runtime, document)}


def event_ref(event: dict[str, Any]) -> dict[str, Any]:
    return {"event_id": event["event_id"], "event_hash": event["content_hash"]}


def make_plan(
    runtime: Any,
    local_public: dict[str, Any],
    remote_public: dict[str, Any],
    endpoints: list[str],
    destination: dict[str, Any],
) -> dict[str, Any]:
    """Local signatures and explicitly unsigned remote proposals."""
    validate_endpoints(endpoints)
    public = [local_public, remote_public]
    authorities = [verify_identity(item) for item in public]
    beings = [a.state.being_ref for a in authorities]
    if beings[0] == beings[1]:
        raise ValueError("chat_link_requires_distinct_peers")
    origins = [p["document"]["origin"] for p in public]
    credentials = [
        a.validate_origin(o, require_active=True)["embodiment_credential_id"]
        for a, o in zip(authorities, origins, strict=True)
    ]
    local_head = next(
        (
            h
            for h in runtime.service.ledger.heads()
            if h["incarnation_id"] == origins[0]["incarnation_id"]
        ),
        None,
    )
    heads = [local_head, None]  # Joining a prepared, never-used peer is explicit.
    start = now()
    link_id = str(uuid.uuid4())
    events = []
    sequences = [h["max_sequence"] if h else 0 for h in heads]
    previous = [h["tip_event_id"] if h else None for h in heads]
    prior_cards = [
        e
        for e in (
            runtime.service.relationships.store.events()
            if runtime.service.relationships
            else []
        )
        if e["kind"] == "matrix/relationship-card" and e["being_ref"] == beings[0]
    ]
    prior_cards.sort(key=lambda e: e["payload"]["sequence"])

    def append(actor: int, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
        payload = rel.validate_relationship_event_payload(
            kind, payload, author_being_ref=beings[actor], causal_parents=()
        )
        sequences[actor] += 1
        core = {
            "protocol": PROTOCOL,
            "event_id": str(uuid.uuid4()),
            "being_ref": beings[actor],
            "manifest_hash": authorities[actor].manifest.digest,
            "origin": origins[actor],
            "sequence": sequences[actor],
            "previous_event_id": previous[actor],
            "occurred_at_ms": rel.relationship_event_occurred_at(kind, payload),
            "causal_parents": [],
            "kind": kind,
            "subject": rel.relationship_event_subject(kind, payload),
            "payload": payload,
            "supersedes": None,
            "sensitivity": "shareable",
        }
        event = {
            **core,
            "content_hash": hashlib.sha256(canonical_bytes(core)).hexdigest(),
        }
        if actor == 0:
            event["signature"] = dict(
                runtime.service.signer.signature(event["content_hash"])
            )
            verify_event(event, authorities[0])
        previous[actor] = event["event_id"]
        events.append(event)
        return event

    validity = {"mode": "until-revoked", "not_before_ms": start}
    resource = {
        "schema": "dm.relationship.resource/v1",
        "resource_nonce": b64url(secrets.token_bytes(32)),
        "controller_being_ref": beings[0],
        "kind": "knowledge",
        "classification": "shareable",
        "operations": ["messaging.read"],
        "descriptor_ref": "dm:content:v1:human-requested-agent-chat",
    }
    resource_id = rel.resource_ref(resource)
    cards = []
    for i in range(2):
        last = prior_cards[-1] if i == 0 and prior_cards else None
        cards.append(
            append(
                i,
                "matrix/relationship-card",
                {
                    "schema": "dm.relationship.card/v2",
                    "card_series_id": rel.card_series_id(beings[i]),
                    "sequence": last["payload"]["sequence"] + 1 if last else 0,
                    "previous_card_event_id": last["event_id"] if last else None,
                    "being_ref": beings[i],
                    "control_position": {
                        "manifest_hash": authorities[i].manifest.digest,
                        "embodiment_id": origins[i]["embodiment_id"],
                        "incarnation_id": origins[i]["incarnation_id"],
                    },
                    "encryption_key": authorities[i].credentials[credentials[i]][
                        "body"
                    ]["encryption_key"],
                    "route_refs": ["dm:route:v1:" + link_id + ":" + str(i)],
                    "capability_refs": ["dm:capability:v1:human-requested-messaging"],
                    "resources": [{"resource_ref": resource_id, "descriptor": resource}]
                    if i == 0
                    else [],
                    "issued_at_ms": start,
                    "validity": validity,
                    "status": "active",
                },
            )
        )
    nonce = b64url(secrets.token_bytes(32))
    relationship = rel.relationship_id(
        nonce=nonce, initiator_being_ref=beings[0], responder_being_ref=beings[1]
    )
    permission = {
        "resource_ref": resource_id,
        "operations": ["messaging.read"],
        "classification": "shareable",
        "delegable": True,
        "remaining_delegation_depth": 1,
    }
    offer = append(
        0,
        "matrix/relationship-offer",
        {
            "schema": "dm.relationship.offer/v2",
            "relationship_id": relationship,
            "nonce": nonce,
            "initiator_being_ref": beings[0],
            "responder_being_ref": beings[1],
            "initiator_card_ref": event_ref(cards[0]),
            "responder_card_ref": event_ref(cards[1]),
            "terms_ref": "dm:terms:v1:human-requested-chat-telegram-mirror",
            "roles": ["peer"],
            "proposed_grants": [
                {
                    "grantor_being_ref": beings[0],
                    "subject_being_ref": beings[1],
                    "permissions": [permission],
                    "validity": validity,
                }
            ],
            "issued_at_ms": start,
            "expires_at_ms": start + 7 * 86400000,
        },
    )
    append(
        1,
        "matrix/relationship-acceptance",
        {
            "schema": "dm.relationship.acceptance/v2",
            "relationship_id": relationship,
            "offer_ref": event_ref(offer),
            "initiator_being_ref": beings[0],
            "responder_being_ref": beings[1],
            "initiator_card_ref": event_ref(cards[0]),
            "responder_card_ref": event_ref(cards[1]),
            "accepted_at_ms": start,
        },
    )
    declaration = {
        "created_at_ms": start,
        "founder_principal_id": beings[0],
        "nonce": b64url(secrets.token_bytes(32)),
        "policy_ref": "dm:tribe-policy:v1:human-requested-chat",
    }
    tribe = rel.tribe_ref(declaration)
    append(
        0,
        "matrix/tribe-declaration",
        {
            "schema": "dm.tribe.declaration/v1",
            "tribe_ref": tribe,
            "declaration": declaration,
        },
    )
    nonce = b64url(secrets.token_bytes(32))
    invitation = append(
        0,
        "matrix/tribe-invitation",
        {
            "schema": "dm.tribe.invitation/v1",
            "tribe_ref": tribe,
            "founder_epoch": 0,
            "founder_being_ref": beings[0],
            "invitation_id": rel.invitation_id(
                tribe=tribe, founder_epoch=0, invitee_being_ref=beings[1], nonce=nonce
            ),
            "invitee_being_ref": beings[1],
            "nonce": nonce,
            "issued_at_ms": start,
            "expires_at_ms": start + 7 * 86400000,
        },
    )
    membership = append(
        1,
        "matrix/tribe-membership-acceptance",
        {
            "schema": "dm.tribe.membership-acceptance/v1",
            "tribe_ref": tribe,
            "founder_epoch": 0,
            "invitation_ref": event_ref(invitation),
            "invitee_being_ref": beings[1],
            "membership_sequence": 0,
            "previous_membership_terminal_ref": None,
            "accepted_at_ms": start,
        },
    )
    grants: list[dict[str, Any]] = []
    for i in range(2):
        nonce = b64url(secrets.token_bytes(32))
        grant_id = rel.grant_id(
            nonce=nonce,
            relationship=relationship,
            grantor_being_ref=beings[i],
            subject_being_ref=beings[1 - i],
        )
        grant = append(
            i,
            "matrix/relationship-grant",
            {
                "schema": "dm.relationship.grant/v2",
                "grant_id": grant_id,
                "nonce": nonce,
                "relationship_id": relationship,
                "tribe_ref": tribe,
                "grantor_being_ref": beings[i],
                "subject_being_ref": beings[1 - i],
                "permissions": [
                    permission
                    if i == 0
                    else {
                        **permission,
                        "delegable": False,
                        "remaining_delegation_depth": 0,
                    }
                ],
                "validity": validity,
                "issued_at_ms": start,
                "parent_grant_ref": None if i == 0 else event_ref(grants[0]),
                "delegation_sequence": 0,
                "previous_delegation_event_id": None,
            },
        )
        append(
            1 - i,
            "matrix/relationship-grant-acceptance",
            {
                "schema": "dm.relationship.grant-acceptance/v2",
                "grant_id": grant_id,
                "grant_ref": event_ref(grant),
                "relationship_id": relationship,
                "grantor_being_ref": beings[i],
                "subject_being_ref": beings[1 - i],
                "accepted_at_ms": start,
            },
        )
        grants.append(grant)
    return {
        "schema": LINK_SCHEMA,
        "link_id": link_id,
        "created_at_ms": start,
        "expires_at_ms": start + 7 * 86400000,
        "identities": public,
        "base_heads": heads,
        "prior_cards": prior_cards,
        "events": events,
        "endpoints": endpoints,
        "destination": destination,
        "tribe_ref": tribe,
        "relationship_id": relationship,
        "resource_ref": resource_id,
        "membership_event": membership["event_id"],
        "grant_events": [event["event_id"] for event in grants],
        "mode": "human-request-only",
    }


def policies(plan: dict[str, Any]) -> list[dict[str, Any]]:
    authorities = [verify_identity(p) for p in plan["identities"]]
    beings = [a.state.being_ref for a in authorities]
    events = {e["event_id"]: e for e in plan["events"]}
    founder_membership = next(
        e["event_id"] for e in plan["events"] if e["kind"] == "matrix/tribe-declaration"
    )
    membership_ids = [founder_membership, plan["membership_event"]]
    result = []
    for i, authority in enumerate(authorities):
        origin = plan["identities"][i]["document"]["origin"]
        credential = authority.validate_origin(origin, require_active=True)[
            "embodiment_credential_id"
        ]
        grant = events[plan["grant_events"][i]]
        result.append(
            json.loads(
                canonical_bytes(
                    asdict(
                        MessagingPeerPolicy(
                            peer_being_ref=beings[i],
                            peer_embodiment_id=origin["embodiment_id"],
                            peer_credential_id=credential,
                            relationship_id=plan["relationship_id"],
                            tribe_ref=plan["tribe_ref"],
                            membership_ref=membership_ids[1 - i],
                            resource_ref=plan["resource_ref"],
                            operation="messaging.read",
                            classification="shareable",
                            grant_refs=(
                                GrantReference(
                                    grant["payload"]["grant_id"],
                                    grant["event_id"],
                                    grant["content_hash"],
                                ),
                            ),
                        )
                    )
                )
            )
        )
    return result


def disclosures(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rules = policies(plan)
    beings = [
        p["document"]["authority"]["manifest"]["being_ref"] for p in plan["identities"]
    ]
    result = []
    for i in range(2):
        scope = {
            "mode": "all-inter-daimon-communications",
            "projected_content": "complete-plaintext-content-and-metadata",
            "channels": [
                {
                    "channel_id": "peer-in" if direction == "incoming" else "peer-out",
                    "direction": direction,
                    "local_being_ref": beings[i],
                    "peer_being_ref": beings[1 - i],
                    "bootstrap_policy": rules[1 - i]
                    if direction == "incoming"
                    else rules[i],
                    "relationship_disclosure": {
                        "owner_directed": True,
                        "purpose": "human-request-only-chat",
                    },
                }
                for direction in ("incoming", "outgoing")
            ],
        }
        result.append(
            {
                "schema": "dm.messaging.visibility-disclosure/v1",
                "issued_at_ms": plan["created_at_ms"],
                "destination": plan["destination"],
                "scope": scope,
                "scope_sha256": config_digest(scope),
                "participants": sorted(beings),
                "risk": (
                    "all-inter-daimon-communication-will-be-posted-as-plaintext"
                    "-to-the-fixed-telegram-destination"
                ),
            }
        )
    return result


def sign_proposals(
    runtime: Any, plan: dict[str, Any], actor: int
) -> list[dict[str, Any]]:
    """Sign only the local actor's exact drafts using its real local key."""
    if (
        plan["schema"] != LINK_SCHEMA
        or plan["mode"] != "human-request-only"
        or now() > plan["expires_at_ms"]
    ):
        raise ValueError("chat_link_plan_expired_or_invalid")
    authorities = [verify_identity(p) for p in plan["identities"]]
    local = plan["identities"][actor]["document"]
    if (
        runtime.service.runtime_id != local["runtime_id"]
        or dict(runtime.service.origin) != local["origin"]
    ):
        raise ValueError("chat_link_local_identity_mismatch")
    if len(plan["events"]) != 11:
        raise ValueError("chat_link_event_count")
    actual = next(
        (
            h
            for h in runtime.service.ledger.heads()
            if h["incarnation_id"] == local["origin"]["incarnation_id"]
        ),
        None,
    )
    if actual != plan["base_heads"][actor]:
        # Refuse a stale plan instead of forking, resetting or copying history.
        raise ValueError("chat_link_local_head_changed")
    result = []
    previous = actual["tip_event_id"] if actual else None
    sequence = actual["max_sequence"] if actual else 0
    allowed = {
        "matrix/relationship-card",
        "matrix/relationship-offer",
        "matrix/relationship-acceptance",
        "matrix/tribe-declaration",
        "matrix/tribe-invitation",
        "matrix/tribe-membership-acceptance",
        "matrix/relationship-grant",
        "matrix/relationship-grant-acceptance",
    }
    for event in plan["events"]:
        owner = 0 if event["being_ref"] == authorities[0].state.being_ref else 1
        if (
            event["being_ref"] != authorities[owner].state.being_ref
            or event["kind"] not in allowed
        ):
            raise ValueError("chat_link_event_scope")
        rel.validate_relationship_event_payload(
            event["kind"],
            event["payload"],
            author_being_ref=event["being_ref"],
            causal_parents=(),
        )
        if event["kind"] == "matrix/relationship-grant" and any(
            p["operations"] != ["messaging.read"] or p["classification"] != "shareable"
            for p in event["payload"]["permissions"]
        ):
            raise ValueError("chat_link_grant_scope")
        if owner != actor:
            verify_event(event, authorities[owner])
            result.append(event)
            continue
        sequence += 1
        if event["sequence"] != sequence or event["previous_event_id"] != previous:
            raise ValueError("chat_link_event_chain")
        signed = create_event(
            authorities[actor],
            local["origin"],
            runtime.service.signer,
            **{
                k: event[k]
                for k in (
                    "event_id",
                    "sequence",
                    "previous_event_id",
                    "occurred_at_ms",
                    "causal_parents",
                    "kind",
                    "subject",
                    "payload",
                    "supersedes",
                    "sensitivity",
                )
            },
        )
        expected = {k: v for k, v in event.items() if k != "signature"}
        if {k: v for k, v in signed.items() if k != "signature"} != expected:
            raise ValueError("chat_link_draft_changed")
        result.append(signed)
        previous = signed["event_id"]
    return result


def encrypt_packet(
    runtime: Any, remote_identity: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """HPKE encrypt to the pinned recipient and sign the ciphertext envelope."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

    authority = verify_identity(remote_identity)
    document = remote_identity["document"]
    member = authority.validate_origin(document["origin"], require_active=True)
    key = authority.credentials[member["embodiment_credential_id"]]["body"][
        "encryption_key"
    ]
    info = {
        "schema": "dm.onboarding.encrypted-link/v1",
        "recipient_runtime_id": document["runtime_id"],
        "recipient_key_id": key["key_id"],
    }
    suite = Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.CHACHA20_POLY1305)
    cek, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    wrapped_key = suite.encrypt(
        cek,
        X25519PublicKey.from_public_bytes(unb64url(key["public"], length=32)),
        info=canonical_bytes(info),
    )
    ciphertext = ChaCha20Poly1305(cek).encrypt(
        nonce, canonical_bytes(payload), canonical_bytes(info)
    )
    document = {
        **info,
        "ciphertext": b64url(ciphertext),
        "wrapped_key": b64url(wrapped_key),
        "nonce": b64url(nonce),
    }
    return {"document": document, "binding": create_binding(runtime, document)}


def decrypt_packet(
    runtime: Any, sender_identity: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any]:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    sender = verify_identity(sender_identity)
    public = sender_identity["document"]
    selected = _public_identity(
        sender, public["origin"], public["runtime_id"], public["runtime_label"], now()
    )
    key = sender.credentials[selected["credential_id"]]["body"]["signing_key"]["public"]
    verify_public_binding(
        selected, unb64url(key, length=32), packet["document"], packet["binding"]
    )
    document = packet["document"]
    if (
        set(document)
        != {
            "schema",
            "recipient_runtime_id",
            "recipient_key_id",
            "ciphertext",
            "wrapped_key",
            "nonce",
        }
        or document["schema"] != "dm.onboarding.encrypted-link/v1"
    ):
        raise ValueError("chat_link_packet_shape")
    if document["recipient_runtime_id"] != runtime.service.runtime_id:
        raise ValueError("chat_link_wrong_recipient")
    info = canonical_bytes(
        {
            k: v
            for k, v in document.items()
            if k not in {"ciphertext", "wrapped_key", "nonce"}
        }
    )
    cek = runtime.peer_context.custody.unwrap(
        document["recipient_key_id"], unb64url(document["wrapped_key"], length=80), info
    )
    plaintext = ChaCha20Poly1305(cek).decrypt(
        unb64url(document["nonce"], length=12), unb64url(document["ciphertext"]), info
    )
    return dict(load_json_document(plaintext))


def put(path: Path, value: Any) -> None:
    raw = value if isinstance(value, bytes) else canonical_bytes(value)
    if path.exists():
        from daimon_matrix.messaging_config import protected_read

        if protected_read(path) != raw:
            raise ValueError("chat_link_existing_output_conflict")
        return
    write(path, raw)


def replace_document(path: Path, value: Any) -> None:
    from daimon_matrix.operator_rebirth import _fsync_directory

    staged = path.with_name(path.name + ".link-staged")
    put(staged, value)
    os.replace(staged, path)
    _fsync_directory(path.parent)


def install_link(
    runtime_root: Path,
    password: bytes,
    output: Path,
    payload: dict[str, Any],
    actor: int,
) -> dict[str, Any]:
    """Apply a fully signed plan through the existing production application loader."""
    from urllib.parse import urlsplit

    from daimon_matrix.messaging_config import (
        load_application,
        protected_read,
        read_publication,
    )
    from daimon_matrix.native_egress import VISIBILITY_SCHEMA_VERSION, closed_visibility
    from daimon_matrix.operator_messaging import _visibility_factory
    from daimon_matrix.operator_messaging import prepare as prepare_app
    from daimon_matrix.operator_rebirth import _fsync_directory
    from daimon_matrix.relationship_store import RelationshipStore
    from daimon_matrix.runtime import load_runtime, verify_relationship_card_authority

    plan, events = payload["plan"], payload["signed_events"]
    validate_endpoints(plan["endpoints"])
    if len(events) != len(plan["events"]) or any(
        {k: v for k, v in signed.items() if k != "signature"}
        != {k: v for k, v in draft.items() if k != "signature"}
        for signed, draft in zip(events, plan["events"], strict=True)
    ):
        raise ValueError("chat_link_signed_plan_changed")
    expected_keys = {
        f"{i}-{phase}.key" for i in range(2) for phase in ("evidence", "message")
    }
    if set(payload["route_keys"]) != expected_keys:
        raise ValueError("chat_link_secret_names")
    for secret in payload["route_keys"].values():
        unb64url(secret, length=32)
    token = unb64url(payload["telegram_token"])
    qualification = payload["telegram_qualification"]
    if (
        hashlib.sha256(token).hexdigest() != qualification["token_sha256"]
        or qualification["get_me_bot_id"] != plan["destination"]["bot_id"]
        or qualification["probe_chat_id"] != plan["destination"]["chat_id"]
        or qualification["probe_topic_id"] != plan["destination"]["topic_id"]
    ):
        raise ValueError("chat_link_telegram_qualification_mismatch")
    authorities = [verify_identity(p) for p in plan["identities"]]
    beings = [a.state.being_ref for a in authorities]
    by_being = dict(zip(beings, authorities, strict=True))
    # Validate every real signature and the complete grant graph before modifying
    # runtime configuration, its canonical ledger, or an application directory.
    import tempfile

    with tempfile.TemporaryDirectory(dir=output) as staging:
        store = RelationshipStore(
            Path(staging) / "check.sqlite",
            authority_resolver=lambda being_ref: by_being[being_ref],
        )
        for event in [*plan["prior_cards"], *events]:
            store.ingest(event)
        view = store.view(
            at_ms=now(),
            card_verifier=lambda card, at: verify_relationship_card_authority(
                card, by_being[card["being_ref"]], at_ms=at
            ),
        )
        snapshot = view.snapshot(plan["tribe_ref"])
        if len(snapshot.value["members"]) != 2 or len(snapshot.value["grants"]) != 2:
            raise ValueError("chat_link_not_mutually_authorized")
    for index, disclosure in enumerate(disclosures(plan)):
        for i in range(2):
            identity = plan["identities"][i]["document"]
            selected = _public_identity(
                authorities[i],
                identity["origin"],
                identity["runtime_id"],
                identity["runtime_label"],
                now(),
            )
            signing = authorities[i].credentials[selected["credential_id"]]["body"][
                "signing_key"
            ]["public"]
            verify_public_binding(
                selected,
                unb64url(signing, length=32),
                disclosure,
                payload["visibility_bindings"][i][index],
            )
    bundle_path = runtime_root / "runtime.json"
    bundle = read_public(bundle_path)
    if bundle["runtime_id"] != plan["identities"][actor]["document"]["runtime_id"]:
        raise ValueError("chat_link_runtime_mismatch")
    uuid.UUID(plan["link_id"])
    preflight = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(password),
        clock=now,
        egress=closed_visibility(clock=now, catalog_mode="migrate"),
    )
    incarnation = plan["identities"][actor]["document"]["origin"]["incarnation_id"]
    actual_head = next(
        (
            h
            for h in preflight.service.ledger.heads()
            if h["incarnation_id"] == incarnation
        ),
        None,
    )
    allowed_heads = [plan["base_heads"][actor]] + [
        {
            "incarnation_id": incarnation,
            "max_sequence": e["sequence"],
            "tip_event_id": e["event_id"],
            "tip_hash": e["content_hash"],
        }
        for e in events
        if e["being_ref"] == beings[actor]
    ]
    if actual_head not in allowed_heads:
        raise ValueError("chat_link_local_head_changed")
    if not (output / "runtime-before.json").exists():
        put(output / "runtime-before.json", bundle)
    peer = plan["identities"][1 - actor]["document"]
    known = {k: v for k, v in peer["authority"].items() if k != "schema"}
    known.update(
        authority_history=peer["authority_history"],
        ledger_filename="peer-" + plan["link_id"] + ".sqlite",
    )
    if bundle["sources"] is None:
        bundle["sources"] = {"cas_filename": "sources.sqlite3", "known_beings": []}
    existing = bundle["sources"]["known_beings"]
    matching = [
        item for item in existing if item["manifest"]["being_ref"] == beings[1 - actor]
    ]
    if matching and matching != [known]:
        raise ValueError("chat_link_peer_authority_conflict")
    if not matching:
        existing.append(known)
    if bundle["relationships"] is None:
        bundle["relationships"] = {
            "store_filename": "relationships.sqlite3",
            "known_being_refs": [],
        }
    refs = bundle["relationships"]["known_being_refs"]
    if beings[1 - actor] not in refs:
        refs.append(beings[1 - actor])
        refs.sort()
    replace_document(bundle_path, bundle)
    runtime = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(password),
        clock=now,
        egress=closed_visibility(clock=now, catalog_mode="migrate"),
    )
    own = [e for e in events if e["being_ref"] == beings[actor]]
    # Ingest exact pre-signed local history, never recreate events on a retry.
    runtime.service.ledger.ingest(own, source="owner-peer-enrollment")
    assert runtime.service.relationships is not None
    for event in [*plan["prior_cards"], *events]:
        runtime.service.relationships.store.ingest(event)
    rules = policies(plan)
    endpoint = urlsplit(plan["endpoints"][actor])
    routes: dict[str, Any] = {}
    keydir = output / "route-keys"
    keydir.mkdir(mode=0o700, exist_ok=True)
    for name, secret in payload["route_keys"].items():
        if name not in {
            f"{i}-{phase}.key" for i in range(2) for phase in ("evidence", "message")
        }:
            raise ValueError("chat_link_secret_name")
        put(keydir / name, unb64url(secret, length=32))
    for direction, target in (("incoming", actor), ("outgoing", 1 - actor)):
        routes[direction] = {}
        for phase in ("evidence", "message"):
            name = f"{target}-{phase}.key"
            routes[direction][phase] = {
                "provider_ref": f"provider:link:{plan['link_id']}:{target}:{phase}",
                "route_ref": f"route:link:{plan['link_id']}:{target}:{phase}",
                "key_ref": f"key:link:{plan['link_id']}:{target}:{phase}",
                "secret_file": name,
                "secret_sha256": hashlib.sha256(
                    protected_read(keydir / name)
                ).hexdigest(),
                "endpoint": plan["endpoints"][target] + "/dm-messaging/v1/" + phase,
            }
    spec = {
        "schema": "dm.messaging.application/v1",
        "listen": {"host": endpoint.hostname, "port": endpoint.port},
        "authorities": [p["document"]["authority"] for p in plan["identities"]],
        "relationship_events": [*plan["prior_cards"], *events],
        "relationship_mode": {
            "mode": "shared",
            "runtime_id": runtime.service.runtime_id,
            "state_root": str(runtime_root),
            "store_filename": bundle["relationships"]["store_filename"],
        },
        "incoming": {
            "channel_id": "peer-in",
            "recipient_being_ref": beings[actor],
            "recipient_credential_id": rules[actor]["peer_credential_id"],
            "policy": rules[1 - actor],
            "routes": routes["incoming"],
        },
        "outgoing": {
            "channel_id": "peer-out",
            "recipient_being_ref": beings[1 - actor],
            "recipient_credential_id": rules[1 - actor]["peer_credential_id"],
            "policy": rules[actor],
            "routes": routes["outgoing"],
        },
        "stores": {
            name: name + ".sqlite"
            for name in (
                "relationships",
                "inbox",
                "outgoing-context",
                "outbox",
                "opaque-evidence",
                "opaque-message",
            )
        },
    }
    app = output / "application"
    if not app.exists():
        prepare_app(
            runtime,
            app,
            spec,
            secret_sources={name: keydir / name for name in payload["route_keys"]},
        )
    selected, _ = read_publication(runtime, app)
    if {k: v for k, v in selected.items() if k != "client"} != spec:
        # Production may normalize only its declared schema; unexpected drift is
        # not authorization to replace an existing application.
        raise ValueError("chat_link_application_conflict")
    visibility = output / "visibility"
    visibility.mkdir(mode=0o700, exist_ok=True)
    token = unb64url(payload["telegram_token"])
    put(visibility / "telegram.token", token)
    if not (visibility / "proof.key").exists():
        write(visibility / "proof.key", secrets.token_bytes(32))
    proof_key = protected_read(visibility / "proof.key", size=32)
    disclosure = disclosures(plan)[actor]
    acceptance = {
        "schema": "dm.messaging.visibility-acceptance-set/v1",
        "disclosure_sha256": config_digest(disclosure),
        "bindings": [
            payload["visibility_bindings"][beings.index(being)][actor]
            for being in sorted(beings)
        ],
    }
    document = {
        "schema": "dm.messaging.visibility-installation/v1",
        "generation": 1,
        "runtime_id": runtime.service.runtime_id,
        "application_sha256": config_digest(selected),
        "disclosure": disclosure,
        "acceptance_set": acceptance,
        "policy": {
            "schema": "daimon-visibility-policy/v2",
            "generation": 1,
            "origin": "owner-directed-peer-enrollment",
            **plan["destination"],
            "acceptance_digest": config_digest(acceptance),
            "proof_key_id": "sha256:" + hashlib.sha256(proof_key).hexdigest(),
        },
        "secrets": {
            "telegram_token_file": "telegram.token",
            "telegram_token_sha256": hashlib.sha256(token).hexdigest(),
            "proof_key_file": "proof.key",
        },
        "telegram_qualification": payload["telegram_qualification"],
    }
    installation = visibility / "installation.json"
    put(
        installation,
        {"document": document, "binding": create_binding(runtime, document)},
    )
    runtime = load_runtime(
        runtime_root,
        "runtime.json",
        lambda: bytearray(password),
        clock=now,
        egress_factory=_visibility_factory(
            selected, installation, clock=now, catalog_mode="migrate"
        ),
    )
    runtime = load_application(runtime, app)
    runtime.egress.migrate_registered_catalogs(version=VISIBILITY_SCHEMA_VERSION)
    runtime.egress.validate_registered_catalogs()
    result = {
        "schema": "dm.onboarding.peer-link-ready/v1",
        "link_id": plan["link_id"],
        "runtime_root": str(runtime_root),
        "app_directory": str(app),
        "visibility_installation": str(installation),
        "incoming_channel": "peer-in",
        "outgoing_channel": "peer-out",
        "endpoint": plan["endpoints"][actor],
        "services_started": 0,
        "inbox_reads": 0,
        "model_calls": 0,
        "application_sha256": config_digest(selected),
    }
    put(output / "ready.json", result)
    _fsync_directory(output)
    return result


def validate_endpoints(endpoints: list[str]) -> None:
    import ipaddress
    from urllib.parse import urlsplit

    if (
        not isinstance(endpoints, list)
        or len(endpoints) != 2
        or len(set(endpoints)) != 2
    ):
        raise ValueError("chat_link_endpoints")
    for endpoint in endpoints:
        url = urlsplit(endpoint)
        if (
            url.scheme != "http"
            or url.username
            or url.password
            or url.path
            or url.query
            or url.fragment
            or url.port is None
            or url.hostname is None
            or not 1024 <= url.port <= 65535
        ):
            raise ValueError("chat_link_endpoint_shape")
        address = ipaddress.ip_address(url.hostname)
        if address.is_unspecified or address.is_multicast:
            raise ValueError("chat_link_endpoint_address")


def verify_document(
    identity: dict[str, Any], document: dict[str, Any], binding: dict[str, Any]
) -> None:
    authority = verify_identity(identity)
    public = identity["document"]
    selected = _public_identity(
        authority,
        public["origin"],
        public["runtime_id"],
        public["runtime_label"],
        now(),
    )
    key = authority.credentials[selected["credential_id"]]["body"]["signing_key"][
        "public"
    ]
    verify_public_binding(selected, unb64url(key, length=32), document, binding)


def offer(
    runtime: Any,
    bundle: dict[str, Any],
    peer: dict[str, Any],
    output: Path,
    endpoints: list[str],
    installation: Path,
) -> Path:
    from daimon_matrix.messaging_config import protected_read

    local = public_identity(runtime, bundle)
    existing = read_public(installation)
    verify_document(local, existing["document"], existing["binding"])
    visibility = existing["document"]
    destination = {
        k: visibility["policy"][k]
        for k in ("bot_id", "chat_id", "topic_id", "representation")
    }
    token_name = visibility["secrets"]["telegram_token_file"]
    if Path(token_name).name != token_name:
        raise ValueError("chat_link_token_path")
    token = protected_read(installation.parent / token_name)
    if (
        hashlib.sha256(token).hexdigest()
        != visibility["secrets"]["telegram_token_sha256"]
    ):
        raise ValueError("chat_link_token_digest")
    if (output / "pending.json").exists():
        payload = read_public(output / "pending.json")
        if (
            payload["plan"]["identities"] != [local, peer]
            or payload["plan"]["endpoints"] != endpoints
            or payload["plan"]["destination"] != destination
        ):
            raise ValueError("chat_link_existing_offer_conflict")
        if (output / "offer.json").exists():
            return output / "offer.json"
    else:
        plan = make_plan(runtime, local, peer, endpoints, destination)
        payload = {
            "plan": plan,
            "route_keys": {
                f"{i}-{p}.key": b64url(secrets.token_bytes(32))
                for i in range(2)
                for p in ("evidence", "message")
            },
            "telegram_token": b64url(token),
            "telegram_qualification": visibility["telegram_qualification"],
            "visibility_bindings": [
                [create_binding(runtime, d) for d in disclosures(plan)],
                [],
            ],
        }
        write(output / "pending.json", payload)
    packet = {
        "sender_identity": local,
        "packet": encrypt_packet(runtime, peer, payload),
    }
    write(output / "offer.json", packet)
    return output / "offer.json"


def accept(
    runtime: Any,
    runtime_root: Path,
    password: bytes,
    packet: dict[str, Any],
    output: Path,
) -> Path:
    payload = decrypt_packet(runtime, packet["sender_identity"], packet["packet"])
    plan = payload["plan"]
    if plan["identities"][0] != packet["sender_identity"]:
        raise ValueError("chat_link_sender_mismatch")
    validate_endpoints(plan["endpoints"])
    cached = output / "accepted-private.json"
    if cached.exists():
        signed_payload = read_public(cached)
        if signed_payload["plan"] != plan:
            raise ValueError("chat_link_existing_plan_conflict")
    else:
        signed_payload = copy.deepcopy(payload)
        signed_payload["signed_events"] = sign_proposals(runtime, plan, 1)
        signed_payload["visibility_bindings"][1] = [
            create_binding(runtime, d) for d in disclosures(plan)
        ]
        signed_payload["signed_at_ms"] = now()
        write(cached, signed_payload)
    ready = install_link(runtime_root, password, output, signed_payload, 1)
    if not (output / "response.json").exists():
        document = {
            "schema": "dm.onboarding.peer-link-response/v1",
            "link_id": plan["link_id"],
            "plan_sha256": config_digest(plan),
            "signed_events": signed_payload["signed_events"],
            "visibility_bindings": signed_payload["visibility_bindings"],
            "signed_at_ms": signed_payload["signed_at_ms"],
            "applied_at_ms": now(),
            "application_sha256": ready["application_sha256"],
        }
        write(
            output / "response.json",
            {"document": document, "binding": create_binding(runtime, document)},
        )
    return output / "response.json"


def finish(
    runtime: Any,
    runtime_root: Path,
    password: bytes,
    response: dict[str, Any],
    output: Path,
) -> Path:
    payload = read_public(output / "pending.json")
    plan = payload["plan"]
    document = response["document"]
    verify_document(plan["identities"][1], document, response["binding"])
    if (
        document["schema"] != "dm.onboarding.peer-link-response/v1"
        or document["plan_sha256"] != config_digest(plan)
        or document["link_id"] != plan["link_id"]
    ):
        raise ValueError("chat_link_response_plan_mismatch")
    payload.update(
        signed_events=document["signed_events"],
        visibility_bindings=document["visibility_bindings"],
    )
    put(output / "completed-private.json", payload)
    install_link(runtime_root, password, output, payload, 0)
    return output / "ready.json"


def main() -> None:
    import argparse

    from daimon_matrix.daemon import _state_root, acquire_lock
    from daimon_matrix.messaging_config import protected_read
    from daimon_matrix.native_egress import closed_visibility
    from daimon_matrix.runtime import load_runtime

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("offer", "accept", "finish", "run"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--local-endpoint")
    parser.add_argument("--peer-endpoint")
    parser.add_argument("--visibility-installation", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = _state_root(args.runtime_root)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = _state_root(args.output)
    supplied = read_public(args.input, args.sha256)
    password = protected_read(args.password_file)
    if args.command == "run":
        from daimon_matrix.operator_messaging import main as run_messaging

        if (
            supplied["schema"] != "dm.onboarding.peer-link-ready/v1"
            or supplied["runtime_root"] != str(root)
            or supplied["app_directory"] != str(output / "application")
            or supplied["visibility_installation"]
            != str(output / "visibility/installation.json")
        ):
            raise ValueError("chat_link_ready_paths")
        installation = read_public(Path(supplied["visibility_installation"]))
        if (
            installation["document"]["application_sha256"]
            != supplied["application_sha256"]
        ):
            raise ValueError("chat_link_ready_application_changed")
        # Pass custody bytes only through an inherited descriptor, never argv.
        descriptor = os.open(args.password_file, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            raise SystemExit(
                run_messaging(
                    [
                        "run",
                        "--state-root",
                        str(root),
                        "--app-dir",
                        supplied["app_directory"],
                        "--password-fd",
                        str(descriptor),
                        "--visibility-installation",
                        supplied["visibility_installation"],
                    ]
                )
            )
        finally:
            os.close(descriptor)
    lock = acquire_lock(root)
    try:
        runtime = load_runtime(
            root,
            "runtime.json",
            lambda: bytearray(password),
            clock=now,
            egress=closed_visibility(clock=now, catalog_mode="migrate"),
        )
        if args.command == "offer":
            result = offer(
                runtime,
                read_public(root / "runtime.json"),
                supplied,
                output,
                [args.local_endpoint, args.peer_endpoint],
                args.visibility_installation,
            )
        elif args.command == "accept":
            result = accept(runtime, root, password, supplied, output)
        else:
            result = finish(runtime, root, password, supplied, output)
        print(
            json.dumps(
                {
                    "file": str(result),
                    "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
                    "services_started": 0,
                    "inbox_reads": 0,
                    "model_calls": 0,
                }
            )
        )
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Inputs contain transport credentials: never echo exception payloads.
        import re

        code = str(exc)
        if not re.fullmatch(r"chat_link_[a-z_]+", code):
            code = type(exc).__name__
        raise SystemExit("chat_link_failed: " + code) from None
