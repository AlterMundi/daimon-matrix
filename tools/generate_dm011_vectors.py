#!/usr/bin/env python3
"""DM-011 conformance-vector generator (synthetic test fixtures only).

Regenerates the checked-in vector tree under ``vectors/v0/`` deterministically:
every nonce, seed, session ID, CEK, and HPKE ephemeral key is derived from a
fixed SHA-256 based counter stream, so two runs produce byte-identical output
equal to the checked-in vectors (stronger than the spec requires; HPKE is
randomized in production, but these vectors pin fixed ephemeral keys so the
fixtures are reproducible).

All key material is synthetic and deterministic; nothing here is a secret, a
real identity, real memory, or live ciphertext.  The disclosure authorization
is a clearly labeled ``x/test`` event fixture, not a DM-012 normative schema.

Per DM-011 Section 10 this reuses, after adaptation, the pinned Tribe PR14
standards-based patterns only: strict I-JSON/JCS (RFC 8785), canonical
base64url (RFC 4648), Ed25519 domain-separated whole-object signatures
(RFC 8032), and RFC 9180 HPKE X25519/HKDF-SHA256/ChaCha20-Poly1305 CEK
wrapping.  RFC 9180 provenance is pinned to upstream commit
``b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb``.  The HPKE helper below is
test/vector-only and rejects the all-zero X25519 shared secret.

Usage:
    python tools/generate_dm011_vectors.py --out vectors/v0
"""

import argparse
import copy
import hashlib
import hmac
import json
import os
import shutil
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Protocol constants (from specs/canonical-artifacts.md, normative)
# ---------------------------------------------------------------------------

SUITE = "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"

DOM_GENESIS = "daimon/genesis/v0"
DOM_ROOT_TRANSITION = "daimon/root-transition/v0"
DOM_RECOVERY_TRANSITION = "daimon/recovery-transition/v0"
DOM_RECOVERY_POLICY = "daimon/recovery-policy/v0"
DOM_CERTIFICATE = "daimon/operational-certificate/v0"
DOM_ACCEPTANCE = "daimon/operational-acceptance/v0"
DOM_REVOCATION = "daimon/revocation/v0"
DOM_LEASE = "daimon/presence-lease/v0"
DOM_LEASE_RECEIPT = "daimon/lease-head-receipt/v0"
DOM_EVENT = "daimon/event/v0"
DOM_CHECKPOINT = "daimon/event-checkpoint/v0"
DOM_SEALED = "daimon/sealed-event/v0"
DOM_SEALED_AAD = "daimon/sealed-event/payload-aad/v0"
DOM_SEALED_CEK = "daimon/sealed-event/cek-wrap/v0"
DOM_OPERATIONAL_ID = "daimon/operational-id/v0"

CEILING_CONTROL = 262144      # control/cert/acceptance/lease/receipt/checkpoint
CEILING_EVENT = 1048576       # event wrapper
CEILING_SEALED = 2097152      # sealed delivery wrapper

MAX_CERT_LIFETIME_MS = 30 * 24 * 3600 * 1000   # V0 profile: 30 days
MAX_PRESENCE_TTL_MS = 300000                   # V0 profile: 300 seconds
MAX_CLOCK_SKEW_MS = 30000                      # V0 profile: 30 seconds
MAX_DELIVERY_TTL_MS = 24 * 3600 * 1000         # 24 hours
SAFE_INT_MAX = 2**53 - 1

RFC9180_PROVENANCE_COMMIT = "b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb"

T0 = 1754000000000  # fixed synthetic base time (Unix ms), 2025-08-01 UTC-ish

# ---------------------------------------------------------------------------
# Deterministic randomness (test-only)
# ---------------------------------------------------------------------------

def det(label, n=32):
    """Deterministic byte stream; replaces every CSPRNG draw in fixtures."""
    out = b""
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(
            b"dm-011-vector-determinism/v0\x00" + label.encode("utf-8")
            + b"\x00" + ctr.to_bytes(4, "big")
        ).digest()
        ctr += 1
    return out[:n]

# ---------------------------------------------------------------------------
# Canonical base64url (RFC 4648, unpadded)
# ---------------------------------------------------------------------------

def b64(data):
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

# ---------------------------------------------------------------------------
# JCS (RFC 8785) for the DM-011 restricted data model
# ---------------------------------------------------------------------------

_JCS_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}

def _jcs_string(s):
    out = ['"']
    for ch in s:
        esc = _JCS_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

def jcs(value):
    """Serialize a restricted-model value to RFC 8785 canonical bytes."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, str):
        return _jcs_string(value).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        # RFC 8785 sorts properties by UTF-16 code units.
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(
            _jcs_string(k).encode("utf-8") + b":" + jcs(v) for k, v in items
        ) + b"}"
    raise TypeError("not in the DM-011 data model: %r" % type(value))

def sha256(data):
    return hashlib.sha256(data).digest()

# ---------------------------------------------------------------------------
# Keys (synthetic, deterministic, purpose-separated)
# ---------------------------------------------------------------------------

class TestKey:
    def __init__(self, name, role, alg):
        self.name = name
        self.role = role
        self.alg = alg
        self.seed = det("key-seed/" + name)
        if alg == "Ed25519":
            self._priv = Ed25519PrivateKey.from_private_bytes(self.seed)
        elif alg == "X25519":
            self._priv = X25519PrivateKey.from_private_bytes(self.seed)
        else:
            raise ValueError(alg)
        self.public = self._priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        self.kid = key_id(alg, b64(self.public))

    def sign(self, preimage):
        assert self.alg == "Ed25519"
        return self._priv.sign(preimage)

    def x25519(self, peer_public_bytes):
        assert self.alg == "X25519"
        peer = _x25519_public_from_raw(peer_public_bytes)
        shared = self._priv.exchange(peer)
        if shared == b"\x00" * 32:
            raise ValueError("all-zero X25519 shared secret rejected")
        return shared

def _x25519_public_from_raw(raw):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PublicKey.from_public_bytes(raw)

def key_id(alg, public_key_b64):
    digest = sha256(jcs({"alg": alg, "public_key": public_key_b64}))
    return "dm:key:v0:" + b64(digest)

def key_desc(key):
    return {"alg": key.alg, "kid": key.kid, "public_key": b64(key.public)}

KEY_SPECS = [
    # name, custody role, alg
    ("root-a", "me1 root (genesis)", "Ed25519"),
    ("root-b", "me1 root (genesis)", "Ed25519"),
    ("root-c", "me1 root (genesis)", "Ed25519"),
    ("newroot-a", "me1 root (transition 0,1)", "Ed25519"),
    ("newroot-b", "me1 root (transition 0,1)", "Ed25519"),
    ("newroot-c", "me1 root (transition 0,1)", "Ed25519"),
    ("proot-a", "me1 post-recovery root (1,0)", "Ed25519"),
    ("proot-b", "me1 post-recovery root (1,0)", "Ed25519"),
    ("rec-a", "me1 recovery (genesis)", "Ed25519"),
    ("rec-b", "me1 recovery (genesis)", "Ed25519"),
    ("rec2-a", "me1 recovery (policy 0,2)", "Ed25519"),
    ("rec2-b", "me1 recovery (policy 0,2)", "Ed25519"),
    ("op1-sign", "me1 operational 1 signing", "Ed25519"),
    ("op1-enc", "me1 operational 1 encryption", "X25519"),
    ("op2-sign", "me1 operational 2 (witness) signing", "Ed25519"),
    ("op2-enc", "me1 operational 2 (witness) encryption", "X25519"),
    ("op3-sign", "me1 operational 3 (revoked) signing", "Ed25519"),
    ("op3-enc", "me1 operational 3 (revoked) encryption", "X25519"),
    ("xroot-a", "me2 root (genesis)", "Ed25519"),
    ("opx-sign", "me2 operational opx signing", "Ed25519"),
    ("opx-enc", "me2 operational opx encryption", "X25519"),
    ("op2-enc2", "me1 operational 2 rotated encryption", "X25519"),
    ("branchroot-a", "scenario superseded-branch root", "Ed25519"),
    ("branchroot-b", "scenario superseded-branch root", "Ed25519"),
    ("sroot-a", "scenario post-recovery root", "Ed25519"),
    ("sroot-b", "scenario post-recovery root", "Ed25519"),
    ("opf-sign", "scenario branch operational signing", "Ed25519"),
    ("opf-enc", "scenario branch operational encryption", "X25519"),
    ("opp-sign", "boundary-fixture operational signing", "Ed25519"),
    ("opp-enc", "boundary-fixture operational encryption", "X25519"),
    ("transport-gov-sign", "untrusted transport governance signing", "Ed25519"),
]

# Structural boundary vectors need 129 distinct, syntactically valid signature
# records.  These extra keys are synthetic vector material only; they do not
# become an identity root or an authorization set.
KEY_SPECS += [
    ("bound-sign-%03d" % index, "resource-boundary signing key", "Ed25519")
    for index in range(129)
]

KEYS = {name: TestKey(name, role, alg) for name, role, alg in KEY_SPECS}

def threshold_set(keys, threshold):
    return {"keys": sorted((key_desc(k) for k in keys), key=lambda d: d["kid"]),
            "threshold": threshold}

def sig_record(key, role, preimage):
    return {"alg": "Ed25519", "kid": key.kid, "role": role,
            "value": b64(key.sign(preimage))}

def sort_sigs(records):
    return sorted(records, key=lambda r: (r["kid"], r["role"]))


def zero_signatures(wrapper):
    """Return a copy whose signature bytes are canonical-length all-zero data."""
    value = copy.deepcopy(wrapper)
    if "signature" in value:
        value["signature"]["value"] = b64(b"\x00" * 64)
    else:
        for record in value["signatures"]:
            record["value"] = b64(b"\x00" * 64)
    return value

# ---------------------------------------------------------------------------
# Test/vector-only RFC 9180 HPKE: DHKEM(X25519, HKDF-SHA256),
# HKDF-SHA256, ChaCha20-Poly1305, base mode.  Rejects all-zero DH.
# ---------------------------------------------------------------------------

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_ID = 0x0003
KEM_SUITE_ID = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE_ID = (b"HPKE" + KEM_ID.to_bytes(2, "big")
                 + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big"))

def _hkdf_extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk, info, length):
    out = b""
    t = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]

def _labeled_extract(suite_id, salt, label, ikm):
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)

def _labeled_expand(suite_id, prk, label, info, length):
    labeled_info = (length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label
                    + info)
    return _hkdf_expand(prk, labeled_info, length)

def dhkem_encap(recipient_public, ephemeral_seed):
    """Deterministic test Encap: returns (shared_secret, enc)."""
    sk_e = X25519PrivateKey.from_private_bytes(ephemeral_seed)
    enc = sk_e.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    dh = sk_e.exchange(_x25519_public_from_raw(recipient_public))
    if dh == b"\x00" * 32:
        raise ValueError("all-zero X25519 DH rejected")
    kem_context = enc + recipient_public
    eae_prk = _labeled_extract(KEM_SUITE_ID, b"", b"eae_prk", dh)
    shared = _labeled_expand(KEM_SUITE_ID, eae_prk, b"shared_secret",
                             kem_context, 32)
    return shared, enc

def hpke_key_schedule(shared_secret, info):
    psk_id_hash = _labeled_extract(HPKE_SUITE_ID, b"", b"psk_id_hash", b"")
    info_hash = _labeled_extract(HPKE_SUITE_ID, b"", b"info_hash", info)
    ks_context = b"\x00" + psk_id_hash + info_hash  # base mode = 0x00
    secret = _labeled_extract(HPKE_SUITE_ID, shared_secret, b"secret", b"")
    key = _labeled_expand(HPKE_SUITE_ID, secret, b"key", ks_context, 32)
    base_nonce = _labeled_expand(HPKE_SUITE_ID, secret, b"base_nonce",
                                 ks_context, 12)
    return key, base_nonce

def hpke_seal(recipient_public, ephemeral_seed, info, plaintext):
    shared, enc = dhkem_encap(recipient_public, ephemeral_seed)
    key, nonce = hpke_key_schedule(shared, info)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, b"")
    return enc, ct

# ---------------------------------------------------------------------------
# Artifact helpers
# ---------------------------------------------------------------------------

def artifact_preimage(domain, body):
    return domain.encode("utf-8") + b"\x00" + jcs(body)

def artifact_hash(domain, body):
    return sha256(artifact_preimage(domain, body))

def possession_preimage(domain, artifact_hash_raw):
    return domain.encode("utf-8") + b"\x00" + artifact_hash_raw

def wrap_control(domain, body, sig_records):
    h = artifact_hash(domain, body)
    return {"artifact_hash": b64(h),
            "artifact_id": "dm:ctl:v0:" + b64(h),
            "body": body,
            "signatures": sort_sigs(sig_records)}

def wrap_special(domain, body, id_prefix, hash_field, id_field, sig_records,
                 single_signature=False):
    h = artifact_hash(domain, body)
    w = {hash_field: b64(h), id_field: id_prefix + b64(h), "body": body}
    if single_signature:
        assert len(sig_records) == 1
        w["signature"] = sig_records[0]
    else:
        w["signatures"] = sort_sigs(sig_records)
    return w

# ---------------------------------------------------------------------------
# Identity artifact builders
# ---------------------------------------------------------------------------

def genesis_core(nonce_label, root_keys, root_threshold, recovery):
    return {
        "protocol": "daimon",
        "version": 0,
        "suite": SUITE,
        "domain_version": 0,
        "genesis_nonce": b64(det(nonce_label)),
        "root": threshold_set(root_keys, root_threshold),
        "recovery": recovery,
    }

def me_id_of(core):
    return "dm:me:v0:" + b64(sha256(jcs(core)))

def build_genesis(nonce_label, root_keys, root_threshold, recovery,
                  created_at_ms, root_signers, recovery_possession_signers,
                  species_release_id=None, birth_offer_id=None):
    core = genesis_core(nonce_label, root_keys, root_threshold, recovery)
    me_id = me_id_of(core)
    body = {
        "schema": "daimon-genesis/v0",
        "core": core,
        "me_id": me_id,
        "policy": {
            "max_certificate_lifetime_ms": MAX_CERT_LIFETIME_MS,
            "max_presence_ttl_ms": MAX_PRESENCE_TTL_MS,
            "max_clock_skew_ms": MAX_CLOCK_SKEW_MS,
            "nonrecoverable": recovery["mode"] == "none",
        },
        "created_at_ms": created_at_ms,
        "species_release_id": species_release_id,
        "birth_offer_id": birth_offer_id,
        "recovery_generation": 0,
        "control_sequence": 0,
    }
    pre = artifact_preimage(DOM_GENESIS, body)
    h = sha256(pre)
    sigs = [sig_record(k, "root-authorization", pre) for k in root_signers]
    if recovery["mode"] == "threshold":
        pos = possession_preimage(DOM_GENESIS, h)
        sigs += [sig_record(k, "recovery-possession", pos)
                 for k in recovery_possession_signers]
    return wrap_control(DOM_GENESIS, body, sigs)

def build_root_transition(prev_wrapper, replacement_root_keys,
                          replacement_threshold, disposition,
                          auth_signers, possession_signers,
                          control_sequence=1, domain=DOM_ROOT_TRANSITION,
                          extra_body=None):
    prev = prev_wrapper["body"]
    body = {
        "schema": "daimon-root-transition/v0",
        "me_id": prev["me_id"],
        "recovery_generation": prev["recovery_generation"],
        "control_sequence": control_sequence,
        "previous_control_hash": prev_wrapper["artifact_hash"],
        "replacement_root": threshold_set(replacement_root_keys,
                                          replacement_threshold),
        "certificate_disposition": disposition,
    }
    if extra_body:
        body.update(extra_body)
    pre = artifact_preimage(domain, body)
    h = sha256(pre)
    sigs = [sig_record(k, "root-authorization", pre) for k in auth_signers]
    pos = possession_preimage(domain, h)
    sigs += [sig_record(k, "root-possession", pos) for k in possession_signers]
    return wrap_control(domain, body, sigs)

def build_recovery_policy(prev_wrapper, replacement_recovery,
                          root_signers, recovery_auth_signers,
                          recovery_possession_signers, control_sequence=2):
    prev = prev_wrapper["body"]
    body = {
        "schema": "daimon-recovery-policy/v0",
        "me_id": prev["me_id"],
        "recovery_generation": prev["recovery_generation"],
        "control_sequence": control_sequence,
        "previous_control_hash": prev_wrapper["artifact_hash"],
        "replacement_recovery": replacement_recovery,
    }
    pre = artifact_preimage(DOM_RECOVERY_POLICY, body)
    h = sha256(pre)
    sigs = [sig_record(k, "root-authorization", pre) for k in root_signers]
    sigs += [sig_record(k, "recovery-authorization", pre)
             for k in recovery_auth_signers]
    pos = possession_preimage(DOM_RECOVERY_POLICY, h)
    sigs += [sig_record(k, "recovery-possession", pos)
             for k in recovery_possession_signers]
    return wrap_control(DOM_RECOVERY_POLICY, body, sigs)

def revocation_entry(reason, target, event_high_waters=None,
                     lease_high_water=None,
                     replacement_artifact_id=None,
                     effective_mode="on_acceptance", prior_control_position=None):
    return {
        "reason": reason,
        "target": target,
        "effective": {
            "mode": effective_mode,
            "prior_control_position": prior_control_position,
        },
        "event_high_waters": event_high_waters or [],
        "lease_high_water": lease_high_water,
        "replacement_artifact_id": replacement_artifact_id,
    }

def sort_revocations(entries):
    return sorted(entries, key=jcs)

def build_recovery_transition(prev_wrapper, post_root_keys, post_threshold,
                              compromise, revocations,
                              recovery_auth_signers, root_possession_signers,
                              extra_body=None, competing=None):
    prev = prev_wrapper["body"]
    body = {
        "schema": "daimon-recovery-transition/v0",
        "me_id": prev["me_id"],
        "recovery_generation": prev["recovery_generation"] + 1,
        "control_sequence": 0,
        "post_recovery_root": threshold_set(post_root_keys, post_threshold),
        "compromise": compromise,
        "revocations": sort_revocations(revocations),
    }
    if competing is not None:
        body["competing_control_hashes"] = sorted(competing)
    else:
        body["previous_control_hash"] = prev_wrapper["artifact_hash"]
    if extra_body:
        body.update(extra_body)
    pre = artifact_preimage(DOM_RECOVERY_TRANSITION, body)
    h = sha256(pre)
    sigs = [sig_record(k, "recovery-authorization", pre)
            for k in recovery_auth_signers]
    pos = possession_preimage(DOM_RECOVERY_TRANSITION, h)
    sigs += [sig_record(k, "root-possession", pos)
             for k in root_possession_signers]
    return wrap_control(DOM_RECOVERY_TRANSITION, body, sigs)

def build_standalone_revocation(prev_wrapper, entry, root_signers):
    prev = prev_wrapper["body"]
    body = {
        "schema": "daimon-revocation/v0",
        "me_id": prev["me_id"],
        "recovery_generation": prev["recovery_generation"],
        "control_sequence": prev["control_sequence"] + 1,
        "previous_control_hash": prev_wrapper["artifact_hash"],
        "revocation": entry,
    }
    pre = artifact_preimage(DOM_REVOCATION, body)
    sigs = [sig_record(k, "root-authorization", pre) for k in root_signers]
    return wrap_control(DOM_REVOCATION, body, sigs)

def operational_id_of(me_id, operational_nonce_b64, signing_desc):
    pre = (DOM_OPERATIONAL_ID.encode("utf-8") + b"\x00" + jcs({
        "operational_nonce": operational_nonce_b64,
        "me_id": me_id,
        "signing_key": signing_desc,
    }))
    return "dm:op:v0:" + b64(sha256(pre))

def build_certificate(me_id, operational_nonce_label, cert_nonce_label, generation,
                      previous_certificate_id, sign_key, enc_key,
                      issuing_control_position, issuing_root_descs,
                      issued_at_ms, not_before_ms, expires_at_ms,
                      purposes, constraints, initial_body_hash,
                      root_signers, signing_desc_override=None,
                      enc_desc_override=None):
    signing_desc = signing_desc_override or key_desc(sign_key)
    enc_desc = enc_desc_override or key_desc(enc_key)
    operational_nonce = b64(det(operational_nonce_label))
    body = {
        "schema": "daimon-operational-certificate/v0",
        "me_id": me_id,
        "operational_id": operational_id_of(me_id, operational_nonce, signing_desc),
        "operational_nonce": operational_nonce,
        "certificate_nonce": b64(det(cert_nonce_label)),
        "certificate_generation": generation,
        "previous_certificate_id": previous_certificate_id,
        "signing_key": signing_desc,
        "encryption_key": enc_desc,
        "issuing_control_position": issuing_control_position,
        "issuing_root_kids": sorted(d["kid"] for d in issuing_root_descs),
        "issued_at_ms": issued_at_ms,
        "not_before_ms": not_before_ms,
        "expires_at_ms": expires_at_ms,
        "purposes": purposes,
        "constraints": constraints,
        "initial_body_hash": initial_body_hash,
    }
    # Certificate IDs deliberately follow DM-010: no domain prefix in the hash.
    digest = sha256(jcs(body))
    cert_id = "dm:cert:v0:" + b64(digest)
    pre = artifact_preimage(DOM_CERTIFICATE, body)
    sigs = [sig_record(k, "root-authorization", pre) for k in root_signers]
    wrapper = {
        "body": body,
        "certificate_hash": b64(digest),
        "certificate_id": cert_id,
        "signatures": sort_sigs(sigs),
    }
    return wrapper

def build_acceptance(me_id, operational_id, cert_wrapper, sign_key,
                     cert_id_override=None, cert_hash_override=None):
    body = {
        "schema": "daimon-operational-acceptance/v0",
        "me_id": me_id,
        "operational_id": operational_id,
        "certificate_id": cert_id_override or cert_wrapper["certificate_id"],
        "certificate_hash": cert_hash_override or cert_wrapper["certificate_hash"],
    }
    pre = artifact_preimage(DOM_ACCEPTANCE, body)
    sig = sig_record(sign_key, "subject-acceptance", pre)
    return wrap_special(DOM_ACCEPTANCE, body, "dm:accept:v0:",
                        "artifact_hash", "artifact_id", [sig])

def build_lease(me_id, operational_id, cert_wrapper, sign_key, session_label,
                lease_sequence, previous_lease_hash, supersedes_session_id,
                issued_at_ms, expires_at_ms, body_hash, capability_hash,
                routes, previous_lease_receipt_id=None,
                supersedes_operational_id=None,
                superseded_event_cutoff=None):
    body = {
        "schema": "daimon-presence-lease/v0",
        "me_id": me_id,
        "operational_id": operational_id,
        "certificate_id": cert_wrapper["certificate_id"],
        "session_id": b64(det(session_label)),
        "lease_sequence": lease_sequence,
        "previous_lease_hash": previous_lease_hash,
        "previous_lease_receipt_id": previous_lease_receipt_id,
        "supersedes_session_id": supersedes_session_id,
        "supersedes_operational_id": supersedes_operational_id,
        "superseded_event_cutoff": superseded_event_cutoff,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "body_hash": body_hash,
        "capability_hash": capability_hash,
        "routes": sorted(routes, key=lambda r: (r["kind"], r["route_id"])),
    }
    pre = artifact_preimage(DOM_LEASE, body)
    sig = sig_record(sign_key, "operational-authorization", pre)
    return wrap_special(DOM_LEASE, body, "dm:lease:v0:",
                        "artifact_hash", "artifact_id", [sig])


def build_lease_receipt(lease_wrapper, event_cutoff,
                        subject_control_position, witness_me_id,
                        witness_operational_id, witness_cert_wrapper,
                        witness_control_position, accepted_at_ms,
                        witness_sign_key):
    lease = lease_wrapper["body"]
    body = {
        "schema": "daimon-lease-head-receipt/v0",
        "subject_me_id": lease["me_id"],
        "lease_id": lease_wrapper["artifact_id"],
        "lease_hash": lease_wrapper["artifact_hash"],
        "lease_sequence": lease["lease_sequence"],
        "session_id": lease["session_id"],
        "operational_id": lease["operational_id"],
        "certificate_id": lease["certificate_id"],
        "body_hash": lease["body_hash"],
        "event_cutoff": event_cutoff,
        "subject_identity_control_position": subject_control_position,
        "witness_me_id": witness_me_id,
        "witness_operational_id": witness_operational_id,
        "witness_certificate_id": witness_cert_wrapper["certificate_id"],
        "witness_identity_control_position": witness_control_position,
        "accepted_at_ms": accepted_at_ms,
    }
    pre = artifact_preimage(DOM_LEASE_RECEIPT, body)
    sig = sig_record(witness_sign_key, "witness-authorization", pre)
    return wrap_special(DOM_LEASE_RECEIPT, body, "dm:lease-receipt:v0:",
                        "artifact_hash", "artifact_id", [sig])

def build_event(me_id, operational_id, cert_wrapper, sign_key, nonce_label,
                event_sequence, previous_event_id, logical_time,
                causal_parents, body_hash, event_type, intent, payload,
                cert_id_override=None, signer_override=None):
    body = {
        "schema": "daimon-event/v0",
        "event_nonce": b64(det(nonce_label)),
        "me_id": me_id,
        "operational_id": operational_id,
        "certificate_id": cert_id_override or cert_wrapper["certificate_id"],
        "event_sequence": event_sequence,
        "previous_event_id": previous_event_id,
        "logical_time": logical_time,
        "causal_parents": causal_parents,
        "body_hash": body_hash,
        "event_type": event_type,
        "intent": intent,
        "payload": payload,
    }
    pre = artifact_preimage(DOM_EVENT, body)
    digest = sha256(pre)
    signer = signer_override or sign_key
    sig = sig_record(signer, "operational-authorization", pre)
    return {
        "body": body,
        "event_hash": b64(digest),
        "event_id": "dm:event:v0:" + b64(digest),
        "signature": sig,
    }

def build_checkpoint(subject_me_id, subject_operational_id, subject_cert_id,
                     high_water_sequence, high_water_event_id,
                     high_water_event_hash, subject_control_position,
                     witness_me_id, witness_operational_id, witness_cert_id,
                     witness_control_position, accepted_at_ms, witness_sign_key):
    body = {
        "schema": "daimon-event-checkpoint/v0",
        "subject_me_id": subject_me_id,
        "subject_operational_id": subject_operational_id,
        "subject_certificate_id": subject_cert_id,
        "high_water_sequence": high_water_sequence,
        "high_water_event_id": high_water_event_id,
        "high_water_event_hash": high_water_event_hash,
        "subject_identity_control_position": subject_control_position,
        "witness_me_id": witness_me_id,
        "witness_operational_id": witness_operational_id,
        "witness_certificate_id": witness_cert_id,
        "witness_identity_control_position": witness_control_position,
        "accepted_at_ms": accepted_at_ms,
    }
    pre = artifact_preimage(DOM_CHECKPOINT, body)
    sig = sig_record(witness_sign_key, "witness-authorization", pre)
    return wrap_special(DOM_CHECKPOINT, body, "dm:checkpoint:v0:",
                        "artifact_hash", "artifact_id", [sig])

# ---------------------------------------------------------------------------
# Sealed delivery builder
# ---------------------------------------------------------------------------

def reduced_recipient(entry):
    return {
        "me_id": entry["me_id"],
        "operational_id": entry["operational_id"],
        "certificate_id": entry["certificate_id"],
        "encryption_kid": entry["encryption_kid"],
    }

def recipient_sort_key(entry):
    return (entry["me_id"], entry["operational_id"], entry["encryption_kid"])

def build_sealed(delivery_label, inner_event_wrapper, sender, auth_id,
                 issued_at_ms, expires_at_ms, recipients,
                 cek_label=None, nonce_label=None, tampered_recipients=None):
    """recipients: list of dicts with me_id/operational_id/certificate_id/
    encryption_kid and the TestKey's public key under 'public'."""
    inner_bytes = jcs(inner_event_wrapper)
    wire_sender = {k: v for k, v in sender.items() if not k.startswith("_")}
    delivery_id = "dm:delivery:v0:" + b64(det("delivery-id/" + delivery_label))
    base = {
        "schema": "daimon-sealed-event/v0",
        "delivery_id": delivery_id,
        "event_id": inner_event_wrapper["event_id"],
        "event_hash": inner_event_wrapper["event_hash"],
        "sender": wire_sender,
        "disclosure_authorization_id": auth_id,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "suite": SUITE,
    }
    reduced = sorted((reduced_recipient(r) for r in recipients),
                     key=recipient_sort_key)
    protected = dict(base)
    protected["recipients"] = reduced
    payload_aad = DOM_SEALED_AAD.encode("utf-8") + b"\x00" + jcs(protected)

    cek = det(cek_label or ("cek/" + delivery_label))
    nonce = det(nonce_label or ("payload-nonce/" + delivery_label), 12)
    ciphertext = ChaCha20Poly1305(cek).encrypt(nonce, inner_bytes, payload_aad)

    full_recipients = []
    for r in sorted(recipients, key=recipient_sort_key):
        info = DOM_SEALED_CEK.encode("utf-8") + b"\x00" + jcs({
            "protected": protected,
            "recipient": reduced_recipient(r),
        })
        eph = det("hpke-eph/" + delivery_label + "/" + r["encryption_kid"])
        enc, wrapped = hpke_seal(r["public"], eph, info, cek)
        full_recipients.append({
            "me_id": r["me_id"],
            "operational_id": r["operational_id"],
            "certificate_id": r["certificate_id"],
            "encryption_kid": r["encryption_kid"],
            "enc": b64(enc),
            "wrapped_cek": b64(wrapped),
        })

    delivery = dict(base)
    delivery["recipients"] = tampered_recipients or full_recipients
    delivery["payload"] = {"nonce": b64(nonce), "ciphertext": b64(ciphertext)}
    pre = DOM_SEALED.encode("utf-8") + b"\x00" + jcs(delivery)
    delivery["signature"] = sig_record(sender["_key"], "delivery-authorization",
                                       pre)
    return delivery

# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def write_json(root, rel, value):
    data = jcs(value)
    # sanity: the model value must round-trip through a strict JSON parse
    assert json.loads(data.decode("utf-8")) == value, rel
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def write_bytes(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

# ---------------------------------------------------------------------------
# Fixture construction
# ---------------------------------------------------------------------------

BODY_DESCRIPTION = {
    "schema": "x/test-body-description/v0",
    "note": "Synthetic DM-011 placeholder body; DM-018 freezes the normative "
            "closed body-description body.",
    "harness": "x/test-harness",
    "model": "x/test-model",
    "provider": "x/test-provider",
    "tools": ["x/test-tool-a", "x/test-tool-b"],
}

BODY_DESCRIPTION_B = dict(BODY_DESCRIPTION, body_label="x/test-body-b")

CAPABILITY_BODY = {
    "schema": "x/test-capability-description/v0",
    "note": "Synthetic DM-011 placeholder body; DM-018 freezes the normative "
            "closed capability body.",
    "operations": ["x/test-op"],
    "scopes": ["x/test-scope"],
}

BODY_HASH = b64(sha256(jcs(BODY_DESCRIPTION)))
BODY_B_HASH = b64(sha256(jcs(BODY_DESCRIPTION_B)))
CAPABILITY_HASH = b64(sha256(jcs(CAPABILITY_BODY)))

FULL_SIGNING_PURPOSES = ["event", "event-checkpoint", "lease-head-receipt",
                         "presence-lease", "sealed-delivery"]


def control_position(wrapper):
    return {
        "recovery_generation": wrapper["body"]["recovery_generation"],
        "control_sequence": wrapper["body"]["control_sequence"],
        "control_hash": wrapper["artifact_hash"],
    }


def build_universe():
    """Build every fixture value. Returns (files, index_entries, meta)."""
    files = {}          # relpath -> JSON value (written via JCS)
    raw_files = {}      # relpath -> bytes (written verbatim)
    entries = []        # index entries
    K = KEYS

    def add(rel, value):
        assert rel not in files
        files[rel] = value
        return value

    # ------------------------------------------------------------------
    # me1 identity-control chain:
    # genesis (0,0); root transition (0,1); recovery policy (0,2);
    # recovery transition (1,0) embedding revocations;
    # standalone revocation (1,1).
    # ------------------------------------------------------------------
    recovery_genesis = {"mode": "threshold",
                        "keys": threshold_set([K["rec-a"], K["rec-b"]], 2)["keys"],
                        "threshold": 2}
    genesis = build_genesis(
        "genesis-nonce-me1",
        [K["root-a"], K["root-b"], K["root-c"]], 2,
        recovery_genesis,
        T0,
        root_signers=[K["root-a"], K["root-b"]],
        recovery_possession_signers=[K["rec-a"], K["rec-b"]],
        species_release_id="x/test-species-release-000",
        birth_offer_id=None)
    add("me1/genesis.json", genesis)
    me1 = genesis["body"]["me_id"]

    # Self-contained positive carry-forward branch. The certificate exists
    # before the rotation and its exact ID is committed by that transition.
    pre_rotation_cert = build_certificate(
        me1, "operational-nonce-pre-rotation",
        "certificate-nonce-pre-rotation", 0, None,
        K["opp-sign"], K["opp-enc"], control_position(genesis),
        [key_desc(K["root-a"]), key_desc(K["root-b"]),
         key_desc(K["root-c"])], T0 + 50, T0 + 50,
        T0 + 50 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": ["x/"]},
        BODY_HASH, root_signers=[K["root-a"], K["root-b"]])
    pre_rotation_op = pre_rotation_cert["body"]["operational_id"]
    pre_rotation_acceptance = build_acceptance(
        me1, pre_rotation_op, pre_rotation_cert, K["opp-sign"])
    carry_forward_transition = build_root_transition(
        genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "carry_forward",
         "carried_forward_certificate_ids": [
             pre_rotation_cert["certificate_id"]]},
        auth_signers=[K["root-b"], K["root-c"]],
        possession_signers=[K["newroot-a"], K["newroot-b"]])
    add("carry-forward/certificate-pre-rotation.json", pre_rotation_cert)
    add("carry-forward/acceptance-pre-rotation.json",
        pre_rotation_acceptance)
    add("carry-forward/root-transition.json", carry_forward_transition)

    root_transition = build_root_transition(
        genesis,
        [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "invalidate_all", "carried_forward_certificate_ids": []},
        auth_signers=[K["root-b"], K["root-c"]],
        possession_signers=[K["newroot-a"], K["newroot-b"]])
    add("me1/root-transition.json", root_transition)

    recovery_policy = build_recovery_policy(
        root_transition,
        {"mode": "threshold",
         "keys": threshold_set([K["rec2-a"], K["rec2-b"]], 2)["keys"],
         "threshold": 2},
        root_signers=[K["newroot-a"], K["newroot-c"]],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        recovery_possession_signers=[K["rec2-a"], K["rec2-b"]])
    add("me1/recovery-policy.json", recovery_policy)

    # Embedded revocations: retire two superseded root keys installed by the
    # root transition at (0,1).
    rev_root_a = revocation_entry(
        "key-retired",
        {"kind": "root-key", "id": root_transition["artifact_id"],
         "kid": K["newroot-a"].kid})
    rev_root_b = revocation_entry(
        "key-retired",
        {"kind": "root-key", "id": root_transition["artifact_id"],
         "kid": K["newroot-b"].kid})
    recovery_transition = build_recovery_transition(
        recovery_policy,
        [K["proot-a"], K["proot-b"]], 2,
        {"mode": "none", "control_cutoff": None,
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        [rev_root_a, rev_root_b],
        recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
        root_possession_signers=[K["proot-a"], K["proot-b"]])
    add("me1/recovery-transition.json", recovery_transition)

    post_root_descs = [key_desc(K["proot-a"]), key_desc(K["proot-b"])]
    issuing_10 = control_position(recovery_transition)

    # ------------------------------------------------------------------
    # me1 certificates
    # ------------------------------------------------------------------
    cert_lifetime = 7 * 24 * 3600 * 1000  # 7 days, within the 30-day ceiling
    cert_op1_gen0 = build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-gen0",
        0, None, K["op1-sign"], K["op1-enc"],
        issuing_10, post_root_descs,
        T0 + 100, T0 + 100, T0 + 100 + cert_lifetime,
        {"signing": FULL_SIGNING_PURPOSES,
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("me1/certificate-op1-gen0.json", cert_op1_gen0)
    op1 = cert_op1_gen0["body"]["operational_id"]
    acc_op1_gen0 = build_acceptance(me1, op1, cert_op1_gen0, K["op1-sign"])
    add("me1/acceptance-op1-gen0.json", acc_op1_gen0)

    cert_op2_gen0 = build_certificate(
        me1, "operational-nonce-op2", "certificate-nonce-op2-gen0",
        0, None, K["op2-sign"], K["op2-enc"],
        issuing_10, post_root_descs,
        T0 + 110, T0 + 110, T0 + 110 + cert_lifetime,
        {"signing": ["event", "event-checkpoint", "presence-lease"],
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("me1/certificate-op2-gen0.json", cert_op2_gen0)
    op2 = cert_op2_gen0["body"]["operational_id"]
    acc_op2_gen0 = build_acceptance(me1, op2, cert_op2_gen0, K["op2-sign"])
    add("me1/acceptance-op2-gen0.json", acc_op2_gen0)

    cert_op3_gen0 = build_certificate(
        me1, "operational-nonce-op3", "certificate-nonce-op3-gen0",
        0, None, K["op3-sign"], K["op3-enc"],
        issuing_10, post_root_descs,
        T0 + 120, T0 + 120, T0 + 120 + cert_lifetime,
        {"signing": ["event", "sealed-delivery"],
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        None,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("me1/certificate-op3-gen0.json", cert_op3_gen0)
    op3 = cert_op3_gen0["body"]["operational_id"]
    acc_op3_gen0 = build_acceptance(
        me1, op3, cert_op3_gen0, K["op3-sign"])
    add("me1/acceptance-op3-gen0.json", acc_op3_gen0)

    # Standalone revocation at (1,1): retires the op3 certificate.
    rev_op3 = revocation_entry(
        "key-retired",
        {"kind": "certificate", "id": cert_op3_gen0["certificate_id"],
         "kid": None})
    standalone_revocation = build_standalone_revocation(
        recovery_transition, rev_op3, [K["proot-a"], K["proot-b"]])
    add("me1/standalone-revocation.json", standalone_revocation)

    # Generation-1 exact renewal of op1: same keys, same operational nonce,
    # fresh certificate nonce, generation exactly +1, names gen0.
    issuing_11 = control_position(standalone_revocation)
    cert_op1_gen1 = build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-gen1",
        1, cert_op1_gen0["certificate_id"], K["op1-sign"], K["op1-enc"],
        issuing_11, post_root_descs,
        T0 + 200, T0 + 200, T0 + 200 + cert_lifetime,
        {"signing": FULL_SIGNING_PURPOSES,
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("me1/certificate-op1-gen1.json", cert_op1_gen1)
    assert cert_op1_gen1["body"]["operational_id"] == op1
    acc_op1_gen1 = build_acceptance(me1, op1, cert_op1_gen1, K["op1-sign"])
    add("me1/acceptance-op1-gen1.json", acc_op1_gen1)

    # op2 encryption-key rotation renewal: same signing key and operational
    # nonce, generation exactly +1, new X25519 key.  The expiry is
    # deliberately short (12 hours after the rotation delivery's issuance)
    # so per-recipient effective expiry can be exercised.
    rotation_delivery_issued = T0 + 20000
    cert_op2_gen1 = build_certificate(
        me1, "operational-nonce-op2", "certificate-nonce-op2-gen1",
        1, cert_op2_gen0["certificate_id"], K["op2-sign"], K["op2-enc2"],
        issuing_11, post_root_descs,
        T0 + 300, T0 + 300, rotation_delivery_issued + 12 * 3600 * 1000,
        {"signing": ["event", "event-checkpoint", "presence-lease"],
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("me1/certificate-op2-gen1.json", cert_op2_gen1)
    assert cert_op2_gen1["body"]["operational_id"] == op2
    acc_op2_gen1 = build_acceptance(me1, op2, cert_op2_gen1, K["op2-sign"])
    add("me1/acceptance-op2-gen1.json", acc_op2_gen1)

    # ------------------------------------------------------------------
    # me2 universe (cross-/me causal parent, second sealed recipient)
    # ------------------------------------------------------------------
    me2_genesis = build_genesis(
        "genesis-nonce-me2",
        [K["xroot-a"]], 1,
        {"mode": "none", "keys": [], "threshold": 0},
        T0,
        root_signers=[K["xroot-a"]],
        recovery_possession_signers=[],
        species_release_id=None,
        birth_offer_id=None)
    add("me2/genesis.json", me2_genesis)
    me2 = me2_genesis["body"]["me_id"]

    cert_opx_gen0 = build_certificate(
        me2, "operational-nonce-opx", "certificate-nonce-opx-gen0",
        0, None, K["opx-sign"], K["opx-enc"],
        control_position(me2_genesis), [key_desc(K["xroot-a"])],
        T0 + 150, T0 + 150, T0 + 150 + cert_lifetime,
        {"signing": ["event", "event-checkpoint", "lease-head-receipt"],
         "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        None,
        root_signers=[K["xroot-a"]])
    add("me2/certificate-opx-gen0.json", cert_opx_gen0)
    opx = cert_opx_gen0["body"]["operational_id"]
    acc_opx_gen0 = build_acceptance(me2, opx, cert_opx_gen0, K["opx-sign"])
    add("me2/acceptance-opx-gen0.json", acc_opx_gen0)

    # ------------------------------------------------------------------
    # Presence lease (op1, generation-1 certificate)
    # ------------------------------------------------------------------
    lease0 = build_lease(
        me1, op1, cert_op1_gen1, K["op1-sign"], "session-op1-a",
        0, None, None,
        T0 + 9000, T0 + 9000 + 240000,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-local"))}])
    add("me1/lease-op1-0.json", lease0)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    thread_id = "dm:thread:v0:" + b64(det("thread-alpha"))
    intent0 = {"thread_id": thread_id, "scope": "x/test-scope",
               "operation": "x/test-op"}
    e0 = build_event(
        me1, op1, cert_op1_gen1, K["op1-sign"], "event-nonce-e0",
        0, None, {"physical_ms": T0 + 1000, "counter": 0}, [],
        BODY_HASH, "x/test-event", intent0,
        {"schema": "x/test-payload/v0", "text": "hello /we",
         "note": "synthetic DM-011 conformance payload"})
    add("me1/event-op1-0.json", e0)

    # Cross-/me parent authored by opx under me2, with its own proof fixtures.
    opxe0 = build_event(
        me2, opx, cert_opx_gen0, K["opx-sign"], "event-nonce-opxe0",
        0, None, {"physical_ms": T0 + 5000, "counter": 3}, [],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "cross-me cause"})
    add("me2/event-opx-0.json", opxe0)

    # Successor: physical component inherited from the cross-/me parent, so
    # the HLC counter advances to 4.
    e1 = build_event(
        me1, op1, cert_op1_gen1, K["op1-sign"], "event-nonce-e1",
        1, e0["event_id"],
        {"physical_ms": T0 + 5000, "counter": 4},
        sorted([e0["event_id"], opxe0["event_id"]]),
        BODY_HASH, "x/test-event", intent0,
        {"schema": "x/test-payload/v0",
         "text": "reply with cross-me cause"})
    add("me1/event-op1-1.json", e1)

    # x/test disclosure authorization event: binds the exact sealed event,
    # sender certificate/key, and concrete recipient certificate/key set.
    # This is a DM-011 test fixture, NOT a DM-012 normative schema.
    recipients_desc = sorted([
        {"me_id": me1, "operational_id": op2,
         "certificate_id": cert_op2_gen0["certificate_id"],
         "encryption_kid": K["op2-enc"].kid},
        {"me_id": me2, "operational_id": opx,
         "certificate_id": cert_opx_gen0["certificate_id"],
         "encryption_kid": K["opx-enc"].kid},
    ], key=recipient_sort_key)
    disclosure_payload = {
        "schema": "x/test-disclosure-authorization/v0",
        "note": "Synthetic x/test disclosure authorization event for DM-011 "
                "conformance vectors only; NOT a DM-012 normative schema.",
        "event_id": e1["event_id"],
        "event_hash": e1["event_hash"],
        "sender": {"me_id": me1, "operational_id": op1,
                   "certificate_id": cert_op1_gen1["certificate_id"],
                   "signing_kid": K["op1-sign"].kid},
        "recipients": recipients_desc,
    }
    e2 = build_event(
        me1, op1, cert_op1_gen1, K["op1-sign"], "event-nonce-e2",
        2, e1["event_id"],
        {"physical_ms": T0 + 6000, "counter": 0},
        [e1["event_id"]],
        BODY_HASH, "x/test-disclosure-authorization", None,
        disclosure_payload)
    add("me1/event-op1-2-disclosure.json", e2)

    # Withheld predecessor: e3 is computed (its ID is on the wire in e4) but
    # its bytes are deliberately not shipped, making e4 'incomplete'.
    e3 = build_event(
        me1, op1, cert_op1_gen1, K["op1-sign"], "event-nonce-e3",
        3, e2["event_id"],
        {"physical_ms": T0 + 7000, "counter": 0},
        [e2["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "withheld predecessor"})
    e4 = build_event(
        me1, op1, cert_op1_gen1, K["op1-sign"], "event-nonce-e4",
        4, e3["event_id"],
        {"physical_ms": T0 + 8000, "counter": 0},
        [e3["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "out-of-order arrival; predecessor bytes withheld"})
    add("me1/event-op1-4-out-of-order.json", e4)

    # x/test recipient sets used below by disclosure-authorization fixtures.
    rotation_recipients_desc = sorted([
        {"me_id": me1, "operational_id": op2,
         "certificate_id": cert_op2_gen1["certificate_id"],
         "encryption_kid": K["op2-enc2"].kid},
        {"me_id": me2, "operational_id": opx,
         "certificate_id": cert_opx_gen0["certificate_id"],
         "encryption_kid": K["opx-enc"].kid},
    ], key=recipient_sort_key)
    # x/test disclosure authorization binding a recipient set that includes
    # the revoked op3 certificate (for the revoked-recipient delivery).
    revoked_recipients_desc = sorted([
        {"me_id": me1, "operational_id": op2,
         "certificate_id": cert_op2_gen0["certificate_id"],
         "encryption_kid": K["op2-enc"].kid},
        {"me_id": me1, "operational_id": op3,
         "certificate_id": cert_op3_gen0["certificate_id"],
         "encryption_kid": K["op3-enc"].kid},
    ], key=recipient_sort_key)
    # Contextually valid op2 event chain (seq 0 -> 1 -> 2 -> 3 -> 4) under the
    # rotated generation-1 certificate: distinct nonces with an identical
    # payload (e0/e1), an NFC payload (e2), the safe-integer HLC counter at a
    # fixed physical millisecond (e3), then the mandated counter reset at a
    # strictly larger physical millisecond (e4).
    op2e0 = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"], "event-nonce-op2e0",
        0, None, {"physical_ms": T0 + 2000, "counter": 0}, [],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "repeated observation"})
    add("me1/event-op2-0.json", op2e0)
    op2e1 = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"], "event-nonce-op2e1",
        1, op2e0["event_id"], {"physical_ms": T0 + 3000, "counter": 0},
        [op2e0["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "repeated observation"})
    add("me1/event-op2-1.json", op2e1)
    op2e2 = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"], "event-nonce-op2e2",
        2, op2e1["event_id"], {"physical_ms": T0 + 4000, "counter": 0},
        [op2e1["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "caf\u00e9"})
    add("me1/event-op2-2-nfc.json", op2e2)
    op2e3 = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"], "event-nonce-op2e3",
        3, op2e2["event_id"],
        {"physical_ms": T0 + 5000, "counter": SAFE_INT_MAX},
        [op2e2["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "HLC counter at the safe-integer maximum"})
    add("me1/event-op2-3-hlc-max-counter.json", op2e3)
    op2e4 = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"], "event-nonce-op2e4",
        4, op2e3["event_id"],
        {"physical_ms": T0 + 5001, "counter": 0},
        [op2e3["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "HLC counter reset after physical time advances"})
    add("me1/event-op2-4-hlc-reset.json", op2e4)

    # The disclosure events extend the complete op2 chain.  No positive
    # delivery fixture depends on the deliberately incomplete op1 suffix.
    rotation_auth = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"],
        "event-nonce-op2-rotation-auth", 5, op2e4["event_id"],
        {"physical_ms": T0 + 9100, "counter": 0}, [op2e4["event_id"]],
        BODY_HASH, "x/test-disclosure-authorization", None,
        {"schema": "x/test-disclosure-authorization/v0",
         "note": "Synthetic x/test disclosure authorization for the "
                 "post-rotation delivery; NOT a DM-012 normative schema.",
         "event_id": e1["event_id"],
         "event_hash": e1["event_hash"],
         "sender": {"me_id": me1, "operational_id": op1,
                    "certificate_id": cert_op1_gen1["certificate_id"],
                    "signing_kid": K["op1-sign"].kid},
         "recipients": rotation_recipients_desc})
    add("me1/event-op2-5-disclosure-rotation.json", rotation_auth)
    revoked_recipient_auth = build_event(
        me1, op2, cert_op2_gen1, K["op2-sign"],
        "event-nonce-op2-revoked-recipient-auth", 6,
        rotation_auth["event_id"],
        {"physical_ms": T0 + 9200, "counter": 0},
        [rotation_auth["event_id"]],
        BODY_HASH, "x/test-disclosure-authorization", None,
        {"schema": "x/test-disclosure-authorization/v0",
         "note": "Synthetic x/test disclosure authorization binding a "
                 "since-revoked recipient; NOT a DM-012 normative schema.",
         "event_id": e1["event_id"],
         "event_hash": e1["event_hash"],
         "sender": {"me_id": me1, "operational_id": op1,
                    "certificate_id": cert_op1_gen1["certificate_id"],
                    "signing_kid": K["op1-sign"].kid},
         "recipients": revoked_recipients_desc})
    add("me1/event-op2-6-disclosure-revoked-recipient.json",
        revoked_recipient_auth)

    # NFD counterpart on the me2 chain (seq 1), contextually valid there.
    opxe1 = build_event(
        me2, opx, cert_opx_gen0, K["opx-sign"], "event-nonce-opxe1",
        1, opxe0["event_id"], {"physical_ms": T0 + 5500, "counter": 0},
        [opxe0["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "cafe\u0301"})
    add("me2/event-opx-1-nfd.json", opxe1)

    # ------------------------------------------------------------------
    # Separate-/me witness checkpoint: me2/opx attests the op1 prefix
    # through event 2, bound to the exact subject certificate and control
    # positions.
    # ------------------------------------------------------------------
    checkpoint = build_checkpoint(
        me1, op1, cert_op1_gen1["certificate_id"],
        2, e2["event_id"], e2["event_hash"],
        issuing_11,
        me2, opx, cert_opx_gen0["certificate_id"],
        control_position(me2_genesis),
        T0 + 9500, K["opx-sign"])
    add("me1/checkpoint-opx-witness.json", checkpoint)

    cutoff0 = {
        "operational_id": op1,
        "certificate_id": cert_op1_gen1["certificate_id"],
        "event_sequence": e2["body"]["event_sequence"],
        "event_id": e2["event_id"],
        "event_hash": e2["event_hash"],
        "checkpoint_id": checkpoint["artifact_id"],
    }
    receipt0 = build_lease_receipt(
        lease0, cutoff0, issuing_11, me2, opx, cert_opx_gen0,
        control_position(me2_genesis), T0 + 9600, K["opx-sign"])
    add("me1/lease-receipt-0.json", receipt0)
    receipt0_alt = build_lease_receipt(
        lease0, cutoff0, issuing_11, me2, opx, cert_opx_gen0,
        control_position(me2_genesis), T0 + 9650, K["opx-sign"])
    add("me1/lease-receipt-0-alt.json", receipt0_alt)
    receipt0_no_events = build_lease_receipt(
        lease0, None, issuing_11, me2, opx, cert_opx_gen0,
        control_position(me2_genesis), T0 + 9550, K["opx-sign"])
    add("me1/lease-receipt-0-no-events.json", receipt0_no_events)

    # ------------------------------------------------------------------
    # Sealed deliveries (fixed multi-recipient, deterministic HPKE)
    # ------------------------------------------------------------------
    sender_desc = {"me_id": me1, "operational_id": op1,
                   "certificate_id": cert_op1_gen1["certificate_id"],
                   "signing_kid": K["op1-sign"].kid,
                   "_key": K["op1-sign"]}
    recipient_fixtures = [
        {"me_id": me1, "operational_id": op2,
         "certificate_id": cert_op2_gen0["certificate_id"],
         "encryption_kid": K["op2-enc"].kid, "public": K["op2-enc"].public},
        {"me_id": me2, "operational_id": opx,
         "certificate_id": cert_opx_gen0["certificate_id"],
         "encryption_kid": K["opx-enc"].kid, "public": K["opx-enc"].public},
    ]
    # d1 uses exactly the 24-hour TTL bound; d2 is the mandated durable
    # reseal, issued only after d1 has expired, retaining the event/message
    # ID under a new delivery ID.
    d1_issued = T0 + 10000
    d1_expires = d1_issued + MAX_DELIVERY_TTL_MS
    d1 = build_sealed("d1", e1, sender_desc, e2["event_id"],
                      d1_issued, d1_expires, recipient_fixtures)
    add("me1/sealed-delivery-1.json", d1)
    d2 = build_sealed("d2", e1, sender_desc, e2["event_id"],
                      d1_expires + 1, d1_expires + 1 + MAX_DELIVERY_TTL_MS,
                      recipient_fixtures)
    add("me1/sealed-delivery-2-reseal.json", d2)
    # Post-rotation delivery: fresh disclosure authorization (e6) binding
    # the rotated concrete recipient set, to each recipient's latest
    # certificate/encryption key.
    rotation_recipient_fixtures = [
        {"me_id": me1, "operational_id": op2,
         "certificate_id": cert_op2_gen1["certificate_id"],
         "encryption_kid": K["op2-enc2"].kid,
         "public": K["op2-enc2"].public},
        {"me_id": me2, "operational_id": opx,
         "certificate_id": cert_opx_gen0["certificate_id"],
         "encryption_kid": K["opx-enc"].kid, "public": K["opx-enc"].public},
    ]
    d3 = build_sealed("d3", e1, sender_desc, rotation_auth["event_id"],
                      rotation_delivery_issued,
                      rotation_delivery_issued + MAX_DELIVERY_TTL_MS,
                      rotation_recipient_fixtures)
    add("me1/sealed-delivery-3-rotation.json", d3)
    # Park/wake to body B under another operational credential. The identity-
    # wide lease sequence continues and the signed cutoff retires op1.
    lease1 = build_lease(
        me1, op2, cert_op2_gen1, K["op2-sign"], "session-op2-b",
        1, lease0["artifact_hash"], lease0["body"]["session_id"],
        T0 + 120000, T0 + 120000 + 240000,
        BODY_B_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op2-local"))}],
        previous_lease_receipt_id=receipt0["artifact_id"],
        supersedes_operational_id=op1,
        superseded_event_cutoff=cutoff0)
    add("me1/lease-op1-1.json", lease1)
    receipt1 = build_lease_receipt(
        lease1, None, issuing_11, me2, opx, cert_opx_gen0,
        control_position(me2_genesis), T0 + 121000, K["opx-sign"])
    add("me1/lease-receipt-1.json", receipt1)

    # The same park/wake is valid when the cited predecessor receipt has no
    # checkpointed event cutoff. Null is copied exactly rather than treated
    # as missing handoff evidence.
    lease1_no_events = build_lease(
        me1, op2, cert_op2_gen1, K["op2-sign"],
        "session-op2-b-no-events", 1, lease0["artifact_hash"],
        lease0["body"]["session_id"], T0 + 120100,
        T0 + 120100 + 240000, BODY_B_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op2-no-events"))}],
        previous_lease_receipt_id=receipt0_no_events["artifact_id"],
        supersedes_operational_id=op1, superseded_event_cutoff=None)
    add("me1/lease-op1-1-no-events.json", lease1_no_events)
    receipt1_no_events = build_lease_receipt(
        lease1_no_events, None, issuing_11, me2, opx, cert_opx_gen0,
        control_position(me2_genesis), T0 + 121100, K["opx-sign"])
    add("me1/lease-receipt-1-no-events.json", receipt1_no_events)

    # ------------------------------------------------------------------
    # Threshold endorsement fixtures: partial quorum, a second distinct
    # quorum subset, and the merged endorsement union; all carry the same
    # genesis body/artifact_id (one artifact, mergeable endorsements).
    # ------------------------------------------------------------------
    def genesis_with_sigs(auth_signers, poss_signers):
        return build_genesis(
            "genesis-nonce-me1",
            [K["root-a"], K["root-b"], K["root-c"]], 2,
            recovery_genesis, T0,
            root_signers=auth_signers,
            recovery_possession_signers=poss_signers,
            species_release_id="x/test-species-release-000",
            birth_offer_id=None)

    add("threshold/genesis-partial.json",
        genesis_with_sigs([K["root-a"]], [K["rec-a"], K["rec-b"]]))
    add("threshold/genesis-quorum-b.json",
        genesis_with_sigs([K["root-b"], K["root-c"]],
                          [K["rec-a"], K["rec-b"]]))
    add("threshold/genesis-merged.json",
        genesis_with_sigs([K["root-a"], K["root-b"], K["root-c"]],
                          [K["rec-a"], K["rec-b"]]))

    add("fixtures/body-description.json", BODY_DESCRIPTION)
    add("fixtures/body-description-b.json", BODY_DESCRIPTION_B)
    add("fixtures/capability-description.json", CAPABILITY_BODY)

    meta = {
        "me1": me1, "me2": me2, "op1": op1, "op2": op2, "op3": op3,
        "opx": opx,
        "withheld_event_id": e3["event_id"],
        "withheld_event_hash": e3["event_hash"],
        "withheld_event_sequence": 3,
        "thread_id": thread_id,
        "fixtures": {
            "genesis": genesis, "root_transition": root_transition,
            "recovery_policy": recovery_policy,
            "recovery_transition": recovery_transition,
            "standalone_revocation": standalone_revocation,
            "cert_op1_gen0": cert_op1_gen0, "cert_op1_gen1": cert_op1_gen1,
            "cert_op2_gen0": cert_op2_gen0, "cert_op3_gen0": cert_op3_gen0,
            "cert_opx_gen0": cert_opx_gen0,
            "acc_op1_gen0": acc_op1_gen0, "acc_op1_gen1": acc_op1_gen1,
            "acc_op2_gen0": acc_op2_gen0, "acc_op3_gen0": acc_op3_gen0,
            "acc_opx_gen0": acc_opx_gen0,
            "lease0": lease0, "lease1": lease1,
            "receipt0": receipt0, "receipt0_alt": receipt0_alt,
            "receipt0_no_events": receipt0_no_events,
            "receipt1": receipt1,
            "lease1_no_events": lease1_no_events,
            "receipt1_no_events": receipt1_no_events,
            "e0": e0, "e1": e1, "e2": e2, "opxe0": opxe0, "opxe1": opxe1,
            "e4": e4,
            "op2e0": op2e0, "op2e1": op2e1, "op2e2": op2e2,
            "op2e3": op2e3, "op2e4": op2e4,
            "rotation_auth": rotation_auth,
            "revoked_recipient_auth": revoked_recipient_auth,
            "cert_op2_gen1": cert_op2_gen1, "acc_op2_gen1": acc_op2_gen1,
            "checkpoint": checkpoint, "d1": d1, "d2": d2, "d3": d3,
        },
        "add": add, "files": files, "raw_files": raw_files,
        "entries": entries, "thread": thread_id,
    }
    return meta

# ---------------------------------------------------------------------------
# Negative / extra fixture construction
# ---------------------------------------------------------------------------

def fabricated_event_ids(label, count):
    return sorted("dm:event:v0:" + b64(det(label + "/%d" % i))
                  for i in range(count))


def build_extras(meta):
    """Build negative semantic variants, tamper descriptors, raw parser
    vectors, and remaining positive fixtures. Returns index entries."""
    K = KEYS
    files = meta["files"]
    raw_files = meta["raw_files"]
    F = meta["fixtures"]
    me1, me2 = meta["me1"], meta["me2"]
    op1, op2, op3, opx = meta["op1"], meta["op2"], meta["op3"], meta["opx"]
    genesis = F["genesis"]
    root_transition = F["root_transition"]
    recovery_policy = F["recovery_policy"]
    recovery_transition = F["recovery_transition"]
    standalone_revocation = F["standalone_revocation"]
    cert_g0, cert_g1 = F["cert_op1_gen0"], F["cert_op1_gen1"]
    cert_i2, cert_i2_g1 = F["cert_op2_gen0"], F["cert_op2_gen1"]
    cert_i3, cert_x = F["cert_op3_gen0"], F["cert_opx_gen0"]
    e0, e1, e2, opxe0, e4 = F["e0"], F["e1"], F["e2"], F["opxe0"], F["e4"]
    checkpoint, d1, d2 = F["checkpoint"], F["d1"], F["d2"]
    issuing_10 = control_position(recovery_transition)
    issuing_11 = control_position(standalone_revocation)
    post_root_descs = [key_desc(K["proot-a"]), key_desc(K["proot-b"])]
    entries = []

    def add(rel, value):
        assert rel not in files
        files[rel] = value
        return value

    def add_raw(rel, data):
        assert rel not in raw_files
        raw_files[rel] = data
        return rel

    def entry(**kw):
        entries.append(kw)

    def neg_event(rel, seq, prev_id, parents, lt, payload_text, **kw):
        ev = build_event(
            me1, op1, cert_g1, K["op1-sign"], "event-nonce-" + rel,
            seq, prev_id, lt, parents, BODY_HASH,
            "x/test-event", None,
            {"schema": "x/test-payload/v0", "text": payload_text}, **kw)
        return add("negative/" + rel + ".json", ev)

    # ------------------------------------------------------------------
    # Raw parser vectors (wire bytes)
    # ------------------------------------------------------------------
    def ceiling_doc(size):
        return ('{"pad":"' + "a" * (size - 10) + '"}').encode("utf-8")

    raw_specs = [
        ("raw/pos-safe-int-max.wire", b"9007199254740991", "accept", CEILING_EVENT,
         "p-jcs-canonical", "safe-integer exact upper boundary is accepted"),
        ("raw/pos-safe-int-min.wire", b"-9007199254740991", "accept", CEILING_EVENT,
         "p-jcs-canonical", "safe-integer exact lower boundary is accepted"),
        ("raw/pos-depth-64.wire", b"[" * 63 + b"0" + b"]" * 63, "accept",
         CEILING_EVENT, "p-jcs-canonical", "nesting depth exactly 64 is accepted"),
        ("raw/pos-ceiling-control.wire", ceiling_doc(CEILING_CONTROL), "accept",
         CEILING_CONTROL, "p-jcs-canonical", "exact 262144-byte control ceiling"),
        ("raw/pos-ceiling-event.wire", ceiling_doc(CEILING_EVENT), "accept",
         CEILING_EVENT, "p-jcs-canonical", "exact 1048576-byte event ceiling"),
        ("raw/pos-ceiling-sealed.wire", ceiling_doc(CEILING_SEALED), "accept",
         CEILING_SEALED, "p-jcs-canonical", "exact 2097152-byte sealed ceiling"),
        ("raw/pos-nfc-string.wire", '{"s":"caf\u00e9"}'.encode("utf-8"), "accept",
         CEILING_EVENT, "p-nfc-nfd-distinct", "NFC string is valid signed data"),
        ("raw/pos-nfd-string.wire", '{"s":"cafe\u0301"}'.encode("utf-8"), "accept",
         CEILING_EVENT, "p-nfc-nfd-distinct",
         "NFD string is valid and distinct from its NFC form"),
        ("raw/neg-unsafe-int.wire", b"9007199254740992", "reject", CEILING_EVENT,
         "n-unsafe-int", "integer above 2^53-1 is rejected"),
        ("raw/neg-unsafe-int-min.wire", b"-9007199254740992", "reject",
         CEILING_EVENT, "n-unsafe-int", "integer below -(2^53-1) is rejected"),
        ("raw/neg-negative-zero.wire", b"-0", "reject", CEILING_EVENT,
         "n-negative-zero", "negative zero is forbidden"),
        ("raw/neg-float.wire", b"1.5", "reject", CEILING_EVENT,
         "n-float", "floating-point values are forbidden"),
        ("raw/neg-exponent.wire", b"1e3", "reject", CEILING_EVENT,
         "n-float", "exponent notation is forbidden"),
        ("raw/neg-depth-65.wire", b"[" * 64 + b"0" + b"]" * 64, "reject",
         CEILING_EVENT, "n-depth", "nesting deeper than 64 levels is rejected"),
        ("raw/neg-ceiling-control-plus1.wire", ceiling_doc(CEILING_CONTROL + 1),
         "reject", CEILING_CONTROL, "n-size-ceiling",
         "control artifact one byte over the exact ceiling"),
        ("raw/neg-ceiling-event-plus1.wire", ceiling_doc(CEILING_EVENT + 1),
         "reject", CEILING_EVENT, "n-size-ceiling",
         "event wrapper one byte over the exact ceiling"),
        ("raw/neg-ceiling-sealed-plus1.wire", ceiling_doc(CEILING_SEALED + 1),
         "reject", CEILING_SEALED, "n-size-ceiling",
         "sealed delivery one byte over the exact ceiling"),
        ("raw/neg-duplicate-escaped-key.wire", b'{"a":1,"\\u0061":2}', "reject",
         CEILING_EVENT, "n-dup-key-escaped",
         'escaped duplicate keys such as "a" plus "\\u0061" are rejected'),
        ("raw/neg-invalid-utf8.wire", b'{"a":"\xff"}', "reject", CEILING_EVENT,
         "n-invalid-utf8", "invalid UTF-8 is rejected"),
        ("raw/neg-unpaired-surrogate.wire", b'{"a":"\\ud800"}', "reject",
         CEILING_EVENT, "n-invalid-utf8", "unpaired surrogates are rejected"),
        ("raw/neg-noncanonical-whitespace.wire", b'{"a": 1}', "reject",
         CEILING_EVENT, "n-noncanonical-wire",
         "alternate whitespace is not canonical wire JSON"),
        ("raw/neg-noncanonical-escape.wire", b'{"a":"\\u0041"}', "reject",
         CEILING_EVENT, "n-noncanonical-wire",
         "alternate escape spelling is not canonical wire JSON"),
        ("raw/neg-noncanonical-key-order.wire", b'{"b":1,"a":2}', "reject",
         CEILING_EVENT, "n-noncanonical-wire",
         "noncanonical key order is rejected"),
    ]
    for rel, data, expect, ceiling, tag, note in raw_specs:
        add_raw(rel, data)
        entry(id="vector-" + rel.split("/")[-1][:-5],
              **{"class": "negative" if expect == "reject" else "positive"},
              execution="executable", check="parse",
              vectors=[rel], params={"ceiling": ceiling}, expect=expect,
              covers=[tag], spec="canonical-artifacts §2.1/§2.2", note=note)

    # ------------------------------------------------------------------
    # Signed semantic negative variants (control/identity chain)
    # ------------------------------------------------------------------
    # Genesis fork: same core and me_id, different statement, threshold-valid.
    genesis_fork = build_genesis(
        "genesis-nonce-me1",
        [K["root-a"], K["root-b"], K["root-c"]], 2,
        {"mode": "threshold",
         "keys": threshold_set([K["rec-a"], K["rec-b"]], 2)["keys"],
         "threshold": 2},
        T0 + 1,
        root_signers=[K["root-a"], K["root-b"]],
        recovery_possession_signers=[K["rec-a"], K["rec-b"]],
        species_release_id="x/test-species-release-001",
        birth_offer_id=None)
    add("negative/genesis-fork-variant.json", genesis_fork)
    assert genesis_fork["body"]["me_id"] == me1
    assert genesis_fork["artifact_id"] != genesis["artifact_id"]

    genesis_unknown_role = copy.deepcopy(genesis)
    genesis_unknown_role["signatures"] = sort_sigs(
        genesis_unknown_role["signatures"] + [
            sig_record(K["root-c"], "operational-authorization",
                       artifact_preimage(DOM_GENESIS, genesis["body"]))
        ])
    add("negative/genesis-unknown-signature-role.json", genesis_unknown_role)
    entry(id="neg-genesis-unknown-signature-role", **{"class": "negative"},
          execution="executable", check="control-wrapper",
          vectors=["negative/genesis-unknown-signature-role.json"],
          params={"artifact": "genesis"}, expect="reject",
          covers=["n-inapplicable-signature-role"],
          spec="canonical-artifacts §4.2/§5.1",
          note="otherwise-valid genesis adds one cryptographically correct "
               "signature under an artifact-inapplicable role")

    # Root rotation signed only by the new root (possession, no authorization).
    add("negative/root-transition-new-root-only.json", build_root_transition(
        genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "invalidate_all", "carried_forward_certificate_ids": []},
        auth_signers=[], possession_signers=[K["newroot-a"], K["newroot-b"]]))
    # Root rotation signed only by the old root (no new possession).
    add("negative/root-transition-old-root-only.json", build_root_transition(
        genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "invalidate_all", "carried_forward_certificate_ids": []},
        auth_signers=[K["root-b"], K["root-c"]], possession_signers=[]))
    # "Carry forward all old certificates" without exact IDs is malformed.
    add("negative/root-transition-carry-forward-without-ids.json",
        build_root_transition(
            genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
            {"mode": "carry_forward",
             "carried_forward_certificate_ids": ["all-prior-certificates"]},
            auth_signers=[K["root-b"], K["root-c"]],
            possession_signers=[K["newroot-a"], K["newroot-b"]]))
    # A second, differently-contented valid successor at (0,1): control fork.
    control_fork_variant = build_root_transition(
        genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "carry_forward", "carried_forward_certificate_ids": []},
        auth_signers=[K["root-b"], K["root-c"]],
        possession_signers=[K["newroot-a"], K["newroot-b"]])
    add("negative/root-transition-fork-variant.json", control_fork_variant)

    # Fully signed, self-contained control-fork recovery scenario.  The branch
    # certificate is anchored to the competing branch, and the recovery names
    # both known heads while cutting off certificates issued from branch B.
    branch_b = build_root_transition(
        genesis, [K["branchroot-a"], K["branchroot-b"]], 2,
        {"mode": "invalidate_all", "carried_forward_certificate_ids": []},
        auth_signers=[K["root-a"], K["root-c"]],
        possession_signers=[K["branchroot-a"], K["branchroot-b"]])
    add("fork/root-transition-branch-b.json", branch_b)
    branch_cert = build_certificate(
        me1, "operational-nonce-opf", "certificate-nonce-opf-gen0",
        0, None, K["opf-sign"], K["opf-enc"],
        control_position(branch_b),
        [key_desc(K["branchroot-a"]), key_desc(K["branchroot-b"])],
        T0 + 130, T0 + 130, T0 + 130 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["branchroot-a"], K["branchroot-b"]])
    add("fork/certificate-opf-gen0.json", branch_cert)
    branch_inc = branch_cert["body"]["operational_id"]
    branch_acceptance = build_acceptance(
        me1, branch_inc, branch_cert, K["opf-sign"])
    add("fork/acceptance-opf-gen0.json", branch_acceptance)
    branch_descendant = build_recovery_policy(
        branch_b,
        {"mode": "threshold",
         "keys": threshold_set([K["rec2-a"], K["rec2-b"]], 2)["keys"],
         "threshold": 2},
        root_signers=[K["branchroot-a"], K["branchroot-b"]],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        recovery_possession_signers=[K["rec2-a"], K["rec2-b"]])
    add("fork/recovery-policy-branch-b-descendant.json", branch_descendant)

    competing_heads = [root_transition["artifact_hash"],
                       branch_b["artifact_hash"]]
    branch_cutoff = control_position(branch_b)
    branch_cutoff_revocation = revocation_entry(
        "key-compromise",
        {"kind": "certificates-from-control-cutoff",
         "id": branch_b["artifact_id"], "kid": None},
        effective_mode="at_prior_position",
        prior_control_position=branch_cutoff)
    fork_resolution = build_recovery_transition(
        genesis, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "confirmed", "control_cutoff": branch_cutoff,
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        [branch_cutoff_revocation],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]],
        competing=competing_heads)
    add("fork/recovery-resolution-a.json", fork_resolution)

    missing_head = b64(det("fork/missing-control-head"))
    incomplete_recovery = build_recovery_transition(
        genesis, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "confirmed", "control_cutoff": control_position(root_transition),
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        [revocation_entry(
            "key-compromise",
            {"kind": "certificates-from-control-cutoff",
             "id": root_transition["artifact_id"], "kid": None},
            effective_mode="at_prior_position",
            prior_control_position=control_position(root_transition))],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]],
        competing=[root_transition["artifact_hash"], missing_head])
    add("negative/recovery-incomplete-head.json", incomplete_recovery)

    omitted_head_recovery = build_recovery_transition(
        genesis, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "confirmed",
         "control_cutoff": control_position(root_transition),
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        [revocation_entry(
            "key-compromise",
            {"kind": "certificates-from-control-cutoff",
             "id": root_transition["artifact_id"], "kid": None},
            effective_mode="at_prior_position",
            prior_control_position=control_position(root_transition))],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]],
        competing=[root_transition["artifact_hash"]])
    add("negative/recovery-omits-known-head.json", omitted_head_recovery)

    conflict_b = build_recovery_transition(
        genesis, [K["proot-a"], K["proot-b"]], 2,
        {"mode": "confirmed",
         "control_cutoff": control_position(root_transition),
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        [revocation_entry(
            "key-compromise",
            {"kind": "certificates-from-control-cutoff",
             "id": root_transition["artifact_id"], "kid": None},
            effective_mode="at_prior_position",
            prior_control_position=control_position(root_transition))],
        recovery_auth_signers=[K["rec-a"], K["rec-b"]],
        root_possession_signers=[K["proot-a"], K["proot-b"]],
        competing=competing_heads)
    add("negative/recovery-conflict-b.json", conflict_b)

    add("negative/control-fork-zero-signature.json",
        zero_signatures(branch_b))

    entry(id="pos-fork-recovery-resolution", **{"class": "positive"},
          execution="executable", check="recovery-cutoff",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "fork/root-transition-branch-b.json",
                   "fork/certificate-opf-gen0.json",
                   "fork/acceptance-opf-gen0.json",
                   "fork/recovery-resolution-a.json"],
          params={"known_heads": ["me1/root-transition.json",
                                  "fork/root-transition-branch-b.json"],
                  "cutoff_branch": "fork/root-transition-branch-b.json"},
          expect="accept", covers=["p-control-fork-recovery",
                                    "p-recovery-control-cutoff"],
          spec="identity-continuity §5/§6.3; canonical-artifacts §5.2",
          note="threshold-valid recovery names both signed competing heads and "
               "revokes certificates from the declared branch-B cutoff")
    entry(id="neg-cutoff-anchored-certificate", **{"class": "negative"},
          execution="executable", check="cutoff-revoked-certificate",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "fork/root-transition-branch-b.json",
                   "fork/certificate-opf-gen0.json",
                   "fork/acceptance-opf-gen0.json",
                   "fork/recovery-resolution-a.json"],
          params={"known_heads": ["me1/root-transition.json",
                                  "fork/root-transition-branch-b.json"],
                  "cutoff_branch": "fork/root-transition-branch-b.json"},
          expect="reject", covers=["n-cutoff-anchored-cert"],
          spec="identity-continuity §6.3/§13; canonical-artifacts §5.2",
          note="the real signed branch certificate is revoked by the real "
               "fork-resolving recovery cutoff, regardless of timestamps")
    entry(id="neg-recovery-incomplete-head", **{"class": "negative"},
          execution="executable", check="recovery-cutoff",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "negative/recovery-incomplete-head.json"],
          params={"known_heads": ["me1/root-transition.json"],
                  "missing_control_hash": missing_head},
          expect="incomplete", covers=["n-recovery-named-head-unavailable"],
          spec="identity-continuity §5; canonical-artifacts §5.2",
          note="signed recovery names an unavailable competing head and remains "
               "incomplete until all named heads are verifiable")
    entry(id="neg-recovery-omits-known-head", **{"class": "negative"},
          execution="executable", check="recovery-cutoff",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "fork/root-transition-branch-b.json",
                   "negative/recovery-omits-known-head.json"],
          params={"known_heads": ["me1/root-transition.json",
                                  "fork/root-transition-branch-b.json"]},
          expect="reject", covers=["n-recovery-omits-competing-head"],
          spec="identity-continuity §5/§13; canonical-artifacts §5.2",
          note="threshold-valid recovery names head A but omits known head B")
    entry(id="neg-conflicting-recovery-freeze", **{"class": "negative"},
          execution="executable", check="pair-fork",
          vectors=["fork/recovery-resolution-a.json",
                   "negative/recovery-conflict-b.json"],
          params={"kind": "recovery",
                  "genesis": "me1/genesis.json",
                  "known_heads": ["me1/root-transition.json",
                                  "fork/root-transition-branch-b.json"]},
          expect="quarantined", covers=["n-conflicting-recovery-freeze"],
          spec="identity-continuity §5/§13",
          note="two threshold-valid recovery artifacts conflict at generation 1")
    entry(id="neg-control-fork-zero-signature", **{"class": "negative"},
          execution="executable", check="control-wrapper",
          vectors=["negative/control-fork-zero-signature.json"],
          params={"artifact": "root-transition",
                  "predecessor": "me1/genesis.json"},
          expect="reject", covers=["n-control-fork-invalid-signature"],
          spec="canonical-artifacts §4.2/§5.2",
          note="zero-signature control variant is rejected before fork handling")
    entry(id="neg-control-fork-descendant-quarantined",
          **{"class": "negative"}, execution="executable",
          check="fork-descendant",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "fork/root-transition-branch-b.json",
                   "fork/recovery-policy-branch-b-descendant.json"],
          params={}, expect="quarantined",
          covers=["n-fork-descendant-quarantine"],
          spec="identity-continuity §5/§13",
          note="cryptographically valid descendant of branch B remains "
               "quarantined while the A/B control fork is unresolved")
    # Control artifact skipping the ordinary control sequence.
    add("negative/control-sequence-skip.json", build_root_transition(
        genesis, [K["newroot-a"], K["newroot-b"], K["newroot-c"]], 2,
        {"mode": "invalidate_all", "carried_forward_certificate_ids": []},
        auth_signers=[K["root-b"], K["root-c"]],
        possession_signers=[K["newroot-a"], K["newroot-b"]],
        control_sequence=5))
    # Recovery policy replaced without the existing recovery threshold.
    add("negative/recovery-policy-no-recovery-authorization.json",
        build_recovery_policy(
            root_transition,
            {"mode": "threshold",
             "keys": threshold_set([K["rec2-a"], K["rec2-b"]], 2)["keys"],
             "threshold": 2},
            root_signers=[K["newroot-a"], K["newroot-c"]],
            recovery_auth_signers=[],
            recovery_possession_signers=[K["rec2-a"], K["rec2-b"]]))
    # Recovery transition "authorized" by a current operational key.
    add("negative/recovery-transition-operational-signed.json",
        build_recovery_transition(
            recovery_policy, [K["proot-a"], K["proot-b"]], 2,
            {"mode": "none", "control_cutoff": None,
             "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
            [revocation_entry(
                "key-retired",
                {"kind": "root-key", "id": root_transition["artifact_id"],
                 "kid": K["newroot-a"].kid})],
            recovery_auth_signers=[K["op1-sign"]],
            root_possession_signers=[K["proot-a"], K["proot-b"]]))
    add("negative/recovery-transition-transport-signed.json",
        build_recovery_transition(
            recovery_policy, [K["proot-a"], K["proot-b"]], 2,
            {"mode": "none", "control_cutoff": None,
             "preserved_certificate_ids": [], "event_high_waters": [],
             "lease_high_water": None},
            [revocation_entry(
                "key-retired",
                {"kind": "root-key", "id": root_transition["artifact_id"],
                 "kid": K["newroot-a"].kid})],
            recovery_auth_signers=[K["transport-gov-sign"]],
            root_possession_signers=[K["proot-a"], K["proot-b"]]))
    entry(id="neg-recovery-transport-governance-signed",
          **{"class": "negative"}, execution="executable",
          check="control-wrapper",
          vectors=["negative/recovery-transition-transport-signed.json"],
          params={"artifact": "recovery-transition"}, expect="reject",
          covers=["n-recovery-transport-governance-signed"],
          spec="identity-continuity §6.3/§13",
          note="transport governance has no identity-control authority even "
               "when it signs a structurally complete recovery transition")
    # One certificate both preserved and effectively revoked: invalid.
    add("negative/recovery-transition-preserved-and-revoked.json",
        build_recovery_transition(
            recovery_policy, [K["proot-a"], K["proot-b"]], 2,
            {"mode": "none", "control_cutoff": None,
             "preserved_certificate_ids": [cert_g0["certificate_id"]],
             "event_high_waters": [], "lease_high_water": None},
            [revocation_entry(
                "key-compromise",
                {"kind": "certificate", "id": cert_g0["certificate_id"],
                 "kid": None})],
            recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
            root_possession_signers=[K["proot-a"], K["proot-b"]]))
    # Fork-resolving form must not also carry a single preferred predecessor.
    add("negative/recovery-transition-both-predecessor-fields.json",
        build_recovery_transition(
            recovery_policy, [K["proot-a"], K["proot-b"]], 2,
            {"mode": "none", "control_cutoff": None,
             "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
            [],
            recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
            root_possession_signers=[K["proot-a"], K["proot-b"]],
            extra_body={"competing_control_hashes": [genesis["artifact_hash"]]}))
    # Standalone root-key revocation outside its successor transition.
    add("negative/standalone-root-key-revocation.json",
        build_standalone_revocation(
            recovery_transition,
            revocation_entry(
                "key-retired",
                {"kind": "root-key", "id": root_transition["artifact_id"],
                 "kid": K["newroot-c"].kid}),
            [K["proot-a"], K["proot-b"]]))

    # Old (genesis) root issues a new certificate after replacement; the
    # transition at (0,1) invalidated all of its certificates.
    add("negative/certificate-old-root-issues.json", build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-oldroot",
        0, None, K["op1-sign"], K["op1-enc"],
        control_position(genesis),
        threshold_set([K["root-a"], K["root-b"], K["root-c"]], 2)["keys"],
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": FULL_SIGNING_PURPOSES, "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["root-a"], K["root-b"]]))
    # Certificate anchored to a control head not on the accepted chain.
    add("negative/certificate-unknown-anchor.json", build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-badanchor",
        0, None, K["op1-sign"], K["op1-enc"],
        {"recovery_generation": 1, "control_sequence": 7,
         "control_hash": b64(det("bogus-control-hash"))},
        post_root_descs,
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": FULL_SIGNING_PURPOSES, "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]]))
    # Certificate-generation gap (0 -> 2).
    add("negative/certificate-generation-gap.json", build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-gap",
        2, cert_g0["certificate_id"], K["op1-sign"], K["op1-enc"],
        issuing_11, post_root_descs,
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": FULL_SIGNING_PURPOSES, "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]]))
    # Renewal naming the wrong predecessor certificate.
    add("negative/certificate-predecessor-mismatch.json", build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-badpred",
        1, "dm:cert:v0:" + b64(det("bogus-cert-id")),
        K["op1-sign"], K["op1-enc"],
        issuing_11, post_root_descs,
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": FULL_SIGNING_PURPOSES, "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]]))
    # Certificate fork: same operational and generation, different content.
    certificate_fork_variant = build_certificate(
        me1, "operational-nonce-op1", "certificate-nonce-op1-fork",
        1, cert_g0["certificate_id"], K["op1-sign"], K["op1-enc"],
        issuing_11, post_root_descs,
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": FULL_SIGNING_PURPOSES, "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("negative/certificate-fork-variant.json", certificate_fork_variant)
    add("negative/certificate-fork-zero-signature.json",
        zero_signatures(certificate_fork_variant))
    entry(id="neg-certificate-fork-zero-signature", **{"class": "negative"},
          execution="executable", check="certificate",
          vectors=["negative/certificate-fork-zero-signature.json"],
          params={}, expect="reject",
          covers=["n-certificate-fork-invalid-signature"],
          spec="canonical-artifacts §4.2/§5.3",
          note="zero-signature certificate variant is rejected before fork handling")
    certificate_duplicate_signature = copy.deepcopy(cert_g1)
    certificate_duplicate_signature["signatures"] = sort_sigs(
        certificate_duplicate_signature["signatures"] +
        [copy.deepcopy(certificate_duplicate_signature["signatures"][0])])
    add("negative/certificate-duplicate-signature-record.json",
        certificate_duplicate_signature)
    entry(id="neg-certificate-duplicate-signature-record",
          **{"class": "negative"}, execution="executable",
          check="certificate",
          vectors=["negative/certificate-duplicate-signature-record.json"],
          params={}, expect="reject", covers=["n-duplicate-signature-record"],
          spec="canonical-artifacts §4.2/§5.3",
          note="certificate wrapper duplicates a valid root signature record")
    # Cross-role key reuse: a root public key as operational encryption key.
    reused_enc_desc = {"alg": "X25519",
                       "kid": key_id("X25519", b64(K["proot-a"].public)),
                       "public_key": b64(K["proot-a"].public)}
    add("negative/certificate-cross-role-key-reuse.json", build_certificate(
        me1, "operational-nonce-op9", "certificate-nonce-op9",
        0, None, K["op1-sign"], K["op1-enc"],
        issuing_11, post_root_descs,
        T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": ["sealed-event-recipient"]},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
        None,
        root_signers=[K["proot-a"], K["proot-b"]],
        enc_desc_override=reused_enc_desc))
    # Two operational IDs claiming one signing key.
    add("negative/certificate-signing-key-two-operationals.json",
        build_certificate(
            me1, "operational-nonce-op1b", "certificate-nonce-op1b",
            0, None, K["op1-sign"], K["op1-enc"],
            issuing_11, post_root_descs,
            T0 + 300, T0 + 300, T0 + 300 + 7 * 24 * 3600 * 1000,
            {"signing": ["event"], "encryption": ["sealed-event-recipient"]},
            {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": ["x/"]},
            None,
            root_signers=[K["proot-a"], K["proot-b"]]))
    # The op1 signing key cannot be certified under another root-bearing /me.
    cross_me_key_certificate = build_certificate(
        me2, "operational-nonce-cross-me-key",
        "certificate-nonce-cross-me-key", 0, None,
        K["op1-sign"], K["opp-enc"],
        control_position(files["me2/genesis.json"]),
        [key_desc(K["xroot-a"])], T0 + 350, T0 + 350,
        T0 + 350 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": ["x/"]},
        None, root_signers=[K["xroot-a"]])
    add("negative/certificate-signing-key-two-me.json",
        cross_me_key_certificate)
    entry(id="neg-signing-key-two-me", **{"class": "negative"},
          execution="executable", check="certificate-me2-key-reuse",
          vectors=["negative/certificate-signing-key-two-me.json"],
          params={}, expect="reject", covers=["n-signing-key-two-me"],
          spec="identity-continuity §13; canonical-artifacts §5.3",
          note="a signing key already owned by one /me cannot be certified "
               "under another /me even with that identity's valid roots")

    # A generation-2 certificate may be structurally valid after learning an
    # unaccepted generation 1, but its subject acceptance must fail because
    # generation 1 never advanced the accepted high-water.
    skip_g0 = build_certificate(
        me1, "operational-nonce-unaccepted-skip",
        "certificate-nonce-unaccepted-skip-g0", 0, None,
        K["opp-sign"], K["opp-enc"], issuing_11, post_root_descs,
        T0 + 400, T0 + 400, T0 + 400 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": ["x/"]}, None,
        root_signers=[K["proot-a"], K["proot-b"]])
    skip_op = skip_g0["body"]["operational_id"]
    skip_a0 = build_acceptance(me1, skip_op, skip_g0, K["opp-sign"])
    skip_g1 = build_certificate(
        me1, "operational-nonce-unaccepted-skip",
        "certificate-nonce-unaccepted-skip-g1", 1,
        skip_g0["certificate_id"], K["opp-sign"], K["opp-enc"],
        issuing_11, post_root_descs, T0 + 500, T0 + 500,
        T0 + 500 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": ["x/"]}, None,
        root_signers=[K["proot-a"], K["proot-b"]])
    skip_g2 = build_certificate(
        me1, "operational-nonce-unaccepted-skip",
        "certificate-nonce-unaccepted-skip-g2", 2,
        skip_g1["certificate_id"], K["opp-sign"], K["opp-enc"],
        issuing_11, post_root_descs, T0 + 600, T0 + 600,
        T0 + 600 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": ["x/"]}, None,
        root_signers=[K["proot-a"], K["proot-b"]])
    skip_a2 = build_acceptance(me1, skip_op, skip_g2, K["opp-sign"])
    for path, artifact in (
            ("negative/certificate-unaccepted-skip-g0.json", skip_g0),
            ("negative/acceptance-unaccepted-skip-g0.json", skip_a0),
            ("negative/certificate-unaccepted-skip-g1.json", skip_g1),
            ("negative/certificate-unaccepted-skip-g2.json", skip_g2),
            ("negative/acceptance-unaccepted-skip-g2.json", skip_a2)):
        add(path, artifact)
    entry(id="neg-unaccepted-generation-skip", **{"class": "negative"},
          execution="executable", check="unaccepted-generation-skip",
          vectors=["negative/certificate-unaccepted-skip-g0.json",
                   "negative/acceptance-unaccepted-skip-g0.json",
                   "negative/certificate-unaccepted-skip-g1.json",
                   "negative/certificate-unaccepted-skip-g2.json",
                   "negative/acceptance-unaccepted-skip-g2.json"],
          params={}, expect="reject",
          covers=["n-unaccepted-generation-skip"],
          spec="identity-continuity §7/§13",
          note="a validated but unaccepted generation cannot be skipped by "
               "accepting its successor")
    # Subject acceptance naming another certificate's hash.
    add("negative/acceptance-hash-mismatch.json", build_acceptance(
        me1, op1, cert_g1, K["op1-sign"],
        cert_hash_override=cert_g0["certificate_hash"]))
    # Subject acceptance naming an unknown certificate.
    bogus_cert_id = "dm:cert:v0:" + b64(det("unknown-cert-id"))
    add("negative/acceptance-unknown-certificate.json", build_acceptance(
        me1, op1, cert_g1, K["op1-sign"],
        cert_id_override=bogus_cert_id,
        cert_hash_override=b64(det("unknown-cert-hash"))))

    # Lease variants.
    add("negative/lease-ttl-exceeded.json", build_lease(
        me1, op1, cert_g1, K["op1-sign"], "session-op1-bad-ttl",
        0, None, None, T0 + 9000, T0 + 9000 + 300001,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-local"))}]))
    add("negative/lease-beyond-certificate.json", build_lease(
        me1, op1, cert_g1, K["op1-sign"], "session-op1-beyond-cert",
        0, None, None, T0 + 9000,
        cert_g1["body"]["expires_at_ms"] + 1,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-local"))}]))
    add("negative/lease-before-certificate-not-before.json", build_lease(
        me1, op1, cert_g1, K["op1-sign"],
        "session-op1-before-certificate", 0, None, None,
        cert_g1["body"]["not_before_ms"] - 100,
        cert_g1["body"]["not_before_ms"] - 1,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" +
          b64(det("route-op1-before-certificate"))}]))
    lease_fork = build_lease(
        me1, op1, cert_g1, K["op1-sign"], "session-op1-fork",
        1, F["lease0"]["artifact_hash"],
        F["lease0"]["body"]["session_id"],
        T0 + 120001, T0 + 120001 + 240000,
        b64(det("body-c-hash")), CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-fork"))}],
        previous_lease_receipt_id=F["receipt0"]["artifact_id"],
        supersedes_operational_id=op1,
        superseded_event_cutoff=F["receipt0"]["body"]["event_cutoff"])
    add("negative/lease-op1-1-fork.json", lease_fork)
    receipt_fork = build_lease_receipt(
        lease_fork, None, issuing_11, me2, meta["opx"], cert_x,
        control_position(files["me2/genesis.json"]), T0 + 121001,
        K["opx-sign"])
    add("negative/lease-receipt-1-fork.json", receipt_fork)
    entry(id="neg-lease-fork", **{"class": "negative"},
          execution="executable", check="lease-fork",
          vectors=["me1/lease-op1-1.json", "me1/lease-receipt-1.json",
                   "negative/lease-op1-1-fork.json",
                   "negative/lease-receipt-1-fork.json"],
          params={"predecessor": "me1/lease-op1-0.json",
                  "predecessor_receipt": "me1/lease-receipt-0.json"},
          expect="quarantined", covers=["n-lease-fork"],
          spec="identity-continuity §8/§10/§13",
          note="two valid leases occupy sequence 1 and extend the same signed "
               "lease predecessor")

    lease_reset = build_lease(
        me1, op2, cert_i2_g1, K["op2-sign"], "session-op2-reset",
        0, None, None, T0 + 120000, T0 + 120000 + 240000,
        BODY_B_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op2-reset"))}])
    add("negative/lease-operational-reset.json", lease_reset)
    entry(id="neg-identity-lease-reset", **{"class": "negative"},
          execution="executable", check="lease-reset",
          vectors=["negative/lease-operational-reset.json"], params={},
          expect="reject", covers=["n-identity-wide-lease-reset"],
          spec="identity-continuity §8/§10/§13",
          note="a fresh operational credential cannot reset the /me lease "
               "sequence to zero")

    unreceipted_wake = build_lease(
        me1, op2, cert_i2_g1, K["op2-sign"], "session-op2-unreceipted",
        1, F["lease0"]["artifact_hash"], F["lease0"]["body"]["session_id"],
        T0 + 120000, T0 + 120000 + 240000,
        BODY_B_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op2-unreceipted"))}],
        previous_lease_receipt_id="dm:lease-receipt:v0:" +
        b64(det("missing-receipt")), supersedes_operational_id=op1,
        superseded_event_cutoff=F["receipt0"]["body"]["event_cutoff"])
    add("negative/lease-wake-unreceipted.json", unreceipted_wake)
    entry(id="neg-unreceipted-wake", **{"class": "negative"},
          execution="executable", check="lease-uncommitted",
          vectors=["negative/lease-wake-unreceipted.json"], params={},
          expect="uncommitted", covers=["n-unreceipted-wake"],
          spec="identity-continuity §8/§10",
          note="a byte-valid wake citing an unavailable receipt remains a "
               "local candidate and never becomes active")

    old_operational_lease = build_lease(
        me1, op1, cert_g1, K["op1-sign"], "session-op1-after-wake",
        2, F["lease1"]["artifact_hash"], F["lease1"]["body"]["session_id"],
        T0 + 130000, T0 + 130000 + 240000,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-after-wake"))}],
        previous_lease_receipt_id=F["receipt1"]["artifact_id"],
        supersedes_operational_id=op2, superseded_event_cutoff=None)
    add("negative/lease-old-operational-after-wake.json",
        old_operational_lease)
    entry(id="neg-old-operational-lease-after-wake",
          **{"class": "negative"}, execution="executable",
          check="old-operational-lease",
          vectors=["negative/lease-old-operational-after-wake.json"],
          params={}, expect="reject", covers=["n-old-operational-after-wake"],
          spec="identity-continuity §8/§10/§13",
          note="the superseded operational credential cannot extend a later "
               "identity-wide head")

    bad_receipt_body = dict(F["receipt0"]["body"])
    bad_receipt_body["lease_hash"] = b64(det("wrong-lease-hash"))
    bad_receipt = wrap_special(
        DOM_LEASE_RECEIPT, bad_receipt_body, "dm:lease-receipt:v0:",
        "artifact_hash", "artifact_id",
        [sig_record(K["opx-sign"], "witness-authorization",
                    artifact_preimage(DOM_LEASE_RECEIPT, bad_receipt_body))])
    add("negative/lease-receipt-wrong-hash.json", bad_receipt)
    entry(id="neg-lease-receipt-wrong-hash", **{"class": "negative"},
          execution="executable", check="lease-receipt",
          vectors=["me1/lease-op1-0.json",
                   "negative/lease-receipt-wrong-hash.json"], params={},
          expect="reject", covers=["n-lease-receipt-binding"],
          spec="canonical-artifacts §5.5",
          note="a correctly signed receipt for the wrong lease hash rejects")

    same_me_receipt = build_lease_receipt(
        F["lease0"], F["receipt0"]["body"]["event_cutoff"], issuing_11,
        me1, op2, cert_i2_g1, issuing_11, T0 + 9600, K["op2-sign"])
    add("negative/lease-receipt-same-me-witness.json", same_me_receipt)
    entry(id="neg-lease-receipt-same-me-witness",
          **{"class": "negative"}, execution="executable",
          check="lease-receipt",
          vectors=["me1/lease-op1-0.json",
                   "negative/lease-receipt-same-me-witness.json"], params={},
          expect="reject", covers=["n-lease-receipt-witness"],
          spec="canonical-artifacts §5.5",
          note="another credential of the same /me is not an independent "
               "external lease-head witness")

    same_session_body_change = build_lease(
        me1, op1, cert_g1, K["op1-sign"], "session-op1-a",
        1, F["lease0"]["artifact_hash"], None,
        T0 + 120000, T0 + 120000 + 240000,
        BODY_B_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-body-change"))}],
        previous_lease_receipt_id=F["receipt0"]["artifact_id"])
    add("negative/lease-same-session-body-change.json",
        same_session_body_change)
    same_session_receipt = build_lease_receipt(
        same_session_body_change, None, issuing_11, me2, meta["opx"], cert_x,
        control_position(files["me2/genesis.json"]), T0 + 121000,
        K["opx-sign"])
    add("negative/lease-receipt-same-session-body-change.json",
        same_session_receipt)
    entry(id="neg-same-session-body-change", **{"class": "negative"},
          execution="executable", check="lease-successor-reject",
          vectors=["negative/lease-same-session-body-change.json",
                   "negative/lease-receipt-same-session-body-change.json"],
          params={}, expect="reject", covers=["n-same-session-body-change"],
          spec="identity-continuity §8/§10",
          note="a same-session refresh cannot silently claim another body")

    old_event = build_event(
        me1, op1, cert_g1, K["op1-sign"], "event-old-op-after-cutoff",
        3, e2["event_id"], {"physical_ms": T0 + 7100, "counter": 0},
        [e2["event_id"]], BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "after wake cutoff"})
    add("negative/event-old-operational-after-cutoff.json", old_event)
    entry(id="neg-old-operational-event-after-wake",
          **{"class": "negative"}, execution="executable",
          check="superseded-event",
          vectors=["negative/event-old-operational-after-cutoff.json"],
          params={"known_events": ["me1/event-op1-0.json",
                                   "me1/event-op1-1.json",
                                   "me1/event-op1-2-disclosure.json"],
                  "cutoff_receipt": "me1/lease-receipt-0.json"},
          expect="reject", covers=["n-old-operational-after-wake"],
          spec="identity-continuity §8",
          note="a cryptographically valid old-key event beyond the committed "
               "handoff cutoff is inadmissible")

    membership_cert = build_certificate(
        me1, "operational-nonce-membership", "certificate-nonce-membership",
        0, None, K["opp-sign"], K["opp-enc"], issuing_11,
        post_root_descs, T0 + 400, T0 + 400,
        T0 + 400 + 24 * 3600 * 1000,
        {"signing": ["we-membership"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT, "event_type_prefixes": []},
        None, root_signers=[K["proot-a"], K["proot-b"]])
    add("negative/certificate-we-membership-purpose.json", membership_cert)
    entry(id="neg-operational-we-membership-authority",
          **{"class": "negative"}, execution="executable",
          check="certificate",
          vectors=["negative/certificate-we-membership-purpose.json"],
          params={}, expect="reject",
          covers=["n-operational-we-membership-authority"],
          spec="identity-continuity §10; canonical-artifacts §5.3",
          note="an operational certificate cannot grant /we membership")

    old_generation_lease = build_lease(
        me1, op1, cert_g0, K["op1-sign"], "session-op1-old-generation",
        0, None, None, T0 + 8000, T0 + 8000 + 240000,
        BODY_HASH, CAPABILITY_HASH,
        [{"kind": "local",
          "route_id": "dm:route:v0:" + b64(det("route-op1-old-gen"))}])
    add("negative/lease-op1-old-generation.json", old_generation_lease)
    entry(id="neg-lease-old-certificate-generation",
          **{"class": "negative"}, execution="executable", check="lease",
          vectors=["negative/lease-op1-old-generation.json"], params={},
          expect="reject", covers=["n-lease-old-certificate-generation"],
          spec="identity-continuity §7/§13",
          note="accepted but superseded certificate generation cannot issue "
               "a new presence lease")
    entry(id="neg-lease-revoked-certificate", **{"class": "negative"},
          execution="executable", check="lease-revoked",
          vectors=["me1/lease-op1-0.json"], params={}, expect="reject",
          covers=["n-lease-revoked-certificate"],
          spec="identity-continuity §9/§13",
          note="otherwise-valid lease is rejected after its certificate is "
               "present in durable revocation state")
    entry(id="neg-lease-expired-at-verification", **{"class": "negative"},
          execution="executable", check="lease-expiry",
          vectors=["me1/lease-op1-0.json"],
          params={"at_ms": F["lease0"]["body"]["expires_at_ms"]},
          expect="reject", covers=["n-lease-expired-at-verification"],
          spec="identity-continuity §10/§13",
          note="injected verification time at exact lease expiry rejects the "
               "otherwise-valid signed lease")
    entry(id="neg-stale-lease-replay", **{"class": "negative"},
          execution="executable", check="lease-rollback",
          vectors=["me1/lease-op1-0.json", "me1/lease-receipt-0.json",
                   "me1/lease-op1-1.json", "me1/lease-receipt-1.json",
                   "me1/lease-op1-0.json"], params={}, expect="reject",
          covers=["n-stale-lease-replay"],
          spec="identity-continuity §10/§13",
          note="durable lease sequence/hash high-water rejects an older "
               "byte-valid replay")

    entry(id="neg-control-head-rollback", **{"class": "negative"},
          execution="executable", check="control-rollback",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "me1/recovery-policy.json", "me1/recovery-transition.json",
                   "me1/standalone-revocation.json",
                   "me1/root-transition.json"],
          params={"accepted_head": "me1/standalone-revocation.json",
                  "replayed": "me1/root-transition.json"},
          expect="reject",
          covers=["n-control-head-rollback", "n-proof-bundle-regression"],
          spec="identity-continuity §13; canonical-artifacts §9",
          note="replaying a genuine old control artifact cannot lower the "
               "durable accepted head")
    post_revocation_transition = build_root_transition(
        standalone_revocation, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "carry_forward", "carried_forward_certificate_ids": []},
        auth_signers=[K["proot-a"], K["proot-b"]],
        possession_signers=[K["sroot-a"], K["sroot-b"]],
        control_sequence=2)
    add("negative/root-transition-after-revocation.json",
        post_revocation_transition)
    entry(id="neg-revocation-cannot-be-negated", **{"class": "negative"},
          execution="executable", check="revocation-monotonic",
          vectors=["me1/genesis.json", "me1/root-transition.json",
                   "me1/recovery-policy.json", "me1/recovery-transition.json",
                   "me1/standalone-revocation.json",
                   "negative/root-transition-after-revocation.json"],
          params={}, expect="accept", covers=["n-revocation-negation"],
          spec="identity-continuity §9/§13",
          note="a valid later control transition advances the head without "
               "removing the previously accepted revocation target")

    # ------------------------------------------------------------------
    # Signed event negatives (each isolates one semantic rule)
    # ------------------------------------------------------------------
    neg_event("event-signed-by-recovery-key", 2, e1["event_id"],
              [e1["event_id"]], {"physical_ms": T0 + 6500, "counter": 0},
              "signed by a recovery key", signer_override=K["rec-a"])
    neg_event("event-sequence-gap", 21, e0["event_id"], [e0["event_id"]],
              {"physical_ms": T0 + 6500, "counter": 0},
              "known predecessor, wrong increment")
    neg_event("event-missing-predecessor-parent", 2, e1["event_id"], [],
              {"physical_ms": T0 + 6500, "counter": 0},
              "local predecessor absent from causal parents")
    neg_event("event-hlc-regression", 2, e1["event_id"], [e1["event_id"]],
              {"physical_ms": T0 + 5000, "counter": 4},
              "HLC tuple not greater than the predecessor tuple")
    neg_event("event-duplicate-parents", 2, e1["event_id"],
              [e1["event_id"], e1["event_id"]],
              {"physical_ms": T0 + 6500, "counter": 0}, "duplicate parents")
    unsorted_parents = sorted([e0["event_id"], opxe0["event_id"]],
                              reverse=True)
    neg_event("event-unsorted-parents", 2, e1["event_id"], unsorted_parents,
              {"physical_ms": T0 + 6500, "counter": 0},
              "causal parents not in canonical sorted order")
    neg_event("event-65-parents", 2, e1["event_id"],
              [e1["event_id"]] + fabricated_event_ids("fake-parent", 64),
              {"physical_ms": T0 + 6500, "counter": 0},
              "more than 64 causal parents")
    unknown_parent = "dm:event:v0:" + b64(det("unknown-parent-id"))
    neg_event("event-unknown-parent", 2, e1["event_id"],
              sorted([e1["event_id"], unknown_parent]),
              {"physical_ms": T0 + 6500, "counter": 0},
              "one causal parent unavailable")
    event_fork_variant = neg_event(
        "event-fork-variant", 1, e0["event_id"], [e0["event_id"]],
        {"physical_ms": T0 + 6500, "counter": 0},
        "different content at the same operational sequence")
    add("negative/event-fork-zero-signature.json",
        zero_signatures(event_fork_variant))
    entry(id="neg-event-fork-zero-signature", **{"class": "negative"},
          execution="executable", check="event-contextual",
          vectors=["negative/event-fork-zero-signature.json"],
          params={"known_events": ["me1/event-op1-0.json"]},
          expect="reject", covers=["n-event-fork-invalid-signature"],
          spec="canonical-artifacts §4.2/§6.2",
          note="zero-signature event variant is rejected before fork handling")
    incomplete_descendant = build_event(
        me1, op1, cert_g1, K["op1-sign"],
        "event-nonce-incomplete-descendant", 5, F["e4"]["event_id"],
        {"physical_ms": T0 + 9000, "counter": 0}, [F["e4"]["event_id"]],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "descendant of an available but incomplete predecessor"})
    add("negative/event-op1-5-incomplete-descendant.json",
        incomplete_descendant)
    entry(id="neg-event-incomplete-ancestor-propagates",
          **{"class": "negative"}, execution="executable",
          check="event-contextual",
          vectors=["negative/event-op1-5-incomplete-descendant.json"],
          params={"known_events": ["me1/event-op1-4-out-of-order.json"]},
          expect="incomplete",
          covers=["n-incomplete-ancestor-propagates",
                  "n-quarantine-descendant-no-effects"],
          spec="canonical-artifacts §6.2/§9",
          note="bytes for the direct predecessor exist, but its own withheld "
               "ancestor keeps this descendant incomplete and unprojectable")
    activation_probe = build_event(
        me1, op2, cert_i2, K["op2-sign"],
        "event-nonce-op2-gen0-activation-probe", 0, None,
        {"physical_ms": T0 + 1500, "counter": 0}, [], BODY_HASH,
        "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "generation-zero activation probe"})
    add("negative/event-op2-gen0-activation-probe.json", activation_probe)
    entry(id="neg-certificate-acceptance-gates-activation",
          **{"class": "negative"}, execution="executable",
          check="activation-acceptance",
          vectors=["me1/certificate-op2-gen0.json",
                   "me1/acceptance-op2-gen0.json",
                   "negative/event-op2-gen0-activation-probe.json",
                   "me1/certificate-op2-gen1.json",
                   "me1/acceptance-op2-gen1.json"],
          params={}, expect="accept",
          covers=["n-certificate-without-acceptance",
                  "p-unaccepted-renewal-does-not-supersede"],
          spec="canonical-artifacts §5.3; identity-continuity §7",
          note="certificate alone grants no authority; an unaccepted renewal "
               "does not deactivate the accepted predecessor, and successful "
               "acceptance advances the active-generation high-water")
    # Late parent revealing an HLC regression.
    opx_late = build_event(
        me2, opx, cert_x, K["opx-sign"], "event-nonce-opx-late",
        1, opxe0["event_id"], {"physical_ms": T0 + 9000, "counter": 0},
        [opxe0["event_id"]], BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0", "text": "late cross-me parent"})
    add("negative/event-opx-late-parent.json", opx_late)
    neg_event("event-late-parent-hlc", 2, e1["event_id"],
              sorted([e1["event_id"], opx_late["event_id"]]),
              {"physical_ms": T0 + 8500, "counter": 0},
              "late parent makes the signed tuple non-increasing")
    # Event under a revoked certificate (op3, revoked at (1,1)).
    ev_revoked = build_event(
        me1, op3, cert_i3, K["op3-sign"], "event-nonce-revoked-cert",
        0, None, {"physical_ms": T0 + 1200, "counter": 0}, [],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "ingested after the certificate revocation was observed"})
    add("negative/event-under-revoked-certificate.json", ev_revoked)
    # New event under the superseded generation-0 certificate.
    ev_old_gen = build_event(
        me1, op1, cert_g1, K["op1-sign"], "event-nonce-old-gen",
        0, None, {"physical_ms": T0 + 1100, "counter": 0}, [],
        BODY_HASH, "x/test-event", None,
        {"schema": "x/test-payload/v0",
         "text": "new event under the superseded certificate generation"},
        cert_id_override=cert_g0["certificate_id"])
    add("negative/event-under-old-generation.json", ev_old_gen)

    # ------------------------------------------------------------------
    # Checkpoint negatives (signed by the witness, semantically wrong)
    # ------------------------------------------------------------------
    add("negative/checkpoint-wrong-sequence.json", build_checkpoint(
        me1, op1, cert_g1["certificate_id"], 2, e1["event_id"],
        e1["event_hash"], issuing_11, me1, op2,
        cert_i2["certificate_id"], issuing_10, T0 + 9500, K["op2-sign"]))
    add("negative/checkpoint-wrong-event-hash.json", build_checkpoint(
        me1, op1, cert_g1["certificate_id"], 1, e1["event_id"],
        e0["event_hash"], issuing_11, me1, op2,
        cert_i2["certificate_id"], issuing_10, T0 + 9500, K["op2-sign"]))
    add("negative/checkpoint-wrong-certificate.json", build_checkpoint(
        me1, op1, cert_g0["certificate_id"], 1, e1["event_id"],
        e1["event_hash"], issuing_11, me1, op2,
        cert_i2["certificate_id"], issuing_10, T0 + 9500, K["op2-sign"]))
    add("negative/checkpoint-witness-equals-subject.json", build_checkpoint(
        me1, op1, cert_g1["certificate_id"], 1, e1["event_id"],
        e1["event_hash"], issuing_11, me1, op1,
        cert_g1["certificate_id"], issuing_11, T0 + 9500, K["op1-sign"]))

    # ------------------------------------------------------------------
    # Sealed-delivery negatives
    # ------------------------------------------------------------------
    sender_desc = {"me_id": me1, "operational_id": op1,
                   "certificate_id": cert_g1["certificate_id"],
                   "signing_kid": K["op1-sign"].kid, "_key": K["op1-sign"]}
    r_op2 = {"me_id": me1, "operational_id": op2,
              "certificate_id": cert_i2["certificate_id"],
              "encryption_kid": K["op2-enc"].kid, "public": K["op2-enc"].public}
    r_opx = {"me_id": me2, "operational_id": opx,
             "certificate_id": cert_x["certificate_id"],
             "encryption_kid": K["opx-enc"].kid, "public": K["opx-enc"].public}
    r_op3 = {"me_id": me1, "operational_id": op3,
              "certificate_id": cert_i3["certificate_id"],
              "encryption_kid": K["op3-enc"].kid,
              "public": K["op3-enc"].public}

    add("negative/sealed-empty-recipients.json", build_sealed(
        "neg-empty", e1, sender_desc, e2["event_id"],
        T0 + 10000, T0 + 10000 + 3600000, []))

    single = build_sealed("neg-single", e1, sender_desc, e2["event_id"],
                          T0 + 10000, T0 + 10000 + 3600000, [r_op2])
    dup_recipients = [single["recipients"][0], dict(single["recipients"][0])]
    add("negative/sealed-duplicate-recipients.json", build_sealed(
        "neg-duplicate", e1, sender_desc, e2["event_id"],
        T0 + 10000, T0 + 10000 + 3600000, [r_op2],
        tampered_recipients=dup_recipients))

    both_sorted = d1["recipients"]
    add("negative/sealed-unsorted-recipients.json", build_sealed(
        "neg-unsorted", e1, sender_desc, e2["event_id"],
        T0 + 10000, T0 + 10000 + 3600000, [r_op2, r_opx],
        tampered_recipients=list(reversed([dict(r) for r in both_sorted]))))

    oversized = []
    for i in range(257):
        if i == 0:
            oversized.append(dict(both_sorted[0]))
        else:
            oversized.append({
                "me_id": me1,
                "operational_id": "dm:op:v0:" + b64(det("fake-op/%d" % i)),
                "certificate_id": "dm:cert:v0:" + b64(det("fake-cert/%d" % i)),
                "encryption_kid": key_id("X25519", b64(det("fake-enc/%d" % i))),
                "enc": b64(det("fake-enc-bytes/%d" % i)),
                "wrapped_cek": b64(det("fake-wrap/%d" % i, 48)),
            })
    oversized.sort(key=recipient_sort_key)
    add("negative/sealed-oversized-recipients.json", build_sealed(
        "neg-oversized", e1, sender_desc, e2["event_id"],
        T0 + 10000, T0 + 10000 + 3600000, [r_op2, r_opx],
        tampered_recipients=oversized))

    add("negative/sealed-ttl-exceeded.json", build_sealed(
        "neg-ttl", e1, sender_desc, e2["event_id"],
        T0 + 10000, T0 + 10000 + MAX_DELIVERY_TTL_MS + 1,
        [r_op2, r_opx]))

    # The outer delivery is freshly and correctly signed, but the decrypted
    # event carries canonical-length all-zero signature bytes.  This isolates
    # the requirement to validate the inner event from scratch.
    inner_zero_signature = zero_signatures(e1)
    add("negative/event-inner-zero-signature.json", inner_zero_signature)
    add("negative/sealed-inner-zero-signature.json", build_sealed(
        "neg-inner-zero-signature", inner_zero_signature, sender_desc,
        e2["event_id"], T0 + 10000, T0 + 10000 + MAX_DELIVERY_TTL_MS,
        [r_op2, r_opx]))

    # The disclosure authorization is valid and exact, but one concrete
    # recipient certificate has already been revoked by the accepted control
    # chain.  The sender and outer signature remain valid.
    add("negative/sealed-revoked-recipient.json", build_sealed(
        "neg-revoked-recipient", e1, sender_desc,
        F["revoked_recipient_auth"]["event_id"],
        T0 + 10000, T0 + 10000 + MAX_DELIVERY_TTL_MS,
        [r_op2, r_op3]))

    # Disclosure authorization variants (validly signed events; the binding
    # to the delivery is wrong).
    def disclosure_variant(rel, **overrides):
        payload = {
            "schema": "x/test-disclosure-authorization/v0",
            "note": "Synthetic x/test disclosure authorization variant; "
                    "NOT a DM-012 normative schema.",
            "event_id": e1["event_id"],
            "event_hash": e1["event_hash"],
            "sender": {"me_id": me1, "operational_id": op1,
                       "certificate_id": cert_g1["certificate_id"],
                       "signing_kid": K["op1-sign"].kid},
            "recipients": sorted([reduced_recipient(r_op2),
                                  reduced_recipient(r_opx)],
                                 key=recipient_sort_key),
        }
        payload.update(overrides)
        ev = build_event(
            me1, op1, cert_g1, K["op1-sign"], "event-nonce-" + rel,
            31, e1["event_id"], {"physical_ms": T0 + 6900, "counter": 0},
            [e1["event_id"]], BODY_HASH,
            "x/test-disclosure-authorization", None, payload)
        return add("negative/" + rel + ".json", ev)

    disclosure_variant("disclosure-wrong-event",
                       event_id=e0["event_id"], event_hash=e0["event_hash"])
    disclosure_variant("disclosure-wrong-sender",
                       sender={"me_id": me1, "operational_id": op1,
                               "certificate_id": cert_g1["certificate_id"],
                               "signing_kid": K["op2-sign"].kid})
    disclosure_variant("disclosure-wrong-recipients",
                       recipients=[reduced_recipient(r_op2)])

    revoked_sender_desc = {
        "me_id": me1, "operational_id": op3,
        "certificate_id": cert_i3["certificate_id"],
        "signing_kid": K["op3-sign"].kid, "_key": K["op3-sign"],
    }
    revoked_sender_auth = build_event(
        me1, op2, cert_i2_g1, K["op2-sign"],
        "event-nonce-disclosure-revoked-sender", 7,
        F["revoked_recipient_auth"]["event_id"],
        {"physical_ms": T0 + 9300, "counter": 0},
        [F["revoked_recipient_auth"]["event_id"]],
        BODY_HASH, "x/test-disclosure-authorization", None,
        {"schema": "x/test-disclosure-authorization/v0",
         "note": "Synthetic x/test authorization binding a since-revoked "
                 "sender; NOT a DM-012 normative schema.",
         "event_id": e1["event_id"], "event_hash": e1["event_hash"],
         "sender": {k: v for k, v in revoked_sender_desc.items()
                    if not k.startswith("_")},
         "recipients": sorted([reduced_recipient(r_op2),
                               reduced_recipient(r_opx)],
                              key=recipient_sort_key)})
    add("negative/disclosure-revoked-sender.json", revoked_sender_auth)
    add("negative/sealed-revoked-sender.json", build_sealed(
        "neg-revoked-sender", e1, revoked_sender_desc,
        revoked_sender_auth["event_id"],
        T0 + 10000, T0 + 10000 + MAX_DELIVERY_TTL_MS,
        [r_op2, r_opx]))

    entry(id="neg-sealed-inner-zero-signature", **{"class": "negative"},
          execution="executable", check="sealed",
          vectors=["negative/sealed-inner-zero-signature.json"],
          params={"authorization": "me1/event-op1-2-disclosure.json",
                  "inner": "negative/event-inner-zero-signature.json"},
          expect="reject", covers=["n-inner-event-signature"],
          spec="canonical-artifacts §8.2/§9",
          note="valid outer signature cannot authorize a zero-signature inner event")
    entry(id="neg-sealed-revoked-sender", **{"class": "negative"},
          execution="executable", check="sealed",
          vectors=["negative/sealed-revoked-sender.json"],
          params={"authorization": "negative/disclosure-revoked-sender.json",
                  "inner": "me1/event-op1-1.json",
                  "revoked_certificates": ["me1/certificate-op3-gen0.json"]},
          expect="reject", covers=["n-revoked-sender-delivery"],
          spec="canonical-artifacts §8.3/§9",
          note="a correctly signed delivery from a revoked sender certificate is rejected")
    entry(id="neg-sealed-revoked-recipient", **{"class": "negative"},
          execution="executable", check="sealed",
          vectors=["negative/sealed-revoked-recipient.json"],
          params={"authorization":
                  "me1/event-op2-6-disclosure-revoked-recipient.json",
                  "inner": "me1/event-op1-1.json",
                  "revoked_certificates": ["me1/certificate-op3-gen0.json"]},
          expect="reject", covers=["n-revoked-recipient-delivery"],
          spec="canonical-artifacts §8.3/§9",
          note="a concretely authorized but revoked recipient is rejected")

    # ------------------------------------------------------------------
    # Tamper descriptors (unsigned byte/field mutations; the mutation must
    # be detected by hash, signature, or AEAD validation)
    # ------------------------------------------------------------------
    def tamper(rel, base, ops, check, note, covers, params=None):
        desc = {"schema": "x/test-tamper-descriptor/v0",
                "note": note, "base": base, "ops": ops, "check": check}
        if params:
            desc["params"] = params
        add("negative/" + rel + ".json", desc)
        entry(id="neg-" + rel, **{"class": "negative"}, execution="executable",
              check="tamper", vectors=["negative/" + rel + ".json"],
              params={}, expect="reject", covers=covers,
              spec="canonical-artifacts §9", note=note)

    ED25519_L = 2**252 + 27742317777372353535851937790883648493
    tamper("tamper-event-modified-body", "me1/event-op1-1.json",
           [{"op": "json-set", "path": ["body", "payload", "text"],
             "value": "tampered"}],
           "event-wrapper", "modified canonical body is rejected",
           ["n-modified-body"])
    tamper("tamper-event-id-mismatch", "me1/event-op1-1.json",
           [{"op": "json-set", "path": ["event_id"], "value": e0["event_id"]}],
           "event-wrapper", "derived event ID mismatch is rejected",
           ["n-id-hash-mismatch"])
    tamper("tamper-genesis-hash-mismatch", "me1/genesis.json",
           [{"op": "json-set", "path": ["artifact_hash"],
             "value": b64(det("bogus-artifact-hash"))}],
           "control-wrapper",
           "derived artifact hash mismatch is rejected",
           ["n-id-hash-mismatch"], params={"artifact": "genesis"})
    tamper("tamper-cross-domain-signature", "me1/lease-op1-0.json",
           [{"op": "set-sig-value-from-file", "file": "me1/event-op1-1.json",
             "from_role": "operational-authorization",
             "to_role": "operational-authorization"}],
           "lease-wrapper",
           "a valid event signature presented under the lease domain is "
           "rejected (same signing key, different domain)",
           ["n-cross-domain-signature"])
    tamper("tamper-authorization-as-possession", "me1/recovery-policy.json",
           [{"op": "set-sig-value-by-role",
             "from_role": "recovery-authorization",
             "to_role": "recovery-possession"}],
           "control-wrapper",
           "an authorization signature used as a possession proof is rejected",
           ["n-authorization-as-possession"], params={"artifact": "recovery-policy"})
    tamper("tamper-possession-cross-transition", "me1/recovery-policy.json",
           [{"op": "set-sig-value-from-file", "file": "me1/root-transition.json",
             "from_role": "root-possession", "to_role": "recovery-possession"}],
           "control-wrapper",
           "a possession proof from one transition attached to a different "
           "transition is rejected",
           ["n-cross-domain-signature"], params={"artifact": "recovery-policy"})
    tamper("tamper-sealed-ciphertext", "me1/sealed-delivery-1.json",
           [{"op": "flip-field-byte", "path": ["payload", "ciphertext"]}],
           "sealed", "tampered payload ciphertext fails AEAD",
           ["n-tampered-delivery"])
    tamper("tamper-sealed-wrapped-cek", "me1/sealed-delivery-1.json",
           [{"op": "flip-field-byte", "path": ["recipients", 0, "wrapped_cek"]}],
           "sealed", "tampered wrapped CEK fails HPKE open",
           ["n-tampered-delivery"])
    tamper("tamper-sealed-nonce", "me1/sealed-delivery-1.json",
           [{"op": "flip-field-byte", "path": ["payload", "nonce"]}],
           "sealed", "tampered payload nonce fails AEAD",
           ["n-tampered-delivery"])
    tamper("tamper-sealed-enc", "me1/sealed-delivery-1.json",
           [{"op": "flip-field-byte", "path": ["recipients", 1, "enc"]}],
           "sealed", "tampered HPKE encapsulation fails decapsulation",
           ["n-tampered-delivery"])
    tamper("tamper-sealed-event-id", "me1/sealed-delivery-1.json",
           [{"op": "json-set", "path": ["event_id"], "value": e0["event_id"]}],
           "sealed", "outer/inner event ID mismatch is rejected",
           ["n-outer-inner-mismatch"])
    tamper("tamper-sealed-signature", "me1/sealed-delivery-1.json",
           [{"op": "flip-field-byte", "path": ["signature", "value"]}],
           "sealed", "tampered outer signature is rejected",
           ["n-tampered-delivery"])
    tamper("tamper-sealed-recipient-descriptor", "me1/sealed-delivery-1.json",
           [{"op": "json-set", "path": ["recipients", 0, "certificate_id"],
             "value": cert_g0["certificate_id"]}],
           "sealed", "tampered recipient descriptor is rejected",
           ["n-tampered-delivery"])
    tamper("tamper-checkpoint-body", "me1/checkpoint-opx-witness.json",
           [{"op": "json-set", "path": ["body", "accepted_at_ms"],
             "value": T0 + 9501}],
           "checkpoint-wrapper", "modified checkpoint body is rejected",
           ["n-modified-body"])
    tamper("tamper-certificate-body", "me1/certificate-op1-gen1.json",
           [{"op": "json-set", "path": ["body", "purposes", "encryption"],
             "value": []}],
           "certificate-wrapper", "modified certificate body is rejected",
           ["n-modified-body"])
    tamper("tamper-ed25519-noncanonical-s", "me1/event-op1-1.json",
           [{"op": "set-signature-s", "s_le_hex": "%064x" % ED25519_L}],
           "event-wrapper",
           "a non-canonical Ed25519 S scalar is rejected",
           ["n-ed25519-noncanonical-s"])
    tamper("tamper-noncanonical-base64", "me1/event-op1-1.json",
           [{"op": "json-set", "path": ["body", "event_nonce"],
             "value": e1["body"]["event_nonce"] + "="}],
           "event-wrapper",
           "padded (non-canonical) base64url is rejected",
           ["n-noncanonical-base64"])
    tamper("tamper-unknown-property", "me1/event-op1-1.json",
           [{"op": "json-set", "path": ["body", "bogus_property"],
             "value": "x"}],
           "event-wrapper",
           "unknown properties in closed protocol objects are rejected",
           ["n-unknown-property"])
    tamper("tamper-duplicate-signature-record", "me1/genesis.json",
           [{"op": "duplicate-first-signature"}],
           "control-wrapper",
           "duplicate (role,kid) signatures are rejected",
           ["n-threshold-duplicate-sig"], params={"artifact": "genesis"})
    tamper("tamper-short-signature", "me1/genesis.json",
           [{"op": "truncate-first-signature", "length": 63}],
           "control-wrapper",
           "short threshold signatures are rejected",
           ["n-threshold-short-sig"], params={"artifact": "genesis"})

    # Delivery conflict: same delivery_id, different canonical bytes.
    tamper("tamper-delivery-conflict", "me1/sealed-delivery-2-reseal.json",
           [{"op": "flip-field-byte", "path": ["payload", "nonce"]}],
           "delivery-conflict",
           "same delivery ID with different bytes is a delivery conflict",
           ["n-delivery-conflict"],
           params={"other": "me1/sealed-delivery-2-reseal.json"})

    # ------------------------------------------------------------------
    # Key-descriptor negatives (raw descriptors, no artifact)
    # ------------------------------------------------------------------
    small_order_desc = {"alg": "Ed25519",
                        "kid": key_id("Ed25519", b64(b"\x01" + b"\x00" * 31)),
                        "public_key": b64(b"\x01" + b"\x00" * 31)}
    add("negative/descriptor-small-order-ed25519.json", {
        "schema": "x/test-descriptor-vector/v0",
        "note": "small-order Ed25519 public point (identity encoding) must "
                "be rejected",
        "descriptor": small_order_desc})
    wrong_kid_desc = {"alg": "Ed25519",
                      "kid": key_id("Ed25519", b64(det("other-key"))),
                      "public_key": b64(K["root-a"].public)}
    add("negative/descriptor-kid-mismatch.json", {
        "schema": "x/test-descriptor-vector/v0",
        "note": "derived key-ID mismatch must be rejected",
        "descriptor": wrong_kid_desc})
    alias_set = {"keys": [
        {"alg": "Ed25519", "kid": key_id("Ed25519", b64(K["root-a"].public)),
         "public_key": b64(K["root-a"].public)},
        {"alg": "Ed25519", "kid": key_id("Ed25519", b64(K["root-a"].public)[::-1]),
         "public_key": b64(K["root-a"].public)},
    ], "threshold": 2}
    alias_set["keys"].sort(key=lambda d: d["kid"])
    add("negative/descriptor-key-alias.json", {
        "schema": "x/test-descriptor-vector/v0",
        "note": "one public key presented under two aliases must be rejected",
        "descriptor": alias_set})

    # ------------------------------------------------------------------
    # Deterministic resource-array boundaries on real protocol wrappers.
    # Every signature below is genuine and covers the exact artifact body.
    # ------------------------------------------------------------------
    boundary_keys = [K["bound-sign-%03d" % i] for i in range(129)]

    threshold_32 = build_genesis(
        "boundary-threshold-32", boundary_keys[:32], 1,
        {"mode": "none", "keys": [], "threshold": 0}, T0,
        root_signers=[boundary_keys[0]], recovery_possession_signers=[],
        species_release_id=None, birth_offer_id=None)
    threshold_33 = build_genesis(
        "boundary-threshold-33", boundary_keys[:33], 1,
        {"mode": "none", "keys": [], "threshold": 0}, T0,
        root_signers=[boundary_keys[0]], recovery_possession_signers=[],
        species_release_id=None, birth_offer_id=None)
    add("boundary/threshold-keys-32.json", threshold_32)
    add("boundary/threshold-keys-33.json", threshold_33)

    # A recovery-policy change can legitimately carry 32 current-root
    # authorizations, 32 current-recovery authorizations, and 32 replacement-
    # recovery possession proofs: 96 signatures, the reachable V0 maximum.
    sig_roots = boundary_keys[:32]
    sig_recovery = boundary_keys[32:64]
    sig_replacement = boundary_keys[64:96]
    signature_genesis = build_genesis(
        "boundary-signatures-genesis", sig_roots, 32,
        {"mode": "threshold",
         "keys": threshold_set(sig_recovery, 32)["keys"], "threshold": 32},
        T0, root_signers=sig_roots,
        recovery_possession_signers=sig_recovery,
        species_release_id=None, birth_offer_id=None)
    add("boundary/signatures-reachable-genesis.json", signature_genesis)
    signatures_96 = build_recovery_policy(
        signature_genesis,
        {"mode": "threshold",
         "keys": threshold_set(sig_replacement, 32)["keys"], "threshold": 32},
        root_signers=sig_roots, recovery_auth_signers=sig_recovery,
        recovery_possession_signers=sig_replacement, control_sequence=1)
    assert len(signatures_96["signatures"]) == 96
    add("boundary/signatures-96-reachable.json", signatures_96)
    signature_preimage = artifact_preimage(
        DOM_RECOVERY_POLICY, signatures_96["body"])
    signatures_128 = copy.deepcopy(signatures_96)
    signatures_128["signatures"] = sort_sigs(
        signatures_128["signatures"] + [
            sig_record(key, "root-authorization", signature_preimage)
            for key in boundary_keys[96:128]
        ])
    signatures_129 = copy.deepcopy(signatures_128)
    signatures_129["signatures"] = sort_sigs(
        signatures_129["signatures"] + [
            sig_record(boundary_keys[128], "root-authorization",
                       signature_preimage)
        ])
    assert len(signatures_128["signatures"]) == 128
    assert len(signatures_129["signatures"]) == 129
    add("boundary/signatures-128.json", signatures_128)
    add("boundary/signatures-129.json", signatures_129)

    revocation_items = [
        revocation_entry(
            "operator-request",
            {"kind": "certificate",
             "id": "dm:cert:v0:" + b64(det("boundary/certificate/%03d" % i)),
             "kid": None})
        for i in range(257)
    ]
    revocations_256 = build_recovery_transition(
        recovery_policy, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "none", "control_cutoff": None,
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        revocation_items[:256],
        recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]])
    revocations_257 = build_recovery_transition(
        recovery_policy, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "none", "control_cutoff": None,
         "preserved_certificate_ids": [], "event_high_waters": [], "lease_high_water": None},
        revocation_items,
        recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]])
    add("boundary/revocations-256.json", revocations_256)
    add("boundary/revocations-257.json", revocations_257)

    route_items = sorted([
        {"kind": "local",
         "route_id": "dm:route:v0:" + b64(det("boundary/route/%03d" % i))}
        for i in range(65)
    ], key=lambda value: (value["kind"], value["route_id"]))
    routes_64 = build_lease(
        me1, op1, cert_g1, K["op1-sign"], "boundary-routes-64",
        0, None, None, T0 + 9000, T0 + 9000 + 240000,
        BODY_HASH, CAPABILITY_HASH, route_items[:64])
    routes_65 = build_lease(
        me1, op1, cert_g1, K["op1-sign"], "boundary-routes-65",
        0, None, None, T0 + 9000, T0 + 9000 + 240000,
        BODY_HASH, CAPABILITY_HASH, route_items)
    add("boundary/routes-64.json", routes_64)
    add("boundary/routes-65.json", routes_65)

    prefix_items = sorted("x/p%03d" % i for i in range(65))
    prefixes_64 = build_certificate(
        me1, "boundary-prefixes-op64", "boundary-prefixes-cert64",
        0, None, K["opp-sign"], K["opp-enc"], issuing_11,
        post_root_descs, T0 + 400, T0 + 400,
        T0 + 400 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": prefix_items[:64]},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    prefixes_65 = build_certificate(
        me1, "boundary-prefixes-inc65", "boundary-prefixes-cert65",
        0, None, K["opp-sign"], K["opp-enc"], issuing_11,
        post_root_descs, T0 + 400, T0 + 400,
        T0 + 400 + 7 * 24 * 3600 * 1000,
        {"signing": ["event"], "encryption": []},
        {"max_event_bytes": CEILING_EVENT,
         "event_type_prefixes": prefix_items},
        BODY_HASH,
        root_signers=[K["proot-a"], K["proot-b"]])
    add("boundary/event-type-prefixes-64.json", prefixes_64)
    add("boundary/event-type-prefixes-65.json", prefixes_65)

    high_water_items = sorted([
        {"operational_id":
         "dm:op:v0:" + b64(det("boundary/operational/%04d" % i)),
         "sequence": i,
         "event_id": "dm:event:v0:" +
         b64(det("boundary/high-water/%04d" % i)),
         "event_hash": b64(det("boundary/high-water/%04d" % i))}
        for i in range(1025)
    ], key=lambda value: value["operational_id"])
    high_waters_1024 = build_recovery_transition(
        recovery_policy, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "none", "control_cutoff": None,
         "preserved_certificate_ids": [],
         "event_high_waters": high_water_items[:1024], "lease_high_water": None},
        [], recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]])
    high_waters_1025 = build_recovery_transition(
        recovery_policy, [K["sroot-a"], K["sroot-b"]], 2,
        {"mode": "none", "control_cutoff": None,
         "preserved_certificate_ids": [],
         "event_high_waters": high_water_items, "lease_high_water": None},
        [], recovery_auth_signers=[K["rec2-a"], K["rec2-b"]],
        root_possession_signers=[K["sroot-a"], K["sroot-b"]])
    add("boundary/high-waters-1024.json", high_waters_1024)
    add("boundary/high-waters-1025.json", high_waters_1025)

    resources = [
        ("threshold-keys", 32, "threshold keys", "canonical-artifacts §2.1"),
        ("revocations", 256, "embedded revocations",
         "canonical-artifacts §2.1/§5.2"),
        ("routes", 64, "presence routes", "canonical-artifacts §2.1/§5.4"),
        ("event-type-prefixes", 64, "certificate event-type prefixes",
         "canonical-artifacts §2.1/§5.3"),
        ("high-waters", 1024, "control high-water entries",
         "canonical-artifacts §2.1/§5.2"),
    ]
    for kind, limit, label, spec in resources:
        for count in (limit, limit + 1):
            accepted = count == limit
            rel = "boundary/%s-%s.json" % (kind, count)
            entry(id=("pos-" if accepted else "neg-") +
                  "%s-boundary-%s" % (kind, count),
                  **{"class": "positive" if accepted else "negative"},
                  execution="executable", check="static-bound",
                  vectors=[rel], params={"kind": kind, "limit": limit},
                  expect="accept" if accepted else "reject",
                  covers=[("p-" if accepted else "n-") +
                          "%s-bound" % kind], spec=spec,
                  note=("real signed artifact at the exact %s-item %s bound" %
                        (limit, label) if accepted else
                        "real signed artifact with %s items exceeds the "
                        "%s-item %s bound" % (count, limit, label)))

    entry(id="pos-signatures-reachable-96", **{"class": "positive"},
          execution="executable", check="static-bound",
          vectors=["boundary/signatures-reachable-genesis.json",
                   "boundary/signatures-96-reachable.json"],
          params={"kind": "signatures", "limit": 128, "target": 1},
          expect="accept", covers=["p-signatures-reachable-maximum"],
          spec="canonical-artifacts §2.1/§5.2",
          note="real recovery-policy wrapper reaches the semantic maximum: "
               "32 root authorizations + 32 recovery authorizations + 32 "
               "replacement-recovery possession proofs")
    entry(id="d-signatures-exact-128", **{"class": "positive"},
          execution="documented", check=None,
          vectors=["boundary/signatures-128.json"], params={},
          expect="see rationale", covers=["p-signatures-bound"],
          spec="canonical-artifacts §2.1/§5.2", note=None,
          rationale="the real wrapper contains 128 cryptographically correct "
                    "distinct signatures over its exact body, but V0 role and "
                    "32-key-set limits make more than 96 authorized signatures "
                    "semantically unreachable; it is therefore not claimed as "
                    "a positive artifact")
    entry(id="neg-signatures-boundary-129", **{"class": "negative"},
          execution="executable", check="static-bound",
          vectors=["boundary/signatures-129.json"],
          params={"kind": "signatures", "limit": 128}, expect="reject",
          covers=["n-signatures-bound"], spec="canonical-artifacts §2.1",
          note="real wrapper with 129 correct signature records is rejected by "
               "the centralized bound before authorization evaluation")

    return entries

# ---------------------------------------------------------------------------
# Index assembly
# ---------------------------------------------------------------------------

def build_index(meta, entries):
    K = KEYS
    F = meta["fixtures"]
    files = meta["files"]
    cert_g0, cert_g1 = F["cert_op1_gen0"], F["cert_op1_gen1"]
    e0, e1, e2 = F["e0"], F["e1"], F["e2"]
    d1, d2, d3 = F["d1"], F["d2"], F["d3"]
    cert_i2_g1 = F["cert_op2_gen1"]
    checkpoint = F["checkpoint"]
    recovery_transition = F["recovery_transition"]

    def entry(**kw):
        entries.append(kw)

    # Missing disclosure authorization field (added here so all tamper
    # descriptors live with the negative set).
    files["negative/tamper-sealed-missing-disclosure.json"] = {
        "schema": "x/test-tamper-descriptor/v0",
        "note": "the mandatory disclosure_authorization_id is absent",
        "base": "me1/sealed-delivery-1.json",
        "ops": [{"op": "json-delete", "path": ["disclosure_authorization_id"]}],
        "check": "sealed"}

    P = [
        # --- positive entries ---
        dict(id="pos-test-keys", **{"class": "positive"}, execution="executable",
             check="keys", vectors=["keys.json"], params={}, expect="accept",
             covers=["p-ed25519-seed-to-public", "p-base64url"],
             spec="canonical-artifacts §4.1/§9",
             note="Ed25519/X25519 seed-to-public-key and content-derived key IDs"),
        dict(id="pos-descriptive-fixtures", **{"class": "positive"},
             execution="executable", check="fixtures",
             vectors=["fixtures/body-description.json",
                      "fixtures/capability-description.json"],
             params={}, expect="accept",
             covers=["p-jcs-canonical", "p-metadata-me-unchanged"],
             spec="canonical-artifacts §5.4/§6.1",
             note="body/capability hashes follow the current formulas; "
                  "bodies are x/test placeholders until DM-018 freezes them"),
        dict(id="pos-identity-chain", **{"class": "positive"},
             execution="executable", check="chain",
             vectors=["me1/genesis.json", "me1/root-transition.json",
                      "me1/recovery-policy.json", "me1/recovery-transition.json",
                      "me1/standalone-revocation.json"],
             params={}, expect="accept",
             covers=["p-genesis-core-me-id", "p-linkage-chain",
                     "p-wrapper-domain-genesis",
                     "p-wrapper-domain-root-transition",
                     "p-wrapper-domain-recovery-policy",
                     "p-wrapper-domain-recovery-transition",
                     "p-wrapper-domain-revocation"],
             spec="canonical-artifacts §5.1/§5.2/§9",
             note="exact chain: genesis (0,0); root transition (0,1); "
                  "recovery policy (0,2); recovery (1,0) embedding "
                  "revocations; standalone revocation (1,1)"),
        dict(id="pos-certificate-carry-forward",
             **{"class": "positive"}, execution="executable",
             check="certificate-carry-forward",
             vectors=["me1/genesis.json",
                      "carry-forward/certificate-pre-rotation.json",
                      "carry-forward/root-transition.json",
                      "carry-forward/acceptance-pre-rotation.json"],
             params={}, expect="accept",
             covers=["p-certificate-carry-forward"],
             spec="identity-continuity §6.2/§13",
             note="a certificate issued before rotation remains valid because "
                  "the transition commits its exact already-validated ID"),
        dict(id="pos-me2-genesis", **{"class": "positive"}, execution="executable",
             check="chain", vectors=["me2/genesis.json"],
             params={"chain": "me2"}, expect="accept",
             covers=["p-genesis-core-me-id"], spec="canonical-artifacts §5.1",
             note="second /me with explicit no-recovery mode"),
        dict(id="pos-certificates", **{"class": "positive"}, execution="executable",
             check="certificates",
             vectors=["me1/certificate-op1-gen0.json",
                      "me1/acceptance-op1-gen0.json",
                      "me1/certificate-op1-gen1.json",
                      "me1/acceptance-op1-gen1.json",
                      "me1/certificate-op2-gen0.json",
                      "me1/acceptance-op2-gen0.json",
                      "me1/certificate-op2-gen1.json",
                      "me1/acceptance-op2-gen1.json",
                      "me1/certificate-op3-gen0.json",
                      "me1/acceptance-op3-gen0.json",
                      "me2/certificate-opx-gen0.json",
                      "me2/acceptance-opx-gen0.json"],
             params={}, expect="accept",
             covers=["p-operational-id", "p-certificate-id", "p-exact-renewal",
                     "p-wrapper-domain-certificate",
                     "p-wrapper-domain-acceptance"],
             spec="canonical-artifacts §5.3/§9",
             note="generation-0 certificate with null previous_certificate_id "
                  "and generation-1 exact renewal, with subject acceptances"),
        dict(id="pos-lease", **{"class": "positive"}, execution="executable",
             check="lease", vectors=["me1/lease-op1-0.json"], params={},
             expect="accept", covers=["p-wrapper-domain-lease"],
             spec="canonical-artifacts §5.4",
             note="first-ever lease: null predecessor, bounded TTL, sorted routes"),
        dict(id="pos-lease-receipt", **{"class": "positive"},
             execution="executable", check="lease-receipt",
             vectors=["me1/lease-op1-0.json",
                      "me1/lease-receipt-0.json"], params={},
             expect="accept",
             covers=["p-wrapper-domain-lease-receipt",
                     "p-external-lease-commit", "p-lease-high-water"],
             spec="canonical-artifacts §5.5",
             note="a designated external /me signs the exact durable lease "
                  "head and receipt-bearing event cutoff"),
        dict(id="pos-park-wake", **{"class": "positive"},
             execution="executable", check="park-wake",
             vectors=["me1/lease-op1-0.json", "me1/lease-receipt-0.json",
                      "me1/lease-op1-1.json", "me1/lease-receipt-1.json"],
             params={}, expect="accept",
             covers=["p-identity-wide-lease", "p-park-wake"],
             spec="identity-continuity §8/§10; canonical-artifacts §5.4/§5.5",
             note="one /me moves from body/op1 to body/op2 while its lease "
                  "sequence continues from the receipt-bearing predecessor"),
        dict(id="pos-park-wake-null-cutoff", **{"class": "positive"},
             execution="executable", check="park-wake",
             vectors=["me1/lease-op1-0.json",
                      "me1/lease-receipt-0-no-events.json",
                      "me1/lease-op1-1-no-events.json",
                      "me1/lease-receipt-1-no-events.json"],
             params={}, expect="accept", covers=["p-null-handoff-cutoff"],
             spec="canonical-artifacts §5.4/§5.5",
             note="a body/key handoff copies a cited receipt's null event "
                  "cutoff exactly when no checkpoint was retained"),
        dict(id="pos-multiple-lease-receipts", **{"class": "positive"},
             execution="executable", check="multiple-lease-receipts",
             vectors=["me1/lease-op1-0.json",
                      "me1/lease-receipt-0.json",
                      "me1/lease-receipt-0-alt.json",
                      "me1/lease-op1-1.json",
                      "me1/lease-receipt-1.json"],
             params={}, expect="accept",
             covers=["p-multiple-lease-receipts"],
             spec="canonical-artifacts §5.5",
             note="receipts for one lease have set semantics: a later "
                  "arrival cannot invalidate a successor citing an earlier "
                  "accepted receipt"),
        dict(id="pos-events", **{"class": "positive"}, execution="executable",
             check="events",
             vectors=["me1/event-op2-0.json", "me1/event-op2-1.json",
                      "me1/event-op2-2-nfc.json",
                      "me1/event-op2-3-hlc-max-counter.json",
                      "me1/event-op2-4-hlc-reset.json",
                      "me2/event-opx-0.json", "me2/event-opx-1-nfd.json"],
             params={}, expect="accept",
             covers=["p-wrapper-domain-event", "p-event-zero",
                     "p-event-successor", "p-event-hlc", "p-cross-me-parent"],
             spec="canonical-artifacts §6.1/§6.2",
             note="complete op2 generation-1 chain through the HLC maximum "
                  "and physical-time reset, plus a complete me2 chain"),
        dict(id="pos-hlc-safe-max-reset", **{"class": "positive"},
             execution="executable", check="hlc-author",
             vectors=["me1/event-op2-3-hlc-max-counter.json",
                      "me1/event-op2-4-hlc-reset.json"],
             params={"known_events": ["me1/event-op2-0.json",
                                      "me1/event-op2-1.json",
                                      "me1/event-op2-2-nfc.json"],
                     "safe_integer_max": SAFE_INT_MAX},
             expect="accept", covers=["p-hlc-counter-overflow-handling"],
             spec="canonical-artifacts §6.2",
             note="counter reaches 2^53-1 at one physical millisecond; the "
                  "next author event waits for a larger millisecond and resets "
                  "the counter to zero"),
        dict(id="pos-out-of-order-incomplete", **{"class": "positive"},
             execution="executable", check="event-contextual",
             vectors=["me1/event-op1-4-out-of-order.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json",
                                      "me1/event-op1-2-disclosure.json"]},
             expect="incomplete", covers=["p-out-of-order-incomplete"],
             spec="canonical-artifacts §6.2",
             note="valid predecessor reference whose bytes are withheld "
                  "(index.withheld) yields incomplete, not reject"),
        dict(id="pos-distinct-nonces", **{"class": "positive"},
             execution="executable", check="events",
             vectors=["me1/event-op2-0.json",
                      "me1/event-op2-1.json"],
             params={"standalone": True}, expect="accept",
             covers=["p-distinct-nonces-two-events"],
             spec="canonical-artifacts §6.1/§9",
             note="identical experience payload with distinct nonces remains "
                  "two events"),
        dict(id="pos-nfc-nfd", **{"class": "positive"}, execution="executable",
             check="nfc-nfd",
             vectors=["me1/event-op2-2-nfc.json",
                      "me2/event-opx-1-nfd.json"],
             params={}, expect="accept", covers=["p-nfc-nfd-distinct"],
             spec="canonical-artifacts §2.1",
             note="NFC and NFD strings remain distinct signed data"),
        dict(id="pos-checkpoint", **{"class": "positive"}, execution="executable",
             check="checkpoint", vectors=["me1/checkpoint-opx-witness.json"],
             params={}, expect="accept",
             covers=["p-wrapper-domain-checkpoint", "p-checkpoint-binding"],
             spec="canonical-artifacts §7",
             note="separate-witness checkpoint with exact subject "
                  "certificate/high-water binding"),
        dict(id="pos-checkpoint-coverage", **{"class": "positive"},
             execution="executable", check="checkpoint-coverage",
             vectors=["me1/checkpoint-opx-witness.json",
                      "me1/event-op1-1.json"],
             params={}, expect="covered", covers=["p-checkpoint-coverage"],
             spec="canonical-artifacts §7",
             note="the named high-water prefix is covered"),
        dict(id="pos-sealed", **{"class": "positive"}, execution="executable",
             check="sealed", vectors=["me1/sealed-delivery-1.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json",
                     "inner": "me1/event-op1-1.json"},
             expect="accept",
             covers=["p-wrapper-domain-sealed", "p-sealed-decryption",
                     "p-multi-recipient", "p-disclosure-authorization"],
             spec="canonical-artifacts §8",
             note="fixed multi-recipient sealed delivery: protected metadata, "
                  "AAD, HPKE info, signature preimage, successful decryption "
                  "for every recipient"),
        dict(id="pos-reseal", **{"class": "positive"}, execution="executable",
             check="reseal",
             vectors=["me1/sealed-delivery-1.json",
                      "me1/sealed-delivery-2-reseal.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json",
                     "inner": "me1/event-op1-1.json"},
             expect="accept", covers=["p-reseal-same-event"],
             spec="canonical-artifacts §8.3",
             note="d1 uses exactly the 24-hour TTL; d2 is issued strictly "
                  "after d1 expires and re-encrypts the same event under a new "
                  "delivery ID"),
        dict(id="pos-delivery-rotation", **{"class": "positive"},
             execution="executable", check="delivery-rotation",
             vectors=["me1/sealed-delivery-1.json",
                      "me1/sealed-delivery-3-rotation.json"],
             params={"old_authorization":
                     "me1/event-op1-2-disclosure.json",
                     "new_authorization":
                     "me1/event-op2-5-disclosure-rotation.json",
                     "old_inner": "me1/event-op1-1.json",
                     "new_inner": "me1/event-op1-1.json"},
             expect="accept", covers=["p-delivery-rotation-authorization"],
             spec="canonical-artifacts §8.3",
             note="rotated recipient key uses its renewed certificate and a "
                  "fresh concrete disclosure authorization"),
        dict(id="pos-delivery-per-recipient-expiry", **{"class": "positive"},
             execution="executable", check="delivery-expiry",
             vectors=["me1/sealed-delivery-3-rotation.json"],
             params={"at_ms": cert_i2_g1["body"]["expires_at_ms"] + 1,
                     "expired_key_name": "op2-enc2",
                     "active_key_name": "opx-enc",
                     "authorization":
                     "me1/event-op2-5-disclosure-rotation.json",
                     "inner": "me1/event-op1-1.json"},
             expect="accept", covers=["p-per-recipient-expiry"],
             spec="canonical-artifacts §8.1/§8.3",
             note="after op2's certificate expiry its recipient path is "
                  "expired while opx remains independently processable"),
        dict(id="pos-threshold", **{"class": "positive"}, execution="executable",
             check="threshold",
             vectors=["threshold/genesis-partial.json", "me1/genesis.json",
                      "threshold/genesis-quorum-b.json",
                      "threshold/genesis-merged.json"],
             params={}, expect="accept",
             covers=["p-threshold-partial-completion", "p-threshold-merge"],
             spec="canonical-artifacts §4.2/§9",
             note="partial quorum then completion; merge of different valid "
                  "quorum subsets represents one artifact"),
        dict(id="pos-event-replay-idempotent", **{"class": "positive"},
             execution="executable", check="idempotent",
             vectors=["me1/event-op1-1.json"], params={"kind": "event"},
             expect="idempotent", covers=["n-event-replay-idempotent"],
             spec="canonical-artifacts §6.3",
             note="same event replay is idempotent"),
        dict(id="pos-delivery-retry-idempotent", **{"class": "positive"},
             execution="executable", check="idempotent",
             vectors=["me1/sealed-delivery-1.json"], params={"kind": "delivery"},
             expect="idempotent", covers=["n-delivery-retry-idempotent"],
             spec="canonical-artifacts §8.3",
             note="exact delivery retry is idempotent"),
        # --- signed semantic negatives (files under negative/) ---
        dict(id="neg-genesis-fork", **{"class": "negative"}, execution="executable",
             check="pair-fork",
             vectors=["me1/genesis.json", "negative/genesis-fork-variant.json"],
             params={"kind": "genesis"}, expect="quarantined",
             covers=["n-genesis-fork"], spec="identity-continuity §4.1",
             note="two threshold-valid genesis statements for one core: "
                  "quarantine; no arrival-order winner"),
        dict(id="neg-root-rotation-new-only", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/root-transition-new-root-only.json"],
             params={"artifact": "root-transition"}, expect="reject",
             covers=["n-root-rotation-new-only"], spec="identity-continuity §13",
             note="root rotation signed only by the new root"),
        dict(id="neg-root-rotation-old-only", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/root-transition-old-root-only.json"],
             params={"artifact": "root-transition"}, expect="reject",
             covers=["n-root-rotation-old-only"], spec="identity-continuity §13",
             note="root rotation signed only by the old root without new "
                  "possession"),
        dict(id="neg-carry-forward-without-ids", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/root-transition-carry-forward-without-ids.json"],
             params={"artifact": "root-transition"}, expect="reject",
             covers=["n-carry-forward-without-ids"],
             spec="canonical-artifacts §5.2",
             note="'carry forward all' without exact certificate IDs is "
                  "malformed"),
        dict(id="neg-control-fork", **{"class": "negative"}, execution="executable",
             check="pair-fork",
             vectors=["me1/root-transition.json",
                      "negative/root-transition-fork-variant.json"],
             params={"kind": "control"}, expect="quarantined",
             covers=["n-control-fork"], spec="identity-continuity §5",
             note="two control successors at one sequence"),
        dict(id="neg-control-sequence-skip", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/control-sequence-skip.json"],
             params={"artifact": "root-transition"}, expect="reject",
             covers=["n-control-sequence-skip"], spec="identity-continuity §13",
             note="control artifact skips an ordinary control sequence"),
        dict(id="neg-policy-without-recovery-threshold", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/recovery-policy-no-recovery-authorization.json"],
             params={"artifact": "recovery-policy"}, expect="reject",
             covers=["n-policy-without-recovery-threshold"],
             spec="identity-continuity §6.4",
             note="recovery policy replaced without its existing threshold "
                  "(also: root alone creating a new policy although genesis "
                  "already declared one)"),
        dict(id="neg-recovery-operational-signed", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/recovery-transition-operational-signed.json"],
             params={"artifact": "recovery-transition"}, expect="reject",
             covers=["n-recovery-operational-signed"],
             spec="identity-continuity §13",
             note="recovery signed by a current operational key"),
        dict(id="neg-preserved-and-revoked", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/recovery-transition-preserved-and-revoked.json"],
             params={"artifact": "recovery-transition"}, expect="reject",
             covers=["n-cert-preserved-and-revoked"],
             spec="canonical-artifacts §5.2",
             note="one certificate both preserved and effectively revoked by "
                  "one recovery transition"),
        dict(id="neg-both-predecessor-fields", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/recovery-transition-both-predecessor-fields.json"],
             params={"artifact": "recovery-transition"}, expect="reject",
             covers=["n-both-predecessor-fields"],
             spec="canonical-artifacts §5.2",
             note="fork-resolving recovery must not also carry a single "
                  "preferred predecessor"),
        dict(id="neg-standalone-root-key-revocation", **{"class": "negative"},
             execution="executable", check="control-wrapper",
             vectors=["negative/standalone-root-key-revocation.json"],
             params={"artifact": "revocation"}, expect="reject",
             covers=["n-standalone-root-key-revocation"],
             spec="canonical-artifacts §5.2",
             note="standalone root/recovery-key revocation is invalid outside "
                  "the transition that installs its successor"),
        dict(id="neg-old-root-issues-cert", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-old-root-issues.json"],
             params={}, expect="reject", covers=["n-old-root-issues-cert"],
             spec="identity-continuity §13",
             note="old root issues a new certificate after replacement "
                  "(invalidate_all at (0,1))"),
        dict(id="neg-cert-unknown-anchor", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-unknown-anchor.json"],
             params={}, expect="reject", covers=["n-cert-unknown-anchor"],
             spec="identity-continuity §13",
             note="certificate anchored to a control head not on the accepted "
                  "chain"),
        dict(id="neg-cert-generation-gap", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-generation-gap.json"],
             params={}, expect="reject", covers=["n-cert-generation-gap"],
             spec="canonical-artifacts §5.3",
             note="certificate-generation gap"),
        dict(id="neg-cert-predecessor-mismatch", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-predecessor-mismatch.json"],
             params={}, expect="reject", covers=["n-cert-predecessor-mismatch"],
             spec="canonical-artifacts §5.3",
             note="renewal names the wrong predecessor certificate"),
        dict(id="neg-cert-fork", **{"class": "negative"}, execution="executable",
             check="pair-fork",
             vectors=["me1/certificate-op1-gen1.json",
                      "negative/certificate-fork-variant.json"],
             params={"kind": "certificate"}, expect="quarantined",
             covers=["n-cert-fork"], spec="canonical-artifacts §5.3",
             note="two certificates at one operational/generation are a fork"),
        dict(id="neg-cross-role-key-reuse", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-cross-role-key-reuse.json"],
             params={}, expect="reject", covers=["n-cross-role-key-reuse"],
             spec="canonical-artifacts §4.1",
             note="a root public key reused as an operational encryption key"),
        dict(id="neg-signing-key-two-operationals", **{"class": "negative"},
             execution="executable", check="certificate",
             vectors=["negative/certificate-signing-key-two-operationals.json"],
             params={}, expect="reject",
             covers=["n-signing-key-two-operationals"],
             spec="canonical-artifacts §5.3",
             note="two operational IDs claiming one signing key: key-reuse "
                  "conflict, not a second operational"),
        dict(id="neg-acceptance-hash-mismatch", **{"class": "negative"},
             execution="executable", check="acceptance",
             vectors=["negative/acceptance-hash-mismatch.json"],
             params={}, expect="reject", covers=["n-acceptance-mismatch"],
             spec="identity-continuity §13",
             note="subject acceptance names another certificate hash"),
        dict(id="neg-acceptance-unknown-certificate", **{"class": "negative"},
             execution="executable", check="acceptance",
             vectors=["negative/acceptance-unknown-certificate.json"],
             params={}, expect="reject", covers=["n-acceptance-mismatch"],
             spec="identity-continuity §13",
             note="subject acceptance names an unknown certificate"),
        dict(id="neg-lease-ttl-exceeded", **{"class": "negative"},
             execution="executable", check="lease",
             vectors=["negative/lease-ttl-exceeded.json"],
             params={}, expect="reject", covers=["n-lease-ttl"],
             spec="identity-continuity §13",
             note="lease exceeds the genesis/V0 presence TTL"),
        dict(id="neg-lease-beyond-certificate", **{"class": "negative"},
             execution="executable", check="lease",
             vectors=["negative/lease-beyond-certificate.json"],
             params={}, expect="reject", covers=["n-lease-ttl"],
             spec="identity-continuity §13",
             note="lease expiry exceeds the certificate expiry"),
        dict(id="neg-lease-before-certificate-not-before",
             **{"class": "negative"}, execution="executable",
             check="lease",
             vectors=["negative/lease-before-certificate-not-before.json"],
             params={}, expect="reject", covers=["n-lease-ttl"],
             spec="identity-continuity §10/§13",
             note="lease interval precedes the certificate validity interval"),
        dict(id="neg-event-signed-by-recovery-key", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-signed-by-recovery-key.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="reject", covers=["n-recovery-key-signs-event"],
             spec="identity-continuity §13",
             note="recovery key signs an ordinary event"),
        dict(id="neg-event-sequence-gap", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-sequence-gap.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="reject", covers=["n-event-sequence-gap"],
             spec="canonical-artifacts §6.2",
             note="known predecessor with a wrong sequence increment"),
        dict(id="neg-event-missing-predecessor-parent", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-missing-predecessor-parent.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json",
                                      "me2/event-opx-0.json"]},
             expect="reject", covers=["n-event-missing-predecessor-parent"],
             spec="canonical-artifacts §6.2",
             note="local predecessor missing from causal parents"),
        dict(id="neg-event-hlc-regression", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-hlc-regression.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json",
                                      "me2/event-opx-0.json"]},
             expect="reject", covers=["n-event-hlc-regression"],
             spec="canonical-artifacts §6.2",
             note="HLC tuple not greater than the known predecessor tuple"),
        dict(id="neg-event-duplicate-parents", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-duplicate-parents.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="reject", covers=["n-event-duplicate-parents"],
             spec="canonical-artifacts §2.2",
             note="duplicate causal parents"),
        dict(id="neg-event-unsorted-parents", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-unsorted-parents.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json",
                                      "me2/event-opx-0.json"]},
             expect="reject", covers=["n-event-unsorted-parents"],
             spec="canonical-artifacts §2.2",
             note="causal parents not in canonical sorted order"),
        dict(id="neg-event-65-parents", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-65-parents.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="reject", covers=["n-event-too-many-parents"],
             spec="canonical-artifacts §2.1",
             note="more than 64 causal parents exceed the resource bound"),
        dict(id="neg-event-unknown-parent", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-unknown-parent.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="incomplete", covers=["n-event-unknown-parent-incomplete"],
             spec="canonical-artifacts §6.2",
             note="unknown causal parent yields incomplete quarantine, not "
                  "silent projection"),
        dict(id="neg-event-fork", **{"class": "negative"}, execution="executable",
             check="pair-fork",
             vectors=["me1/event-op1-1.json",
                      "negative/event-fork-variant.json"],
             params={"kind": "event"}, expect="quarantined",
             covers=["n-event-fork"], spec="canonical-artifacts §6.2/§6.3",
             note="same operational/sequence, different event: fork"),
        dict(id="neg-late-parent-hlc", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-late-parent-hlc.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json",
                                      "me2/event-opx-0.json",
                                      "negative/event-opx-late-parent.json"]},
             expect="reject", covers=["n-late-parent-hlc"],
             spec="canonical-artifacts §6.2",
             note="a late parent revealing an HLC regression invalidates the "
                  "causal evidence"),
        dict(id="neg-event-under-revoked-certificate", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-under-revoked-certificate.json"],
             params={"revoked_certificates":
                     ["me1/certificate-op3-gen0.json"]},
             expect="reject", covers=["n-revoked-cert-event"],
             spec="identity-continuity §9/§13",
             note="event ingested after the certificate revocation was "
                  "observed (backdating does not help)"),
        dict(id="neg-event-under-old-generation", **{"class": "negative"},
             execution="executable", check="event-contextual",
             vectors=["negative/event-under-old-generation.json"],
             params={"known_events": ["me1/event-op1-0.json",
                                      "me1/event-op1-1.json"]},
             expect="reject", covers=["n-old-generation-event"],
             spec="identity-continuity §7",
             note="a superseded certificate generation cannot authorize new "
                  "events"),
        dict(id="neg-old-generation-replay", **{"class": "negative"},
             execution="executable", check="old-generation-replay",
             vectors=["me1/certificate-op1-gen0.json",
                      "me1/acceptance-op1-gen0.json"],
             params={"highest_generation": 1}, expect="reject",
             covers=["n-old-generation-replay"],
             spec="identity-continuity §7/§13",
             note="replay of an older broader certificate after renewal must "
                  "not reinstate old authority"),
        dict(id="neg-checkpoint-wrong-sequence", **{"class": "negative"},
             execution="executable", check="checkpoint",
             vectors=["negative/checkpoint-wrong-sequence.json"],
             params={}, expect="reject", covers=["n-checkpoint-mismatch"],
             spec="canonical-artifacts §7",
             note="checkpoint high-water sequence mismatch"),
        dict(id="neg-checkpoint-wrong-event-hash", **{"class": "negative"},
             execution="executable", check="checkpoint",
             vectors=["negative/checkpoint-wrong-event-hash.json"],
             params={}, expect="reject", covers=["n-checkpoint-mismatch"],
             spec="canonical-artifacts §7",
             note="checkpoint high-water event hash mismatch"),
        dict(id="neg-checkpoint-wrong-certificate", **{"class": "negative"},
             execution="executable", check="checkpoint",
             vectors=["negative/checkpoint-wrong-certificate.json"],
             params={}, expect="reject", covers=["n-checkpoint-mismatch"],
             spec="canonical-artifacts §7",
             note="checkpoint subject certificate mismatch (cannot pair an "
                  "old event with another certificate)"),
        dict(id="neg-checkpoint-witness-equals-subject", **{"class": "negative"},
             execution="executable", check="checkpoint",
             vectors=["negative/checkpoint-witness-equals-subject.json"],
             params={}, expect="reject", covers=["n-checkpoint-mismatch"],
             spec="canonical-artifacts §7",
             note="the witness must differ from the subject operational"),
        dict(id="neg-checkpoint-revoked-witness", **{"class": "negative"},
             execution="executable", check="checkpoint-revoked-witness",
             vectors=["me1/checkpoint-opx-witness.json"], params={},
             expect="reject", covers=["n-checkpoint-mismatch"],
             spec="canonical-artifacts §7",
             note="a checkpoint witnessed by a revoked certificate is "
                  "rejected even when its signature and ancestry are valid"),
        dict(id="neg-checkpoint-beyond-high-water", **{"class": "negative"},
             execution="executable", check="checkpoint-coverage",
             vectors=["me1/checkpoint-opx-witness.json",
                      "me1/event-op1-4-out-of-order.json"],
             params={}, expect="not-covered",
             covers=["n-checkpoint-beyond-high-water"],
             spec="canonical-artifacts §7",
             note="a checkpoint claiming a descendant beyond its high-water "
                  "does not cover it"),
        dict(id="neg-checkpoint-cross-operational", **{"class": "negative"},
             execution="executable", check="checkpoint-coverage",
             vectors=["me1/checkpoint-opx-witness.json",
                      "me2/event-opx-0.json"],
             params={}, expect="not-covered",
             covers=["n-checkpoint-cross-operational-coverage"],
             spec="canonical-artifacts §7",
             note="a subject checkpoint does not cover another operational's "
                  "event merely because it is a causal parent"),
        dict(id="neg-sealed-empty-recipients", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["negative/sealed-empty-recipients.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json"},
             expect="reject", covers=["n-recipients-empty"],
             spec="canonical-artifacts §8.1", note="empty recipient set"),
        dict(id="neg-sealed-duplicate-recipients", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["negative/sealed-duplicate-recipients.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json"},
             expect="reject", covers=["n-recipients-duplicate"],
             spec="canonical-artifacts §8.1", note="duplicate recipient triple"),
        dict(id="neg-sealed-unsorted-recipients", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["negative/sealed-unsorted-recipients.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json"},
             expect="reject", covers=["n-recipients-unsorted"],
             spec="canonical-artifacts §8.1/§2.2",
             note="recipient set not in canonical sorted order"),
        dict(id="neg-sealed-oversized-recipients", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["negative/sealed-oversized-recipients.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json"},
             expect="reject", covers=["n-recipients-oversized"],
             spec="canonical-artifacts §2.1",
             note="257 recipients exceed the 256 recipient bound"),
        dict(id="neg-sealed-ttl-exceeded", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["negative/sealed-ttl-exceeded.json"],
             params={"authorization": "me1/event-op1-2-disclosure.json"},
             expect="reject", covers=["n-delivery-ttl"],
             spec="canonical-artifacts §8.1",
             note="delivery TTL above 24 hours"),
        dict(id="neg-sealed-missing-disclosure", **{"class": "negative"},
             execution="executable", check="tamper",
             vectors=["negative/tamper-sealed-missing-disclosure.json"],
             params={}, expect="reject", covers=["n-disclosure-missing"],
             spec="canonical-artifacts §8.1",
             note="the mandatory disclosure_authorization_id is absent"),
        dict(id="neg-disclosure-wrong-event", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["me1/sealed-delivery-1.json"],
             params={"authorization": "negative/disclosure-wrong-event.json"},
             expect="reject", covers=["n-disclosure-wrong-event"],
             spec="canonical-artifacts §8.1",
             note="disclosure authorization binds a different event"),
        dict(id="neg-disclosure-wrong-sender", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["me1/sealed-delivery-1.json"],
             params={"authorization": "negative/disclosure-wrong-sender.json"},
             expect="reject", covers=["n-disclosure-wrong-sender"],
             spec="canonical-artifacts §8.1",
             note="disclosure authorization binds a different sender key"),
        dict(id="neg-disclosure-wrong-recipients", **{"class": "negative"},
             execution="executable", check="sealed",
             vectors=["me1/sealed-delivery-1.json"],
             params={"authorization":
                     "negative/disclosure-wrong-recipients.json"},
             expect="reject", covers=["n-disclosure-wrong-recipient"],
             spec="canonical-artifacts §8.1",
             note="disclosure authorization binds a different recipient set"),
        dict(id="neg-small-order-ed25519", **{"class": "negative"},
             execution="executable", check="key-descriptor",
             vectors=["negative/descriptor-small-order-ed25519.json"],
             params={}, expect="reject", covers=["n-ed25519-small-order"],
             spec="canonical-artifacts §4.1",
             note="small-order Ed25519 points are rejected"),
        dict(id="neg-kid-mismatch", **{"class": "negative"},
             execution="executable", check="key-descriptor",
             vectors=["negative/descriptor-kid-mismatch.json"],
             params={}, expect="reject", covers=["n-kid-mismatch"],
             spec="canonical-artifacts §4.1",
             note="derived key-ID mismatch is rejected"),
        dict(id="neg-key-alias", **{"class": "negative"},
             execution="executable", check="key-descriptor",
             vectors=["negative/descriptor-key-alias.json"],
             params={}, expect="reject", covers=["n-key-alias"],
             spec="canonical-artifacts §4.1",
             note="one public key under several aliases is rejected"),
        dict(id="neg-hpke-all-zero-dh", **{"class": "negative"},
             execution="executable", check="hpke-all-zero-dh", vectors=[],
             params={}, expect="reject", covers=["n-x25519-all-zero-dh"],
             spec="canonical-artifacts §4.1",
             note="X25519 low-order/all-zero-DH inputs are rejected by the "
                  "test-only HPKE helper"),
    ]

    entries.extend(P)

    # ------------------------------------------------------------------
    # Documented conformance expectations (state-machine / time-oracle
    # behavior that byte vectors cannot execute offline).  These are
    # normative expectations, marked explicitly rather than executed.
    # ------------------------------------------------------------------
    D = [
        ("d-stale-root-successor", "identity-continuity §6.1",
         "a stale restored root signer creating another successor freezes "
         "identity control; requires custodial/session state"),
        ("d-recovery-generation-wins", "identity-continuity §5",
         "a longer ordinary branch never beats a valid higher recovery "
         "generation; requires branch bookkeeping"),
        ("d-challenge-replay", "identity-continuity §11",
         "a proof-of-possession challenge replayed for another nonce or "
         "audience is rejected; DM-011 defines no interactive-challenge "
         "wire format, so this is an implementation expectation"),
        ("d-copied-database", "identity-continuity §13",
         "a copied database without a certificate chain is unverifiable"),
        ("d-reachable-no-lease", "identity-continuity §10",
         "a reachable process without a lease is excluded from /we"),
        ("d-clock-backward", "identity-continuity §10",
         "a backward wall-clock jump never resurrects or extends a lease"),
        ("d-clock-uncertainty", "identity-continuity §10",
         "clock uncertainty beyond policy fails closed for new/extended "
         "presence"),
        ("d-all-authority-lost", "identity-continuity §6.5",
         "loss of all root and recovery authority freezes identity or "
         "starts a new /me; never a silent reset"),
        ("d-distinct-me-eligible", "identity-continuity §13",
         "two distinct me_id values with valid collective membership and "
         "receipt-bearing leases may both be eligible for /we routing"),
        ("d-quarantined-lease", "identity-continuity §13",
         "a quarantined identity presenting a valid lease is excluded "
         "from /we"),
        ("d-post-expiry-event", "identity-continuity §7",
         "an event first seen after certificate expiry with no pre-expiry "
         "checkpoint is attributable but not automatically timely/canonical"),
        ("d-witness-checkpoint-expired", "canonical-artifacts §7",
         "a witness checkpoint first seen after witness expiry without an "
         "explicit attestor policy remains attributable but not timely"),
        ("d-attested-timely-policy", "canonical-artifacts §7",
         "with an explicit local attestor policy the same evidence is "
         "attested-timely, not objective cryptographic time"),
        ("d-planned-vs-compromised-key", "canonical-artifacts §8.3",
         "an authorized delivery to a planned-retirement key remains "
         "processable until min(wrapper expiry, old certificate expiry); a "
         "compromised key rejects pending processing immediately"),
        ("d-remote-error-membership", "canonical-artifacts §9",
         "remote errors must not expose identity membership to an "
         "unauthorized caller"),
        ("d-checkpoint-timeliness-classes", "canonical-artifacts §7",
         "post-expiry timeliness is established by exactly one of: prior "
         "durable local acceptance, a root/recovery high-water, or an "
         "explicit attestor policy (attested-timely)"),
        ("d-lease-session-claims", "identity-continuity §13",
         "one session may refresh capability claims but cannot silently "
         "change body; every accepted successor replaces rather than unions "
         "stale claims"),
    ]
    for tag, spec, rationale in D:
        entry(id=tag, **{"class": "negative"}, execution="documented",
              check=None, vectors=[], params={}, expect="see rationale",
              covers=[tag], spec=spec, note=None, rationale=rationale)

    index = {
        "schema": "dm-011-vector-index/v0",
        "suite": SUITE,
        "generator": "tools/generate_dm011_vectors.py",
        "determinism": ("Every field is derived deterministically "
                        "(SHA-256 counter stream; fixed HPKE ephemeral "
                        "keys). Regeneration is byte-identical and equal "
                        "to the checked-in vectors."),
        "provenance": {
            "rfc9180": {
                "repository": "https://github.com/cfrg/draft-irtf-cfrg-hpke",
                "commit": RFC9180_PROVENANCE_COMMIT,
            },
        },
        "keys": "keys.json",
        "withheld": {
            "note": ("Bytes of this validly signed predecessor event are "
                     "deliberately not shipped; me1/event-op1-4-out-of-order.json"
                     " references it and is therefore 'incomplete'."),
            "event_id": meta["withheld_event_id"],
            "event_hash": meta["withheld_event_hash"],
            "event_sequence": meta["withheld_event_sequence"],
        },
        "entries": entries,
    }
    return index


README = """\
# Matrix cryptographic primitive vectors

The supported ontology and operational schemas are in `schemas/weave/v1`.
This directory remains a low-level adversarial corpus for canonical JSON,
Ed25519, HPKE, hash chains, control evidence, and tamper rejection. Fixture
names involving presence, leases, or collective membership are not current
scope or single-body semantics. New ontology vectors belong under
`vectors/weave/v1`.

Synthetic conformance vectors retained for primitive validation. All key
material is synthetic and deterministically derived;
nothing here is a real identity, real memory, a credential, or live
ciphertext.

## Layout

- `index.json` — machine-readable inventory mapping the Section 9
  positive/negative inventory (and the DM-010 Section 13 scenarios) to
  vector files, execution mode, and expected outcome.  Entries with
  `execution: "documented"` are state-machine/time-oracle conformance
  expectations that byte vectors cannot execute offline; they carry a
  normative `rationale`.
- `keys.json` — all synthetic test keys, including private material so
  implementations can exercise decryption.  Not secrets.
- `fixtures/` — x/test placeholder body/capability bodies (DM-018
  freezes the normative bodies; their hashes follow the current formulas).
- `me1/`, `me2/` — identity-control chains, certificates, acceptances,
  lease, events, checkpoint, sealed deliveries.
- `threshold/` — mergeable threshold-endorsement variants of the me1
  genesis wrapper.
- `fork/` — a real signed competing control branch, its branch-anchored
  certificate/acceptance, and a quorum-signed fork-resolving recovery.
- `boundary/` — real signed protocol wrappers at exact resource limits and
  one over; the index explains why 128 authorized signatures is unreachable.
- `negative/` — signed semantic negatives and tamper descriptors.
- `raw/*.wire` — exact parser/JCS byte vectors (consume the bytes verbatim).

## Rules for consumers

- Consume the checked-in bytes; do not regenerate random fields and
  compare whole files (regeneration via
  `tools/generate_dm011_vectors.py --out <dir>` is byte-identical and is
  exercised by the test suite as a determinism check).
- The disclosure authorization is a clearly labeled
  `x/test-disclosure-authorization` event fixture binding the exact event,
  sender certificate/key, and concrete recipient certificate/key set.  It
  is not a DM-012 normative schema.
- HPKE in production is randomized; these vectors pin fixed ephemeral keys
  so fixtures are reproducible.  Decryption of the checked-in sealed
  vectors is normative.
- RFC 9180 helper provenance is pinned to upstream commit
  `b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb`.
"""


def build_keys_file():
    return {
        "schema": "dm-011-test-keys/v0",
        "note": ("All key material is synthetic and deterministically "
                 "derived from a fixed SHA-256 counter stream. These are "
                 "published conformance test keys, not secrets; private "
                 "material is included so implementations can verify "
                 "decryption and signature behavior."),
        "keys": [
            {
                "name": k.name,
                "role": k.role,
                "alg": k.alg,
                "seed_b64": b64(k.seed),
                "public_key_b64": b64(k.public),
                "kid": k.kid,
            }
            for k in KEYS.values()
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="vectors/v0",
                        help="output directory (default: vectors/v0)")
    args = parser.parse_args(argv)

    out = args.out
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    meta = build_universe()
    entries = build_extras(meta)
    index = build_index(meta, entries)

    files = meta["files"]
    files["keys.json"] = build_keys_file()
    files["index.json"] = index

    for rel in sorted(files):
        write_json(out, rel, files[rel])
    for rel in sorted(meta["raw_files"]):
        write_bytes(out, rel, meta["raw_files"][rel])
    write_bytes(out, "README.md", README.encode("utf-8"))

    n = len(files) + len(meta["raw_files"]) + 1
    print("dm-011 vectors: wrote %d files to %s "
          "(%d index entries: %d executable, %d documented)" % (
              n, out, len(index["entries"]),
              sum(1 for e in index["entries"] if e["execution"] == "executable"),
              sum(1 for e in index["entries"] if e["execution"] == "documented")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
