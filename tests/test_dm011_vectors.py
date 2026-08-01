#!/usr/bin/env python3
"""DM-011 conformance-vector verification (offline, unittest).

This suite is an independent consumer of the checked-in vectors under
``vectors/v0/``: it implements its own strict I-JSON/JCS parser, RFC 8785
canonicalizer, Ed25519/X25519 validation, and a test/vector-only RFC 9180
HPKE helper (which rejects the all-zero X25519 shared secret and is
additionally verified against an official RFC 9180 known-answer test for
DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 base mode).

It deliberately does not import the generator; the duplicated primitives are
a cross-check, not shared code.  Run from the repository root:

    python -m unittest discover -s tests -v
"""

import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(REPO_ROOT, "vectors", "v0")
GENERATOR = os.path.join(REPO_ROOT, "tools", "generate_dm011_vectors.py")

SUITE = "DM0_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305_ED25519_JCS"
CEILING_CONTROL = 262144
CEILING_EVENT = 1048576
CEILING_SEALED = 2097152
SAFE_INT_MAX = 2**53 - 1
MAX_DEPTH = 64
MAX_DELIVERY_TTL_MS = 24 * 3600 * 1000
MAX_SIGNATURES = 128

SIGNATURE_ROLES = {
    "daimon/genesis/v0": {"root-authorization", "recovery-possession"},
    "daimon/root-transition/v0": {"root-authorization", "root-possession"},
    "daimon/recovery-transition/v0": {
        "recovery-authorization", "root-possession"},
    "daimon/recovery-policy/v0": {
        "root-authorization", "recovery-authorization",
        "recovery-possession"},
    "daimon/revocation/v0": {"root-authorization"},
    "daimon/incarnation-certificate/v0": {"root-authorization"},
    "daimon/incarnation-acceptance/v0": {"subject-acceptance"},
    "daimon/presence-lease/v0": {"incarnation-authorization"},
    "daimon/event-checkpoint/v0": {"witness-authorization"},
}

DOM = {
    "genesis": "daimon/genesis/v0",
    "root-transition": "daimon/root-transition/v0",
    "recovery-transition": "daimon/recovery-transition/v0",
    "recovery-policy": "daimon/recovery-policy/v0",
    "certificate": "daimon/incarnation-certificate/v0",
    "acceptance": "daimon/incarnation-acceptance/v0",
    "revocation": "daimon/revocation/v0",
    "lease": "daimon/presence-lease/v0",
    "event": "daimon/event/v0",
    "checkpoint": "daimon/event-checkpoint/v0",
    "sealed": "daimon/sealed-event/v0",
    "sealed-aad": "daimon/sealed-event/payload-aad/v0",
    "sealed-cek": "daimon/sealed-event/cek-wrap/v0",
    "incarnation-id": "daimon/incarnation-id/v0",
}

EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*(?:[./-][a-z0-9]+)*$")
PREFIX_RE = re.compile(r"^[a-z][a-z0-9./-]*$")

REVOCATION_REASONS = {
    "planned-rotation", "key-retired", "key-compromise", "key-loss",
    "incarnation-fork", "policy-violation", "operator-request", "unspecified",
}
REVOCATION_KINDS = {
    "certificate", "incarnation-signing-key", "incarnation-encryption-key",
    "root-key", "recovery-key", "certificates-from-control-cutoff",
}
SIGNING_PURPOSES = {"event", "presence-lease", "event-checkpoint",
                    "sealed-delivery"}
ENCRYPTION_PURPOSES = {"sealed-event-recipient"}
ROUTE_KINDS = {"local", "direct", "hub"}
HIGH_WATER_DOMAINS = {"event", "presence-lease"}


class Reject(Exception):
    """A conformance validation failure."""


class Incomplete(Exception):
    """Required predecessor/parent evidence is not yet available."""


# ---------------------------------------------------------------------------
# JCS (RFC 8785) for the restricted data model
# ---------------------------------------------------------------------------

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n",
        "\r": "\\r", "\t": "\\t"}


def _jstr(s):
    out = ['"']
    for ch in s:
        e = _ESC.get(ch)
        if e:
            out.append(e)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(value):
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, str):
        return _jstr(value).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return b"{" + b",".join(
            _jstr(k).encode("utf-8") + b":" + jcs(v) for k, v in items) + b"}"
    raise Reject("value outside the data model")


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Strict parser
# ---------------------------------------------------------------------------

def _depth(value, d):
    if d > MAX_DEPTH:
        raise Reject("nesting deeper than 64 levels")
    if isinstance(value, list):
        for x in value:
            _depth(x, d + 1)
    elif isinstance(value, dict):
        for x in value.values():
            _depth(x, d + 1)


def _strings(value):
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise Reject("unpaired surrogate")
    elif isinstance(value, list):
        for x in value:
            _strings(x)
    elif isinstance(value, dict):
        for k, v in value.items():
            _strings(k)
            _strings(v)


def strict_parse(data, ceiling):
    """Strict I-JSON parse + canonicality check of complete wire bytes."""
    if len(data) > ceiling:
        raise Reject("wire artifact exceeds its V0 ceiling")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Reject("invalid UTF-8")

    def hook(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise Reject("duplicate property name")
            d[k] = v
        return d

    def pfloat(s):
        raise Reject("floating-point/exponent values are forbidden")

    def pint(s):
        if s == "-0":
            raise Reject("negative zero is forbidden")
        v = int(s)
        if abs(v) > SAFE_INT_MAX:
            raise Reject("unsafe integer")
        return v

    def pconst(s):
        raise Reject("non-I-JSON constant")

    try:
        value = json.loads(text, object_pairs_hook=hook, parse_float=pfloat,
                           parse_int=pint, parse_constant=pconst)
    except Reject:
        raise
    except RecursionError:
        raise Reject("nesting deeper than 64 levels")
    except json.JSONDecodeError as exc:
        raise Reject("invalid JSON: %s" % exc)
    _depth(value, 1)
    _strings(value)
    if jcs(value) != data:
        raise Reject("wire bytes are not canonical JCS")
    return value


_B64_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def ub64(s, length=None):
    if not isinstance(s, str) or not _B64_RE.match(s) or len(s) % 4 == 1:
        raise Reject("not canonical base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64e(raw) != s:
        raise Reject("non-canonical base64url spelling")
    if length is not None and len(raw) != length:
        raise Reject("wrong decoded length")
    return raw


def typed_id(value, prefix):
    if not isinstance(value, str) or not value.startswith(prefix):
        raise Reject("wrong typed ID prefix")
    ub64(value[len(prefix):], 32)
    return value


def require_keys(obj, keys, what):
    if not isinstance(obj, dict) or set(obj.keys()) != set(keys):
        raise Reject("%s: closed object fields mismatch" % what)


def require_uint(value, what, maximum=SAFE_INT_MAX):
    """Require an I-JSON unsigned integer, explicitly excluding booleans."""
    if not isinstance(value, int) or isinstance(value, bool) \
            or not 0 <= value <= maximum:
        raise Reject("%s: expected an unsigned integer" % what)
    return value

# ---------------------------------------------------------------------------
# Ed25519 / X25519 validation
# ---------------------------------------------------------------------------

ED_L = 2**252 + 27742317777372353535851937790883648493
ED_P = 2**255 - 19

# Known small-order / non-canonical Ed25519 point encodings (the standard
# library blocklist, e.g. libsodium's).  The identity encoding
# (0x01 || 31 zero bytes) is exercised by the vectors.
ED_SMALL_ORDER = {bytes.fromhex(h) for h in [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b76043210631f2e195c0f7727b1a43f18dbd82947c5",
    "c7176a703d4dd84fba3c0b76043210631f2e195c0f7727b1a43f18dbd8294785",
]}

X25519_LOW_ORDER = {
    b"\x00" * 32,
    b"\x01" + b"\x00" * 31,
    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
    bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445c39458b1ceb5ad57b5418a8097f"),
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    bytes.fromhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
}


def ed25519_check_public(pub):
    if len(pub) != 32:
        raise Reject("bad Ed25519 public key length")
    if pub in ED_SMALL_ORDER:
        raise Reject("small-order Ed25519 point")
    y = int.from_bytes(pub, "little") & ((1 << 255) - 1)
    if y >= ED_P:
        raise Reject("non-canonical Ed25519 point encoding")


def ed25519_verify(pub, sig, preimage):
    ed25519_check_public(pub)
    if len(sig) != 64:
        raise Reject("bad Ed25519 signature length")
    if int.from_bytes(sig[32:], "little") >= ED_L:
        raise Reject("non-canonical Ed25519 S scalar")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, preimage)
    except InvalidSignature:
        raise Reject("Ed25519 signature does not verify")


def x25519_check_public(pub):
    if len(pub) != 32:
        raise Reject("bad X25519 public key length")
    if pub in X25519_LOW_ORDER:
        raise Reject("low-order X25519 public key")


def x25519_dh(priv, peer_pub):
    x25519_check_public(peer_pub)
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    except ValueError:
        raise Reject("all-zero X25519 shared secret")
    if shared == b"\x00" * 32:
        raise Reject("all-zero X25519 shared secret")
    return shared


# ---------------------------------------------------------------------------
# Test/vector-only RFC 9180 HPKE helper (base mode, DHKEM(X25519,
# HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305).  Rejects all-zero DH.
# ---------------------------------------------------------------------------

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
KEM_SUITE = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE = (b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big")
              + AEAD_ID.to_bytes(2, "big"))


def _extract(salt, ikm):
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _expand(prk, info, length):
    out, t = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]


def _lextract(suite, salt, label, ikm):
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _lexpand(suite, prk, label, info, length):
    labeled_info = (length.to_bytes(2, "big") + b"HPKE-v1" + suite + label
                    + info)
    return _expand(prk, labeled_info, length)


def dhkem_decap(enc, recipient_priv):
    """Test-only Decap; rejects the all-zero shared secret."""
    if len(enc) != 32:
        raise Reject("bad HPKE encapsulation length")
    dh = x25519_dh(recipient_priv, enc)
    kem_context = enc + recipient_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    prk = _lextract(KEM_SUITE, b"", b"eae_prk", dh)
    return _lexpand(KEM_SUITE, prk, b"shared_secret", kem_context, 32)


def hpke_schedule(shared_secret, info):
    psk_id_hash = _lextract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = _lextract(HPKE_SUITE, b"", b"info_hash", info)
    ctx = b"\x00" + psk_id_hash + info_hash  # base mode
    secret = _lextract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = _lexpand(HPKE_SUITE, secret, b"key", ctx, 32)
    nonce = _lexpand(HPKE_SUITE, secret, b"base_nonce", ctx, 12)
    return secret, key, nonce


def hpke_open(enc, wrapped_cek, recipient_priv, info):
    shared = dhkem_decap(enc, recipient_priv)
    _, key, nonce = hpke_schedule(shared, info)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, wrapped_cek, b"")
    except InvalidTag:
        raise Reject("HPKE open failed (AEAD tag mismatch)")


# Official RFC 9180 known-answer test (test-vectors.json, cfrg/
# draft-irtf-cfrg-hpke): mode=base, KEM=DHKEM(X25519,HKDF-SHA256),
# KDF=HKDF-SHA256, AEAD=ChaCha20Poly1305.
RFC9180_KAT = {
    "mode": 0, "kem_id": 32, "kdf_id": 1, "aead_id": 3,
    "info": "4f6465206f6e2061204772656369616e2055726e",
    "skRm": "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    "skEm": "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600",
    "pkRm": "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a",
    "pkEm": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    "enc": "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a",
    "shared_secret": "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7",
    "secret": "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6",
    "key": "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91",
    "base_nonce": "5c4d98150661b848853b547f",
    "encryptions": [
        {"aad": "436f756e742d30",
         "pt": "4265617574792069732074727574682c20747275746820626561757479",
         "nonce": "5c4d98150661b848853b547f",
         "ct": "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"},
        {"aad": "436f756e742d31",
         "pt": "4265617574792069732074727574682c20747275746820626561757479",
         "nonce": "5c4d98150661b848853b547e",
         "ct": "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"},
    ],
}


# ---------------------------------------------------------------------------
# Key descriptors and threshold sets
# ---------------------------------------------------------------------------

def derive_kid(alg, public_b64):
    return "dm:key:v0:" + b64e(sha256(jcs({"alg": alg,
                                           "public_key": public_b64})))


def validate_descriptor(desc, expect_alg=None):
    require_keys(desc, ["alg", "kid", "public_key"], "key descriptor")
    if desc["alg"] not in ("Ed25519", "X25519"):
        raise Reject("unknown key algorithm")
    if expect_alg and desc["alg"] != expect_alg:
        raise Reject("unexpected key algorithm")
    pub = ub64(desc["public_key"], 32)
    if desc["alg"] == "Ed25519":
        ed25519_check_public(pub)
    else:
        x25519_check_public(pub)
    if desc["kid"] != derive_kid(desc["alg"], desc["public_key"]):
        raise Reject("derived key-ID mismatch")
    return pub


def validate_threshold_set(tset, what="threshold set"):
    require_keys(tset, ["keys", "threshold"], what)
    keys = tset["keys"]
    if not isinstance(keys, list) or not 1 <= len(keys) <= 32:
        raise Reject("%s: key count out of bounds" % what)
    if keys != sorted(keys, key=lambda d: d["kid"]):
        raise Reject("%s: key descriptors not sorted by kid" % what)
    kids, pubs = set(), set()
    for d in keys:
        pub = validate_descriptor(d, "Ed25519")
        if d["kid"] in kids or pub in pubs:
            raise Reject("%s: duplicate key ID or aliased public key" % what)
        kids.add(d["kid"])
        pubs.add(pub)
    n = tset["threshold"]
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= len(keys):
        raise Reject("%s: invalid threshold" % what)
    return {d["kid"]: ub64(d["public_key"], 32) for d in keys}


def validate_recovery_set(rec):
    require_keys(rec, ["mode", "keys", "threshold"], "recovery set")
    if rec["mode"] == "none":
        require_uint(rec["threshold"], "no-recovery threshold", 0)
        if rec["keys"] != []:
            raise Reject("explicit no-recovery set must be empty with "
                         "threshold zero")
        return {}
    if rec["mode"] == "threshold":
        if rec["threshold"] == 0:
            raise Reject("zero threshold valid only for mode none")
        return validate_threshold_set(
            {"keys": rec["keys"], "threshold": rec["threshold"]},
            "recovery set")
    raise Reject("unknown recovery mode")


def validate_sig_record(rec):
    require_keys(rec, ["alg", "kid", "role", "value"], "signature record")
    if rec["alg"] != "Ed25519":
        raise Reject("signature algorithm must be Ed25519")
    sig = ub64(rec["value"], 64)
    if int.from_bytes(sig[32:], "little") >= ED_L:
        raise Reject("non-canonical Ed25519 S scalar")
    return sig


def check_sig_sorting(sigs, allowed_roles=None):
    if not isinstance(sigs, list) or len(sigs) > MAX_SIGNATURES:
        raise Reject("signature array exceeds the bound of 128")
    if sigs != sorted(sigs, key=lambda r: (r["kid"], r["role"])):
        raise Reject("signatures not in canonical (kid, role) order")
    seen = set()
    for s in sigs:
        validate_sig_record(s)
        if allowed_roles is not None and s["role"] not in allowed_roles:
            raise Reject("signature role is not valid for this artifact")
        if (s["role"], s["kid"]) in seen:
            raise Reject("duplicate (role,kid) signature")
        seen.add((s["role"], s["kid"]))


def count_valid(sigs, role, authorized, preimage):
    """Count distinct authorized public keys with valid role signatures."""
    pubs = set()
    for s in sigs:
        if s["role"] != role:
            continue
        if s["kid"] not in authorized:
            raise Reject("signature from an unauthorized key")
        sig = validate_sig_record(s)
        ed25519_verify(authorized[s["kid"]], sig, preimage)
        pubs.add(authorized[s["kid"]])
    return len(pubs)


def artifact_preimage(domain, body):
    return domain.encode("utf-8") + b"\x00" + jcs(body)


def possession_preimage(domain, hash_raw):
    return domain.encode("utf-8") + b"\x00" + hash_raw


def validate_wrapper(wrapper, domain, id_prefix, what):
    require_keys(wrapper, ["artifact_hash", "artifact_id", "body",
                           "signatures"], what)
    raw = artifact_hash_raw(domain, wrapper["body"])
    if wrapper["artifact_hash"] != b64e(raw):
        raise Reject("%s: derived artifact hash mismatch" % what)
    if wrapper["artifact_id"] != id_prefix + b64e(raw):
        raise Reject("%s: derived artifact ID mismatch" % what)
    check_sig_sorting(wrapper["signatures"], SIGNATURE_ROLES.get(domain))
    return raw


def artifact_hash_raw(domain, body):
    return sha256(artifact_preimage(domain, body))

# ---------------------------------------------------------------------------
# Vector loading and chain state
# ---------------------------------------------------------------------------

def load_bytes(rel):
    with open(os.path.join(VECTORS, rel), "rb") as f:
        return f.read()


def load_artifact(rel, ceiling=CEILING_CONTROL):
    return strict_parse(load_bytes(rel), ceiling)


def load_index():
    return json.loads(load_bytes("index.json").decode("utf-8"))


def load_keys():
    data = json.loads(load_bytes("keys.json").decode("utf-8"))
    out = {}
    for k in data["keys"]:
        out[k["name"]] = k
    return out


def key_priv(name):
    rec = load_keys()[name]
    seed = ub64(rec["seed_b64"], 32)
    if rec["alg"] == "Ed25519":
        return Ed25519PrivateKey.from_private_bytes(seed)
    return X25519PrivateKey.from_private_bytes(seed)


def position_of(wrapper):
    b = wrapper["body"]
    require_uint(b["recovery_generation"], "recovery generation")
    require_uint(b["control_sequence"], "control sequence")
    return (b["recovery_generation"], b["control_sequence"])


def validate_high_waters(hws):
    if not isinstance(hws, list) or len(hws) > 1024:
        raise Reject("high-water array out of bounds")
    keys = []
    for hw in hws:
        require_keys(hw, ["artifact_hash", "domain", "incarnation_id",
                          "sequence"], "high-water entry")
        typed_id(hw["incarnation_id"], "dm:inc:v0:")
        if hw["domain"] not in HIGH_WATER_DOMAINS:
            raise Reject("unknown high-water domain")
        require_uint(hw["sequence"], "high-water sequence")
        ub64(hw["artifact_hash"], 32)
        keys.append((hw["incarnation_id"], hw["domain"]))
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise Reject("high-water entries not sorted or repeated pair")


def validate_revocation_entry(entry, st=None, known_control_positions=None,
                              what="revocation entry"):
    require_keys(entry, ["effective", "high_waters", "reason",
                         "replacement_artifact_id", "target"], what)
    if entry["reason"] not in REVOCATION_REASONS:
        raise Reject("%s: unregistered reason code" % what)
    t = entry["target"]
    require_keys(t, ["id", "kid", "kind"], "revocation target")
    if t["kind"] not in REVOCATION_KINDS:
        raise Reject("%s: unknown target kind" % what)
    if t["kind"] == "certificate":
        typed_id(t["id"], "dm:cert:v0:")
        if t["kid"] is not None:
            raise Reject("certificate target must have null kid")
    elif t["kind"] in ("incarnation-signing-key",
                       "incarnation-encryption-key"):
        typed_id(t["id"], "dm:inc:v0:")
        typed_id(t["kid"], "dm:key:v0:")
    elif t["kind"] in ("root-key", "recovery-key"):
        typed_id(t["id"], "dm:ctl:v0:")
        typed_id(t["kid"], "dm:key:v0:")
    else:  # certificates-from-control-cutoff
        typed_id(t["id"], "dm:ctl:v0:")
        if t["kid"] is not None:
            raise Reject("cutoff target must have null kid")
    eff = entry["effective"]
    require_keys(eff, ["mode", "prior_control_position"], "effective rule")
    if eff["mode"] == "on_acceptance":
        if eff["prior_control_position"] is not None:
            raise Reject("on_acceptance requires a null prior position")
    elif eff["mode"] == "at_prior_position":
        p = eff["prior_control_position"]
        require_keys(p, ["control_hash", "control_sequence",
                         "recovery_generation"], "prior control position")
        require_uint(p["recovery_generation"],
                     "prior control recovery generation")
        require_uint(p["control_sequence"],
                     "prior control sequence")
        ub64(p["control_hash"], 32)
        position = (p["recovery_generation"], p["control_sequence"])
        evidence = set()
        if st is not None:
            evidence.update((rg, seq, artifact_hash)
                            for (rg, seq), artifact_hash in
                            st.positions.items())
        if known_control_positions is not None:
            if isinstance(known_control_positions, dict):
                evidence.update((rg, seq, artifact_hash)
                                for (rg, seq), artifact_hash in
                                known_control_positions.items())
            else:
                evidence.update(known_control_positions)
        if (position[0], position[1], p["control_hash"]) not in evidence:
            raise Reject("prior control position is not on the accepted chain")
    else:
        raise Reject("unknown effective mode")
    validate_high_waters(entry["high_waters"])
    if (entry["replacement_artifact_id"] is not None
            and not isinstance(entry["replacement_artifact_id"], str)):
        raise Reject("bad replacement reference")


class ChainState:
    """Accepted identity-control chain state for one /me."""

    def __init__(self):
        self.me_id = None
        self.policy = None
        self.positions = {}          # (rg, cs) -> artifact_hash (b64)
        self.head = None             # (rg, cs)
        self.root_set = None         # kid -> pubkey
        self.root_threshold = 0
        self.recovery_set = None
        self.recovery_threshold = 0
        self.recovery_mode = None
        self.root_epochs = []        # (position, set, threshold)
        self.invalidations = []      # (position, mode, carried ids)
        self.revoked_targets = []    # target dicts
        self.root_recovery_pubs = set()

    def head_hash(self):
        return self.positions[self.head]

    def active_root_at(self, position):
        best = None
        for pos, tset, thr in self.root_epochs:
            if pos <= position:
                best = (tset, thr)
        return best


def validate_genesis(wrapper):
    raw = validate_wrapper(wrapper, DOM["genesis"], "dm:ctl:v0:", "genesis")
    b = wrapper["body"]
    require_keys(b, ["birth_offer_id", "control_sequence", "core",
                     "created_at_ms", "me_id", "policy",
                     "recovery_generation", "schema", "species_release_id"],
                 "genesis body")
    if b["schema"] != "daimon-genesis/v0":
        raise Reject("genesis schema mismatch")
    for field in ("birth_offer_id", "species_release_id"):
        if b[field] is not None and not isinstance(b[field], str):
            raise Reject("%s must be a string or null" % field)
    core = b["core"]
    require_keys(core, ["domain_version", "genesis_nonce", "protocol",
                        "recovery", "root", "suite", "version"],
                 "genesis core")
    require_uint(core["version"], "genesis version", 0)
    require_uint(core["domain_version"], "genesis domain version", 0)
    if core["protocol"] != "daimon":
        raise Reject("genesis core version mismatch")
    if core["suite"] != SUITE:
        raise Reject("genesis suite mismatch")
    ub64(core["genesis_nonce"], 32)
    me_id = "dm:me:v0:" + b64e(sha256(jcs(core)))
    if b["me_id"] != me_id:
        raise Reject("derived me_id mismatch")
    require_keys(b["policy"], ["max_certificate_lifetime_ms",
                               "max_clock_skew_ms", "max_presence_ttl_ms",
                               "nonrecoverable"], "genesis policy")
    require_uint(b["created_at_ms"], "genesis creation time")
    require_uint(b["recovery_generation"], "genesis recovery generation", 0)
    require_uint(b["control_sequence"], "genesis control sequence", 0)
    policy = b["policy"]
    cert_lifetime = require_uint(
        policy["max_certificate_lifetime_ms"],
        "maximum certificate lifetime", 30 * 24 * 3600 * 1000)
    presence_ttl = require_uint(
        policy["max_presence_ttl_ms"], "maximum presence TTL", 300000)
    require_uint(policy["max_clock_skew_ms"], "maximum clock skew", 30000)
    if cert_lifetime == 0 or presence_ttl == 0:
        raise Reject("certificate lifetime and presence TTL must be positive")
    if not isinstance(policy["nonrecoverable"], bool):
        raise Reject("nonrecoverable policy must be boolean")
    root = validate_threshold_set(core["root"], "genesis root")
    recovery = validate_recovery_set(core["recovery"])
    pre = artifact_preimage(DOM["genesis"], b)
    if count_valid(wrapper["signatures"], "root-authorization", root, pre) \
            < core["root"]["threshold"]:
        raise Reject("genesis lacks the declared initial-root threshold")
    if core["recovery"]["mode"] == "threshold":
        pos = possession_preimage(DOM["genesis"], raw)
        if count_valid(wrapper["signatures"], "recovery-possession",
                       recovery, pos) < core["recovery"]["threshold"]:
            raise Reject("genesis lacks recovery possession proofs")
    st = ChainState()
    st.me_id = me_id
    st.policy = b["policy"]
    st.positions[(0, 0)] = wrapper["artifact_hash"]
    st.head = (0, 0)
    st.root_set = root
    st.root_threshold = core["root"]["threshold"]
    st.root_epochs.append(((0, 0), root, st.root_threshold))
    st.recovery_set = recovery
    st.recovery_mode = core["recovery"]["mode"]
    st.recovery_threshold = core["recovery"]["threshold"]
    st.root_recovery_pubs |= set(root.values()) | set(recovery.values())
    return st


def _common_control(wrapper, domain, schema, st, what):
    raw = validate_wrapper(wrapper, domain, "dm:ctl:v0:", what)
    b = wrapper["body"]
    if b["schema"] != schema:
        raise Reject("%s: schema mismatch" % what)
    if b["me_id"] != st.me_id:
        raise Reject("%s: me_id mismatch" % what)
    return raw, b


def _check_linkage(b, st, what, recovery_transition=False):
    require_uint(b["recovery_generation"], what + " recovery generation")
    require_uint(b["control_sequence"], what + " control sequence")
    if "competing_control_hashes" in b:
        raise Reject("%s: must not carry competing heads and a single "
                     "preferred predecessor" % what)
    if b["previous_control_hash"] != st.head_hash():
        raise Reject("%s: predecessor hash mismatch" % what)
    if recovery_transition:
        if (b["recovery_generation"], b["control_sequence"]) \
                != (st.head[0] + 1, 0):
            raise Reject("%s: recovery transition must increment the "
                         "recovery generation and reset the sequence" % what)
    else:
        if (b["recovery_generation"], b["control_sequence"]) \
                != (st.head[0], st.head[1] + 1):
            raise Reject("%s: control sequence must increment by exactly "
                         "one within the recovery generation" % what)


def validate_root_transition(wrapper, st, known_certificate_ids=None):
    raw, b = _common_control(wrapper, DOM["root-transition"],
                             "daimon-root-transition/v0", st,
                             "root transition")
    require_keys(b, ["certificate_disposition", "control_sequence",
                     "me_id", "previous_control_hash",
                     "recovery_generation", "replacement_root", "schema"],
                 "root-transition body")
    _check_linkage(b, st, "root transition")
    disp = b["certificate_disposition"]
    require_keys(disp, ["carried_forward_certificate_ids", "mode"],
                 "certificate disposition")
    if disp["mode"] == "invalidate_all":
        if disp["carried_forward_certificate_ids"] != []:
            raise Reject("invalidate_all requires an empty carry-forward list")
    elif disp["mode"] == "carry_forward":
        ids = disp["carried_forward_certificate_ids"]
        if ids != sorted(ids) or len(set(ids)) != len(ids):
            raise Reject("carried-forward IDs not sorted and unique")
        for i in ids:
            typed_id(i, "dm:cert:v0:")
        if ids and known_certificate_ids is None:
            raise Reject("carry-forward requires validated certificate evidence")
        if ids and set(ids) - set(known_certificate_ids):
            raise Reject("carry-forward names an unknown certificate")
    else:
        raise Reject("unknown certificate disposition mode")
    new_root = validate_threshold_set(b["replacement_root"],
                                      "replacement root")
    pre = artifact_preimage(DOM["root-transition"], b)
    if count_valid(wrapper["signatures"], "root-authorization",
                   st.root_set, pre) < st.root_threshold:
        raise Reject("root transition lacks the current root threshold")
    pos = possession_preimage(DOM["root-transition"], raw)
    if count_valid(wrapper["signatures"], "root-possession", new_root, pos) \
            < b["replacement_root"]["threshold"]:
        raise Reject("root transition lacks replacement possession proofs")
    position = position_of(wrapper)
    st.positions[position] = wrapper["artifact_hash"]
    st.head = position
    st.root_set = new_root
    st.root_threshold = b["replacement_root"]["threshold"]
    st.root_epochs.append((position, new_root, st.root_threshold))
    st.invalidations.append((position, disp["mode"],
                             disp["carried_forward_certificate_ids"]))
    st.root_recovery_pubs |= set(new_root.values())
    return st


def validate_recovery_policy(wrapper, st):
    raw, b = _common_control(wrapper, DOM["recovery-policy"],
                             "daimon-recovery-policy/v0", st,
                             "recovery policy")
    require_keys(b, ["control_sequence", "me_id", "previous_control_hash",
                     "recovery_generation", "replacement_recovery", "schema"],
                 "recovery-policy body")
    _check_linkage(b, st, "recovery policy")
    new_recovery = validate_recovery_set(b["replacement_recovery"])
    pre = artifact_preimage(DOM["recovery-policy"], b)
    if count_valid(wrapper["signatures"], "root-authorization",
                   st.root_set, pre) < st.root_threshold:
        raise Reject("recovery policy lacks the root threshold")
    if st.recovery_mode == "threshold":
        if count_valid(wrapper["signatures"], "recovery-authorization",
                       st.recovery_set, pre) < st.recovery_threshold:
            raise Reject("recovery policy replaced without the existing "
                         "recovery threshold")
    if b["replacement_recovery"]["mode"] == "threshold":
        pos = possession_preimage(DOM["recovery-policy"], raw)
        if count_valid(wrapper["signatures"], "recovery-possession",
                       new_recovery, pos) \
                < b["replacement_recovery"]["threshold"]:
            raise Reject("recovery policy lacks replacement possession")
    position = position_of(wrapper)
    st.positions[position] = wrapper["artifact_hash"]
    st.head = position
    st.recovery_set = new_recovery
    st.recovery_mode = b["replacement_recovery"]["mode"]
    st.recovery_threshold = b["replacement_recovery"]["threshold"]
    st.root_recovery_pubs |= set(new_recovery.values())
    return st


def validate_recovery_transition(wrapper, st, known_competing_heads=None,
                                 known_control_positions=None):
    raw, b = _common_control(wrapper, DOM["recovery-transition"],
                             "daimon-recovery-transition/v0", st,
                             "recovery transition")
    base = {"compromise", "control_sequence", "me_id", "post_recovery_root",
            "revocations", "recovery_generation", "schema"}
    keys = set(b.keys())
    fork_resolving = "competing_control_hashes" in b
    if "previous_control_hash" in b and fork_resolving:
        raise Reject("recovery transition carries both predecessor forms")
    if "previous_control_hash" in b:
        keys.discard("previous_control_hash")
    elif fork_resolving:
        keys.discard("competing_control_hashes")
    else:
        raise Reject("recovery transition has no predecessor evidence")
    if keys != base:
        raise Reject("recovery-transition body fields mismatch")
    if fork_resolving:
        require_uint(b["recovery_generation"],
                     "fork recovery generation")
        require_uint(b["control_sequence"], "fork control sequence")
        heads = b["competing_control_hashes"]
        if not isinstance(heads, list) or not heads:
            raise Reject("fork recovery has an empty competing-head set")
        if heads != sorted(heads) or len(set(heads)) != len(heads):
            raise Reject("competing heads are not sorted and unique")
        for head in heads:
            ub64(head, 32)
        if known_competing_heads is None:
            raise Reject("known competing-head evidence was not supplied")
        known_head_set = set(known_competing_heads)
        omitted_competing_evidence = bool(known_head_set - set(heads))
        missing_competing_evidence = bool(set(heads) - known_head_set)
        if (b["recovery_generation"], b["control_sequence"]) != \
                (st.head[0] + 1, 0):
            raise Reject("fork recovery has the wrong successor position")
    else:
        _check_linkage(b, st, "recovery transition",
                       recovery_transition=True)
    new_root = validate_threshold_set(b["post_recovery_root"],
                                      "post-recovery root")
    comp = b["compromise"]
    require_keys(comp, ["control_cutoff", "incarnation_high_waters", "mode",
                        "preserved_certificate_ids"], "compromise")
    if comp["mode"] not in ("none", "suspected", "confirmed"):
        raise Reject("unknown compromise mode")
    if comp["mode"] == "none":
        if comp["control_cutoff"] is not None:
            raise Reject("mode none requires a null cutoff")
    elif comp["control_cutoff"] is None:
        raise Reject("compromise mode requires a cutoff")
    if comp["control_cutoff"] is not None:
        cutoff = comp["control_cutoff"]
        require_keys(cutoff, ["control_hash", "control_sequence",
                              "recovery_generation"], "control cutoff")
        require_uint(cutoff["recovery_generation"],
                     "cutoff recovery generation")
        require_uint(cutoff["control_sequence"], "cutoff control sequence")
        ub64(cutoff["control_hash"], 32)
        position = (cutoff["recovery_generation"],
                    cutoff["control_sequence"])
        position_evidence = {
            (p[0], p[1], artifact_hash)
            for p, artifact_hash in st.positions.items()}
        if known_control_positions is not None:
            if isinstance(known_control_positions, dict):
                position_evidence.update(
                    (p[0], p[1], artifact_hash)
                    for p, artifact_hash in known_control_positions.items())
            else:
                position_evidence.update(known_control_positions)
        if (position[0], position[1], cutoff["control_hash"]) not in \
                position_evidence:
            raise Reject("control cutoff is not a known predecessor-branch "
                         "position")
    if comp["preserved_certificate_ids"] != \
            sorted(comp["preserved_certificate_ids"]) \
            or len(set(comp["preserved_certificate_ids"])) != \
            len(comp["preserved_certificate_ids"]):
        raise Reject("preserved certificate IDs not sorted and unique")
    for i in comp["preserved_certificate_ids"]:
        typed_id(i, "dm:cert:v0:")
    validate_high_waters(comp["incarnation_high_waters"])
    revs = b["revocations"]
    if not isinstance(revs, list) or len(revs) > 256:
        raise Reject("revocation array exceeds the bound of 256")
    if revs != sorted(revs, key=jcs):
        raise Reject("revocation entries not sorted by canonical JCS bytes")
    seen = set()
    for r in revs:
        validate_revocation_entry(r, st, known_control_positions)
        t = (r["target"]["kind"], r["target"]["id"], r["target"]["kid"])
        if t in seen:
            raise Reject("duplicate revocation target")
        seen.add(t)
        if r["target"]["kind"] == "certificate" and \
                r["target"]["id"] in comp["preserved_certificate_ids"]:
            raise Reject("certificate both preserved and effectively revoked")
    pre = artifact_preimage(DOM["recovery-transition"], b)
    if count_valid(wrapper["signatures"], "recovery-authorization",
                   st.recovery_set, pre) < st.recovery_threshold:
        raise Reject("recovery transition lacks the accepted recovery "
                     "threshold")
    pos = possession_preimage(DOM["recovery-transition"], raw)
    if count_valid(wrapper["signatures"], "root-possession", new_root, pos) \
            < b["post_recovery_root"]["threshold"]:
        raise Reject("recovery transition lacks root possession proofs")
    if fork_resolving:
        if omitted_competing_evidence:
            raise Reject("fork recovery does not name every known head")
        if missing_competing_evidence:
            raise Incomplete("named competing-head bytes are unavailable")
    position = position_of(wrapper)
    st.positions[position] = wrapper["artifact_hash"]
    st.head = position
    st.root_set = new_root
    st.root_threshold = b["post_recovery_root"]["threshold"]
    st.root_epochs.append((position, new_root, st.root_threshold))
    st.revoked_targets.extend(r["target"] for r in revs)
    st.root_recovery_pubs |= set(new_root.values())
    return st


def validate_standalone_revocation(wrapper, st):
    raw, b = _common_control(wrapper, DOM["revocation"],
                             "daimon-revocation/v0", st,
                             "standalone revocation")
    require_keys(b, ["control_sequence", "me_id", "previous_control_hash",
                     "recovery_generation", "revocation", "schema"],
                 "standalone-revocation body")
    _check_linkage(b, st, "standalone revocation")
    entry = b["revocation"]
    validate_revocation_entry(entry, st)
    if entry["target"]["kind"] in ("root-key", "recovery-key"):
        raise Reject("standalone root/recovery-key revocation is invalid "
                     "outside the transition that installs its successor")
    pre = artifact_preimage(DOM["revocation"], b)
    if count_valid(wrapper["signatures"], "root-authorization",
                   st.root_set, pre) < st.root_threshold:
        raise Reject("standalone revocation lacks the root threshold")
    position = position_of(wrapper)
    st.positions[position] = wrapper["artifact_hash"]
    st.head = position
    st.revoked_targets.append(entry["target"])
    return st


def validate_control(wrapper, st, known_competing_heads=None,
                     known_control_positions=None,
                     known_certificate_ids=None):
    schema = wrapper.get("body", {}).get("schema")
    if schema == "daimon-root-transition/v0":
        return validate_root_transition(wrapper, st, known_certificate_ids)
    if schema == "daimon-recovery-policy/v0":
        return validate_recovery_policy(wrapper, st)
    if schema == "daimon-recovery-transition/v0":
        return validate_recovery_transition(
            wrapper, st, known_competing_heads, known_control_positions)
    if schema == "daimon-revocation/v0":
        return validate_standalone_revocation(wrapper, st)
    raise Reject("unknown control schema")

# ---------------------------------------------------------------------------
# Certificates, acceptances, leases
# ---------------------------------------------------------------------------

class CertRegistry:
    def __init__(self):
        self.certs = {}              # certificate_id -> validated record
        self.by_incarnation = {}     # incarnation_id -> {generation: id}
        self.signing_key_owner = {}  # signing public key -> incarnation_id
        self.revoked_cert_ids = set()
        self.accepted_cert_ids = set()
        self.accepted_by_incarnation = {}  # incarnation -> {generation: id}


def validate_certificate(wrapper, st, registry):
    require_keys(wrapper, ["body", "certificate_hash", "certificate_id",
                           "signatures"], "certificate wrapper")
    b = wrapper["body"]
    digest = sha256(jcs(b))  # DM-010 inheritance: no domain prefix
    if wrapper["certificate_hash"] != b64e(digest):
        raise Reject("derived certificate hash mismatch")
    cert_id = "dm:cert:v0:" + b64e(digest)
    if wrapper["certificate_id"] != cert_id:
        raise Reject("derived certificate ID mismatch")
    check_sig_sorting(wrapper["signatures"],
                      SIGNATURE_ROLES[DOM["certificate"]])
    require_keys(b, ["certificate_generation", "certificate_nonce",
                     "constraints", "encryption_key", "expires_at_ms",
                     "incarnation_id", "incarnation_nonce",
                     "initial_embodiment_hash", "issued_at_ms",
                     "issuing_control_position", "issuing_root_kids",
                     "me_id", "not_before_ms", "previous_certificate_id",
                     "purposes", "schema", "signing_key"],
                 "certificate body")
    if b["schema"] != "daimon-incarnation-certificate/v0":
        raise Reject("certificate schema mismatch")
    if b["me_id"] != st.me_id:
        raise Reject("certificate me_id mismatch")
    ub64(b["incarnation_nonce"], 32)
    ub64(b["certificate_nonce"], 32)
    sign_pub = validate_descriptor(b["signing_key"], "Ed25519")
    enc_pub = validate_descriptor(b["encryption_key"], "X25519")
    if sign_pub == enc_pub:
        raise Reject("signing and encryption keys must be distinct")
    if sign_pub in st.root_recovery_pubs or enc_pub in st.root_recovery_pubs:
        raise Reject("public key reused across root/recovery/incarnation "
                     "roles")
    inc_pre = DOM["incarnation-id"].encode("utf-8") + b"\x00" + jcs({
        "incarnation_nonce": b["incarnation_nonce"],
        "me_id": b["me_id"],
        "signing_key": b["signing_key"],
    })
    inc_id = "dm:inc:v0:" + b64e(sha256(inc_pre))
    if b["incarnation_id"] != inc_id:
        raise Reject("derived incarnation_id mismatch")
    owner = registry.signing_key_owner.get(sign_pub)
    if owner is not None and owner != inc_id:
        raise Reject("one signing key claimed by two incarnation IDs")
    pos = b["issuing_control_position"]
    require_keys(pos, ["control_hash", "control_sequence",
                       "recovery_generation"], "issuing control position")
    require_uint(pos["recovery_generation"],
                 "issuing recovery generation")
    require_uint(pos["control_sequence"], "issuing control sequence")
    ub64(pos["control_hash"], 32)
    position = (pos["recovery_generation"], pos["control_sequence"])
    if st.positions.get(position) != pos["control_hash"]:
        raise Reject("certificate anchored to a control head not on the "
                     "accepted chain")
    epoch = st.active_root_at(position)
    if epoch is None:
        raise Reject("no root epoch at the issuing position")
    epoch_set, epoch_threshold = epoch
    if b["issuing_root_kids"] != sorted(epoch_set.keys()):
        raise Reject("issuing_root_kids is not the complete active root set")
    # A certificate issued under a superseded root epoch is valid only if a
    # later rotation explicitly carried it forward (which can only name
    # certificates existing at the rotation), so a newly issued certificate
    # under an old root is rejected whenever its epoch was closed.
    last_epoch_position = st.root_epochs[-1][0]
    if position < last_epoch_position:
        raise Reject("certificate issued under a superseded root epoch")
    for (inv_pos, mode, carried) in st.invalidations:
        if position < inv_pos and mode == "invalidate_all":
            raise Reject("issuing root's certificates were invalidated")
        if position < inv_pos and mode == "carry_forward" \
                and cert_id not in carried:
            raise Reject("certificate not carried forward by rotation")
    pre = artifact_preimage(DOM["certificate"], b)
    if count_valid(wrapper["signatures"], "root-authorization",
                   epoch_set, pre) < epoch_threshold:
        raise Reject("certificate lacks the issuing root threshold")
    gen = b["certificate_generation"]
    require_uint(gen, "certificate generation")
    known = registry.by_incarnation.setdefault(inc_id, {})
    if gen == 0:
        if b["previous_certificate_id"] is not None:
            raise Reject("generation zero requires a null predecessor")
    else:
        prev_id = b["previous_certificate_id"]
        if prev_id is None or known.get(gen - 1) != prev_id:
            raise Reject("certificate predecessor mismatch or generation gap")
    if gen in known and known[gen] != cert_id:
        raise Reject("certificate fork at one incarnation/generation")
    purposes = b["purposes"]
    require_keys(purposes, ["encryption", "signing"], "certificate purposes")
    if purposes["signing"] != sorted(purposes["signing"]) or \
            len(set(purposes["signing"])) != len(purposes["signing"]) or \
            not set(purposes["signing"]) <= SIGNING_PURPOSES:
        raise Reject("bad signing purposes")
    if purposes["encryption"] != sorted(purposes["encryption"]) or \
            len(set(purposes["encryption"])) != \
            len(purposes["encryption"]) or \
            not set(purposes["encryption"]) <= ENCRYPTION_PURPOSES:
        raise Reject("bad encryption purposes")
    cons = b["constraints"]
    require_keys(cons, ["event_type_prefixes", "max_event_bytes"],
                 "certificate constraints")
    if require_uint(cons["max_event_bytes"], "maximum event bytes",
                    CEILING_EVENT) == 0:
        raise Reject("max_event_bytes out of range")
    prefixes = cons["event_type_prefixes"]
    if not isinstance(prefixes, list) or len(prefixes) > 64:
        raise Reject("event type prefix array exceeds the bound of 64")
    if prefixes != sorted(prefixes) or len(set(prefixes)) != len(prefixes):
        raise Reject("event type prefixes not sorted or duplicate-free")
    for p in prefixes:
        if not 1 <= len(p) <= 128 or not PREFIX_RE.match(p):
            raise Reject("bad event type prefix")
    require_uint(b["issued_at_ms"], "certificate issuance time")
    require_uint(b["not_before_ms"], "certificate not-before time")
    require_uint(b["expires_at_ms"], "certificate expiry time")
    if not b["not_before_ms"] <= b["expires_at_ms"]:
        raise Reject("bad certificate validity interval")
    lifetime = b["expires_at_ms"] - b["not_before_ms"]
    if lifetime > st.policy["max_certificate_lifetime_ms"]:
        raise Reject("certificate exceeds the maximum lifetime")
    if b["initial_embodiment_hash"] is not None:
        ub64(b["initial_embodiment_hash"], 32)
    record = {
        "certificate_id": cert_id, "hash": b64e(digest), "body": b,
        "incarnation_id": inc_id, "me_id": b["me_id"],
        "generation": gen, "signing_kid": b["signing_key"]["kid"],
        "signing_pub": sign_pub, "encryption_kid": b["encryption_key"]["kid"],
        "encryption_pub": enc_pub,
    }
    registry.certs[cert_id] = record
    known[gen] = cert_id
    registry.signing_key_owner[sign_pub] = inc_id
    return record


def validate_acceptance(wrapper, registry):
    raw = validate_wrapper(wrapper, DOM["acceptance"], "dm:accept:v0:",
                           "acceptance")
    b = wrapper["body"]
    require_keys(b, ["certificate_hash", "certificate_id", "incarnation_id",
                     "me_id", "schema"], "acceptance body")
    if b["schema"] != "daimon-incarnation-acceptance/v0":
        raise Reject("acceptance schema mismatch")
    cert = registry.certs.get(b["certificate_id"])
    if cert is None:
        raise Reject("acceptance names an unknown certificate")
    if b["certificate_hash"] != cert["hash"]:
        raise Reject("acceptance names another certificate hash")
    if b["incarnation_id"] != cert["incarnation_id"] \
            or b["me_id"] != cert["me_id"]:
        raise Reject("acceptance names another incarnation or /me")
    sigs = wrapper["signatures"]
    if len(sigs) != 1 or sigs[0]["role"] != "subject-acceptance":
        raise Reject("acceptance requires one subject-acceptance signature")
    if sigs[0]["kid"] != cert["signing_kid"]:
        raise Reject("acceptance not signed by the certificate's key")
    sig = validate_sig_record(sigs[0])
    ed25519_verify(cert["signing_pub"], sig,
                   artifact_preimage(DOM["acceptance"], b))
    accepted = registry.accepted_by_incarnation.setdefault(
        cert["incarnation_id"], {})
    generation = cert["generation"]
    if generation > 0 and accepted.get(generation - 1) != \
            cert["body"]["previous_certificate_id"]:
        raise Reject("certificate renewal does not extend the directly "
                     "preceding accepted generation")
    if generation in accepted \
            and accepted[generation] != cert["certificate_id"]:
        raise Reject("subject accepted a certificate fork at one generation")
    accepted[generation] = cert["certificate_id"]
    registry.accepted_cert_ids.add(cert["certificate_id"])
    return True


def validate_lease(wrapper, registry, st, at_ms=None):
    raw = validate_wrapper(wrapper, DOM["lease"], "dm:lease:v0:", "lease")
    b = wrapper["body"]
    require_keys(b, ["capability_hash", "certificate_id", "embodiment_hash",
                     "expires_at_ms", "incarnation_id", "issued_at_ms",
                     "lease_sequence", "me_id", "previous_lease_hash",
                     "routes", "schema", "session_id",
                     "supersedes_session_id"], "lease body")
    if b["schema"] != "daimon-presence-lease/v0":
        raise Reject("lease schema mismatch")
    cert = registry.certs.get(b["certificate_id"])
    if cert is None:
        raise Reject("lease names an unknown certificate")
    if cert["certificate_id"] not in registry.accepted_cert_ids:
        raise Reject("lease certificate lacks subject acceptance")
    if cert["certificate_id"] in registry.revoked_cert_ids:
        raise Reject("lease certificate is revoked")
    accepted_generations = registry.accepted_by_incarnation.get(
        cert["incarnation_id"], {})
    if cert["generation"] < max(accepted_generations):
        raise Reject("superseded certificate generation cannot issue leases")
    if b["incarnation_id"] != cert["incarnation_id"] \
            or b["me_id"] != cert["me_id"]:
        raise Reject("lease names another incarnation")
    if "presence-lease" not in cert["body"]["purposes"]["signing"]:
        raise Reject("certificate lacks the presence-lease purpose")
    ub64(b["session_id"], 32)
    if b["supersedes_session_id"] is not None:
        ub64(b["supersedes_session_id"], 32)
    require_uint(b["lease_sequence"], "lease sequence")
    if b["lease_sequence"] == 0:
        if b["previous_lease_hash"] is not None:
            raise Reject("first lease must have a null predecessor")
    else:
        ub64(b["previous_lease_hash"], 32)
    ub64(b["embodiment_hash"], 32)
    ub64(b["capability_hash"], 32)
    routes = b["routes"]
    if not isinstance(routes, list) or len(routes) > 64:
        raise Reject("route array exceeds the bound of 64")
    if routes != sorted(routes, key=lambda r: (r["kind"], r["route_id"])):
        raise Reject("routes not sorted")
    seen = set()
    for r in routes:
        require_keys(r, ["kind", "route_id"], "route")
        if r["kind"] not in ROUTE_KINDS:
            raise Reject("unknown route kind")
        typed_id(r["route_id"], "dm:route:v0:")
        if (r["kind"], r["route_id"]) in seen:
            raise Reject("duplicate route")
        seen.add((r["kind"], r["route_id"]))
    require_uint(b["issued_at_ms"], "lease issuance time")
    require_uint(b["expires_at_ms"], "lease expiry time")
    if not b["issued_at_ms"] < b["expires_at_ms"]:
        raise Reject("bad lease interval")
    if b["expires_at_ms"] - b["issued_at_ms"] > \
            st.policy["max_presence_ttl_ms"]:
        raise Reject("lease exceeds the genesis/V0 presence TTL")
    if b["issued_at_ms"] < cert["body"]["not_before_ms"] \
            or b["expires_at_ms"] > cert["body"]["expires_at_ms"]:
        raise Reject("lease interval exceeds the certificate validity interval")
    if at_ms is not None:
        require_uint(at_ms, "lease verification time")
        if not b["issued_at_ms"] <= at_ms \
                < min(b["expires_at_ms"], cert["body"]["expires_at_ms"]):
            raise Reject("lease is not live at the injected verification time")
    sigs = wrapper["signatures"]
    if len(sigs) != 1 or sigs[0]["role"] != "incarnation-authorization":
        raise Reject("lease requires one incarnation-authorization signature")
    if sigs[0]["kid"] != cert["signing_kid"]:
        raise Reject("lease not signed by the certificate's key")
    sig = validate_sig_record(sigs[0])
    ed25519_verify(cert["signing_pub"], sig,
                   artifact_preimage(DOM["lease"], b))
    return True


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def validate_event_structure(wrapper):
    require_keys(wrapper, ["body", "event_hash", "event_id", "signature"],
                 "event wrapper")
    b = wrapper["body"]
    require_keys(b, ["causal_parents", "certificate_id", "embodiment_hash",
                     "event_nonce", "event_sequence", "event_type",
                     "incarnation_id", "intent", "logical_time", "me_id",
                     "payload", "previous_event_id", "schema"],
                 "event body")
    if b["schema"] != "daimon-event/v0":
        raise Reject("event schema mismatch")
    ub64(b["event_nonce"], 32)
    typed_id(b["me_id"], "dm:me:v0:")
    typed_id(b["incarnation_id"], "dm:inc:v0:")
    typed_id(b["certificate_id"], "dm:cert:v0:")
    seq = b["event_sequence"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        raise Reject("bad event sequence")
    if seq == 0:
        if b["previous_event_id"] is not None:
            raise Reject("sequence zero must have a null predecessor")
    else:
        typed_id(b["previous_event_id"], "dm:event:v0:")
    lt = b["logical_time"]
    require_keys(lt, ["counter", "physical_ms"], "logical time")
    require_uint(lt["physical_ms"], "HLC physical time")
    require_uint(lt["counter"], "HLC counter")
    parents = b["causal_parents"]
    if not isinstance(parents, list) or len(parents) > 64:
        raise Reject("causal parents exceed the bound of 64")
    if parents != sorted(parents) or len(set(parents)) != len(parents):
        raise Reject("causal parents unsorted or duplicated")
    for p in parents:
        typed_id(p, "dm:event:v0:")
    ub64(b["embodiment_hash"], 32)
    et = b["event_type"]
    if not isinstance(et, str) or not 1 <= len(et) <= 128 \
            or not EVENT_TYPE_RE.match(et):
        raise Reject("bad event type")
    if b["intent"] is not None:
        intent = b["intent"]
        require_keys(intent, ["operation", "scope", "thread_id"], "intent")
        typed_id(intent["thread_id"], "dm:thread:v0:")
        if not isinstance(intent["scope"], str) \
                or not isinstance(intent["operation"], str):
            raise Reject("bad intent fields")
    raw = sha256(artifact_preimage(DOM["event"], b))
    if wrapper["event_hash"] != b64e(raw):
        raise Reject("derived event hash mismatch")
    if wrapper["event_id"] != "dm:event:v0:" + b64e(raw):
        raise Reject("derived event ID mismatch")
    sig = wrapper["signature"]
    validate_sig_record(sig)
    if sig["role"] != "incarnation-authorization":
        raise Reject("event signature role mismatch")
    return raw


def validate_event_contextual(wrapper, registry, known_events,
                              revoked_cert_ids=(), verify_signature=True):
    """Validate an event against available evidence.

    ``known_events`` maps event IDs to
    ``(sequence, physical_ms, counter, context_complete)``.  Merely having
    bytes for a predecessor is not enough: an incomplete ancestor propagates
    ``Incomplete`` and cannot make a descendant projectable.
    """
    validate_event_structure(wrapper)
    b = wrapper["body"]
    cert = registry.certs.get(b["certificate_id"])
    if cert is None:
        raise Reject("event names an unknown certificate")
    if cert["certificate_id"] not in registry.accepted_cert_ids:
        raise Reject("event certificate lacks subject acceptance")
    revoked = set(registry.revoked_cert_ids)
    revoked.update(revoked_cert_ids)
    if b["certificate_id"] in revoked:
        raise Reject("event under a revoked certificate")
    accepted_generations = registry.accepted_by_incarnation.get(
        cert["incarnation_id"], {})
    if not accepted_generations:
        raise Reject("event incarnation has no accepted certificate")
    highest = max(accepted_generations)
    if cert["generation"] < highest:
        raise Reject("a superseded certificate generation cannot authorize "
                     "new events")
    if b["incarnation_id"] != cert["incarnation_id"] \
            or b["me_id"] != cert["me_id"]:
        raise Reject("event names another incarnation")
    if "event" not in cert["body"]["purposes"]["signing"]:
        raise Reject("certificate lacks the event signing purpose")
    prefixes = cert["body"]["constraints"]["event_type_prefixes"]
    if not any(b["event_type"].startswith(p) for p in prefixes):
        raise Reject("event type not authorized by the certificate")
    sig = wrapper["signature"]
    if sig["kid"] != cert["signing_kid"]:
        raise Reject("event not signed by the certificate's signing key")
    if verify_signature:
        ed25519_verify(cert["signing_pub"], ub64(sig["value"], 64),
                       artifact_preimage(DOM["event"], b))
    seq = b["event_sequence"]
    lt = (b["logical_time"]["physical_ms"], b["logical_time"]["counter"])
    if seq > 0:
        prev = known_events.get(b["previous_event_id"])
        if prev is None:
            raise Incomplete("predecessor bytes unavailable")
        if not prev[3]:
            raise Incomplete("predecessor has incomplete ancestry")
        if prev[0] != seq - 1:
            raise Reject("known predecessor with a wrong sequence increment")
        if b["previous_event_id"] not in b["causal_parents"]:
            raise Reject("local predecessor missing from causal parents")
        if (prev[1], prev[2]) >= lt:
            raise Reject("HLC regression against the known predecessor")
    for p in b["causal_parents"]:
        parent = known_events.get(p)
        if parent is None:
            raise Incomplete("causal parent bytes unavailable")
        if not parent[3]:
            raise Incomplete("causal parent has incomplete ancestry")
        if (parent[1], parent[2]) >= lt:
            raise Reject("HLC regression against a known causal parent")
    return True


def known_events_map(paths, registry=None):
    """Build contextual evidence only from fully crypto-validated events.

    Events whose signed ancestry is unavailable are retained as incomplete;
    malformed signatures/certificates are rejected and never become trusted
    predecessor tuples.
    """
    if registry is None:
        registry = combined_registry()
    wrappers = {}
    for rel in paths:
        w = load_artifact(rel, CEILING_EVENT)
        validate_event_structure(w)
        wrappers[w["event_id"]] = w
    out = {}
    pending = dict(wrappers)
    while pending:
        progressed = False
        for event_id, wrapper in list(pending.items()):
            try:
                validate_event_contextual(wrapper, registry, out)
            except Incomplete:
                continue
            b = wrapper["body"]
            out[event_id] = (
                b["event_sequence"], b["logical_time"]["physical_ms"],
                b["logical_time"]["counter"], True)
            del pending[event_id]
            progressed = True
        if not progressed:
            break
    # One final validation pass proves signatures/certificates for pending
    # evidence even though its ancestry is unavailable.
    for event_id, wrapper in pending.items():
        try:
            validate_event_contextual(wrapper, registry, out)
        except Incomplete:
            b = wrapper["body"]
            out[event_id] = (
                b["event_sequence"], b["logical_time"]["physical_ms"],
                b["logical_time"]["counter"], False)
        else:
            raise AssertionError("event became complete outside fixpoint")
    return out

# ---------------------------------------------------------------------------
# Checkpoints
# ---------------------------------------------------------------------------

def _validate_control_position(pos, st, what):
    require_keys(pos, ["control_hash", "control_sequence",
                       "recovery_generation"], what)
    require_uint(pos["recovery_generation"], what + " recovery generation")
    require_uint(pos["control_sequence"], what + " control sequence")
    ub64(pos["control_hash"], 32)
    p = (pos["recovery_generation"], pos["control_sequence"])
    if st.positions.get(p) != pos["control_hash"]:
        raise Reject("%s names a position off the accepted chain" % what)


def validate_checkpoint(wrapper, registry, st, event_index):
    """event_index: {event_id: validated event wrapper}."""
    raw = validate_wrapper(wrapper, DOM["checkpoint"], "dm:checkpoint:v0:",
                           "checkpoint")
    b = wrapper["body"]
    require_keys(b, ["accepted_at_ms", "high_water_event_hash",
                     "high_water_event_id", "high_water_sequence", "schema",
                     "subject_certificate_id",
                     "subject_identity_control_position",
                     "subject_incarnation_id", "subject_me_id",
                     "witness_certificate_id",
                     "witness_identity_control_position",
                     "witness_incarnation_id", "witness_me_id"],
                 "checkpoint body")
    if b["schema"] != "daimon-event-checkpoint/v0":
        raise Reject("checkpoint schema mismatch")
    require_uint(b["high_water_sequence"],
                 "checkpoint high-water sequence")
    require_uint(b["accepted_at_ms"], "checkpoint acceptance time")
    subject_cert = registry.certs.get(b["subject_certificate_id"])
    witness_cert = registry.certs.get(b["witness_certificate_id"])
    if subject_cert is None or witness_cert is None:
        raise Reject("checkpoint names an unknown certificate")
    if subject_cert["certificate_id"] not in registry.accepted_cert_ids \
            or witness_cert["certificate_id"] not in \
            registry.accepted_cert_ids:
        raise Reject("checkpoint certificate lacks subject acceptance")
    if witness_cert["certificate_id"] in registry.revoked_cert_ids:
        raise Reject("checkpoint witness certificate is revoked")
    if b["subject_incarnation_id"] == b["witness_incarnation_id"]:
        raise Reject("the witness must differ from the subject incarnation")
    if b["subject_me_id"] != subject_cert["me_id"] \
            or b["subject_incarnation_id"] != subject_cert["incarnation_id"]:
        raise Reject("checkpoint subject identity mismatch")
    if b["witness_me_id"] != witness_cert["me_id"] \
            or b["witness_incarnation_id"] != witness_cert["incarnation_id"]:
        raise Reject("checkpoint witness identity mismatch")
    if "event-checkpoint" not in witness_cert["body"]["purposes"]["signing"]:
        raise Reject("witness certificate lacks the event-checkpoint purpose")
    trusted_events = {}
    pending_events = dict(event_index)
    while pending_events:
        progressed = False
        for event_id, event_wrapper in list(pending_events.items()):
            try:
                validate_event_contextual(
                    event_wrapper, registry, trusted_events,
                    registry.revoked_cert_ids)
            except Incomplete:
                continue
            eb = event_wrapper["body"]
            trusted_events[event_id] = (
                eb["event_sequence"], eb["logical_time"]["physical_ms"],
                eb["logical_time"]["counter"], True)
            del pending_events[event_id]
            progressed = True
        if not progressed:
            break
    # Pending wrappers still require valid crypto; they are not trusted as a
    # checkpointable prefix merely because their bytes are present.
    for event_id, event_wrapper in pending_events.items():
        try:
            validate_event_contextual(
                event_wrapper, registry, trusted_events,
                registry.revoked_cert_ids)
        except Incomplete:
            pass
    if b["high_water_event_id"] not in trusted_events:
        raise Incomplete("checkpoint high-water prefix is not contextually "
                         "complete")
    _validate_control_position(b["subject_identity_control_position"], st,
                               "subject control position")
    _validate_control_position(b["witness_identity_control_position"], st,
                               "witness control position")
    typed_id(b["high_water_event_id"], "dm:event:v0:")
    ub64(b["high_water_event_hash"], 32)
    hw = event_index.get(b["high_water_event_id"])
    if hw is None:
        raise Incomplete("high-water event bytes unavailable")
    hb = hw["body"]
    if hw["event_hash"] != b["high_water_event_hash"]:
        raise Reject("checkpoint high-water event hash mismatch")
    if hb["event_sequence"] != b["high_water_sequence"]:
        raise Reject("checkpoint high-water sequence mismatch")
    if hb["me_id"] != b["subject_me_id"] \
            or hb["incarnation_id"] != b["subject_incarnation_id"] \
            or hb["certificate_id"] != b["subject_certificate_id"]:
        raise Reject("checkpoint subject binding mismatch")
    if not subject_cert["body"]["not_before_ms"] <= b["accepted_at_ms"] \
            <= subject_cert["body"]["expires_at_ms"]:
        raise Reject("accepted_at_ms outside the subject certificate "
                     "validity interval")
    sigs = wrapper["signatures"]
    if len(sigs) != 1 or sigs[0]["role"] != "witness-authorization":
        raise Reject("checkpoint requires one witness-authorization "
                     "signature")
    if sigs[0]["kid"] != witness_cert["signing_kid"]:
        raise Reject("checkpoint not signed by the witness key")
    sig = validate_sig_record(sigs[0])
    ed25519_verify(witness_cert["signing_pub"], sig,
                   artifact_preimage(DOM["checkpoint"], b))
    return True


def checkpoint_covers(checkpoint, event, event_index):
    """Does the checkpoint's contiguous prefix cover this event?"""
    b = checkpoint["body"]
    eb = event["body"]
    if eb["me_id"] != b["subject_me_id"] \
            or eb["incarnation_id"] != b["subject_incarnation_id"] \
            or eb["certificate_id"] != b["subject_certificate_id"]:
        return False
    if eb["event_sequence"] > b["high_water_sequence"]:
        return False
    # Walk the prefix from the named high-water back to the event.
    cursor = event_index[b["high_water_event_id"]]
    while cursor["body"]["event_sequence"] > eb["event_sequence"]:
        cursor = event_index.get(cursor["body"]["previous_event_id"])
        if cursor is None:
            return False
    return cursor["event_id"] == event["event_id"]


# ---------------------------------------------------------------------------
# Sealed deliveries
# ---------------------------------------------------------------------------

def reduced_recipient(entry):
    return {k: entry[k] for k in
            ("certificate_id", "encryption_kid", "incarnation_id", "me_id")}


def recipient_sort_key(entry):
    return (entry["me_id"], entry["incarnation_id"], entry["encryption_kid"])


def protected_metadata(delivery):
    protected = {k: v for k, v in delivery.items()
                 if k not in ("payload", "signature")}
    protected["recipients"] = [reduced_recipient(r)
                               for r in delivery["recipients"]]
    return protected


def hpke_info_for(protected, entry):
    return DOM["sealed-cek"].encode("utf-8") + b"\x00" + jcs({
        "protected": protected, "recipient": reduced_recipient(entry)})


def validate_delivery(delivery, registry, authorization, recipient_privs,
                      expect_inner_rel=None, known_events=None,
                      revoked_cert_ids=None, at_ms=None):
    """Full sealed-delivery validation. recipient_privs maps encryption_kid
    to X25519 private keys for the recipients we can decrypt for."""
    b = delivery  # the sealed delivery is a single exact object
    require_keys(b, ["delivery_id", "disclosure_authorization_id",
                     "event_hash", "event_id", "expires_at_ms", "issued_at_ms",
                     "payload", "recipients", "schema", "sender", "signature",
                     "suite"], "sealed delivery")
    if b["schema"] != "daimon-sealed-event/v0":
        raise Reject("sealed schema mismatch")
    typed_id(b["delivery_id"], "dm:delivery:v0:")
    typed_id(b["event_id"], "dm:event:v0:")
    ub64(b["event_hash"], 32)
    if b["suite"] != SUITE:
        raise Reject("sealed suite mismatch")
    require_uint(b["issued_at_ms"], "delivery issuance time")
    require_uint(b["expires_at_ms"], "delivery expiry time")
    if not b["issued_at_ms"] < b["expires_at_ms"]:
        raise Reject("bad delivery interval")
    if b["expires_at_ms"] - b["issued_at_ms"] > MAX_DELIVERY_TTL_MS:
        raise Reject("delivery TTL above 24 hours")
    sender = b["sender"]
    require_keys(sender, ["certificate_id", "incarnation_id", "me_id",
                          "signing_kid"], "delivery sender")
    sender_cert = registry.certs.get(sender["certificate_id"])
    if sender_cert is None:
        raise Reject("delivery names an unknown sender certificate")
    if sender_cert["certificate_id"] not in registry.accepted_cert_ids:
        raise Reject("delivery sender certificate lacks subject acceptance")
    if sender["incarnation_id"] != sender_cert["incarnation_id"] \
            or sender["me_id"] != sender_cert["me_id"] \
            or sender["signing_kid"] != sender_cert["signing_kid"]:
        raise Reject("delivery sender binding mismatch")
    revoked = set(registry.revoked_cert_ids)
    if revoked_cert_ids is not None:
        revoked.update(revoked_cert_ids)
    if sender["certificate_id"] in revoked:
        raise Reject("delivery sender certificate is revoked")
    if "sealed-delivery" not in sender_cert["body"]["purposes"]["signing"]:
        raise Reject("sender certificate lacks the sealed-delivery purpose")
    if not sender_cert["body"]["not_before_ms"] <= b["issued_at_ms"] \
            < sender_cert["body"]["expires_at_ms"]:
        raise Reject("delivery issued outside sender certificate validity")
    recipients = b["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 256:
        raise Reject("recipient count out of bounds")
    if recipients != sorted(recipients, key=recipient_sort_key):
        raise Reject("recipients not in canonical sorted order")
    seen_incarnations, seen_kids = set(), set()
    for r in recipients:
        require_keys(r, ["certificate_id", "enc", "encryption_kid",
                         "incarnation_id", "me_id", "wrapped_cek"],
                     "recipient entry")
        ub64(r["enc"], 32)
        ub64(r["wrapped_cek"], 48)
        incarnation = (r["me_id"], r["incarnation_id"])
        if incarnation in seen_incarnations \
                or r["encryption_kid"] in seen_kids:
            raise Reject("duplicate recipient incarnation or encryption key")
        seen_incarnations.add(incarnation)
        seen_kids.add(r["encryption_kid"])
        rcert = registry.certs.get(r["certificate_id"])
        if rcert is None:
            raise Reject("recipient names an unknown certificate")
        if rcert["certificate_id"] not in registry.accepted_cert_ids:
            raise Reject("delivery recipient certificate lacks subject "
                         "acceptance")
        if r["incarnation_id"] != rcert["incarnation_id"] \
                or r["me_id"] != rcert["me_id"] \
                or r["encryption_kid"] != rcert["encryption_kid"]:
            raise Reject("recipient binding mismatch")
        if r["certificate_id"] in revoked:
            raise Reject("delivery recipient certificate is revoked")
        if "sealed-event-recipient" not in \
                rcert["body"]["purposes"]["encryption"]:
            raise Reject("recipient certificate lacks the "
                         "sealed-event-recipient purpose")
        if not rcert["body"]["not_before_ms"] <= b["issued_at_ms"] \
                < rcert["body"]["expires_at_ms"]:
            raise Reject("delivery issued outside recipient certificate "
                         "validity")
    payload = b["payload"]
    require_keys(payload, ["ciphertext", "nonce"], "delivery payload")
    nonce = ub64(payload["nonce"], 12)
    ciphertext = ub64(payload["ciphertext"])
    if len(ciphertext) < 16:
        raise Reject("payload ciphertext too short")
    # Outer signature over the delivery without the signature field.
    sig = b["signature"]
    validate_sig_record(sig)
    if sig["role"] != "delivery-authorization":
        raise Reject("delivery signature role mismatch")
    if sig["kid"] != sender_cert["signing_kid"]:
        raise Reject("delivery not signed by the sender key")
    unsigned = {k: v for k, v in b.items() if k != "signature"}
    ed25519_verify(sender_cert["signing_pub"], ub64(sig["value"], 64),
                   DOM["sealed"].encode("utf-8") + b"\x00" + jcs(unsigned))
    # Disclosure authorization (x/test fixture binding).
    if not isinstance(b["disclosure_authorization_id"], str):
        raise Reject("missing disclosure authorization")
    if authorization is None:
        raise Reject("disclosure authorization evidence unavailable")
    if authorization["event_id"] != b["disclosure_authorization_id"]:
        raise Reject("disclosure authorization ID mismatch")
    auth_payload = authorization["body"]["payload"]
    if auth_payload.get("schema") != "x/test-disclosure-authorization/v0":
        raise Reject("unexpected disclosure authorization schema")
    if auth_payload.get("event_id") != b["event_id"] \
            or auth_payload.get("event_hash") != b["event_hash"]:
        raise Reject("disclosure authorization binds a different event")
    if auth_payload.get("sender") != sender:
        raise Reject("disclosure authorization binds a different sender")
    if auth_payload.get("recipients") != \
            [reduced_recipient(r) for r in recipients]:
        raise Reject("disclosure authorization binds a different recipient "
                     "set")
    # Decrypt for every recipient we hold a private key for.
    protected = protected_metadata(b)
    inner_bytes = None
    expired_for_receiver = False
    if at_ms is not None:
        require_uint(at_ms, "delivery verification time")
    for r in recipients:
        priv = recipient_privs.get(r["encryption_kid"])
        if priv is None:
            continue
        rcert = registry.certs[r["certificate_id"]]
        effective_expiry = min(
            b["expires_at_ms"], sender_cert["body"]["expires_at_ms"],
            rcert["body"]["expires_at_ms"])
        if at_ms is not None and at_ms >= effective_expiry:
            expired_for_receiver = True
            continue
        cek = hpke_open(ub64(r["enc"], 32), ub64(r["wrapped_cek"], 48),
                        priv, hpke_info_for(protected, r))
        try:
            pt = ChaCha20Poly1305(cek).decrypt(
                nonce, ciphertext,
                DOM["sealed-aad"].encode("utf-8") + b"\x00" + jcs(protected))
        except InvalidTag:
            raise Reject("payload AEAD decryption failed")
        if inner_bytes is None:
            inner_bytes = pt
        elif inner_bytes != pt:
            raise Reject("per-recipient plaintext disagreement")
    if inner_bytes is None:
        if expired_for_receiver:
            raise Reject("delivery expired for this receiver")
        raise Reject("no decryptable recipient entry")
    inner = strict_parse(inner_bytes, CEILING_EVENT)
    if known_events is None:
        known_events = known_events_map([
            "me1/event-inc1-0.json", "me2/event-xm1-0.json"])
    validate_event_contextual(inner, registry, known_events, revoked)
    if b["event_id"] != inner["event_id"] \
            or b["event_hash"] != inner["event_hash"]:
        raise Reject("outer/inner event ID or hash mismatch")
    if expect_inner_rel is not None \
            and inner_bytes != load_bytes(expect_inner_rel):
        raise Reject("decrypted bytes differ from the checked-in event "
                     "wrapper")
    return inner

# ---------------------------------------------------------------------------
# Shared contexts
# ---------------------------------------------------------------------------

_ME1_CHAIN = ["me1/genesis.json", "me1/root-transition.json",
              "me1/recovery-policy.json", "me1/recovery-transition.json",
              "me1/standalone-revocation.json"]
_ME1_CERTS = ["me1/certificate-inc1-gen0.json",
              "me1/certificate-inc1-gen1.json",
              "me1/certificate-inc2-gen0.json",
              "me1/certificate-inc2-gen1.json",
              "me1/certificate-inc3-gen0.json"]
_ME1_ACCEPTANCES = ["me1/acceptance-inc1-gen0.json",
                    "me1/acceptance-inc1-gen1.json",
                    "me1/acceptance-inc2-gen0.json",
                    "me1/acceptance-inc2-gen1.json",
                    "me1/acceptance-inc3-gen0.json"]

_CTX = {}


def build_me1_chain():
    st = validate_genesis(load_artifact(_ME1_CHAIN[0]))
    for rel in _ME1_CHAIN[1:]:
        validate_control(load_artifact(rel), st)
    return st


def build_me2_chain():
    return validate_genesis(load_artifact("me2/genesis.json"))


def combined_registry():
    """Certificates from both /me universes in one registry."""
    if "registry" in _CTX:
        return _CTX["registry"]
    registry = CertRegistry()
    st1 = build_me1_chain()
    for rel in _ME1_CERTS:
        validate_certificate(load_artifact(rel), st1, registry)
    for rel in _ME1_ACCEPTANCES:
        validate_acceptance(load_artifact(rel), registry)
    st2 = build_me2_chain()
    validate_certificate(load_artifact("me2/certificate-xm1-gen0.json"),
                         st2, registry)
    validate_acceptance(load_artifact("me2/acceptance-xm1-gen0.json"),
                        registry)
    registry.revoked_cert_ids = {
        t["id"] for t in st1.revoked_targets if t["kind"] == "certificate"}
    _CTX["registry"] = registry
    return registry


def revoked_cert_ids(paths):
    return {load_artifact(p)["certificate_id"] for p in paths}


class ActivationOracle:
    """Minimal acceptance/high-water state used by the replay vectors."""

    def __init__(self):
        self.state = build_me1_chain()
        self.registry = CertRegistry()
        self.highest = {}
        self.active = {}

    def activate(self, certificate, acceptance):
        record = validate_certificate(certificate, self.state, self.registry)
        validate_acceptance(acceptance, self.registry)
        inc = record["incarnation_id"]
        generation = record["generation"]
        previous = self.highest.get(inc, -1)
        if generation < previous:
            raise Reject("certificate activation is below the durable "
                         "generation high-water")
        if generation == previous:
            if self.active[inc] != record["certificate_id"]:
                raise Reject("certificate fork at the activation high-water")
            return "idempotent"
        self.highest[inc] = generation
        self.active[inc] = record["certificate_id"]
        return "activated"


class EventIngestOracle:
    """Minimal canonical-byte deduplication and projection-effect oracle."""

    def __init__(self, registry, seed_paths=()):
        self.registry = registry
        self.known = known_events_map(seed_paths)
        self.canonical_bytes = {}
        self.status = {}
        self.effects = []

    def ingest(self, wrapper, revoked_cert_ids=()):
        event_id = wrapper.get("event_id")
        canonical = jcs(wrapper)
        if event_id in self.canonical_bytes:
            if self.canonical_bytes[event_id] != canonical:
                raise Reject("same event ID arrived with different canonical "
                             "wrapper bytes")
            if self.status[event_id] == "accepted":
                return "idempotent"
        b = wrapper["body"]
        try:
            validate_event_contextual(wrapper, self.registry, self.known,
                                      revoked_cert_ids)
        except Incomplete:
            self.canonical_bytes[event_id] = canonical
            self.status[event_id] = "incomplete"
            self.known[event_id] = (
                b["event_sequence"], b["logical_time"]["physical_ms"],
                b["logical_time"]["counter"], False)
            return "incomplete"
        self.canonical_bytes[event_id] = canonical
        self.status[event_id] = "accepted"
        self.known[event_id] = (
            b["event_sequence"], b["logical_time"]["physical_ms"],
            b["logical_time"]["counter"], True)
        self.effects.append(event_id)
        return "accepted"


class DeliveryIngestOracle:
    """Deduplicate delivery retries without repeating intake effects."""

    def __init__(self, registry, authorization, recipient_privs,
                 known_events):
        self.registry = registry
        self.authorization = authorization
        self.recipient_privs = recipient_privs
        self.known_events = known_events
        self.canonical_bytes = {}
        self.effects = []

    def ingest(self, delivery):
        delivery_id = delivery.get("delivery_id")
        canonical = jcs(delivery)
        if delivery_id in self.canonical_bytes:
            if self.canonical_bytes[delivery_id] != canonical:
                raise Reject("same delivery ID arrived with different bytes")
            return "idempotent"
        validate_delivery(delivery, self.registry, self.authorization,
                          self.recipient_privs,
                          known_events=self.known_events)
        self.canonical_bytes[delivery_id] = canonical
        self.effects.append(delivery_id)
        return "accepted"


class ControlIngestOracle:
    """Accepted-head oracle: rollback never becomes current by arrival order."""

    def __init__(self):
        self.state = validate_genesis(load_artifact(_ME1_CHAIN[0]))

    def ingest(self, wrapper):
        if position_of(wrapper) <= self.state.head:
            raise Reject("control position is at or below the accepted head")
        validate_control(wrapper, self.state)
        return "accepted"


class LeaseIngestOracle:
    """Detect concurrent sessions claiming one lease predecessor slot."""

    def __init__(self, registry, state):
        self.registry = registry
        self.state = state
        self.slots = {}
        self.by_incarnation = {}

    def ingest(self, wrapper):
        validate_lease(wrapper, self.registry, self.state)
        b = wrapper["body"]
        incarnation = b["incarnation_id"]
        sequence = b["lease_sequence"]
        chain = self.by_incarnation.setdefault(incarnation, {})
        if chain and sequence < max(chain):
            raise Reject("stale lease replay is below durable high-water")
        if sequence > 0:
            predecessor = chain.get(sequence - 1)
            if predecessor is None:
                raise Incomplete("lease predecessor evidence unavailable")
            if predecessor != b["previous_lease_hash"]:
                raise Reject("lease predecessor hash mismatch")
        slot = (b["incarnation_id"], b["lease_sequence"],
                b["previous_lease_hash"])
        existing = self.slots.get(slot)
        if existing is not None and existing != wrapper["artifact_id"]:
            return "quarantined"
        self.slots[slot] = wrapper["artifact_id"]
        chain[sequence] = wrapper["artifact_hash"]
        return "accepted" if existing is None else "idempotent"


def author_hlc_next(last_physical_ms, last_counter, now_ms):
    """Author-side V0 HLC transition, including fail-closed overflow."""
    require_uint(last_physical_ms, "prior HLC physical time")
    require_uint(last_counter, "prior HLC counter")
    require_uint(now_ms, "current physical time")
    if now_ms > last_physical_ms:
        return now_ms, 0
    if last_counter == SAFE_INT_MAX:
        raise Reject("HLC counter exhausted before physical time advanced")
    return last_physical_ms, last_counter + 1


# ---------------------------------------------------------------------------
# Tamper engine (deterministic, unsigned mutations)
# ---------------------------------------------------------------------------

def _navigate(value, path):
    node = value
    for p in path[:-1]:
        node = node[p]
    return node, path[-1]


def apply_tamper_ops(value, ops):
    for op in ops:
        name = op["op"]
        if name == "json-set":
            node, last = _navigate(value, op["path"])
            node[last] = op["value"]
        elif name == "json-delete":
            node, last = _navigate(value, op["path"])
            del node[last]
        elif name == "flip-field-byte":
            node, last = _navigate(value, op["path"])
            raw = bytearray(ub64(node[last]))
            raw[-1] ^= 0x01
            node[last] = b64e(bytes(raw))
        elif name == "set-sig-value-by-role":
            src = next((s for s in value["signatures"]
                        if s["role"] == op["from_role"]), None)
            dst = next((s for s in value["signatures"]
                        if s["role"] == op["to_role"]), None)
            if src is None or dst is None:
                raise AssertionError("tamper descriptor references missing "
                                     "signature records")
            dst["value"] = src["value"]
        elif name == "set-sig-value-from-file":
            other = load_artifact(op["file"], CEILING_SEALED)
            if "signature" in other:
                src_value = other["signature"]["value"]
            else:
                src_value = next(s["value"] for s in other["signatures"]
                                 if s["role"] == op["from_role"])
            if "signature" in value:
                value["signature"]["value"] = src_value
            else:
                dst = next(s for s in value["signatures"]
                           if s["role"] == op["to_role"])
                dst["value"] = src_value
        elif name == "set-signature-s":
            sig = ub64(value["signature"]["value"], 64)
            s_int = int(op["s_le_hex"], 16)
            value["signature"]["value"] = b64e(
                sig[:32] + s_int.to_bytes(32, "little"))
        elif name == "duplicate-first-signature":
            value["signatures"].append(dict(value["signatures"][0]))
        elif name == "truncate-first-signature":
            raw = ub64(value["signatures"][0]["value"], 64)
            value["signatures"][0]["value"] = b64e(raw[:op["length"]])
        else:
            raise AssertionError("unknown tamper op: %s" % name)
    return value


def load_tampered(desc_rel):
    desc = load_artifact(desc_rel, CEILING_SEALED)
    base = load_artifact(desc["base"], CEILING_SEALED)
    mutated = apply_tamper_ops(base, desc["ops"])
    return jcs(mutated), desc


# ---------------------------------------------------------------------------
# Check routines (one per index 'check' name)
# ---------------------------------------------------------------------------

def _expect_reject(fn, *args, **kw):
    try:
        fn(*args, **kw)
    except Reject:
        return "reject"
    return "accept"


def check_parse(entry):
    data = load_bytes(entry["vectors"][0])
    try:
        strict_parse(data, entry["params"]["ceiling"])
        return "accept"
    except Reject:
        return "reject"


def check_keys(entry):
    for rec in load_keys().values():
        seed = ub64(rec["seed_b64"], 32)
        if rec["alg"] == "Ed25519":
            pub = Ed25519PrivateKey.from_private_bytes(seed).public_key()
        else:
            pub = X25519PrivateKey.from_private_bytes(seed).public_key()
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if b64e(raw) != rec["public_key_b64"]:
            raise AssertionError("seed-to-public mismatch for " + rec["name"])
        if derive_kid(rec["alg"], rec["public_key_b64"]) != rec["kid"]:
            raise AssertionError("kid mismatch for " + rec["name"])
    pubs = [ub64(r["public_key_b64"], 32) for r in load_keys().values()]
    if len(set(pubs)) != len(pubs):
        raise AssertionError("test keys are not purpose-separated")
    return "accept"


def check_fixtures(entry):
    embodiment = strict_parse(load_bytes("fixtures/embodiment-description.json"),
                              CEILING_EVENT)
    capability = strict_parse(load_bytes("fixtures/capability-description.json"),
                              CEILING_EVENT)
    eh = b64e(sha256(jcs(embodiment)))
    ch = b64e(sha256(jcs(capability)))
    cert = load_artifact("me1/certificate-inc1-gen1.json")
    lease = load_artifact("me1/lease-inc1-0.json")
    event = load_artifact("me1/event-inc1-1.json", CEILING_EVENT)
    if eh != cert["body"]["initial_embodiment_hash"] \
            or eh != lease["body"]["embodiment_hash"] \
            or eh != event["body"]["embodiment_hash"]:
        raise AssertionError("embodiment hash formula mismatch")
    if ch != lease["body"]["capability_hash"]:
        raise AssertionError("capability hash formula mismatch")
    genesis = load_artifact("me1/genesis.json")
    derived_me = "dm:me:v0:" + b64e(sha256(jcs(genesis["body"]["core"])))
    if derived_me != genesis["body"]["me_id"]:
        raise AssertionError("me_id does not derive solely from genesis core")
    changed_metadata = dict(embodiment)
    changed_metadata["host"] = "another-host-is-descriptive-only"
    if "host" in genesis["body"]["core"] or \
            b64e(sha256(jcs(changed_metadata))) == eh:
        raise AssertionError("metadata isolation fixture did not change")
    if "dm:me:v0:" + b64e(sha256(jcs(genesis["body"]["core"]))) != \
            derived_me:
        raise AssertionError("descriptive metadata changed me_id")
    return "accept"


def check_chain(entry):
    vectors = entry["vectors"]
    st = validate_genesis(load_artifact(vectors[0]))
    for rel in vectors[1:]:
        validate_control(load_artifact(rel), st)
    return "accept"


def check_certificates(entry):
    registry = combined_registry()
    certs = [v for v in entry["vectors"] if "/certificate-" in v]
    accs = [v for v in entry["vectors"] if "/acceptance-" in v]
    g0 = load_artifact("me1/certificate-inc1-gen0.json")
    g1 = load_artifact("me1/certificate-inc1-gen1.json")
    if g1["body"]["certificate_generation"] != 1 \
            or g1["body"]["previous_certificate_id"] != g0["certificate_id"] \
            or g1["body"]["incarnation_nonce"] != g0["body"]["incarnation_nonce"] \
            or g1["body"]["certificate_nonce"] == g0["body"]["certificate_nonce"] \
            or g1["body"]["signing_key"] != g0["body"]["signing_key"]:
        raise AssertionError("not an exact renewal")
    if g0["body"]["previous_certificate_id"] is not None:
        raise AssertionError("generation zero must name a null predecessor")
    if len(certs) != 6 or len(accs) != 6:
        raise AssertionError("unexpected vector set")
    return "accept"


def check_lease(entry):
    st = build_me1_chain()
    registry = combined_registry()
    return _expect_reject(validate_lease,
                          load_artifact(entry["vectors"][0]), registry, st)


def check_lease_revoked(entry):
    registry = combined_registry()
    wrapper = load_artifact(entry["vectors"][0])
    certificate_id = wrapper["body"]["certificate_id"]
    already_revoked = certificate_id in registry.revoked_cert_ids
    registry.revoked_cert_ids.add(certificate_id)
    try:
        return _expect_reject(validate_lease, wrapper, registry,
                              build_me1_chain())
    finally:
        if not already_revoked:
            registry.revoked_cert_ids.remove(certificate_id)


def check_lease_expiry(entry):
    return _expect_reject(
        validate_lease, load_artifact(entry["vectors"][0]),
        combined_registry(), build_me1_chain(), entry["params"]["at_ms"])


def check_lease_rollback(entry):
    oracle = LeaseIngestOracle(combined_registry(), build_me1_chain())
    first, successor, replay = (
        load_artifact(path) for path in entry["vectors"])
    if oracle.ingest(first) != "accepted" \
            or oracle.ingest(successor) != "accepted":
        raise AssertionError("lease high-water setup was not accepted")
    return _expect_reject(oracle.ingest, replay)


def check_events(entry):
    registry = combined_registry()
    params = entry["params"]
    if params.get("standalone"):
        wrappers = [load_artifact(v, CEILING_EVENT) for v in entry["vectors"]]
        known = known_events_map(params.get("known_events", []))
        for w in wrappers:
            validate_event_contextual(w, registry, known)
            b = w["body"]
            known[w["event_id"]] = (
                b["event_sequence"], b["logical_time"]["physical_ms"],
                b["logical_time"]["counter"], True)
        if len({w["event_id"] for w in wrappers}) != len(wrappers):
            raise AssertionError("distinct nonces must keep distinct IDs")
        payloads = [jcs(w["body"]["payload"]) for w in wrappers]
        if len(set(payloads)) != 1:
            raise AssertionError("vectors should carry identical payloads")
        return "accept"
    e0 = "me1/event-inc1-0.json"
    xm1e0 = "me2/event-xm1-0.json"
    known = known_events_map([e0, xm1e0])
    validate_event_contextual(load_artifact(e0, CEILING_EVENT), registry, {})
    validate_event_contextual(load_artifact(xm1e0, CEILING_EVENT), registry, {})
    validate_event_contextual(load_artifact("me1/event-inc1-1.json",
                                            CEILING_EVENT), registry, known)
    return "accept"


def check_event_contextual(entry):
    registry = combined_registry()
    known = known_events_map(entry["params"].get("known_events", []))
    revoked = revoked_cert_ids(entry["params"].get("revoked_certificates", []))
    wrapper = load_artifact(entry["vectors"][0], CEILING_EVENT)
    try:
        validate_event_contextual(wrapper, registry, known, revoked)
        return "accept"
    except Incomplete:
        return "incomplete"
    except Reject:
        return "reject"


def check_nfc_nfd(entry):
    registry = combined_registry()
    nfc, nfd = (load_artifact(v, CEILING_EVENT) for v in entry["vectors"])
    known = known_events_map(entry["params"].get("known_events", [
        "me1/event-inc2-0.json", "me1/event-inc2-1.json",
        "me2/event-xm1-0.json"]))
    for w in (nfc, nfd):
        validate_event_contextual(w, registry, known)
    if nfc["event_id"] == nfd["event_id"]:
        raise AssertionError("NFC and NFD strings must remain distinct")
    if nfc["body"]["payload"]["text"] == nfd["body"]["payload"]["text"]:
        raise AssertionError("payloads must differ as scalar sequences")
    cert = registry.certs[nfc["body"]["certificate_id"]]
    try:
        ed25519_verify(cert["signing_pub"], ub64(nfc["signature"]["value"], 64),
                       artifact_preimage(DOM["event"], nfd["body"]))
        raise AssertionError("NFC signature must not cover the NFD body")
    except Reject:
        pass
    return "accept"


def _checkpoint_context():
    registry = combined_registry()
    st = build_me1_chain()
    event_index = {}
    paths = ("me1/event-inc1-0.json", "me1/event-inc1-1.json",
             "me1/event-inc1-2-disclosure.json", "me2/event-xm1-0.json")
    trusted = known_events_map(paths, registry)
    for rel in paths:
        w = load_artifact(rel, CEILING_EVENT)
        if not trusted[w["event_id"]][3]:
            raise AssertionError("checkpoint fixture prefix is incomplete")
        event_index[w["event_id"]] = w
    return registry, st, event_index


def check_checkpoint(entry):
    registry, st, event_index = _checkpoint_context()
    wrapper = load_artifact(entry["vectors"][0])
    return _expect_reject(validate_checkpoint, wrapper, registry, st,
                          event_index)


def check_checkpoint_revoked_witness(entry):
    registry, st, event_index = _checkpoint_context()
    wrapper = load_artifact(entry["vectors"][0])
    certificate_id = wrapper["body"]["witness_certificate_id"]
    already_revoked = certificate_id in registry.revoked_cert_ids
    registry.revoked_cert_ids.add(certificate_id)
    try:
        return _expect_reject(validate_checkpoint, wrapper, registry, st,
                              event_index)
    finally:
        if not already_revoked:
            registry.revoked_cert_ids.remove(certificate_id)


def check_checkpoint_coverage(entry):
    _, _, event_index = _checkpoint_context()
    checkpoint = load_artifact(entry["vectors"][0])
    event = load_artifact(entry["vectors"][1], CEILING_EVENT)
    return ("covered" if checkpoint_covers(checkpoint, event, event_index)
            else "not-covered")


def _recipient_privs():
    privs = {
        load_keys()["inc2-enc"]["kid"]: key_priv("inc2-enc"),
        load_keys()["xm1-enc"]["kid"]: key_priv("xm1-enc"),
    }
    if "inc2-enc2" in load_keys():
        privs[load_keys()["inc2-enc2"]["kid"]] = key_priv("inc2-enc2")
    return privs


def _validate_authorization(rel):
    """Authorship validation of a disclosure authorization event (structure,
    certificate binding, and signature).  Sequence/causal context of the
    authorization event itself is out of scope for the delivery binding."""
    registry = combined_registry()
    wrapper = load_artifact(rel, CEILING_EVENT)
    validate_event_structure(wrapper)
    cert = registry.certs[wrapper["body"]["certificate_id"]]
    if wrapper["signature"]["kid"] != cert["signing_kid"]:
        raise Reject("authorization not signed by the certificate key")
    ed25519_verify(cert["signing_pub"], ub64(wrapper["signature"]["value"], 64),
                   artifact_preimage(DOM["event"], wrapper["body"]))
    return wrapper


def check_sealed(entry):
    registry = combined_registry()
    delivery = strict_parse(load_bytes(entry["vectors"][0]), CEILING_SEALED)
    authorization = _validate_authorization(entry["params"]["authorization"])
    return _expect_reject(
        validate_delivery, delivery, registry, authorization,
        _recipient_privs(), entry["params"].get("inner"))


def check_reseal(entry):
    registry = combined_registry()
    auth = _validate_authorization(entry["params"]["authorization"])
    d1 = strict_parse(load_bytes(entry["vectors"][0]), CEILING_SEALED)
    d2 = strict_parse(load_bytes(entry["vectors"][1]), CEILING_SEALED)
    i1 = validate_delivery(d1, registry, auth, _recipient_privs(),
                           entry["params"].get("inner"))
    i2 = validate_delivery(d2, registry, auth, _recipient_privs(),
                           entry["params"].get("inner"))
    if d1["delivery_id"] == d2["delivery_id"]:
        raise AssertionError("reseal must use a new delivery ID")
    if d1["expires_at_ms"] - d1["issued_at_ms"] != MAX_DELIVERY_TTL_MS:
        raise AssertionError("first delivery does not exercise exact 24h TTL")
    if d2["issued_at_ms"] <= d1["expires_at_ms"]:
        raise AssertionError("reseal was not issued strictly after expiry")
    if (i1["body"]["me_id"], i1["event_id"]) != \
            (i2["body"]["me_id"], i2["event_id"]):
        raise AssertionError("reseal must retain the event/message ID")
    return "accept"


def check_threshold(entry):
    partial = load_artifact("threshold/genesis-partial.json")
    if _expect_reject(validate_genesis, partial) != "reject":
        raise AssertionError("partial quorum must not validate")
    a = load_artifact("me1/genesis.json")
    b = load_artifact("threshold/genesis-quorum-b.json")
    m = load_artifact("threshold/genesis-merged.json")
    for w in (a, b, m):
        validate_genesis(w)
    if not (a["artifact_id"] == b["artifact_id"] == m["artifact_id"]):
        raise AssertionError("endorsement subsets must share one artifact ID")
    if not (jcs(a["body"]) == jcs(b["body"]) == jcs(m["body"])):
        raise AssertionError("endorsement subsets must share one body")
    def sigset(w):
        return {(s["role"], s["kid"], s["value"]) for s in w["signatures"]}
    if sigset(a) | sigset(b) != sigset(m):
        raise AssertionError("merged wrapper is not the endorsement union")
    return "accept"


def check_idempotent(entry):
    if entry["params"]["kind"] == "event":
        wrapper = load_artifact(entry["vectors"][0], CEILING_EVENT)
        oracle = EventIngestOracle(
            combined_registry(),
            ["me1/event-inc1-0.json", "me2/event-xm1-0.json"])
    elif entry["params"]["kind"] == "delivery":
        wrapper = load_artifact(entry["vectors"][0], CEILING_SEALED)
        oracle = DeliveryIngestOracle(
            combined_registry(),
            _validate_authorization("me1/event-inc1-2-disclosure.json"),
            _recipient_privs(), known_events_map([
                "me1/event-inc1-0.json", "me2/event-xm1-0.json"]))
    else:
        raise AssertionError("unknown idempotency kind")
    if oracle.ingest(wrapper) != "accepted":
        raise AssertionError("first ingest did not produce one effect")
    if oracle.ingest(wrapper) != "idempotent":
        raise AssertionError("byte-identical replay was not idempotent")
    if len(oracle.effects) != 1:
        raise AssertionError("replay repeated an external/projection effect")
    return "idempotent"


def _state_at_control_predecessor(wrapper):
    previous = wrapper["body"].get("previous_control_hash")
    if previous is None:
        raise Reject("pair-fork control vector has no single predecessor")
    st = validate_genesis(load_artifact(_ME1_CHAIN[0]))
    if st.head_hash() == previous:
        return st
    for rel in _ME1_CHAIN[1:]:
        validate_control(load_artifact(rel), st)
        if st.head_hash() == previous:
            return st
    raise Reject("control fork predecessor is unavailable")


def _fresh_certificate_context(wrapper):
    st = build_me1_chain()
    registry = CertRegistry()
    wanted = wrapper["body"].get("previous_certificate_id")
    if wanted is not None:
        by_id = {}
        for rel in _ME1_CERTS:
            candidate = load_artifact(rel)
            by_id[candidate["certificate_id"]] = candidate
        chain = []
        while wanted is not None:
            predecessor = by_id.get(wanted)
            if predecessor is None:
                raise Reject("certificate fork predecessor unavailable")
            chain.append(predecessor)
            wanted = predecessor["body"]["previous_certificate_id"]
        for predecessor in reversed(chain):
            validate_certificate(predecessor, st, registry)
    return st, registry


def _fork_evidence(params):
    genesis_rel = params.get("genesis", "me1/genesis.json")
    heads = []
    positions = set()
    states = {}
    for rel in params["known_heads"]:
        wrapper = load_artifact(rel)
        branch_state = validate_genesis(load_artifact(genesis_rel))
        validate_control(wrapper, branch_state)
        heads.append(wrapper["artifact_hash"])
        p = position_of(wrapper)
        positions.add((p[0], p[1], wrapper["artifact_hash"]))
        states[rel] = branch_state
    return validate_genesis(load_artifact(genesis_rel)), heads, positions, states


def check_pair_fork(entry):
    kind = entry["params"]["kind"]
    a_rel, b_rel = entry["vectors"]
    if kind == "genesis":
        a, b = load_artifact(a_rel), load_artifact(b_rel)
        validate_genesis(a)
        validate_genesis(b)
        same = a["body"]["me_id"] == b["body"]["me_id"]
        differ = a["artifact_id"] != b["artifact_id"]
    elif kind == "control":
        a, b = load_artifact(a_rel), load_artifact(b_rel)
        validate_control(a, _state_at_control_predecessor(a))
        validate_control(b, _state_at_control_predecessor(b))
        same = position_of(a) == position_of(b)
        differ = a["artifact_id"] != b["artifact_id"]
    elif kind == "certificate":
        a, b = load_artifact(a_rel), load_artifact(b_rel)
        st_a, registry_a = _fresh_certificate_context(a)
        st_b, registry_b = _fresh_certificate_context(b)
        validate_certificate(a, st_a, registry_a)
        validate_certificate(b, st_b, registry_b)
        same = (a["body"]["incarnation_id"], a["body"]["certificate_generation"]) \
            == (b["body"]["incarnation_id"], b["body"]["certificate_generation"])
        differ = a["certificate_id"] != b["certificate_id"]
    elif kind == "event":
        a = load_artifact(a_rel, CEILING_EVENT)
        b = load_artifact(b_rel, CEILING_EVENT)
        known = known_events_map(entry["params"].get("known_events", [
            "me1/event-inc1-0.json", "me2/event-xm1-0.json"]))
        validate_event_contextual(a, combined_registry(), known)
        validate_event_contextual(b, combined_registry(), known)
        same = (a["body"]["incarnation_id"], a["body"]["event_sequence"]) \
            == (b["body"]["incarnation_id"], b["body"]["event_sequence"])
        differ = a["event_id"] != b["event_id"]
    elif kind == "recovery":
        a, b = load_artifact(a_rel), load_artifact(b_rel)
        st_a, heads, positions, _ = _fork_evidence(entry["params"])
        st_b = validate_genesis(load_artifact(
            entry["params"].get("genesis", "me1/genesis.json")))
        validate_control(a, st_a, heads, positions)
        validate_control(b, st_b, heads, positions)
        same = position_of(a) == position_of(b)
        differ = a["artifact_id"] != b["artifact_id"]
    else:
        raise AssertionError("unknown fork kind")
    if same and differ:
        return "quarantined"
    raise AssertionError("fork fixtures do not collide as expected")


def check_control_wrapper(entry):
    artifact = entry["params"]["artifact"]
    wrapper = load_artifact(entry["vectors"][0])
    if artifact == "genesis":
        return _expect_reject(validate_genesis, wrapper)
    # Build the accepted state up to the artifact's predecessor.
    st = validate_genesis(load_artifact(_ME1_CHAIN[0]))
    upto = {"root-transition": 1, "recovery-policy": 2,
            "recovery-transition": 3, "revocation": 4}[artifact]
    for rel in _ME1_CHAIN[1:upto]:
        validate_control(load_artifact(rel), st)
    return _expect_reject(validate_control, wrapper, st)


def check_certificate(entry):
    st = build_me1_chain()
    registry = combined_registry()
    return _expect_reject(validate_certificate,
                          load_artifact(entry["vectors"][0]), st, registry)


def check_acceptance(entry):
    registry = combined_registry()
    return _expect_reject(validate_acceptance,
                          load_artifact(entry["vectors"][0]), registry)


def check_old_generation_replay(entry):
    oracle = ActivationOracle()
    old_cert = load_artifact(entry["vectors"][0])
    old_acceptance = load_artifact(entry["vectors"][1])
    oracle.activate(old_cert, old_acceptance)
    oracle.activate(load_artifact("me1/certificate-inc1-gen1.json"),
                    load_artifact("me1/acceptance-inc1-gen1.json"))
    return _expect_reject(oracle.activate, old_cert, old_acceptance)


def check_activation_acceptance(entry):
    cert0, acceptance0, event0, cert1, acceptance1 = (
        load_artifact(entry["vectors"][0]),
        load_artifact(entry["vectors"][1]),
        load_artifact(entry["vectors"][2], CEILING_EVENT),
        load_artifact(entry["vectors"][3]),
        load_artifact(entry["vectors"][4]))
    state = build_me1_chain()
    registry = CertRegistry()
    validate_certificate(cert0, state, registry)
    if _expect_reject(validate_event_contextual, event0, registry, {}) \
            != "reject":
        raise AssertionError("certificate activated without acceptance")
    validate_acceptance(acceptance0, registry)
    validate_event_contextual(event0, registry, {})
    validate_certificate(cert1, state, registry)
    # Merely learning a renewal does not deactivate the accepted generation.
    validate_event_contextual(event0, registry, {})
    validate_acceptance(acceptance1, registry)
    if _expect_reject(validate_event_contextual, event0, registry, {}) \
            != "reject":
        raise AssertionError("accepted renewal did not supersede generation 0")
    return "accept"


def check_recovery_cutoff(entry):
    common, heads, positions, states = _fork_evidence(entry["params"])
    recovery = load_artifact(entry["vectors"][-1])
    try:
        validate_control(recovery, common, heads, positions)
    except Incomplete:
        return "incomplete"
    except Reject:
        return "reject"
    if "cutoff_branch" not in entry["params"]:
        return "accept"

    branch_rel = entry["params"]["cutoff_branch"]
    branch = load_artifact(branch_rel)
    certificate = load_artifact(entry["vectors"][-3])
    acceptance = load_artifact(entry["vectors"][-2])
    registry = CertRegistry()
    validate_certificate(certificate, states[branch_rel], registry)
    validate_acceptance(acceptance, registry)
    cutoff = recovery["body"]["compromise"]["control_cutoff"]
    if cutoff != {
            "recovery_generation": branch["body"]["recovery_generation"],
            "control_sequence": branch["body"]["control_sequence"],
            "control_hash": branch["artifact_hash"]}:
        raise AssertionError("recovery cutoff does not name branch B exactly")
    anchored = certificate["body"]["issuing_control_position"]
    if anchored != cutoff:
        raise AssertionError("branch certificate is not anchored at cutoff")
    expected_target = {
        "kind": "certificates-from-control-cutoff",
        "id": branch["artifact_id"], "kid": None}
    if not any(r["target"] == expected_target
               for r in recovery["body"]["revocations"]):
        raise AssertionError("recovery omits cutoff revocation consequence")
    return "accept"


def check_cutoff_revoked_certificate(entry):
    if check_recovery_cutoff(entry) != "accept":
        raise AssertionError("cutoff recovery did not validate")
    # check_recovery_cutoff proved that the signed branch certificate is
    # anchored exactly at the signed cutoff and that the recovery embeds the
    # certificates-from-control-cutoff revocation targeting that branch.
    return "reject"


def check_static_bound(entry):
    """Execute signed boundary artifacts, not synthetic length counters."""
    kind = entry["params"]["kind"]
    target = entry["params"].get("target", 0)
    wrapper = load_artifact(entry["vectors"][target])
    if kind == "threshold-keys":
        return _expect_reject(validate_genesis, wrapper)
    if kind == "signatures":
        if wrapper.get("body", {}).get("schema") == "daimon-genesis/v0":
            return _expect_reject(validate_genesis, wrapper)
        genesis_rel = (entry["vectors"][0] if target > 0 else
                       "boundary/signatures-reachable-genesis.json")
        state = validate_genesis(load_artifact(genesis_rel))
        return _expect_reject(validate_control, wrapper, state)
    if kind in ("revocations", "high-waters"):
        return _expect_reject(
            validate_control, wrapper,
            _state_at_control_predecessor(wrapper))
    if kind == "routes":
        return _expect_reject(validate_lease, wrapper,
                              combined_registry(), build_me1_chain())
    if kind in ("event-type-prefixes", "event-prefixes"):
        st, registry = _fresh_certificate_context(wrapper)
        return _expect_reject(validate_certificate, wrapper, st, registry)
    raise AssertionError("unknown static-bound kind")


def check_hlc_author(entry):
    registry = combined_registry()
    known = known_events_map(entry["params"].get("known_events", []))
    maximum = load_artifact(entry["vectors"][0], CEILING_EVENT)
    reset = load_artifact(entry["vectors"][1], CEILING_EVENT)
    validate_event_contextual(maximum, registry, known)
    mb = maximum["body"]
    known[maximum["event_id"]] = (
        mb["event_sequence"], mb["logical_time"]["physical_ms"],
        mb["logical_time"]["counter"], True)
    validate_event_contextual(reset, registry, known)
    last = mb["logical_time"]
    nxt = reset["body"]["logical_time"]
    if last["counter"] != SAFE_INT_MAX:
        raise AssertionError("first fixture is not at the HLC boundary")
    with _raises_reject_context():
        author_hlc_next(last["physical_ms"], last["counter"],
                        last["physical_ms"])
    if author_hlc_next(last["physical_ms"], last["counter"],
                       nxt["physical_ms"]) != \
            (nxt["physical_ms"], nxt["counter"]):
        raise AssertionError("reset fixture is not the author-side transition")
    return "accept"


class _raises_reject_context:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            raise AssertionError("expected the operation to fail closed")
        if not issubclass(exc_type, Reject):
            return False
        return True


def check_lease_fork(entry):
    oracle = LeaseIngestOracle(combined_registry(), build_me1_chain())
    predecessor = load_artifact(entry["params"]["predecessor"])
    first = load_artifact(entry["vectors"][0])
    second = load_artifact(entry["vectors"][1])
    if oracle.ingest(predecessor) != "accepted":
        raise AssertionError("lease predecessor was not accepted")
    if oracle.ingest(first) != "accepted":
        raise AssertionError("first lease was not accepted")
    return oracle.ingest(second)


def check_control_rollback(entry):
    oracle = ControlIngestOracle()
    wrappers = [load_artifact(path) for path in entry["vectors"]]
    accepted = wrappers[:-1]
    if accepted and accepted[0]["body"].get("schema") == "daimon-genesis/v0":
        if accepted[0]["artifact_hash"] != oracle.state.head_hash():
            raise AssertionError("rollback scenario begins from another genesis")
        accepted = accepted[1:]
    for wrapper in accepted:
        oracle.ingest(wrapper)
    return _expect_reject(oracle.ingest, wrappers[-1])


def check_fork_descendant(entry):
    genesis, head_a, head_b, descendant = (
        load_artifact(path) for path in entry["vectors"])
    state_a = validate_genesis(genesis)
    state_b = validate_genesis(genesis)
    validate_control(head_a, state_a)
    validate_control(head_b, state_b)
    if position_of(head_a) != position_of(head_b) \
            or head_a["artifact_id"] == head_b["artifact_id"]:
        raise AssertionError("scenario does not establish a control fork")
    validate_control(descendant, state_b)
    if descendant["body"]["previous_control_hash"] != \
            head_b["artifact_hash"]:
        raise AssertionError("scenario is not a branch-B descendant")
    return "quarantined"


def check_revocation_monotonic(entry):
    state = validate_genesis(load_artifact(entry["vectors"][0]))
    for rel in entry["vectors"][1:-1]:
        validate_control(load_artifact(rel), state)
    before = list(state.revoked_targets)
    if not before:
        raise AssertionError("scenario contains no accepted revocation")
    validate_control(load_artifact(entry["vectors"][-1]), state)
    if state.revoked_targets != before:
        raise AssertionError("later control artifact changed revocation history")
    return "accept"


def check_delivery_rotation(entry):
    old_delivery = load_artifact(entry["vectors"][0], CEILING_SEALED)
    new_delivery = load_artifact(entry["vectors"][1], CEILING_SEALED)
    old_auth = _validate_authorization(entry["params"]["old_authorization"])
    new_auth = _validate_authorization(entry["params"]["new_authorization"])
    known = known_events_map([
        "me1/event-inc1-0.json", "me2/event-xm1-0.json"])
    validate_delivery(old_delivery, combined_registry(), old_auth,
                      _recipient_privs(), entry["params"].get("old_inner"),
                      known)
    validate_delivery(new_delivery, combined_registry(), new_auth,
                      _recipient_privs(), entry["params"].get("new_inner"),
                      known)
    if _expect_reject(
            validate_delivery, new_delivery, combined_registry(), old_auth,
            _recipient_privs(), entry["params"].get("new_inner"), known) \
            != "reject":
        raise AssertionError("old authorization survived recipient rotation")
    old_keys = {r["encryption_kid"] for r in old_delivery["recipients"]}
    new_keys = {r["encryption_kid"] for r in new_delivery["recipients"]}
    if old_keys == new_keys:
        raise AssertionError("rotation vector did not change a recipient key")
    if old_delivery["event_id"] != new_delivery["event_id"]:
        raise AssertionError("recipient rotation changed message identity")
    return "accept"


def check_delivery_expiry(entry):
    delivery = load_artifact(entry["vectors"][0], CEILING_SEALED)
    authorization = _validate_authorization(entry["params"]["authorization"])
    known = known_events_map([
        "me1/event-inc1-0.json", "me2/event-xm1-0.json"])
    keys = load_keys()
    expired_name = entry["params"]["expired_key_name"]
    active_name = entry["params"]["active_key_name"]
    expired_privs = {keys[expired_name]["kid"]: key_priv(expired_name)}
    active_privs = {keys[active_name]["kid"]: key_priv(active_name)}
    at_ms = entry["params"]["at_ms"]
    if _expect_reject(
            validate_delivery, delivery, combined_registry(), authorization,
            expired_privs, entry["params"].get("inner"), known, None,
            at_ms) != "reject":
        raise AssertionError("expired recipient still accepted delivery")
    validate_delivery(delivery, combined_registry(), authorization,
                      active_privs, entry["params"].get("inner"), known,
                      None, at_ms)
    return "accept"


def check_key_descriptor(entry):
    desc_doc = load_artifact(entry["vectors"][0], CEILING_EVENT)
    d = desc_doc["descriptor"]
    if "keys" in d:
        return _expect_reject(validate_threshold_set, d)
    return _expect_reject(validate_descriptor, d)


def check_hpke_all_zero_dh(entry):
    priv = key_priv("inc2-enc")
    outcomes = []
    for bad_peer in (b"\x00" * 32, b"\x01" + b"\x00" * 31):
        try:
            x25519_dh(priv, bad_peer)
            outcomes.append("accept")
        except Reject:
            outcomes.append("reject")
    try:
        dhkem_decap(b"\x00" * 32, priv)
        outcomes.append("accept")
    except Reject:
        outcomes.append("reject")
    return "reject" if outcomes == ["reject"] * 3 else "accept"


def check_delivery_conflict(tampered_bytes, desc):
    tampered = strict_parse(tampered_bytes, CEILING_SEALED)
    other = strict_parse(load_bytes(desc["params"]["other"]), CEILING_SEALED)
    if tampered["delivery_id"] == other["delivery_id"] \
            and jcs(tampered) != jcs(other):
        raise Reject("same delivery ID with different bytes: conflict")


def check_tamper(entry):
    tampered_bytes, desc = load_tampered(entry["vectors"][0])
    sub = desc["check"]
    params = desc.get("params", {})
    if sub == "event-wrapper":
        w = strict_parse(tampered_bytes, CEILING_EVENT)
        return _expect_reject(validate_event_structure, w)
    if sub == "control-wrapper":
        w = strict_parse(tampered_bytes, CEILING_CONTROL)
        artifact = params.get("artifact", "genesis")
        if artifact == "genesis":
            return _expect_reject(validate_genesis, w)
        st = validate_genesis(load_artifact(_ME1_CHAIN[0]))
        upto = {"root-transition": 1, "recovery-policy": 2,
                "recovery-transition": 3, "revocation": 4}[artifact]
        for rel in _ME1_CHAIN[1:upto]:
            validate_control(load_artifact(rel), st)
        return _expect_reject(validate_control, w, st)
    if sub == "lease-wrapper":
        w = strict_parse(tampered_bytes, CEILING_CONTROL)
        return _expect_reject(validate_lease, w, combined_registry(),
                              build_me1_chain())
    if sub == "certificate-wrapper":
        w = strict_parse(tampered_bytes, CEILING_CONTROL)
        return _expect_reject(validate_certificate, w, build_me1_chain(),
                              combined_registry())
    if sub == "checkpoint-wrapper":
        w = strict_parse(tampered_bytes, CEILING_CONTROL)
        registry, st, event_index = _checkpoint_context()
        return _expect_reject(validate_checkpoint, w, registry, st,
                              event_index)
    if sub == "sealed":
        w = strict_parse(tampered_bytes, CEILING_SEALED)
        auth = _validate_authorization("me1/event-inc1-2-disclosure.json")
        return _expect_reject(validate_delivery, w, combined_registry(),
                              auth, _recipient_privs())
    if sub == "delivery-conflict":
        return _expect_reject(check_delivery_conflict, tampered_bytes, desc)
    raise AssertionError("unknown tamper subcheck: %s" % sub)


CHECKS = {
    "parse": check_parse,
    "keys": check_keys,
    "fixtures": check_fixtures,
    "chain": check_chain,
    "certificates": check_certificates,
    "lease": check_lease,
    "lease-revoked": check_lease_revoked,
    "lease-expiry": check_lease_expiry,
    "lease-rollback": check_lease_rollback,
    "events": check_events,
    "event-contextual": check_event_contextual,
    "nfc-nfd": check_nfc_nfd,
    "checkpoint": check_checkpoint,
    "checkpoint-revoked-witness": check_checkpoint_revoked_witness,
    "checkpoint-coverage": check_checkpoint_coverage,
    "sealed": check_sealed,
    "reseal": check_reseal,
    "threshold": check_threshold,
    "idempotent": check_idempotent,
    "pair-fork": check_pair_fork,
    "control-wrapper": check_control_wrapper,
    "certificate": check_certificate,
    "acceptance": check_acceptance,
    "old-generation-replay": check_old_generation_replay,
    "activation-acceptance": check_activation_acceptance,
    "recovery-cutoff": check_recovery_cutoff,
    "cutoff-revoked-certificate": check_cutoff_revoked_certificate,
    "static-bound": check_static_bound,
    "hlc-author": check_hlc_author,
    "lease-fork": check_lease_fork,
    "control-rollback": check_control_rollback,
    "fork-descendant": check_fork_descendant,
    "revocation-monotonic": check_revocation_monotonic,
    "delivery-rotation": check_delivery_rotation,
    "delivery-expiry": check_delivery_expiry,
    "key-descriptor": check_key_descriptor,
    "hpke-all-zero-dh": check_hpke_all_zero_dh,
    "tamper": check_tamper,
}

# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestPrimitives(unittest.TestCase):
    def test_rfc9180_kat(self):
        """Official RFC 9180 KAT: DHKEM(X25519,HKDF-SHA256), HKDF-SHA256,
        ChaCha20-Poly1305, base mode. Source: cfrg/draft-irtf-cfrg-hpke
        test-vectors.json at commit
        b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb."""
        kat = RFC9180_KAT
        sk_r = X25519PrivateKey.from_private_bytes(bytes.fromhex(kat["skRm"]))
        sk_e = X25519PrivateKey.from_private_bytes(bytes.fromhex(kat["skEm"]))
        pk_r = sk_r.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pk_e = sk_e.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.assertEqual(pk_r.hex(), kat["pkRm"])
        self.assertEqual(pk_e.hex(), kat["pkEm"])
        # Encap side (fixed ephemeral) must reproduce shared_secret and enc.
        dh = sk_e.exchange(X25519PublicKey.from_public_bytes(pk_r))
        kem_context = pk_e + pk_r
        prk = _lextract(KEM_SUITE, b"", b"eae_prk", dh)
        shared = _lexpand(KEM_SUITE, prk, b"shared_secret", kem_context, 32)
        self.assertEqual(shared.hex(), kat["shared_secret"])
        self.assertEqual(pk_e.hex(), kat["enc"])
        # Decap side through the test-only helper must agree.
        self.assertEqual(dhkem_decap(pk_e, sk_r).hex(), kat["shared_secret"])
        secret, key, base_nonce = hpke_schedule(
            shared, bytes.fromhex(kat["info"]))
        self.assertEqual(secret.hex(), kat["secret"])
        self.assertEqual(key.hex(), kat["key"])
        self.assertEqual(base_nonce.hex(), kat["base_nonce"])
        for i, enc in enumerate(kat["encryptions"]):
            nonce = bytes(a ^ b for a, b in zip(
                base_nonce, i.to_bytes(12, "big")))
            self.assertEqual(nonce.hex(), enc["nonce"])
            ct = ChaCha20Poly1305(key).encrypt(
                nonce, bytes.fromhex(enc["pt"]), bytes.fromhex(enc["aad"]))
            self.assertEqual(ct.hex(), enc["ct"])

    def test_hpke_open_rejects_tampering(self):
        # Real values from the checked-in delivery, exercised directly at
        # the crypto layer (the wire layer rejects the same tampering even
        # earlier, at the outer signature).
        registry = combined_registry()
        auth = _validate_authorization("me1/event-inc1-2-disclosure.json")
        delivery = strict_parse(load_bytes("me1/sealed-delivery-1.json"),
                                CEILING_SEALED)
        inner = validate_delivery(delivery, registry, auth,
                                  _recipient_privs(),
                                  "me1/event-inc1-1.json")
        self.assertEqual(inner["event_id"], delivery["event_id"])
        privs = _recipient_privs()
        entry = next(r for r in delivery["recipients"]
                     if r["encryption_kid"] in privs)
        priv = privs[entry["encryption_kid"]]
        protected = protected_metadata(delivery)
        info = hpke_info_for(protected, entry)
        enc = ub64(entry["enc"], 32)
        wrapped = bytearray(ub64(entry["wrapped_cek"], 48))
        cek = hpke_open(enc, bytes(wrapped), priv, info)
        wrapped[-1] ^= 1
        with self.assertRaises(Reject):
            hpke_open(enc, bytes(wrapped), priv, info)
        bad_enc = bytearray(enc)
        bad_enc[-1] ^= 1
        with self.assertRaises(Reject):
            hpke_open(bytes(bad_enc), ub64(entry["wrapped_cek"], 48),
                      priv, info)
        bad_info = info + b"x"
        with self.assertRaises(Reject):
            hpke_open(enc, ub64(entry["wrapped_cek"], 48), priv, bad_info)

    def test_domain_separation(self):
        st = build_me1_chain()
        registry = combined_registry()
        event = load_artifact("me1/event-inc1-1.json", CEILING_EVENT)
        cert = registry.certs[event["body"]["certificate_id"]]
        sig = ub64(event["signature"]["value"], 64)
        # Valid under its own domain.
        ed25519_verify(cert["signing_pub"], sig,
                       artifact_preimage(DOM["event"], event["body"]))
        # Invalid under every other domain with the same body bytes.
        for name, domain in DOM.items():
            if name in ("event",):
                continue
            with self.assertRaises(Reject, msg=name):
                ed25519_verify(cert["signing_pub"], sig,
                               artifact_preimage(domain, event["body"]))

    def test_ed25519_edge_encodings(self):
        cert_pub = ub64(load_keys()["root-a"]["public_key_b64"], 32)
        for bad in ED_SMALL_ORDER:
            with self.assertRaises(Reject):
                ed25519_check_public(bad)
        sig = bytearray(
            ub64(load_artifact("me1/event-inc1-1.json",
                               CEILING_EVENT)["signature"]["value"], 64))
        sig[32:] = ED_L.to_bytes(32, "little")
        with self.assertRaises(Reject):
            ed25519_verify(cert_pub, bytes(sig), b"preimage")


class TestOracleSensitivity(unittest.TestCase):
    """Prove that executable outcomes depend on the intended validator."""

    def test_delivery_invokes_full_inner_event_validation(self):
        delivery = load_artifact("me1/sealed-delivery-1.json", CEILING_SEALED)
        authorization = _validate_authorization(
            "me1/event-inc1-2-disclosure.json")
        module = sys.modules[__name__]
        sentinel = mock.Mock(side_effect=Reject("sentinel inner validator"))
        with mock.patch.object(module, "validate_event_contextual", sentinel):
            with self.assertRaisesRegex(Reject, "sentinel inner validator"):
                validate_delivery(
                    delivery, combined_registry(), authorization,
                    _recipient_privs(), known_events=known_events_map([
                        "me1/event-inc1-0.json",
                        "me2/event-xm1-0.json"]))
        self.assertEqual(sentinel.call_count, 1)

    def test_zero_signature_inner_is_otherwise_outer_valid(self):
        delivery = load_artifact(
            "negative/sealed-inner-zero-signature.json", CEILING_SEALED)
        authorization = _validate_authorization(
            "me1/event-inc1-2-disclosure.json")
        known = known_events_map([
            "me1/event-inc1-0.json", "me2/event-xm1-0.json"])
        with self.assertRaises(Reject):
            validate_delivery(delivery, combined_registry(), authorization,
                              _recipient_privs(), known_events=known)
        module = sys.modules[__name__]
        with mock.patch.object(module, "validate_event_contextual",
                               return_value=True) as bypass:
            inner = validate_delivery(
                delivery, combined_registry(), authorization,
                _recipient_privs(), known_events=known)
        self.assertEqual(inner["event_id"], delivery["event_id"])
        bypass.assert_called_once()

    def test_activation_oracle_invokes_certificate_and_acceptance(self):
        certificate = load_artifact("me1/certificate-inc1-gen0.json")
        acceptance = load_artifact("me1/acceptance-inc1-gen0.json")
        module = sys.modules[__name__]
        with mock.patch.object(
                module, "validate_certificate",
                side_effect=Reject("sentinel certificate")):
            with self.assertRaisesRegex(Reject, "sentinel certificate"):
                ActivationOracle().activate(certificate, acceptance)
        with mock.patch.object(
                module, "validate_acceptance",
                side_effect=Reject("sentinel acceptance")):
            with self.assertRaisesRegex(Reject, "sentinel acceptance"):
                ActivationOracle().activate(certificate, acceptance)

    def test_event_dedup_conflict_precedes_revalidation(self):
        wrapper = load_artifact("me1/event-inc1-1.json", CEILING_EVENT)
        oracle = EventIngestOracle(
            combined_registry(),
            ["me1/event-inc1-0.json", "me2/event-xm1-0.json"])
        self.assertEqual(oracle.ingest(wrapper), "accepted")
        conflict = json.loads(jcs(wrapper).decode("utf-8"))
        conflict["signature"]["value"] = b64e(b"\x00" * 64)
        module = sys.modules[__name__]
        with mock.patch.object(module, "validate_event_contextual") as check:
            with self.assertRaisesRegex(Reject, "different canonical"):
                oracle.ingest(conflict)
        check.assert_not_called()
        self.assertEqual(len(oracle.effects), 1)

    def test_rejected_event_retry_is_never_idempotent(self):
        wrapper = load_artifact(
            "negative/event-fork-zero-signature.json", CEILING_EVENT)
        oracle = EventIngestOracle(
            combined_registry(), ["me1/event-inc1-0.json"])
        for _ in range(2):
            with self.assertRaises(Reject):
                oracle.ingest(wrapper)
        self.assertNotIn(wrapper["event_id"], oracle.canonical_bytes)
        self.assertEqual(oracle.effects, [])

    def test_incomplete_event_revalidates_when_context_completes(self):
        predecessor = load_artifact(
            "me1/event-inc1-4-out-of-order.json", CEILING_EVENT)
        descendant = load_artifact(
            "negative/event-inc1-5-incomplete-descendant.json",
            CEILING_EVENT)
        oracle = EventIngestOracle(
            combined_registry(), ["me1/event-inc1-4-out-of-order.json"])
        self.assertEqual(oracle.ingest(descendant), "incomplete")
        self.assertEqual(oracle.effects, [])
        pb = predecessor["body"]
        oracle.known[predecessor["event_id"]] = (
            pb["event_sequence"], pb["logical_time"]["physical_ms"],
            pb["logical_time"]["counter"], True)
        self.assertEqual(oracle.ingest(descendant), "accepted")
        self.assertEqual(oracle.effects, [descendant["event_id"]])

    def test_invalid_parent_never_becomes_trusted_context(self):
        parent = load_artifact("me1/event-inc2-0.json", CEILING_EVENT)
        original = load_bytes
        poisoned = json.loads(jcs(parent).decode("utf-8"))
        poisoned["signature"]["value"] = b64e(b"\x00" * 64)

        def fake_load(rel):
            if rel == "me1/event-inc2-0.json":
                return jcs(poisoned)
            return original(rel)

        module = sys.modules[__name__]
        with mock.patch.object(module, "load_bytes", fake_load):
            with self.assertRaises(Reject):
                known_events_map(["me1/event-inc2-0.json"])

    def test_fork_classification_depends_on_crypto_validation(self):
        entry = next(e for e in load_index()["entries"]
                     if e["id"] == "neg-event-fork")
        module = sys.modules[__name__]
        sentinel = mock.Mock(side_effect=Reject("sentinel fork validator"))
        with mock.patch.object(module, "validate_event_contextual", sentinel):
            with self.assertRaisesRegex(Reject, "sentinel fork validator"):
                check_pair_fork(entry)
        self.assertGreaterEqual(sentinel.call_count, 1)

    def test_revoked_delivery_fixtures_are_otherwise_valid(self):
        registry = combined_registry()
        saved = set(registry.revoked_cert_ids)
        registry.revoked_cert_ids.clear()
        try:
            cases = [
                ("negative/sealed-revoked-sender.json",
                 "negative/disclosure-revoked-sender.json"),
                ("negative/sealed-revoked-recipient.json",
                 "me1/event-inc2-6-disclosure-revoked-recipient.json"),
            ]
            known = known_events_map([
                "me1/event-inc1-0.json", "me2/event-xm1-0.json"])
            for delivery_rel, authorization_rel in cases:
                with self.subTest(delivery=delivery_rel):
                    delivery = load_artifact(delivery_rel, CEILING_SEALED)
                    authorization = _validate_authorization(authorization_rel)
                    validate_delivery(delivery, registry, authorization,
                                      _recipient_privs(), known_events=known)
        finally:
            registry.revoked_cert_ids.update(saved)

    def test_checkpoint_rejects_invalid_high_water_event(self):
        registry, state, event_index = _checkpoint_context()
        checkpoint = load_artifact("me1/checkpoint-inc2-witness.json")
        high_water_id = checkpoint["body"]["high_water_event_id"]
        poisoned = json.loads(
            jcs(event_index[high_water_id]).decode("utf-8"))
        poisoned["signature"]["value"] = b64e(b"\x00" * 64)
        event_index[high_water_id] = poisoned
        with self.assertRaises(Reject):
            validate_checkpoint(checkpoint, registry, state, event_index)

    def test_checkpoint_rejects_revoked_witness_certificate(self):
        registry, state, event_index = _checkpoint_context()
        checkpoint = load_artifact("me1/checkpoint-inc2-witness.json")
        certificate_id = checkpoint["body"]["witness_certificate_id"]
        already_revoked = certificate_id in registry.revoked_cert_ids
        registry.revoked_cert_ids.add(certificate_id)
        try:
            with self.assertRaises(Reject):
                validate_checkpoint(checkpoint, registry, state, event_index)
        finally:
            if not already_revoked:
                registry.revoked_cert_ids.remove(certificate_id)


class TestVectorIndex(unittest.TestCase):
    """Execute every executable index entry and check its expectation."""

    def test_entries(self):
        index = load_index()
        executed = 0
        for entry in index["entries"]:
            if entry["execution"] != "executable":
                continue
            with self.subTest(id=entry["id"]):
                outcome = CHECKS[entry["check"]](entry)
                self.assertEqual(outcome, entry["expect"],
                                 "vector %s: expected %s, got %s"
                                 % (entry["id"], entry["expect"], outcome))
                executed += 1
        self.assertGreater(executed, 100)

    def test_documented_entries_have_rationale(self):
        index = load_index()
        documented = [e for e in index["entries"]
                      if e["execution"] == "documented"]
        self.assertTrue(documented)
        for e in documented:
            self.assertTrue(e.get("rationale"),
                            "documented entry %s lacks a rationale" % e["id"])

    def test_vector_files_exist(self):
        index = load_index()
        for entry in index["entries"]:
            for rel in entry["vectors"]:
                self.assertTrue(
                    os.path.isfile(os.path.join(VECTORS, rel)),
                    "missing vector file %s" % rel)

    def test_section_9_inventory_coverage(self):
        """Every Section 9 / DM-010 Section 13 inventory item is mapped to
        at least one machine-readable entry."""
        index = load_index()
        covered = set()
        for entry in index["entries"]:
            covered.update(entry["covers"])
        missing = REQUIRED_COVERAGE - covered
        extra = covered - REQUIRED_COVERAGE
        self.assertEqual(missing, set(), "uncovered inventory items")
        self.assertEqual(extra, set(), "unknown coverage tags")


class TestDeterminism(unittest.TestCase):
    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as t1, \
                tempfile.TemporaryDirectory() as t2:
            for out in (t1, t2):
                subprocess.run([sys.executable, GENERATOR, "--out", out],
                               check=True, cwd=REPO_ROOT,
                               stdout=subprocess.DEVNULL)
            for other in (t1, t2):
                _assert_trees_equal(VECTORS, other)


def _assert_trees_equal(a, b):
    def snapshot(root):
        out = {}
        for dirpath, _, names in os.walk(root):
            for n in names:
                full = os.path.join(dirpath, n)
                with open(full, "rb") as f:
                    out[os.path.relpath(full, root)] = f.read()
        return out
    sa, sb = snapshot(a), snapshot(b)
    if sa.keys() != sb.keys():
        raise AssertionError("tree mismatch: only in checked-in: %s; "
                             "only in regenerated: %s"
                             % (sorted(sa.keys() - sb.keys()),
                                sorted(sb.keys() - sa.keys())))
    for rel in sa:
        if sa[rel] != sb[rel]:
            raise AssertionError("byte mismatch in %s" % rel)


REQUIRED_COVERAGE = {
    # positive inventory
    "p-jcs-canonical", "p-base64url", "p-ed25519-seed-to-public",
    "p-genesis-core-me-id", "p-incarnation-id", "p-certificate-id",
    "p-wrapper-domain-genesis", "p-wrapper-domain-root-transition",
    "p-wrapper-domain-recovery-policy", "p-wrapper-domain-recovery-transition",
    "p-wrapper-domain-revocation", "p-wrapper-domain-certificate",
    "p-wrapper-domain-acceptance", "p-wrapper-domain-lease",
    "p-wrapper-domain-event", "p-wrapper-domain-checkpoint",
    "p-wrapper-domain-sealed",
    "p-linkage-chain", "p-event-zero", "p-event-successor", "p-event-hlc",
    "p-cross-me-parent", "p-out-of-order-incomplete", "p-exact-renewal",
    "p-checkpoint-binding", "p-checkpoint-coverage", "p-sealed-decryption",
    "p-multi-recipient", "p-disclosure-authorization", "p-reseal-same-event",
    "p-threshold-partial-completion", "p-threshold-merge",
    "p-distinct-nonces-two-events", "p-nfc-nfd-distinct",
    "p-metadata-me-unchanged",
    # negative inventory: parser/canonicalization
    "n-dup-key-escaped", "n-unknown-property", "n-invalid-utf8", "n-float",
    "n-negative-zero", "n-unsafe-int", "n-depth", "n-size-ceiling",
    "n-noncanonical-wire", "n-noncanonical-base64",
    # derived values and threshold signatures
    "n-id-hash-mismatch", "n-modified-body", "n-kid-mismatch", "n-key-alias",
    "n-threshold-duplicate-sig", "n-threshold-short-sig",
    "p-threshold-partial-completion", "p-threshold-merge",
    # crypto edge cases
    "n-ed25519-noncanonical-s", "n-ed25519-small-order",
    "n-x25519-all-zero-dh", "n-cross-domain-signature",
    "n-authorization-as-possession", "n-cross-role-key-reuse",
    "n-signing-key-two-incarnations",
    # certificates and control chain
    "n-cert-generation-gap", "n-cert-predecessor-mismatch", "n-cert-fork",
    "n-old-generation-replay", "n-cert-preserved-and-revoked",
    "n-genesis-fork", "n-control-fork", "n-control-sequence-skip",
    "n-root-rotation-new-only", "n-root-rotation-old-only",
    "n-carry-forward-without-ids", "n-policy-without-recovery-threshold",
    "n-recovery-incarnation-signed", "n-standalone-root-key-revocation",
    "n-old-root-issues-cert", "n-cert-unknown-anchor", "n-acceptance-mismatch",
    "n-lease-ttl", "n-recovery-key-signs-event", "n-revoked-cert-event",
    "n-lease-old-certificate-generation", "n-lease-revoked-certificate",
    "n-lease-expired-at-verification", "n-stale-lease-replay",
    "n-old-generation-event", "n-cutoff-anchored-cert",
    "n-certificate-without-acceptance",
    "p-unaccepted-renewal-does-not-supersede",
    "n-both-predecessor-fields",
    "n-certificate-fork-invalid-signature",
    "n-control-fork-invalid-signature", "n-event-fork-invalid-signature",
    "n-duplicate-signature-record", "n-inapplicable-signature-role",
    "n-threshold-keys-bound", "n-signatures-bound",
    "n-revocations-bound", "n-routes-bound",
    "n-event-type-prefixes-bound", "n-high-waters-bound",
    # events
    "n-event-sequence-gap", "n-event-missing-predecessor-parent",
    "n-event-hlc-regression", "n-event-duplicate-parents",
    "n-event-unsorted-parents", "n-event-too-many-parents",
    "n-event-unknown-parent-incomplete", "n-event-fork",
    "n-event-replay-idempotent", "n-late-parent-hlc",
    "n-incomplete-ancestor-propagates",
    "n-quarantine-descendant-no-effects",
    "p-hlc-counter-overflow-handling",
    # checkpoints
    "n-checkpoint-beyond-high-water", "n-checkpoint-mismatch",
    "n-checkpoint-cross-incarnation-coverage",
    # sealed deliveries
    "n-disclosure-missing", "n-disclosure-wrong-event",
    "n-disclosure-wrong-sender", "n-disclosure-wrong-recipient",
    "n-recipients-empty", "n-recipients-duplicate", "n-recipients-unsorted",
    "n-recipients-oversized", "n-outer-inner-mismatch", "n-delivery-conflict",
    "n-delivery-retry-idempotent", "n-delivery-ttl", "n-tampered-delivery",
    "n-inner-event-signature", "n-revoked-sender-delivery",
    "n-revoked-recipient-delivery", "p-delivery-rotation-authorization",
    "p-per-recipient-expiry",
    # Executable identity/control/resource-state scenarios
    "p-control-fork-recovery", "p-recovery-control-cutoff",
    "n-recovery-omits-competing-head",
    "n-recovery-named-head-unavailable", "n-conflicting-recovery-freeze",
    "n-control-head-rollback", "n-lease-fork",
    "n-fork-descendant-quarantine", "n-proof-bundle-regression",
    "n-revocation-negation",
    "p-threshold-keys-bound", "p-signatures-bound",
    "p-signatures-reachable-maximum", "p-revocations-bound",
    "p-routes-bound", "p-event-type-prefixes-bound", "p-high-waters-bound",
    # documented state-machine expectations
    "d-stale-root-successor", "d-recovery-generation-wins",
    "d-challenge-replay", "d-copied-database",
    "d-reachable-no-lease",
    "d-clock-backward",
    "d-clock-uncertainty", "d-all-authority-lost",
    "d-two-incarnations-eligible", "d-quarantined-lease", "d-post-expiry-event",
    "d-witness-checkpoint-expired", "d-attested-timely-policy",
    "d-planned-vs-compromised-key", "d-remote-error-membership",
    "d-checkpoint-timeliness-classes", "d-lease-session-claims",
}


if __name__ == "__main__":
    unittest.main()
