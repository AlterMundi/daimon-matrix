"""Owner-local embodiment labels: presentation and routing, never authority.

A label reads ``<being>.<harness>@<host>`` and exists so humans and harness tools
can name one body. Identity stays ``being_ref`` plus ``embodiment_id``: a label
never authenticates, authorizes, resolves scope or widens authority, and host,
harness, model or display name never determine being membership.

Labels are derived from signed body facts (the ``body_ref`` of an embodiment's
origin) plus an owner-local registry supplying the human name of a being and any
explicit harness or host wording. Missing facts fail closed: no name is invented
from an opaque reference, and an ambiguous label is never silently resolved.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

LABEL_SCHEMA: Final = "dm.labels.registry/v1"
MAX_LABEL_BYTES: Final = 128
DISCRIMINATOR_BYTES: Final = 3

_BEING_REF: Final = re.compile(r"^dm:being:v1:[A-Za-z0-9_-]{43}$")
_BEING_NAME: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
_WORD: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_DISCRIMINATOR: Final = re.compile(r"^[a-z0-9]{2,8}$")
_EMBODIMENT_ID: Final = re.compile(r"^embodiment:[A-Za-z0-9._-]{1,180}$")
_OVERRIDE_FIELDS: Final = frozenset({"discriminator", "harness", "host"})


class LabelError(ValueError):
    """Stable fail-closed error. A label is derived or refused, never guessed."""


@dataclass(frozen=True)
class LabelTarget:
    """One labelled embodiment. Refs are identity; the label is presentation."""

    being_ref: str
    embodiment_id: str
    label: str
    harness: str
    host: str


@dataclass(frozen=True)
class LabelSelector:
    """What a human or tool typed: one body, or a whole being."""

    being_name: str
    harness: str | None
    host: str | None

    @property
    def being_level(self) -> bool:
        """True when the selector names a being rather than one body."""
        return self.harness is None and self.host is None


def _text(value: Any, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise LabelError(code)
    return value


def validate_registry(value: Any) -> dict[str, Any]:
    """Validate one closed owner-local label registry."""
    if not isinstance(value, Mapping):
        raise LabelError("labels_registry_invalid")
    if set(value) != {"beings", "overrides", "schema"}:
        raise LabelError("labels_registry_invalid")
    if value["schema"] != LABEL_SCHEMA:
        raise LabelError("labels_registry_invalid")
    beings_raw = value["beings"]
    overrides_raw = value["overrides"]
    if not isinstance(beings_raw, Mapping) or not isinstance(overrides_raw, Mapping):
        raise LabelError("labels_registry_invalid")
    beings: dict[str, str] = {}
    for key, name in beings_raw.items():
        being_ref = _text(key, "labels_registry_invalid")
        if not _BEING_REF.match(being_ref):
            raise LabelError("labels_registry_invalid")
        text = _text(name, "labels_registry_invalid")
        if not _BEING_NAME.match(text):
            raise LabelError("labels_registry_invalid")
        beings[being_ref] = text
    if len(set(beings.values())) != len(beings):
        raise LabelError("labels_being_name_duplicated")
    overrides: dict[str, dict[str, str]] = {}
    for key, row in overrides_raw.items():
        embodiment_id = _text(key, "labels_registry_invalid")
        if not _EMBODIMENT_ID.match(embodiment_id):
            raise LabelError("labels_registry_invalid")
        if not isinstance(row, Mapping) or not set(row) <= _OVERRIDE_FIELDS or not row:
            raise LabelError("labels_registry_invalid")
        clean: dict[str, str] = {}
        for field, raw in row.items():
            text = _text(raw, "labels_registry_invalid")
            pattern = _DISCRIMINATOR if field == "discriminator" else _WORD
            if not pattern.match(text):
                raise LabelError("labels_registry_invalid")
            clean[str(field)] = text
        overrides[embodiment_id] = clean
    return {"beings": beings, "overrides": overrides, "schema": LABEL_SCHEMA}


def body_ref_parts(body_ref: str) -> tuple[str, str, str]:
    """Split one signed ``<kind>:<host>:<name>`` body reference."""
    text = _text(body_ref, "label_body_ref_invalid")
    parts = text.split(":")
    if len(parts) != 3 or any(not part or part.isspace() for part in parts):
        raise LabelError("label_body_ref_invalid")
    kind, host, name = parts
    if not _WORD.match(kind) or not _WORD.match(host):
        raise LabelError("label_body_ref_invalid")
    return kind, host, name


def discriminator(embodiment_id: str) -> str:
    """Deterministic short discriminator derived from one embodiment ID."""
    text = _text(embodiment_id, "label_invalid")
    return hashlib.sha256(text.encode()).hexdigest()[: DISCRIMINATOR_BYTES * 2]


def derive_labels(
    entries: Sequence[Mapping[str, Any]], registry: Mapping[str, Any]
) -> dict[str, LabelTarget]:
    """Derive one label per embodiment from signed facts and the registry.

    Each entry needs ``being_ref``, ``embodiment_id`` and ``body_ref``. Collisions
    get a deterministic discriminator; an unresolved collision fails closed.
    """
    validated = validate_registry(dict(registry))
    beings: Mapping[str, str] = validated["beings"]
    overrides: Mapping[str, Mapping[str, str]] = validated["overrides"]
    derived: dict[str, LabelTarget] = {}
    seen: dict[str, list[str]] = {}
    for row in entries:
        if not isinstance(row, Mapping):
            raise LabelError("label_entry_invalid")
        being_ref = _text(row.get("being_ref"), "label_entry_invalid")
        embodiment_id = _text(row.get("embodiment_id"), "label_entry_invalid")
        if not _BEING_REF.match(being_ref) or not _EMBODIMENT_ID.match(embodiment_id):
            raise LabelError("label_entry_invalid")
        if embodiment_id in derived:
            raise LabelError("label_entry_duplicated")
        name = beings.get(being_ref)
        if name is None:
            raise LabelError("labels_being_name_missing")
        body_ref = _text(row.get("body_ref"), "label_entry_invalid")
        kind, host_part, _ = body_ref_parts(body_ref)
        override = overrides.get(embodiment_id, {})
        harness = override.get("harness", kind)
        host = override.get("host", host_part)
        base = f"{name}.{harness}@{host}"
        seen.setdefault(base, []).append(embodiment_id)
        derived[embodiment_id] = LabelTarget(
            being_ref=being_ref,
            embodiment_id=embodiment_id,
            label=base,
            harness=harness,
            host=host,
        )
    for base, embodiment_ids in seen.items():
        if len(embodiment_ids) < 2:
            continue
        for embodiment_id in sorted(embodiment_ids):
            override = overrides.get(embodiment_id, {})
            suffix = override.get("discriminator") or discriminator(embodiment_id)
            if not _DISCRIMINATOR.match(suffix):
                raise LabelError("label_collision_unresolved")
            target = derived[embodiment_id]
            derived[embodiment_id] = LabelTarget(
                being_ref=target.being_ref,
                embodiment_id=target.embodiment_id,
                label=f"{base}-{suffix}",
                harness=target.harness,
                host=target.host,
            )
    labels = [target.label for target in derived.values()]
    if len(set(labels)) != len(labels):
        raise LabelError("label_collision_unresolved")
    for label in labels:
        if len(label.encode()) > MAX_LABEL_BYTES or re.search(r"\s", label):
            raise LabelError("label_invalid")
    return derived


def parse_selector(text: Any) -> LabelSelector:
    """Parse ``<being>`` or ``<being>.<harness>@<host>``; nothing else."""
    value = _text(text, "label_invalid")
    if len(value.encode()) > MAX_LABEL_BYTES or re.search(r"\s", value):
        raise LabelError("label_invalid")
    if "@" not in value and "." not in value:
        if not _BEING_NAME.match(value):
            raise LabelError("label_invalid")
        return LabelSelector(being_name=value, harness=None, host=None)
    match = re.fullmatch(r"([^.@]+)\.([^.@]+)@([^.@]+)", value)
    if match is None:
        raise LabelError("label_invalid")
    being_name, harness, host = match.groups()
    if not _BEING_NAME.match(being_name):
        raise LabelError("label_invalid")
    if not _WORD.match(harness) or not _WORD.match(host):
        raise LabelError("label_invalid")
    return LabelSelector(being_name=being_name, harness=harness, host=host)


class LabelIndex:
    """Read-only label view over derived targets. It authorizes nothing."""

    def __init__(
        self, entries: Sequence[Mapping[str, Any]], registry: Mapping[str, Any]
    ) -> None:
        self._targets = derive_labels(entries, registry)
        self._by_label = {target.label: target for target in self._targets.values()}
        self._by_being: dict[str, str] = {}
        for row in validate_registry(dict(registry))["beings"].items():
            self._by_being[row[1]] = row[0]

    @property
    def targets(self) -> Mapping[str, LabelTarget]:
        return dict(self._targets)

    def label_of(self, embodiment_id: str) -> str:
        target = self._targets.get(_text(embodiment_id, "label_unknown"))
        if target is None:
            raise LabelError("label_unknown")
        return target.label

    def being_ref_of_name(self, being_name: str) -> str:
        name = _text(being_name, "label_unknown")
        being_ref = self._by_being.get(name)
        if being_ref is None:
            raise LabelError("label_unknown")
        return being_ref

    def resolve(self, text: Any) -> tuple[LabelTarget, ...]:
        """Resolve one selector to targets, or fail closed."""
        selector = parse_selector(text)
        if selector.being_level:
            being_ref = self.being_ref_of_name(selector.being_name)
            matched = sorted(
                (
                    target
                    for target in self._targets.values()
                    if target.being_ref == being_ref
                ),
                key=lambda target: target.label,
            )
            if not matched:
                raise LabelError("label_unknown")
            return tuple(matched)
        target = self._by_label.get(
            f"{selector.being_name}.{selector.harness}@{selector.host}"
        )
        if target is None:
            raise LabelError("label_unknown")
        return (target,)
