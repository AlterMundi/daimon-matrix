"""Least-authority capability profile invariants for operator clients."""

from __future__ import annotations

import itertools
import uuid

import pytest

from daimon_matrix.local_api import LocalApiError, create_capability, create_request
from daimon_matrix.operator_capabilities import (
    OPERATOR_CAPABILITY_TTL_MS,
    OPERATOR_PROFILE_NAMES,
    OperatorCapabilityError,
    create_operator_capability_set,
    operator_capability_lifecycle,
    validate_operator_capability_set,
)
from daimon_matrix.service import (
    OBSERVE_METHODS,
    OPERATOR_CAPABILITY_PROFILES,
    SERVICE_METHODS,
)


def test_profiles_partition_the_complete_service_surface() -> None:
    profiles = OPERATOR_CAPABILITY_PROFILES
    assert set(profiles) == {
        "communication",
        "curator",
        "memory",
        "observe",
        "relationships",
        "review",
        "routes",
        "sources",
        "species",
        "weave",
    }
    assert all(methods for methods in profiles.values())
    assert frozenset().union(*profiles.values()) == SERVICE_METHODS
    for (left_name, left), (right_name, right) in itertools.combinations(
        profiles.items(), 2
    ):
        assert not left & right, f"profiles overlap: {left_name}, {right_name}"


def test_observe_profile_has_no_semantic_mutation() -> None:
    forbidden = {
        "communication.accept",
        "curator.enqueue",
        "memory.execute",
        "relationship.accept",
        "review.authorize",
        "route.submit",
        "source.claim",
        "species.apply",
        "we.decide",
    }
    assert OPERATOR_CAPABILITY_PROFILES["observe"] == OBSERVE_METHODS
    assert not forbidden & OBSERVE_METHODS
    assert OBSERVE_METHODS < SERVICE_METHODS


def test_no_profile_is_a_complete_signer_oracle() -> None:
    assert all(
        methods < SERVICE_METHODS for methods in OPERATOR_CAPABILITY_PROFILES.values()
    )


@pytest.mark.parametrize(("profile", "methods"), OPERATOR_CAPABILITY_PROFILES.items())
def test_stolen_profile_key_cannot_prepare_cross_profile_request(
    profile: str, methods: frozenset[str]
) -> None:
    now_ms = 1_800_000_000_000
    capabilities, _keys, _slots = create_operator_capability_set(
        "legion", issued_at_ms=now_ms
    )
    capability = capabilities[profile]
    for method in sorted(SERVICE_METHODS - methods):
        with pytest.raises(LocalApiError, match="authentication_failed"):
            create_request(
                capability,
                request_id=str(uuid.uuid4()),
                issued_at_ms=now_ms,
                method=method,
                params={},
                nonce=b"x" * 16,
            )


def test_provisioned_profiles_have_distinct_keys_slots_and_bounded_lifetime() -> None:
    now_ms = 1_800_000_000_000
    counter = iter(range(1, len(OPERATOR_PROFILE_NAMES) + 1))
    capabilities, keys, slots = create_operator_capability_set(
        "legion",
        issued_at_ms=now_ms,
        key_factory=lambda size: bytes([next(counter)]) * size,
    )
    assert tuple(capabilities) == OPERATOR_PROFILE_NAMES
    assert len(set(keys.values())) == len(OPERATOR_PROFILE_NAMES)
    assert len(set(slots.values())) == len(OPERATOR_PROFILE_NAMES)
    lifecycle = operator_capability_lifecycle(now_ms)
    assert lifecycle["expires_at_ms"] == now_ms + OPERATOR_CAPABILITY_TTL_MS
    assert lifecycle["reprovision_at_ms"] < lifecycle["expires_at_ms"]
    validated = validate_operator_capability_set(
        {
            profile: capability.descriptor
            for profile, capability in capabilities.items()
        },
        slots,
        {slots[profile]: keys[profile] for profile in OPERATOR_PROFILE_NAMES},
        label="legion",
        issued_at_ms=now_ms,
        observed_at_ms=now_ms,
    )
    assert set(validated) == set(OPERATOR_PROFILE_NAMES)
    assert all(
        frozenset(validated[profile].methods) == OPERATOR_CAPABILITY_PROFILES[profile]
        for profile in OPERATOR_PROFILE_NAMES
    )


def test_reprovision_is_disjoint_and_expiry_revocation_fail_closed() -> None:
    now_ms = 1_800_000_000_000
    first, first_keys, first_slots = create_operator_capability_set(
        "legion", issued_at_ms=now_ms
    )
    second, second_keys, _second_slots = create_operator_capability_set(
        "legion", issued_at_ms=now_ms + 1
    )
    assert set(first_keys.values()).isdisjoint(second_keys.values())
    assert {capability.capability_id for capability in first.values()}.isdisjoint(
        capability.capability_id for capability in second.values()
    )

    descriptors = {
        profile: capability.descriptor for profile, capability in first.items()
    }
    secrets_by_slot = {
        first_slots[profile]: first_keys[profile] for profile in OPERATOR_PROFILE_NAMES
    }
    expiry = operator_capability_lifecycle(now_ms)["expires_at_ms"]
    with pytest.raises(
        OperatorCapabilityError, match="operator_capability_policy_rejected"
    ):
        validate_operator_capability_set(
            descriptors,
            first_slots,
            secrets_by_slot,
            label="legion",
            issued_at_ms=now_ms,
            observed_at_ms=expiry,
        )

    revoked = dict(descriptors)
    revoked["weave"] = create_capability(
        first_keys["weave"],
        client_id="client:operator:legion:weave",
        methods=sorted(OPERATOR_CAPABILITY_PROFILES["weave"]),
        not_before_ms=now_ms - 60_000,
        not_after_ms=expiry,
        status="revoked",
    ).descriptor
    with pytest.raises(
        OperatorCapabilityError, match="operator_capability_policy_rejected"
    ):
        validate_operator_capability_set(
            revoked,
            first_slots,
            secrets_by_slot,
            label="legion",
            issued_at_ms=now_ms,
            observed_at_ms=now_ms,
        )
