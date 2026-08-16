"""Least-authority capability profile invariants for operator clients."""

from __future__ import annotations

import itertools

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
        methods < SERVICE_METHODS
        for methods in OPERATOR_CAPABILITY_PROFILES.values()
    )
