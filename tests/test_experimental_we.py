from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from daimon_matrix.experimental_we.core import (
    Ledger,
    SpikeError,
    event_core,
    ingest,
    init_state,
    load_config,
    observe,
    preview,
    sign_event,
    sync_with_peer,
    trust_incarnation,
    validate_event,
    write_config,
)


def initialized_pair(tmp_path: Path) -> tuple[Path, Path]:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left_config = init_state(
        left,
        me_id="compaii",
        incarnation_id="codex-compaii@legion",
        host="legion",
        harness="codex",
    )
    right_config = init_state(
        right,
        me_id="compaii",
        incarnation_id="hermes-compaii@daimonmatrix",
        host="daimonmatrix",
        harness="hermes",
    )
    trust_incarnation(
        left,
        incarnation_id=right_config["incarnation_id"],
        public_key=right_config["public_key"],
    )
    trust_incarnation(
        right,
        incarnation_id=left_config["incarnation_id"],
        public_key=left_config["public_key"],
    )
    return left, right


def test_preview_does_not_mutate_and_ingest_is_idempotent(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(left, title="Legion experience", content="left", tags=["test"])
    observe(right, title="Remote experience", content="right", tags=["test"])

    left_before = Ledger(left).status()
    incoming = preview(left, Ledger(right).envelopes())
    assert incoming["missing_count"] == 1
    assert incoming["mutated"] is False
    assert Ledger(left).status() == left_before

    first = ingest(left, Ledger(right).envelopes(), imported_from="test")
    second = ingest(left, Ledger(right).envelopes(), imported_from="test")
    assert first["inserted"] == 1
    assert first["projected"] == 0
    assert second["inserted"] == 0
    assert second["projected"] == 0
    assert second["duplicates"] == 1
    assert Ledger(left).status()["events"] == 2


def test_bidirectional_convergence_preserves_provenance(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(left, title="Legion experience", content="left", tags=[])
    observe(right, title="Remote experience", content="right", tags=[])

    ingest(left, Ledger(right).envelopes(), imported_from="right")
    ingest(right, Ledger(left).envelopes(), imported_from="left")

    left_status = Ledger(left).status()
    right_status = Ledger(right).status()
    assert left_status["events"] == right_status["events"] == 2
    assert left_status["head"] == right_status["head"]
    assert {item["incarnation"] for item in left_status["origins"]} == {
        "codex-compaii@legion",
        "hermes-compaii@daimonmatrix",
    }


def test_tampered_event_is_rejected(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(right, title="Remote experience", content="right", tags=[])
    event = Ledger(right).envelopes()[0]
    event["payload"]["content"] = "tampered"
    with pytest.raises(SpikeError, match="hash mismatch"):
        validate_event(event, json.loads((left / "config.json").read_text()))


def test_untrusted_incarnation_is_rejected(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    init_state(
        left,
        me_id="compaii",
        incarnation_id="left",
        host="left",
        harness="codex",
    )
    init_state(
        right,
        me_id="compaii",
        incarnation_id="right",
        host="right",
        harness="hermes",
    )
    observe(right, title="Remote", content="right", tags=[])
    with pytest.raises(SpikeError, match="untrusted incarnation"):
        preview(left, Ledger(right).envelopes())


def test_same_incarnation_sequence_cannot_fork(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(right, title="Original", content="one", tags=[])
    original = Ledger(right).envelopes()[0]
    ingest(left, [original], imported_from="right")

    right_config = load_config(right)
    conflicting = sign_event(
        right,
        event_core(
            right_config,
            event_id="865f756a-320a-43c7-8ca5-c155c38a3c45",
            sequence=1,
            previous_event_id=None,
            title="Conflicting signed event",
            content="different",
            tags=[],
        ),
    )
    with pytest.raises(SpikeError, match="forked incarnation sequence"):
        ingest(left, [conflicting], imported_from="right")


def test_invalid_batch_does_not_partially_mutate(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(right, title="Valid", content="one", tags=[])
    valid = Ledger(right).envelopes()[0]
    tampered = json.loads(json.dumps(valid))
    tampered["event_id"] = "b6855578-73b4-42c2-82f8-203b68febd08"

    with pytest.raises(SpikeError):
        ingest(left, [valid, tampered], imported_from="right")
    assert Ledger(left).status()["events"] == 0


def test_validly_signed_sequence_fork_rejects_whole_batch(tmp_path: Path) -> None:
    left, right = initialized_pair(tmp_path)
    observe(right, title="Original", content="one", tags=[])
    original = Ledger(right).envelopes()[0]
    config = load_config(right)
    forks = [
        sign_event(
            right,
            event_core(
                config,
                event_id=event_id,
                sequence=2,
                previous_event_id=original["event_id"],
                title=title,
                content=title,
                tags=[],
            ),
        )
        for event_id, title in (
            ("a331ef26-a386-4c50-b93a-fc636ca4b036", "First fork"),
            ("42704ec8-7c68-4c84-8bb2-7f423d80ee4b", "Second fork"),
        )
    ]

    with pytest.raises(SpikeError, match="forked incarnation sequence"):
        ingest(left, [original, *forks], imported_from="right")
    assert Ledger(left).status()["events"] == 0


def test_disabled_hmk_projection_remains_retryable(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "state"
    init_state(
        state,
        me_id="compaii",
        incarnation_id="codex-compaii@legion",
        host="legion",
        harness="codex",
    )
    observed = observe(state, title="Pending", content="project me later", tags=[])
    event = Ledger(state).envelopes()[0]

    assert observed["projection"] == "pending"
    assert Ledger(state).projection(event["event_id"]) is None
    assert Ledger(state).status()["projected"] == 0

    config = load_config(state)
    config["hmk"].update(
        {"wrapper": "/opt/hmk", "base": "/memory", "hermes_home": "/hermes"}
    )
    write_config(state, config)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, stdout='{"ok": true, "chapter_id": 43}\n', stderr=""
        )

    monkeypatch.setattr("daimon_matrix.experimental_we.core.subprocess.run", fake_run)
    retried = ingest(state, [event], imported_from="retry")

    assert retried["inserted"] == 0
    assert retried["projected"] == 1
    assert len(calls) == 1
    assert Ledger(state).projection(event["event_id"])["provider"] == "hmk"


def test_low_level_encoding_and_sqlite_errors_are_structured(
    tmp_path: Path, monkeypatch
) -> None:
    state = tmp_path / "state"
    init_state(
        state,
        me_id="compaii",
        incarnation_id="codex-compaii@legion",
        host="legion",
        harness="codex",
    )
    with pytest.raises(SpikeError, match="invalid (base64|Ed25519 public key)"):
        trust_incarnation(state, incarnation_id="broken", public_key="not-a-key")

    ledger = Ledger(state)

    def broken_connect():
        raise sqlite3.OperationalError("synthetic database failure")

    monkeypatch.setattr(ledger, "connect", broken_connect)
    with pytest.raises(SpikeError, match="cannot read experimental ledger"):
        ledger.status()


def test_hmk_projection_uses_public_interface_once(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "state"
    init_state(
        state,
        me_id="compaii",
        incarnation_id="codex-compaii@legion",
        host="legion",
        harness="codex",
        hmk_wrapper="/opt/hmk",
        hmk_base="/memory",
        hermes_home="/hermes",
    )
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(
            command, 0, stdout='{"ok": true, "chapter_id": 42}\n', stderr=""
        )

    monkeypatch.setattr("daimon_matrix.experimental_we.core.subprocess.run", fake_run)
    observed = observe(
        state,
        title="A lived experience",
        content="Something happened.",
        tags=["test"],
    )
    event = Ledger(state).envelopes()[0]
    repeated = ingest(state, [event], imported_from="repeat")

    assert observed["projection"] == "projected"
    assert repeated["projected"] == 0
    assert len(calls) == 1
    command, options = calls[0]
    assert command[:3] == ["/opt/hmk", "memoryctl.py", "add-text"]
    assert "dm-event:" + event["event_id"] in command[command.index("--tags") + 1]
    raw = command[command.index("--raw") + 1]
    assert "origin_incarnation: codex-compaii@legion" in raw
    assert options["env"]["HMK_AGENT_MEMORY_BASE"] == "/memory"


def test_interrupted_sync_resumes_and_repeats_without_duplicates(
    tmp_path: Path, monkeypatch
) -> None:
    left, right = initialized_pair(tmp_path)
    observe(left, title="Legion experience", content="left", tags=[])
    observe(right, title="Remote experience", content="right", tags=[])

    class InProcessPeer:
        def __init__(self, _state_dir, _peer_id):
            pass

        def export(self):
            return Ledger(right).envelopes()

        def preview(self, events):
            return preview(right, events)

        def ingest(self, events):
            return ingest(right, events, imported_from="left")

    monkeypatch.setattr("daimon_matrix.experimental_we.core.SshPeer", InProcessPeer)

    interrupted = sync_with_peer(left, "right", stop_after_push=True)
    assert interrupted["interrupted"] is True
    assert Ledger(left).status()["events"] == 1
    assert Ledger(right).status()["events"] == 2

    resumed = sync_with_peer(left, "right")
    repeated = sync_with_peer(left, "right")
    assert resumed["interrupted"] is False
    assert Ledger(left).status()["head"] == Ledger(right).status()["head"]
    assert repeated["pushed"]["inserted"] == 0
    assert repeated["pulled"]["inserted"] == 0
    assert repeated["completed"]["inserted"] == 0
    assert Ledger(left).status()["events"] == Ledger(right).status()["events"] == 2
