"""Passive Telegram provenance, paired humans and durable public effects."""

from __future__ import annotations

import copy
import json
import sqlite3
import threading
import uuid
from contextlib import closing
from dataclasses import replace
from typing import Any
from unittest.mock import patch

from daimon_matrix import mandatory_echo as echo
from daimon_matrix.canonical import canonical_bytes
from daimon_matrix.human_tribu import (
    REPLY_SCHEMA,
    HumanTribu,
    HumanTribuError,
    Participant,
    digest,
)
from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA
from tests.test_dm022_ledger import NOW, RootLedgerFixture, seed


def person(fixture: RootLedgerFixture) -> Participant:
    return Participant(
        being_ref=fixture.state.being_ref,
        label="compaii.codex@daimonmatrix",
        human_id=111,
        human_name="Nico",
        username="compaii_bot",
        bot_id=234,
        origin=fixture.origins["legion"],
        authority={
            "schema": AUTHORITY_SCHEMA,
            "control_artifacts": [fixture.genesis],
            "control_head": fixture.state.head,
            "manifest": fixture.manifest.value,
            "credentials": list(fixture.credentials.values()),
            "incarnations": list(fixture.incarnations.values()),
        },
        token="a" * 64,
        proof_keys={("test", "synthetic-proof-key"): b"k" * 32},
    )


def message(
    *,
    ident: int = 10,
    update: int = 1,
    human: int = 111,
    text: str = "@compaii_bot check this",
    edit: bool = False,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "message_id": ident,
        "date": 100,
        "from": {"id": human, "is_bot": False},
        "chat": {"id": -123, "type": "supergroup"},
        "text": text,
        "entities": [{"type": "mention", "offset": 0, "length": 12}],
    }
    if edit:
        value["edit_date"] = 101
    return {"update_id": update, "edited_message" if edit else "message": value}


def response(sent: list[dict[str, Any]], request: dict[str, Any]) -> bytes:
    sent.append(request)
    parent = request["reply_parameters"]["message_id"]
    result = {
        "message_id": 1000 + len(sent),
        "from": {"id": 123, "is_bot": True},
        "chat": {"id": -123, "type": "supergroup"},
        "text": request["text"],
        "entities": request.get("entities", []),
        "reply_to_message": {
            "message_id": parent,
            "from": {"id": 111 if parent == 10 else 123, "is_bot": parent != 10},
            "chat": {"id": -123, "type": "supergroup"},
            "message_thread_id": 10,
        },
        "message_thread_id": 10,
    }
    return json.dumps({"ok": True, "result": result}).encode()


class NativeTestTransport:
    def __init__(self, start_id: int = 1) -> None:
        self.roots: dict[int, int] = {}
        self.next_id = start_id

    def send(self, request: dict[str, Any]) -> bytes:
        ident = self.next_id
        self.next_id += 1
        result: dict[str, Any] = {
            "message_id": ident,
            "from": {"id": 123, "is_bot": True},
            "chat": {"id": -123, "type": "supergroup"},
            "text": request["text"],
        }
        root = ident
        if "entities" in request:
            result["entities"] = request["entities"]
        if "reply_parameters" in request:
            parent = request["reply_parameters"]["message_id"]
            root = self.roots.get(parent, parent)
            result.update(
                message_thread_id=root,
                reply_to_message={
                    "message_id": parent,
                    "from": {"id": 123, "is_bot": True},
                    "chat": {"id": -123, "type": "supergroup"},
                },
            )
            if parent != root:
                result["reply_to_message"]["message_thread_id"] = root
        self.roots[ident] = root
        return canonical_bytes({"ok": True, "result": result})


def native_proof(
    fixture: RootLedgerFixture,
    *,
    text: str = "hello",
    representation: str = "plain-json/v2",
    sender: str | None = None,
    key: bytes = b"k" * 32,
    key_id: str = "synthetic-proof-key",
    filename: str = "echo.sqlite",
    start_id: int = 1,
) -> tuple[dict[str, Any], dict[str, Any]]:
    event = fixture.ledger_a.append_local(
        kind="experience.observed",
        subject="communication",
        payload={
            "schema": "dm.communication.message/v1",
            "body": {"text": text},
        },
        signer=fixture.signers["legion"],
        occurred_at_ms=NOW,
    )
    projection = {
        "event_id": event["event_id"],
        "event_digest": event["content_hash"],
        "sender": person(fixture).label if sender is None else sender,
        "recipients": ["eko"],
        "thread_id": "thread",
        "reply_to": None,
        "kind": "message",
        "content": {"text": text},
    }
    with closing(
        sqlite3.connect(fixture.root_path / filename, isolation_level=None)
    ) as db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("BEGIN IMMEDIATE")
        echo.EchoJournal.initialize(db, catalog_id="test", authentication_key=key)
        db.commit()
        journal = echo.EchoJournal(db, catalog_id="test", authentication_key=key)
        db.execute("BEGIN IMMEDIATE")
        binding = journal.admit(
            "native",
            projection,
            {
                "schema": "daimon-visibility-policy/v2",
                "generation": 1,
                "origin": "synthetic-runtime",
                "bot_id": 123,
                "chat_id": -123,
                "topic_id": None,
                "representation": representation,
                "acceptance_digest": "a" * 64,
                "proof_key_id": key_id,
            },
        )
        db.commit()
        worker = echo.MandatoryEcho(
            journal,
            transport=NativeTestTransport(start_id),
            resolve=lambda _: projection,
            authorize=lambda _: True,
        )
        for _part in journal._load("native", binding)["parts"]:
            worker.advance("native", binding)
        proof = worker.require_confirmed("native", binding)
    return event, proof


class HumanTribuTests(RootLedgerFixture):
    def setUp(self) -> None:
        super().setUp()
        self.person = person(self)
        self.people = [self.person]
        self.store = self.reopen()
        self.sent: list[dict[str, Any]] = []

    def reopen(self) -> HumanTribu:
        return HumanTribu(
            self.root_path / "human.sqlite",
            bot_id=123,
            chat_id=-123,
            participants=lambda: self.people,
            clock=lambda: NOW,
        )

    def intent(
        self, *, text: str = "Here is the answer.", source: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if source is None:
            source = self.store.page(self.person)["items"][-1]
        operation = str(uuid.uuid4())
        return self.ledger_a.append_local(
            kind="experience.observed",
            subject="tribu-human-reply",
            payload={
                "schema": REPLY_SCHEMA,
                "request_id": operation,
                "source_id": source["id"],
                "revision": source["revision"],
                "text": text,
            },
            sensitivity="shareable",
            event_id=operation,
            signer=self.signers["legion"],
            occurred_at_ms=NOW,
        )

    def exchange(self, request: dict[str, Any]) -> bytes:
        return response(self.sent, request)

    def test_transactional_cursor_pair_gate_duplicate_and_restart(self) -> None:
        for human in (222, True):
            self.store.ingest(message(human=human, update=int(human) + 100))
        forwarded = message(update=500)
        forwarded["message"]["forward_origin"] = {"type": "user"}
        self.store.ingest(forwarded)
        self.assertEqual(self.store.page(self.person)["items"], [])
        selected = message(update=501)
        self.assertEqual(self.store.ingest(selected)["retained"], 1)
        self.assertTrue(self.reopen().ingest(selected)["duplicate"])
        self.assertEqual(self.store.status()["last_update_id"], 501)
        self.assertFalse(self.store.status()["automatic_inference"])
        tampered = copy.deepcopy(selected)
        tampered["message"]["text"] += "!"
        with self.assertRaisesRegex(HumanTribuError, "update_conflict"):
            self.store.ingest(tampered)
        self.assertEqual(self.store.status()["last_update_id"], 501)
        self.assertEqual(len(self.store.page(self.person)["items"]), 1)

    def test_unicode_mention_entities_and_no_text_based_authority(self) -> None:
        value = message(text="😀 @compaii_bot hello")
        value["message"]["entities"][0]["offset"] = 3
        self.assertEqual(self.store.ingest(value)["retained"], 1)
        decomposed = message(update=3, ident=12, text="@compaii_bot cafe\u0301")
        self.store.ingest(decomposed)
        self.assertEqual(
            self.store.page(self.person)["items"][-1]["text"],
            decomposed["message"]["text"],
        )
        coordinates = message(update=4, human=222, ident=13)
        coordinates["message"]["location"] = {"latitude": 12.5, "longitude": -1.5}
        self.assertEqual(self.store.ingest(coordinates)["retained"], 0)
        value = message(update=2, ident=11)
        value["message"]["entities"] = []
        self.assertEqual(self.store.ingest(value)["retained"], 0)
        with self.assertRaisesRegex(HumanTribuError, "unauthorized"):
            self.store.authenticate("b" * 64)

    def test_revisions_and_withdrawal_preserve_history_and_refuse_old_reply(
        self,
    ) -> None:
        self.store.ingest(message())
        event = self.intent()
        edited = message(update=2, edit=True, text="I withdraw this mention.")
        edited["edited_message"]["entities"] = []
        self.store.ingest(edited)
        items = self.store.page(self.person)["items"]
        self.assertEqual(len(items), 2)
        self.assertTrue(items[0]["superseded"])
        self.assertFalse(items[1]["eligible"])
        with self.assertRaisesRegex(HumanTribuError, "changed"):
            self.store.reply(self.person, event, self.exchange)
        self.assertEqual(self.sent, [])
        self.assertEqual(
            self.store.page(self.person, after=items[-1]["sequence"])["items"], []
        )

    def test_literal_paginated_reply_real_receipts_and_retry_no_duplicate(self) -> None:
        self.store.ingest(message())
        event = self.intent(text="hello 😀 <literal>\n" * 500)
        result = self.store.reply(self.person, event, self.exchange)
        self.assertEqual(result["state"], "confirmed")
        self.assertGreater(len(self.sent), 1)
        self.assertEqual(self.sent[0]["reply_parameters"]["message_id"], 10)
        self.assertEqual(self.sent[1]["reply_parameters"]["message_id"], 1001)
        count = len(self.sent)
        self.assertEqual(self.reopen().reply(self.person, event, self.exchange), result)
        self.assertEqual(len(self.sent), count)
        followup = message(ident=20, update=2, text="Reply without mention")
        followup["message"]["entities"] = []
        followup["message"]["reply_to_message"] = {"message_id": 1001}
        self.assertEqual(self.store.ingest(followup)["retained"], 1)

    def test_uncertain_response_retained_and_never_resent(self) -> None:
        self.store.ingest(message())
        event = self.intent()

        def uncertain(request: dict[str, Any]) -> bytes:
            self.exchange(request)
            raise TimeoutError("a private token must never enter the record")

        result = self.store.reply(self.person, event, uncertain)
        self.assertEqual(result["state"], "uncertain")
        self.assertEqual(self.reopen().reply(self.person, event, self.exchange), result)
        self.assertEqual(len(self.sent), 1)
        self.assertNotIn("private token", json.dumps(result))

    def test_concurrent_retry_and_queries_do_not_block_or_duplicate(self) -> None:
        self.store.ingest(message())
        event = self.intent()
        entered, release = threading.Event(), threading.Event()

        def delayed(request: dict[str, Any]) -> bytes:
            entered.set()
            if not release.wait(10):
                raise TimeoutError
            return self.exchange(request)

        worker = threading.Thread(
            target=self.store.reply, args=(self.person, event, delayed)
        )
        worker.start()
        try:
            self.assertTrue(entered.wait(10))
            self.assertEqual(len(self.store.page(self.person)["items"]), 1)
            self.assertEqual(
                self.reopen().reply(self.person, event, self.exchange)["state"],
                "sending",
            )
        finally:
            release.set()
            worker.join(10)
        self.assertEqual(len(self.sent), 1)

    def test_disabled_policy_and_forged_signed_intent_refused(self) -> None:
        self.store.ingest(message())
        event = self.intent()
        forged = copy.deepcopy(event)
        forged["payload"]["text"] = "forged"
        with self.assertRaises(ValueError):
            self.store.reply(self.person, forged, self.exchange)
        self.people = [replace(self.person, enabled=False)]
        with self.assertRaisesRegex(HumanTribuError, "unauthorized"):
            self.store.reply(self.person, event, self.exchange)
        self.assertEqual(self.sent, [])

    def test_changed_human_refused_before_publication_and_history_not_exposed(
        self,
    ) -> None:
        self.store.ingest(message())
        event = self.intent()
        self.people = [replace(self.person, human_id=222, human_name="New human")]
        with self.assertRaisesRegex(HumanTribuError, "human_changed"):
            self.store.reply(self.person, event, self.exchange)
        self.assertEqual(self.sent, [])
        self.assertEqual(self.store.page(self.person)["items"], [])

    def test_missing_continuation_parent_is_uncertain_and_never_republished(
        self,
    ) -> None:
        self.store.ingest(message())
        event = self.intent(text="a long reply\n" * 900)

        def missing_parent(request: dict[str, Any]) -> bytes:
            raw = self.exchange(request)
            if len(self.sent) > 1:
                value = json.loads(raw)
                value["result"].pop("reply_to_message")
                value["result"].pop("message_thread_id")
                return canonical_bytes(value)
            return raw

        result = self.store.reply(self.person, event, missing_parent)
        self.assertEqual(result["state"], "uncertain")
        self.assertEqual(result["parts"][0]["state"], "confirmed")
        self.reopen().reply(self.person, event, self.exchange)
        self.assertEqual(len(self.sent), 2)

    def test_native_pagination_first_page_anchoring_and_pending_revisions(self) -> None:
        event, proof = native_proof(
            self, text="long native text\n" * 900, representation="compact-text/v1"
        )
        self.assertGreater(len(proof["parts"]), 3)
        candidate = message(ident=20, text="plain human reply")
        candidate["message"]["entities"] = []
        candidate["message"]["reply_to_message"] = {"message_id": 3}
        self.store.ingest(candidate)
        edited = copy.deepcopy(candidate)
        edited["update_id"] = 2
        edited["edited_message"] = edited.pop("message")
        edited["edited_message"].update(text="corrected human reply", edit_date=101)
        self.store.ingest(edited)
        self.assertEqual(self.store.page(self.person)["items"], [])
        self.assertEqual(len(self.store.parents(self.person)["items"]), 2)
        self.store.register_post(self.person, event, proof)
        items = self.store.page(self.person)["items"]
        self.assertEqual(len(items), 2)
        self.assertTrue(items[0]["superseded"])
        self.assertEqual(items[1]["text"], "corrected human reply")
        self.assertEqual(self.store.parents(self.person)["items"], [])

    def test_late_parent_requalifies_edited_reply_without_mutating_history(
        self,
    ) -> None:
        event, proof = native_proof(self)
        candidate = message()
        candidate["message"]["reply_to_message"] = {"message_id": 1}
        self.store.ingest(candidate)
        edited = copy.deepcopy(candidate)
        edited["update_id"] = 2
        edited["edited_message"] = edited.pop("message")
        edited["edited_message"].update(
            text="reply remains directed by its parent", entities=[], edit_date=101
        )
        self.store.ingest(edited)
        with closing(sqlite3.connect(self.store.path)) as db:
            before = db.execute(
                "SELECT record FROM revisions ORDER BY sequence"
            ).fetchall()
        self.assertFalse(self.store.page(self.person)["items"][-1]["eligible"])
        self.store.register_post(self.person, event, proof)
        items = self.store.page(self.person)["items"]
        self.assertFalse(items[-1]["intake_eligible"])
        self.assertTrue(items[-1]["eligible"])
        self.assertEqual(
            self.store.reply(self.person, self.intent(source=items[-1]), self.exchange)[
                "state"
            ],
            "confirmed",
        )
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(
                db.execute("SELECT record FROM revisions ORDER BY sequence").fetchall(),
                before,
            )
        withdrawn = copy.deepcopy(edited)
        withdrawn["update_id"] = 3
        withdrawn["edited_message"].pop("reply_to_message")
        withdrawn["edited_message"]["edit_date"] = 102
        self.store.ingest(withdrawn)
        last = self.store.page(self.person)["items"][-1]
        self.assertFalse(last["eligible"])
        with self.assertRaisesRegex(HumanTribuError, "source_withdrawn"):
            self.store.reply(self.person, self.intent(source=last), self.exchange)
        self.assertEqual(len(self.sent), 1)

    def test_historical_labels_and_distinct_keys_of_same_catalog(self) -> None:
        event, proof = native_proof(self, sender=self.person.being_ref)
        self.people = [
            replace(
                self.person,
                proof_keys={
                    **self.person.proof_keys,
                    ("test", "second-native-key"): b"m" * 32,
                },
            )
        ]
        self.assertEqual(
            self.store.register_post(self.person, event, proof)["registered"], [1]
        )
        second, other_proof = native_proof(
            self,
            key=b"m" * 32,
            key_id="second-native-key",
            filename="other.sqlite",
            start_id=50,
        )
        self.assertEqual(
            self.store.register_post(self.person, second, other_proof)["registered"],
            [50],
        )
        tampered = copy.deepcopy(other_proof)
        tampered["binding"]["policy"]["proof_key_id"] = "synthetic-proof-key"
        tampered["binding_digest"] = digest(tampered["binding"])
        with self.assertRaisesRegex(HumanTribuError, "post_proof_rejected"):
            self.store.register_post(self.person, second, tampered)
        self.people = [self.person]
        with self.assertRaisesRegex(HumanTribuError, "post_catalog_rejected"):
            self.store.register_post(self.person, second, other_proof)
        reply = message(text="reply to the retained historical publication")
        reply["message"]["entities"] = []
        reply["message"]["reply_to_message"] = {"message_id": 1}
        self.store.ingest(reply)
        self.assertEqual(
            self.store.reply(self.person, self.intent(), self.exchange)["state"],
            "confirmed",
        )

    def test_each_being_accepts_only_its_paired_human_and_queries_are_isolated(
        self,
    ) -> None:
        other = RootLedgerFixture()
        with patch(
            "tests.test_dm022_ledger.seed",
            side_effect=lambda label: seed("other-" + label),
        ):
            other.setUp()
        self.addCleanup(other.tearDown)
        second = replace(
            person(other),
            label="eko.codex@daimonmatrix",
            human_id=222,
            human_name="Sai",
            username="eko_human_bot",
            bot_id=235,
            token="b" * 64,
        )
        self.people.append(second)
        wrong = message(text="@eko_human_bot cross-human request")
        wrong["message"]["entities"][0]["length"] = 14
        self.assertEqual(self.store.ingest(wrong)["retained"], 0)
        own = message(update=2, text="@eko_human_bot own request", human=222)
        own["message"]["entities"][0]["length"] = 14
        self.assertEqual(self.store.ingest(own)["retained"], 1)
        self.assertEqual(self.store.page(self.person)["items"], [])
        self.assertEqual(len(self.store.page(second)["items"]), 1)
        self.store.ingest(message(update=3, ident=11))
        event = self.intent()
        with self.assertRaises(ValueError):
            self.store.reply(second, event, self.exchange)
        self.assertEqual(self.sent, [])

    def test_invalid_update_does_not_acknowledge_or_skip_and_fifo_is_refused(
        self,
    ) -> None:
        value = message()
        value["message"]["entities"][0]["offset"] = 99999
        with self.assertRaisesRegex(HumanTribuError, "invalid_entity"):
            self.store.ingest(value)
        self.assertIsNone(self.store.status()["last_update_id"])
        self.assertEqual(self.store.ingest(message())["retained"], 1)
        import os

        fifo = self.root_path / "forbidden.fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(HumanTribuError, "file_untrusted"):
            HumanTribu(fifo, bot_id=123, chat_id=-123, participants=lambda: self.people)

    def test_full_native_proof_registration_is_idempotent_and_routes_replies(
        self,
    ) -> None:
        event, proof = native_proof(self)
        self.assertEqual(
            self.store.register_post(self.person, event, proof)["registered"], [1]
        )
        self.assertEqual(
            self.store.register_post(self.person, event, proof)["registered"], [1]
        )
        reply = message(ident=20, text="about that")
        reply["message"]["entities"] = []
        reply["message"]["reply_to_message"] = {"message_id": 1}
        self.assertEqual(self.store.ingest(reply)["retained"], 1)
        proof["parts"][0]["text"] = "fake"
        with self.assertRaisesRegex(HumanTribuError, "proof_rejected"):
            self.store.register_post(self.person, event, proof)
