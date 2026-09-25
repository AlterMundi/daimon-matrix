"""Intra-being conversation: audience, addressee and sealing rules."""

from __future__ import annotations

import unittest
import uuid
from typing import Any

from daimon_matrix.communication import RESOLUTION_PAYLOAD_SCHEMA
from daimon_matrix.sealed import (
    DisclosureAuthorization,
    SealedDeliveryError,
    open_event,
    recipient_descriptor,
    seal_event,
    sender_descriptor,
)
from daimon_matrix.we_messaging import (
    WeLaneError,
    open_we_conversation,
    seal_we_message,
    we_addressees,
    we_audience,
    we_conversation_payload,
    we_message_body,
    we_receipt_payload,
    we_recipient_targets,
)
from daimon_matrix.weave import create_event
from tests.test_dm022_ledger import NOW
from tests.test_dm051_sealed import SealedFixture

MESSAGE_SCHEMA = "dm.communication.message/v1"
LEGION = "embodiment:legion"
REMOTE = "embodiment:daimonmatrix"


class WeLaneTests(SealedFixture):
    def target(self, embodiment_id: str) -> dict[str, Any]:
        return {
            "evidence_cursor": "dm:scope-evidence:v1:" + "A" * 43,
            "receipt_origin_embodiment_id": embodiment_id,
            "recipient_id": embodiment_id,
            "recipient_type": "embodiment",
            "scope_kind": "we",
        }

    def author(
        self,
        *,
        addressees: tuple[str, ...] = (REMOTE,),
        text: str = "hola",
        include_sender: bool = False,
    ) -> tuple[dict[str, Any], dict[str, Any], str]:
        thread_id = str(uuid.uuid4())
        message = self.append(
            self.ledger_a,
            "legion",
            "communication",
            payload={
                "schema": MESSAGE_SCHEMA,
                "body": we_message_body(text, addressees),
                "intent": {
                    "operation": "we.converse",
                    "scope": "/we",
                    "thread_id": thread_id,
                },
                "reply": None,
            },
        )
        head = next(
            row
            for row in self.ledger_a.heads()
            if row["incarnation_id"] == self.origins["legion"]["incarnation_id"]
        )
        # A resolution freezes exactly this message's audience, so the sender is
        # not a target unless the test asks for the wider /we shape.
        rows = (
            (self.target(LEGION), self.target(REMOTE))
            if include_sender
            else (self.target(REMOTE),)
        )
        targets = sorted(
            rows, key=lambda row: (row["recipient_type"], row["recipient_id"])
        )
        resolution = create_event(
            self.authority,
            self.origins["legion"],
            self.signers["legion"],
            event_id=str(uuid.uuid4()),
            sequence=head["max_sequence"] + 1,
            previous_event_id=head["tip_event_id"],
            occurred_at_ms=NOW + 1,
            causal_parents=(message["event_id"],),
            kind="experience.observed",
            subject="communication-resolution",
            payload={
                "schema": RESOLUTION_PAYLOAD_SCHEMA,
                "message_id": message["event_id"],
                "scope": "/we",
                "targets": targets,
            },
            supersedes=None,
            sensitivity="shareable",
        )
        self.ledger_a.ingest([resolution], source="test:we-lane")
        return message, resolution, thread_id

    def test_audience_is_every_sibling_and_never_the_sender(self) -> None:
        message, resolution, _ = self.author(include_sender=True)
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        self.assertEqual([row["recipient_id"] for row in audience], [REMOTE])
        self.assertEqual(
            we_addressees(audience, [REMOTE]),
            (REMOTE,),
        )

    def test_addressee_must_be_inside_the_audience(self) -> None:
        message, resolution, _ = self.author()
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        for bad, code in (
            ([], "we_lane_addressee_empty"),
            ([LEGION], "we_lane_addressee_not_in_audience"),
            (["embodiment:stranger"], "we_lane_addressee_not_in_audience"),
            ([REMOTE, REMOTE], "we_lane_addressee_duplicated"),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(WeLaneError) as caught:
                    we_addressees(audience, list(bad))
                self.assertEqual(str(caught.exception), code)

    def test_message_body_is_closed_and_bounded(self) -> None:
        body = we_message_body("hola hermano", [REMOTE])
        self.assertEqual(body, {"addressee": [REMOTE], "text": "hola hermano"})
        with self.assertRaises(WeLaneError):
            we_message_body("", [REMOTE])
        with self.assertRaises(WeLaneError):
            we_message_body("x" * (64 * 1024 + 1), [REMOTE])
        with self.assertRaises(WeLaneError):
            we_message_body("hola", REMOTE)

    def test_recipient_targets_resolve_one_credential_per_sibling(self) -> None:
        message, resolution, _ = self.author()
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        self.assertEqual(
            we_recipient_targets(self.authority, audience),
            (self.targets["daimonmatrix"],),
        )

    def test_seal_and_open_one_envelope_for_the_sibling(self) -> None:
        message, resolution, _ = self.author()
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        targets = we_recipient_targets(self.authority, audience)
        expires = NOW + 30_000
        raw = seal_we_message(
            message,
            resolution,
            authority=self.authority,
            recipient_targets=targets,
            custody=self.custodies["legion"],
            issued_at_ms=NOW + 1,
            expires_at_ms=expires,
            authorization_id="00000000-0000-4000-8000-000000000e17",
        )
        self.assertIsInstance(raw, bytes)
        authorization = DisclosureAuthorization.from_resolution_event(
            event=message,
            resolution_event=resolution,
            authority=self.authority,
            expires_at_ms=expires,
            authorization_id="00000000-0000-4000-8000-000000000e17",
        )
        opened = open_event(
            raw,
            sender_authority=self.authority,
            local_target=self.targets["daimonmatrix"],
            recipient_targets=list(targets),
            authorization=authorization,
            custody=self.custodies["daimonmatrix"],
            at_ms=NOW + 2,
        )
        self.assertEqual(opened["event_id"], message["event_id"])
        self.assertEqual(opened["payload"]["intent"]["scope"], "/we")
        self.assertEqual(opened["payload"]["body"]["addressee"], [REMOTE])

    def test_a_non_audience_embodiment_cannot_open_the_envelope(self) -> None:
        message, resolution, _ = self.author()
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        targets = we_recipient_targets(self.authority, audience)
        expires = NOW + 30_000
        raw = seal_we_message(
            message,
            resolution,
            authority=self.authority,
            recipient_targets=targets,
            custody=self.custodies["legion"],
            issued_at_ms=NOW + 1,
            expires_at_ms=expires,
        )
        authorization = DisclosureAuthorization.from_resolution_event(
            event=message,
            resolution_event=resolution,
            authority=self.authority,
            expires_at_ms=expires,
        )
        with self.assertRaises(SealedDeliveryError):
            open_event(
                raw,
                sender_authority=self.authority,
                local_target=self.targets["legion"],
                recipient_targets=list(targets),
                authorization=authorization,
                custody=self.custodies["legion"],
                at_ms=NOW + 2,
            )

    def send_and_receive(
        self, **kwargs: Any
    ) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any], dict[str, Any]]:
        message, resolution, thread_id = self.author(**kwargs)
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        targets = we_recipient_targets(self.authority, audience)
        expires = NOW + 30_000
        raw = seal_we_message(
            message,
            resolution,
            authority=self.authority,
            recipient_targets=targets,
            custody=self.custodies["legion"],
            issued_at_ms=NOW + 1,
            expires_at_ms=expires,
        )
        payload = we_conversation_payload(envelope=raw, resolution=resolution)
        opened = open_we_conversation(
            payload,
            authority=self.authority,
            local_credential_id=self.targets["daimonmatrix"].credential_id,
            custody=self.custodies["daimonmatrix"],
            at_ms=NOW + 2,
        )
        return message, resolution, thread_id, payload, opened

    def test_receiver_opens_one_message_and_names_its_addressee(self) -> None:
        message, resolution, thread_id, _payload, opened = self.send_and_receive()
        self.assertEqual(opened["message"]["event_id"], message["event_id"])
        self.assertEqual(opened["resolution"]["event_id"], resolution["event_id"])
        self.assertEqual(opened["addressees"], (REMOTE,))
        self.assertEqual([row["recipient_id"] for row in opened["audience"]], [REMOTE])
        receipt = we_receipt_payload(
            message=opened["message"],
            resolution=opened["resolution"],
            local_embodiment_id=REMOTE,
            observed_at_ms=NOW + 3,
        )
        self.assertEqual(receipt["recipient_type"], "embodiment")
        self.assertEqual(receipt["recipient_id"], REMOTE)
        self.assertEqual(receipt["outcome"], "delivered")
        self.assertEqual(receipt["thread_id"], thread_id)
        self.assertEqual(receipt["message_ref"]["event_id"], message["event_id"])
        self.assertEqual(receipt["resolution_ref"]["event_id"], resolution["event_id"])

    def test_sender_cannot_receive_its_own_message(self) -> None:
        message, resolution, _thread, _payload, _opened = self.send_and_receive()
        audience = we_audience(
            resolution, message_id=message["event_id"], local_embodiment_id=LEGION
        )
        targets = we_recipient_targets(self.authority, audience)
        raw = seal_we_message(
            message,
            resolution,
            authority=self.authority,
            recipient_targets=targets,
            custody=self.custodies["legion"],
            issued_at_ms=NOW + 1,
            expires_at_ms=NOW + 30_000,
        )
        payload = we_conversation_payload(envelope=raw, resolution=resolution)
        with self.assertRaises(WeLaneError) as caught:
            open_we_conversation(
                payload,
                authority=self.authority,
                local_credential_id=self.targets["legion"].credential_id,
                custody=self.custodies["legion"],
                at_ms=NOW + 2,
            )
        self.assertEqual(str(caught.exception), "we_lane_sender_is_local")

    def test_unbound_or_malformed_payloads_fail_closed(self) -> None:
        _message, _resolution, _thread, payload, _opened = self.send_and_receive()
        stranger = self.append(self.ledger_a, "legion", "unrelated")
        cases = [
            ({**payload, "schema": "dm.we.conversation/v2"}, "we_lane_payload_invalid"),
            ({**payload, "extra": 1}, "we_lane_payload_invalid"),
            (
                {**payload, "resolution": stranger},
                None,
            ),
        ]
        for bad, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(Exception) as caught:
                    open_we_conversation(
                        bad,
                        authority=self.authority,
                        local_credential_id=self.targets["daimonmatrix"].credential_id,
                        custody=self.custodies["daimonmatrix"],
                        at_ms=NOW + 2,
                    )
                if code is not None:
                    self.assertEqual(str(caught.exception), code)

    def test_a_wider_envelope_audience_than_the_resolution_fails_closed(self) -> None:
        """The signed resolution names the audience; a wider envelope may not."""
        message, resolution, _thread = self.author()
        expires = NOW + 30_000
        both = [self.targets["legion"], self.targets["daimonmatrix"]]
        authorization = DisclosureAuthorization.synthetic(
            event=message,
            sender=sender_descriptor(message, self.authority, at_ms=NOW),
            recipients=sorted(
                (recipient_descriptor(target, at_ms=NOW) for target in both),
                key=lambda row: (
                    row["being_ref"],
                    row["embodiment_id"],
                    row["encryption_kid"],
                ),
            ),
            evidence_hash=resolution["content_hash"],
            authorized_at_ms=resolution["occurred_at_ms"],
            expires_at_ms=expires,
            authorization_id=str(uuid.uuid4()),
        )
        raw = seal_event(
            message,
            sender_authority=self.authority,
            recipients=both,
            authorization=authorization,
            custody=self.custodies["legion"],
            issued_at_ms=NOW + 1,
            expires_at_ms=expires,
        )
        payload = we_conversation_payload(envelope=raw, resolution=resolution)
        with self.assertRaises(SealedDeliveryError):
            open_we_conversation(
                payload,
                authority=self.authority,
                local_credential_id=self.targets["daimonmatrix"].credential_id,
                custody=self.custodies["daimonmatrix"],
                at_ms=NOW + 2,
            )


if __name__ == "__main__":
    unittest.main()
