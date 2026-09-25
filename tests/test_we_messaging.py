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
)
from daimon_matrix.we_messaging import (
    WeLaneError,
    seal_we_message,
    we_addressees,
    we_audience,
    we_message_body,
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


if __name__ == "__main__":
    unittest.main()
