"""A migrated communication store has to be openable, not just migratable.

`CommunicationStore` persists its schema version and `_meta` requires the persisted
version to equal the version its own constructor flags imply. So a store that has
been upgraded to receipts v2 or legs v3 cannot be reopened with the default flags:
it fails closed with `communication_metadata_mismatch`.

The service already selected an already-migrated schema rather than assuming the
oldest one, but it recognised only version 2. A store upgraded to legs v3 -- the mode
that lets one membership be received by several bodies, which is what tribe
conversation needs -- was therefore unopenable after the upgrade succeeded. These
tests pin the version that is actually persisted, and pin that the regression was
real: without selection, opening a v3 store fails.
"""

from __future__ import annotations

import unittest

from daimon_matrix.communication import (
    HISTORICAL_LEGS_SCHEMA_VERSION,
    RECEIPTS_V2_SCHEMA_VERSION,
    STORE_SCHEMA_VERSION,
    CommunicationError,
    CommunicationStore,
    persisted_schema_version,
    select_persisted_schema,
)
from tests.test_dm022_ledger import NOW, RootLedgerFixture
from tests.test_dm052_communication import LogicalCommunicationFixture


class PersistedVersionTests(RootLedgerFixture):
    def test_no_store_declares_no_version(self) -> None:
        """Absence is not version 1, so a caller cannot mistake it for a choice."""

        self.assertIsNone(persisted_schema_version(self.ledger_a))


class SchemaSelectionTests(LogicalCommunicationFixture):
    def _fresh(self) -> CommunicationStore:
        return CommunicationStore(self.ledger_a, clock=lambda: NOW)

    def test_the_persisted_version_tracks_the_migrations(self) -> None:
        self.assertEqual(STORE_SCHEMA_VERSION, persisted_schema_version(self.ledger_a))

        self.store.upgrade_receipts_v2()
        self.assertEqual(
            RECEIPTS_V2_SCHEMA_VERSION, persisted_schema_version(self.ledger_a)
        )

        self.store.upgrade_legs_v3()
        self.assertEqual(
            HISTORICAL_LEGS_SCHEMA_VERSION, persisted_schema_version(self.ledger_a)
        )

    def test_a_legs_v3_store_is_unopenable_with_default_flags(self) -> None:
        """The regression, stated as a failure rather than asserted as a fix."""

        self.store.upgrade_receipts_v2()
        self.store.upgrade_legs_v3()

        with self.assertRaisesRegex(
            CommunicationError, "communication_metadata_mismatch"
        ):
            self._fresh().initialize()

    def test_selection_makes_a_legs_v3_store_openable(self) -> None:
        self.store.upgrade_receipts_v2()
        self.store.upgrade_legs_v3()

        reopened = self._fresh()
        select_persisted_schema(reopened, self.ledger_a)

        self.assertTrue(reopened.receipts_v2)
        self.assertTrue(reopened.legs_v3)
        self.assertEqual(
            HISTORICAL_LEGS_SCHEMA_VERSION, reopened._expected_schema_version()
        )
        reopened.initialize()

    def test_selection_adopts_receipts_v2_without_claiming_legs_v3(self) -> None:
        self.store.upgrade_receipts_v2()

        reopened = self._fresh()
        select_persisted_schema(reopened, self.ledger_a)

        self.assertTrue(reopened.receipts_v2)
        self.assertFalse(reopened.legs_v3)
        reopened.initialize()

    def test_selection_never_migrates_anything(self) -> None:
        """Selecting is not authorizing: an unmigrated store stays unmigrated."""

        reopened = self._fresh()
        select_persisted_schema(reopened, self.ledger_a)

        self.assertFalse(reopened.receipts_v2)
        self.assertFalse(reopened.legs_v3)
        self.assertEqual(STORE_SCHEMA_VERSION, reopened._expected_schema_version())
        reopened.initialize()
        self.assertEqual(STORE_SCHEMA_VERSION, persisted_schema_version(self.ledger_a))

    def test_selection_is_idempotent_on_a_migrated_store(self) -> None:
        self.store.upgrade_receipts_v2()
        self.store.upgrade_legs_v3()

        reopened = self._fresh()
        select_persisted_schema(reopened, self.ledger_a)
        select_persisted_schema(reopened, self.ledger_a)

        self.assertTrue(reopened.legs_v3)
        reopened.initialize()


if __name__ == "__main__":
    unittest.main()
