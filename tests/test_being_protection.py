"""Real authenticated protection retains full SQLite and credential history."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from tools import export_being as exporter
from tools import protected_being as tool


class ProtectedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        _, x25519, _ = tool.crypto()
        self.key = x25519.X25519PrivateKey.generate()
        self.private = self.root / "transfer-key"
        self.private.write_bytes(self.key.private_bytes_raw())
        self.private.chmod(0o600)
        self.recipient = dict(
            schema=tool.RECIPIENT,
            name="oliva",
            owner="ani",
            request_id=str(uuid.uuid4()),
            expected_being_ref="dm:being:v1:" + "a" * 43,
            public_key=tool.encoded(self.key.public_key().public_bytes_raw()),
            expires_ms=int(time.time() * 1000) + 3600000,
        )

    def seal(self):
        original, sealed = self.root / "original", self.root / "protected"
        original.write_bytes(os.urandom(1024 * 1024 + 83))
        tool.seal(original, sealed, self.recipient)
        return original, sealed

    def test_streaming_roundtrip_does_not_publish_or_modify_plaintext(self):
        original, sealed = self.seal()
        destination = self.root / "received"
        proof = tool.open_archive(sealed, destination, self.recipient, self.private)
        self.assertTrue(proof["authenticated"])
        self.assertEqual(proof["recipient_digest"], tool.fingerprint(self.recipient))
        self.assertEqual(original.read_bytes(), destination.read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(original.read_bytes()[:80], sealed.read_bytes())
        with self.assertRaises(tool.ProtectionError):
            tool.open_archive(sealed, destination, self.recipient, self.private)
        self.assertEqual(original.read_bytes(), destination.read_bytes())
        self.assertFalse(list(self.root.glob(".opening-*")))
        self.assertFalse(list(self.root.glob(".protected-*")))

    def test_ciphertext_tag_header_and_truncation_fail_before_plaintext_publication(
        self,
    ):
        original, sealed = self.seal()
        before = original.read_bytes()
        raw = sealed.read_bytes()
        mutations = []
        for index in (len(tool.MAGIC) + 8, len(raw) // 2, len(raw) - 1):
            changed = bytearray(raw)
            changed[index] ^= 1
            mutations.append(bytes(changed))
        mutations.extend((raw[:-1], raw + b"extra"))
        for number, value in enumerate(mutations):
            changed, output = (
                self.root / ("changed-" + str(number)),
                self.root / ("out-" + str(number)),
            )
            changed.write_bytes(value)
            with self.assertRaises(tool.ProtectionError):
                tool.open_archive(changed, output, self.recipient, self.private)
            self.assertFalse(output.exists())
            self.assertFalse(list(self.root.glob(".opening-*")))
        self.assertEqual(before, original.read_bytes())

    def test_wrong_owner_request_root_or_key_cannot_relabel_a_delivery(self):
        _, sealed = self.seal()
        for key, value in (
            ("owner", "sai"),
            ("name", "eko"),
            ("request_id", str(uuid.uuid4())),
            ("expected_being_ref", "dm:being:v1:" + "b" * 43),
        ):
            with self.assertRaises(tool.ProtectionError):
                tool.open_archive(
                    sealed,
                    self.root / key,
                    {**self.recipient, key: value},
                    self.private,
                )
            self.assertFalse((self.root / key).exists())
        _, x25519, _ = tool.crypto()
        wrong = self.root / "wrong-key"
        wrong.write_bytes(x25519.X25519PrivateKey.generate().private_bytes_raw())
        wrong.chmod(0o600)
        with self.assertRaises(tool.ProtectionError):
            tool.open_archive(sealed, self.root / "wrong", self.recipient, wrong)
        self.private.chmod(0o644)
        with self.assertRaises(tool.ProtectionError):
            tool.open_archive(
                sealed, self.root / "exposed-key", self.recipient, self.private
            )

    def test_expired_or_malformed_recipients_never_generate_an_export(self):
        source = self.root / "source"
        source.write_bytes(b"ordinary data")
        for changed in (
            {**self.recipient, "expires_ms": 0},
            {**self.recipient, "public_key": "wrong"},
            {**self.recipient, "expected_being_ref": "label"},
            {**self.recipient, "expires_ms": True},
            {**self.recipient, "request_id": "not a UUID"},
            {**self.recipient, "password": "not accepted"},
        ):
            with self.assertRaises(tool.ProtectionError):
                tool.seal(source, self.root / "absent", changed)
            self.assertFalse((self.root / "absent").exists())

    def test_full_logical_and_physical_sqlite_history(
        self,
    ):
        home = self.root / "history"
        home.mkdir(mode=0o700)
        database = home / "history.db"
        (home / "SOUL.md").write_text("I am Oliva. This is my own history.\n")
        (home / "custody.json").write_text('{"must_remain_local":true}')
        connection = sqlite3.connect(database)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY,body TEXT)")
        # Deliberately recognizable, inert fixture material, not a credential.
        credential = "sk-" + "fixture" * 6
        connection.execute("INSERT INTO messages VALUES(?,?)", (1, credential))
        connection.execute(
            "INSERT INTO messages VALUES(?,?)", (2, "complete recent history")
        )
        connection.commit()
        files = {p.name: p.read_bytes() for p in home.iterdir()}
        plain_source = self.root / "ordinary-probe"
        shutil.copytree(home, plain_source)
        ordinary_plan = exporter.discover("Oliva", [("sessions", plain_source)])
        with self.assertRaisesRegex(
            exporter.ExportError, "embedded_credential_requires_separate_handoff"
        ):
            exporter.export(
                ordinary_plan, self.root / "plain.tgz", writers_stopped=True
            )
        plan = exporter.discover("Oliva", [("sessions", home)])
        output = self.root / "oliva.dm-protected"
        result = exporter.export(
            plan, output, writers_stopped=True, recipient=self.recipient
        )
        self.assertTrue(result["protection"]["protected"])
        self.assertFalse((self.root / "plain.tgz").exists())
        self.assertNotIn(credential.encode(), output.read_bytes())
        self.assertEqual(files, {p.name: p.read_bytes() for p in home.iterdir()})
        plain = self.root / "opened.tgz"
        tool.open_archive(output, plain, self.recipient, self.private)
        unpacked = self.root / "unpacked"
        exporter.verify(plain, destination=unpacked)
        manifest = json.loads((unpacked / "manifest.json").read_bytes())
        self.assertEqual(
            manifest["protected_history"]["recipient_digest"],
            tool.fingerprint(self.recipient),
        )
        normalized = next(entry for entry in manifest["files"] if entry["sqlite"])
        preserved = sqlite3.connect(unpacked / normalized["path"])
        self.addCleanup(preserved.close)
        self.assertEqual(
            preserved.execute("SELECT * FROM messages ORDER BY id").fetchall(),
            [(1, credential), (2, "complete recent history")],
        )
        originals = {
            entry["original_relative_path"]: entry
            for entry in manifest["files"]
            if entry.get("derivation") == "exact_sqlite_physical_original"
        }
        self.assertEqual(
            set(originals), {name for name in files if name.startswith("history.db")}
        )
        self.assertFalse(
            any("custody.json" in entry["path"] for entry in manifest["files"])
        )
        for name, entry in originals.items():
            self.assertEqual(files[name], (unpacked / entry["path"]).read_bytes())
        # Ordinary receiving still refuses credential-bearing plaintext. An
        # authenticated protected intake must explicitly handle this history.
        from tools import receive_being

        selection = receive_being.discover(plain, exporter.digest(plain))
        with self.assertRaisesRegex(
            exporter.ExportError, "embedded_credential_requires_separate_handoff"
        ):
            receive_being.prepare(
                plain, exporter.digest(plain), selection, self.root / "refused-ordinary"
            )
        self.assertFalse((self.root / "received").exists())
        self.assertGreater(len(manifest["protected_history"]["credential_members"]), 0)
        self.assertEqual(selection["being_label"], "Oliva")

    def history_export(self):
        home = self.root / "source-history"
        home.mkdir(mode=0o700)
        (home / "SOUL.md").write_text("I am Oliva, with my preserved identity.\n")
        credential = "sk-" + "fixture" * 6
        with contextlib.closing(sqlite3.connect(home / "library.db")) as database:
            database.execute("CREATE TABLE messages(body TEXT)")
            database.executemany(
                "INSERT INTO messages VALUES(?)",
                [("old history",), (credential,), ("recent history",)],
            )
            database.commit()
        (home / "past-session.json").write_text(json.dumps({"past": credential}))
        plan = exporter.discover("Oliva", [("memory", home)])
        sealed = self.root / "history.dm-protected"
        exporter.export(plan, sealed, writers_stopped=True, recipient=self.recipient)
        return home, sealed, credential

    def test_authenticated_receiving_keeps_full_history_and_writable_memory(self):
        from tools import receive_being as receiver

        home, sealed, credential = self.history_export()
        before = {p.name: p.read_bytes() for p in home.iterdir()}
        digest = exporter.digest(sealed)
        selection = receiver.discover(
            sealed, digest, recipient=self.recipient, recipient_key=self.private
        )
        selection["memory_coverage"] = "complete-authorized"
        output = self.root / "received-protected"
        result = receiver.prepare(
            sealed,
            digest,
            selection,
            output,
            recipient=self.recipient,
            recipient_key=self.private,
        )
        self.assertTrue(result["prepared"])
        self.assertFalse(result["matrix_enrolled"])
        report = json.loads((output / "preparation.json").read_bytes())
        self.assertEqual(report["archive_sha256"], digest)
        self.assertTrue(report["protected_transport"]["authenticated"])
        self.assertEqual((output / "source.archive").read_bytes(), sealed.read_bytes())
        database = output / "memory" / "store-001" / "library.db"
        with contextlib.closing(sqlite3.connect(database)) as working:
            self.assertEqual(
                working.execute("SELECT body FROM messages").fetchall(),
                [("old history",), (credential,), ("recent history",)],
            )
            working.execute("INSERT INTO messages VALUES('receiving write')")
            working.commit()
        written = database.read_bytes()
        with self.assertRaises(FileExistsError):
            receiver.prepare(
                sealed,
                digest,
                selection,
                output,
                recipient=self.recipient,
                recipient_key=self.private,
            )
        self.assertEqual(database.read_bytes(), written)
        self.assertEqual(before, {p.name: p.read_bytes() for p in home.iterdir()})
        self.assertFalse(list(self.root.glob(".receiving-*")))
        self.assertEqual(
            (output / "context" / "SOUL.md").read_bytes(), before["SOUL.md"]
        )

    def test_protected_receiver_refuses_owner_mismatch_and_tamper_before_preparation(
        self,
    ):
        from tools import receive_being as receiver

        _, sealed, _ = self.history_export()
        digest = exporter.digest(sealed)
        selection = receiver.discover(
            sealed, digest, recipient=self.recipient, recipient_key=self.private
        )
        output = self.root / "refused"
        with self.assertRaises(tool.ProtectionError):
            receiver.prepare(
                sealed,
                digest,
                selection,
                output,
                recipient={**self.recipient, "owner": "sai"},
                recipient_key=self.private,
            )
        self.assertFalse(output.exists())
        changed = bytearray(sealed.read_bytes())
        changed[-1] ^= 1
        sealed.write_bytes(changed)
        with self.assertRaisesRegex(
            receiver.ReceivingError, "transport_digest_mismatch"
        ):
            receiver.prepare(
                sealed,
                digest,
                selection,
                output,
                recipient=self.recipient,
                recipient_key=self.private,
            )
        self.assertFalse(output.exists())
        with self.assertRaises(tool.ProtectionError):
            receiver.prepare(
                sealed,
                exporter.digest(sealed),
                selection,
                output,
                recipient=self.recipient,
                recipient_key=self.private,
            )
        self.assertFalse(output.exists())

    def test_authenticated_manifest_cannot_forge_history_classification(self):
        from tools import receive_being as receiver

        _, sealed, _ = self.history_export()
        plain = self.root / "plain-original.tgz"
        tool.open_archive(sealed, plain, self.recipient, self.private)
        extracted = self.root / "changed-manifest"
        exporter.verify(plain, destination=extracted)
        manifest_path = extracted / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["protected_history"]["credential_members"] = []
        manifest_path.write_bytes(exporter.json_bytes(manifest))
        changed = self.root / "changed.tgz"
        with tarfile.open(changed, "w:gz") as archive:
            for name in ["manifest.json", *[e["path"] for e in manifest["files"]]]:
                archive.add(extracted / name, arcname=name, recursive=False)
        forged = self.root / "forged.dm-protected"
        tool.seal(changed, forged, self.recipient)
        selection = receiver.discover(
            forged,
            exporter.digest(forged),
            recipient=self.recipient,
            recipient_key=self.private,
        )
        output = self.root / "refused-forged"
        with self.assertRaisesRegex(
            exporter.ExportError, "embedded_credential_requires_separate_handoff"
        ):
            receiver.prepare(
                forged,
                exporter.digest(forged),
                selection,
                output,
                recipient=self.recipient,
                recipient_key=self.private,
            )
        self.assertFalse((output / "preparation.json").exists())
        self.assertFalse((output / "context").exists())
        self.assertTrue((output / "source.archive").exists())

    def test_output_retry_refuses_replacement_and_keeps_existing_ciphertext(self):
        original, sealed = self.seal()
        before = sealed.read_bytes()
        with self.assertRaises(tool.ProtectionError):
            tool.seal(original, sealed, self.recipient)
        self.assertEqual(before, sealed.read_bytes())
        alias = self.root / "alias"
        alias.symlink_to(sealed)
        with self.assertRaises(tool.ProtectionError):
            tool.open_archive(
                alias, self.root / "alias-out", self.recipient, self.private
            )


if __name__ == "__main__":
    unittest.main()
