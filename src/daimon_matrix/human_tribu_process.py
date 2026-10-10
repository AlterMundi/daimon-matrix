"""One explicit passive Telegram consumer and scoped manual owner client.

Run serve only during authorized deployment. All other verbs make one human-
requested call then exit. Neither branch contains a harness/model dispatcher.
"""

from __future__ import annotations

import argparse
import fcntl
import http.server
import json
import os
import re
import signal
import sqlite3
import ssl
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Mapping
from contextlib import closing, suppress
from pathlib import Path
from typing import Any, cast

from .client import (
    ClientConfig,
    LocalClient,
    load_prepared_request,
    store_prepared_request,
)
from .human_tribu import (
    MAX_DOCUMENT,
    REPLY_SCHEMA,
    HumanTribu,
    HumanTribuError,
    Participant,
    closed,
    document,
    integer,
    json_bytes,
)
from .messaging_config import _directory, protected_read
from .telegram_mirror import _NoRedirect

HOST_SCHEMA = "dm.tribu-human-host/v1"
CLIENT_SCHEMA = "dm.tribu-human-client/v1"


def _path(value: Any) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise HumanTribuError("configuration_path_invalid")
    return Path(value)


def host_config(path: Path) -> dict[str, Any]:
    value = document(protected_read(path))
    closed(
        value,
        {
            "schema",
            "token_file",
            "bot_id",
            "chat_id",
            "database",
            "listen_host",
            "listen_port",
            "tls_cert",
            "tls_key",
            "participants",
        },
    )
    if value["schema"] != HOST_SCHEMA:
        raise HumanTribuError("host_configuration_invalid")
    for field in ("token_file", "database", "tls_cert", "tls_key"):
        _path(value[field])
    integer(value["bot_id"], minimum=1)
    if type(value["chat_id"]) is not int or not -(2**52) < value["chat_id"] < 0:
        raise HumanTribuError("host_chat_invalid")
    if (
        type(value["listen_port"]) is not int
        or not 1024 <= value["listen_port"] <= 65535
    ):
        raise HumanTribuError("host_listener_invalid")
    if (
        not isinstance(value["listen_host"], str)
        or not isinstance(value["participants"], list)
        or not 1 <= len(value["participants"]) <= 16
    ):
        raise HumanTribuError("host_configuration_invalid")
    return value


def participants(path: Path) -> list[Participant]:
    value = host_config(path)
    result = []
    for row in value["participants"]:
        closed(
            row,
            {
                "being_ref",
                "label",
                "human_id",
                "human_name",
                "username",
                "bot_id",
                "origin",
                "authority_file",
                "token_file",
                "proof_keys",
                "enabled",
            },
        )
        if type(row["enabled"]) is not bool or not isinstance(row["proof_keys"], dict):
            raise HumanTribuError("participant_invalid")
        result.append(
            Participant(
                being_ref=row["being_ref"],
                label=row["label"],
                human_id=row["human_id"],
                human_name=row["human_name"],
                username=row["username"],
                bot_id=row["bot_id"],
                origin=row["origin"],
                authority=document(protected_read(_path(row["authority_file"]))),
                token=protected_read(_path(row["token_file"])).decode().strip(),
                proof_keys={
                    name: protected_read(_path(filename), size=32)
                    for name, filename in row["proof_keys"].items()
                },
                enabled=row["enabled"],
            )
        )
    return result


def _http(
    url: str,
    payload: Mapping[str, Any],
    *,
    token: str | None = None,
    ca: Path | None = None,
    timeout: float = 30,
) -> bytes:
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    context = ssl.create_default_context(cafile=None if ca is None else str(ca))
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, data=json_bytes(payload), headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_DOCUMENT + 1)
    except urllib.error.HTTPError as error:
        # Telegram bot URLs contain credentials: never serialize the exception.
        raw = error.read(MAX_DOCUMENT + 1)
        error.close()
    except Exception:
        raise HumanTribuError("transport_uncertain") from None
    if not 0 < len(raw) <= MAX_DOCUMENT:
        raise HumanTribuError("response_size")
    return cast(bytes, raw)


class TelegramIngress:
    def __init__(self, *, token: str, bot_id: int, chat_id: int) -> None:
        if not token.startswith(str(bot_id) + ":"):
            raise HumanTribuError("telegram_identity_invalid")
        self.token, self.bot_id, self.chat_id = token, bot_id, chat_id

    def call(self, method: str, payload: Mapping[str, Any]) -> bytes:
        return _http(
            "https://api.telegram.org/bot" + self.token + "/" + method,
            payload,
            timeout=40,
        )

    def qualify(self) -> None:
        me = document(self.call("getMe", {}))
        chat = document(self.call("getChat", {"chat_id": self.chat_id}))
        webhook = document(self.call("getWebhookInfo", {}))
        if (
            me.get("ok") is not True
            or me.get("result", {}).get("id") != self.bot_id
            or me["result"].get("is_bot") is not True
            or me["result"].get("can_read_all_group_messages") is not True
            or chat.get("ok") is not True
            or chat.get("result", {}).get("id") != self.chat_id
            or chat["result"].get("type") != "supergroup"
            or webhook.get("ok") is not True
            or webhook.get("result", {}).get("url")
        ):
            raise HumanTribuError("telegram_ingress_unqualified")

    def updates(self, offset: int | None) -> list[dict[str, Any]]:
        value = document(
            self.call(
                "getUpdates",
                {
                    "offset": offset,
                    "timeout": 20,
                    "limit": 100,
                    "allowed_updates": ["message", "edited_message"],
                },
            )
        )
        if value.get("ok") is not True:
            if value.get("error_code") == 409:
                raise HumanTribuError("telegram_consumer_conflict")
            raise HumanTribuError("telegram_updates_unavailable")
        if not isinstance(value.get("result"), list):
            raise HumanTribuError("telegram_updates_invalid")
        return cast(list[dict[str, Any]], value["result"])


def api_server(
    store: HumanTribu, telegram: TelegramIngress, host: str, port: int
) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_args: Any) -> None:
            pass  # No client content, credentials or paths in the access log.

        def do_POST(self) -> None:
            status = 200
            try:
                self.connection.settimeout(15)
                header = self.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    raise HumanTribuError("unauthorized")
                person = store.authenticate(header[7:])
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_DOCUMENT:
                    raise HumanTribuError("document_size")
                value = document(self.rfile.read(length))
                if self.path == "/query":
                    closed(value, {"after", "limit"})
                    result = store.page(
                        person, after=value["after"], limit=value["limit"]
                    )
                elif self.path == "/parents":
                    closed(value, {"after", "limit"})
                    result = store.parents(
                        person, after=value["after"], limit=value["limit"]
                    )
                elif self.path == "/reply":
                    closed(value, {"event"})
                    result = store.reply(
                        person,
                        value["event"],
                        lambda request: telegram.call("sendMessage", request),
                    )
                elif self.path == "/post":
                    closed(value, {"event", "proof"})
                    result = store.register_post(person, value["event"], value["proof"])
                elif self.path == "/publication":
                    closed(value, {"id"})
                    result = store.publication(person, value["id"])
                elif self.path == "/status":
                    closed(value, set())
                    result = store.status()
                else:
                    raise HumanTribuError("unknown_operation")
                response = {"ok": True, "being_ref": person.being_ref, "result": result}
            except Exception as error:
                code = (
                    str(error)
                    if isinstance(error, HumanTribuError)
                    else "operation_rejected"
                )
                if len(code) > 128:
                    code = "operation_rejected"
                status = 403 if code == "unauthorized" else 400
                response = {"ok": False, "error": code}
            raw = json_bytes(response)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            with suppress(OSError):
                self.wfile.write(raw)  # Durable state already records the effect.

    server = http.server.ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve(path: Path, *, check: bool = False) -> int:
    settings = host_config(path)
    parent = _directory(_path(settings["database"]).parent)
    lock = os.open(
        parent / "ingress.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HumanTribuError("telegram_consumer_conflict") from None
        store = HumanTribu(
            _path(settings["database"]),
            bot_id=settings["bot_id"],
            chat_id=settings["chat_id"],
            participants=lambda: participants(path),
        )
        store._people()
        telegram = TelegramIngress(
            token=protected_read(_path(settings["token_file"])).decode().strip(),
            bot_id=settings["bot_id"],
            chat_id=settings["chat_id"],
        )
        telegram.qualify()
        if check:
            print(json.dumps({"qualified": True, "status": store.status()}))
            return 0
        server = api_server(
            store, telegram, settings["listen_host"], settings["listen_port"]
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(settings["tls_cert"], settings["tls_key"])
        server.socket = context.wrap_socket(
            server.socket, server_side=True, do_handshake_on_connect=False
        )
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda _signum, _frame: stop.set())
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            while not stop.is_set():
                offset = store.status()["last_update_id"]
                try:
                    updates = telegram.updates(None if offset is None else offset + 1)
                except HumanTribuError as error:
                    if str(error) == "telegram_consumer_conflict":
                        raise
                    print(
                        "tribu_ingress_transport_unavailable",
                        file=sys.stderr,
                        flush=True,
                    )
                    stop.wait(3)
                    continue
                for update in updates:
                    store.ingest(update)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        return 0
    finally:
        os.close(lock)


class OwnerClient:
    def __init__(self, path: Path) -> None:
        self.settings = document(protected_read(path))
        closed(
            self.settings,
            {
                "schema",
                "being_ref",
                "service_url",
                "service_ca",
                "token_file",
                "native_binding",
                "request_dir",
                "native_ledger",
                "native_echo_stores",
            },
        )
        if self.settings["schema"] != CLIENT_SCHEMA or not isinstance(
            self.settings["service_url"], str
        ):
            raise HumanTribuError("client_configuration_invalid")
        endpoint = urllib.parse.urlsplit(self.settings["service_url"])
        if (
            endpoint.scheme != "https"
            or not endpoint.hostname
            or endpoint.username
            or endpoint.password
            or endpoint.query
            or endpoint.fragment
            or endpoint.path not in ("", "/")
        ):
            raise HumanTribuError("client_endpoint_invalid")
        for field in ("service_ca", "token_file", "request_dir", "native_ledger"):
            _path(self.settings[field])
        if (
            not isinstance(self.settings["native_echo_stores"], list)
            or len(self.settings["native_echo_stores"]) > 16
        ):
            raise HumanTribuError("client_public_catalogs_invalid")
        for echo in self.settings["native_echo_stores"]:
            _path(echo)
        self.token = protected_read(_path(self.settings["token_file"])).decode().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", self.token):
            raise HumanTribuError("client_token_invalid")

    def call(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        raw = _http(
            self.settings["service_url"].rstrip("/") + "/" + operation,
            payload,
            token=self.token,
            ca=_path(self.settings["service_ca"]),
            timeout=120,
        )
        value = document(raw)
        if value.get("ok") is not True:
            raise HumanTribuError(value.get("error", "service_rejected"))
        if value.get("being_ref") != self.settings["being_ref"] or not isinstance(
            value.get("result"), dict
        ):
            raise HumanTribuError("service_identity_mismatch")
        return cast(dict[str, Any], value["result"])

    def _native(self) -> LocalClient:
        binding = closed(
            self.settings["native_binding"], {"socket", "client_config", "client_key"}
        )
        config = ClientConfig.load(
            _path(binding["client_config"]),
            protected_read(_path(binding["client_key"]), size=32),
        )
        return LocalClient(_path(binding["socket"]), config, timeout_seconds=60)

    def reply(
        self, *, source_id: str, revision: str, text: str, operation_id: str
    ) -> dict[str, Any]:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise HumanTribuError("operation_id_invalid")
        native = self._native()
        directory = _directory(_path(self.settings["request_dir"]))
        path = directory / (operation_id + ".json")
        params: dict[str, Any] = {
            "subject": "tribu-human-reply",
            "payload": {
                "schema": REPLY_SCHEMA,
                "request_id": operation_id,
                "source_id": source_id,
                "revision": revision,
                "text": text,
            },
            "sensitivity": "shareable",
            "causal_parents": [],
            "occurred_at_ms": None,
            "event_id": operation_id,
        }
        if path.exists():
            request = load_prepared_request(
                path,
                capability=native.config.capability,
                method="we.observe",
                params=params,
            )
        else:
            request = native.prepare("we.observe", params, request_id=operation_id)
            store_prepared_request(path, request)
        response = native.send(request)
        if response.get("ok") is not True:
            raise HumanTribuError("native_reply_intent_rejected")
        event = response["result"]["event"]
        if event.get("origin") != dict(native.config.expected_server):
            raise HumanTribuError("native_reply_author_mismatch")
        return self.call("reply", {"event": event})

    def retry(self, operation_id: str) -> dict[str, Any]:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise HumanTribuError("operation_id_invalid")
        path = _path(self.settings["request_dir"]) / (operation_id + ".json")
        request = document(protected_read(path))
        payload = request["params"]["payload"]
        return self.reply(
            source_id=payload["source_id"],
            revision=payload["revision"],
            text=payload["text"],
            operation_id=operation_id,
        )

    def read(
        self, *, after: int = 0, limit: int = 20, parents_after: int = 0
    ) -> dict[str, Any]:
        pending = self.call("parents", {"after": parents_after, "limit": 100})
        ids = list({item["parent_id"] for item in pending["items"]})
        registered: list[int] = []
        if ids:
            placeholders = ",".join("?" for _ in ids)
            query = (
                "SELECT DISTINCT o.record FROM echo_v2_obligations o "
                "JOIN json_each(o.record,'$.parts') p "
                "JOIN json_each(p.value,'$.attempts') a "
                "WHERE json_extract(o.record,'$.binding.projection.kind') "
                "IN ('message','reply') "
                "AND json_extract(json_extract(a.value,'$.response'),"
                "'$.result.message_id') IN (" + placeholders + ") LIMIT 100"
            )
            for selected in self.settings["native_echo_stores"]:
                path = _path(selected)
                _directory(path.parent)
                info = path.lstat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise HumanTribuError("native_public_catalog_untrusted")
                with closing(
                    sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
                ) as db:
                    rows = db.execute(query, ids).fetchall()
                for row in rows:
                    proof = document(row[0].encode())
                    try:
                        registered.extend(self.publish_post(proof)["registered"])
                    except HumanTribuError:
                        continue  # Unqualified proof cannot establish a target.
        result = self.call("query", {"after": after, "limit": limit})
        result["parent_resolution"] = {
            "registered": registered,
            "unresolved": [
                item
                for item in pending["items"]
                if item["parent_id"] not in set(registered)
            ],
            "state": "only verified parents establish accepted mentions",
            "next": pending["next"],
            "has_more": pending["has_more"],
        }
        return result

    def publish_post(self, record: dict[str, Any]) -> dict[str, Any]:
        """Read only this already-authored event; never load runtime/custody."""
        projection = record["binding"]["projection"]
        path = _path(self.settings["native_ledger"])
        _directory(path.parent)
        if (
            path.is_symlink()
            or not stat.S_ISREG(path.stat().st_mode)
            or path.stat().st_uid != os.geteuid()
            or path.stat().st_mode & 0o077
        ):
            raise HumanTribuError("native_ledger_untrusted")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            row = db.execute(
                "SELECT event_json FROM events WHERE event_id=? AND status='known'",
                (projection["event_id"],),
            ).fetchone()
        if row is None:
            raise HumanTribuError("native_post_unavailable")
        event = document(row[0].encode() if isinstance(row[0], str) else bytes(row[0]))
        return self.call("post", {"event": event, "proof": record})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    commands = parser.add_subparsers(dest="verb", required=True)
    host = commands.add_parser("serve")
    host.add_argument("--check", action="store_true")
    read = commands.add_parser("read")
    read.add_argument("--after", type=int, default=0)
    read.add_argument("--limit", type=int, default=20)
    read.add_argument("--parents-after", type=int, default=0)
    reply = commands.add_parser("reply")
    reply.add_argument("--source", required=True)
    reply.add_argument("--revision", required=True)
    reply.add_argument("--text", required=True)
    reply.add_argument("--id", default=None)
    retry = commands.add_parser("retry")
    retry.add_argument("id")
    publication = commands.add_parser("publication")
    publication.add_argument("id")
    commands.add_parser("status")
    post = commands.add_parser("register-post")
    post.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.verb == "serve":
            return serve(args.config, check=args.check)
        client = OwnerClient(args.config)
        if args.verb == "read":
            result = client.read(
                after=args.after, limit=args.limit, parents_after=args.parents_after
            )
        elif args.verb == "reply":
            result = client.reply(
                source_id=args.source,
                revision=args.revision,
                text=args.text,
                operation_id=args.id or str(uuid.uuid4()),
            )
        elif args.verb == "retry":
            result = client.retry(args.id)
        elif args.verb == "publication":
            result = client.call("publication", {"id": args.id})
        elif args.verb == "register-post":
            result = client.publish_post(document(protected_read(args.proof)))
        else:
            result = client.call("status", {})
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as error:
        code = (
            str(error)
            if isinstance(error, HumanTribuError)
            else "tribu_human_operation_rejected"
        )
        if not re.fullmatch(r"[a-z_]{1,128}", code):
            code = "tribu_human_operation_rejected"
        print(json.dumps({"ok": False, "error": code}), file=sys.stderr)
        return 2 if code == "telegram_consumer_conflict" else 1


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
