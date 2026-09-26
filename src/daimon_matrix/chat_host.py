"""One owner-local process hosting explicit identities and independent chat links.

Each runtime is opened and locked once. Each signed application keeps its own
capability, socket, transport, visibility controller and retry stores. No inbox
polling, message generation or harness execution is performed by this host.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import daemon
from .authority_epochs import RootHistoryAuthority
from .messaging_config import (
    _directory,
    load_application,
    protected_read,
    read_document,
    read_publication,
)
from .native_egress import closed_visibility
from .operator_messaging import _visibility_factory, host_visibility_factory
from .runtime import HostedRuntime, VisibilityFactoryContext, load_runtime
from .service import MESSAGING_METHODS
from .weave import RootAuthority


def visibility_context(runtime: HostedRuntime) -> VisibilityFactoryContext:
    """Reuse verified authority; never reopen or copy private custody."""
    from .messaging_config import config_digest

    authority = runtime.service.ledger.authority
    if not isinstance(authority, (RootAuthority, RootHistoryAuthority)):
        raise ValueError("chat_host_authority_invalid")
    return VisibilityFactoryContext(
        authority=authority,
        origin=runtime.service.origin,
        runtime_id=runtime.service.runtime_id,
        runtime_label=runtime.service.runtime_label,
        signer_public_key=runtime.service.signer.public_key,
        bundle_sha256=config_digest(read_document(runtime.state_root / "runtime.json")),
        authorities={},  # App factory validates its own pinned public authorities.
    )


def application_view(
    base: HostedRuntime,
    app: Path,
    visibility: Path,
    *,
    catalog_mode: str = "validate",
) -> HostedRuntime:
    """Additional link with independent visibility, no duplicate native transport."""
    document, _ = read_publication(base, app)
    controller = _visibility_factory(
        document, visibility, clock=base.service.clock, catalog_mode=catalog_mode
    )(visibility_context(base))
    view = load_application(replace(base, egress=controller), app)
    return replace(
        view,
        peer_dispatcher=None,
        peer_context=None,
        peer_outbox=None,
        peer_listen=None,
        service=replace(
            view.service,
            router=None,
            peer_context=None,
            capabilities={
                key: capability
                for key, capability in view.service.capabilities.items()
                if set(capability.methods) <= MESSAGING_METHODS
            },
            visibility_status=controller.status,
        ),
    )


def validate_config(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "runtimes"}
        or value["schema"] != "dm.chat-host/v1"
        or not isinstance(value["runtimes"], list)
        or not 1 <= len(value["runtimes"]) <= 16
    ):
        raise ValueError("chat_host_config_invalid")
    roots: set[str] = set()
    apps: set[str] = set()
    for row in value["runtimes"]:
        if not isinstance(row, dict) or set(row) != {
            "state_root",
            "password_file",
            "applications",
        }:
            raise ValueError("chat_host_runtime_invalid")
        for name in ("state_root", "password_file"):
            if not isinstance(row[name], str) or not Path(row[name]).is_absolute():
                raise ValueError("chat_host_path_invalid")
        canonical_root = str(Path(row["state_root"]).resolve())
        if canonical_root in roots:
            raise ValueError("chat_host_duplicate_runtime")
        roots.add(canonical_root)
        if (
            not isinstance(row["applications"], list)
            or not 0 <= len(row["applications"]) <= 16
        ):
            raise ValueError("chat_host_applications_invalid")
        sockets: set[str] = set()
        for app in row["applications"]:
            if not isinstance(app, dict) or set(app) != {
                "directory",
                "visibility",
                "socket",
            }:
                raise ValueError("chat_host_application_invalid")
            for name in ("directory", "visibility"):
                if not isinstance(app[name], str) or not Path(app[name]).is_absolute():
                    raise ValueError("chat_host_path_invalid")
            if (
                not isinstance(app["socket"], str)
                or re.fullmatch(r"[A-Za-z0-9_-]{1,24}\.sock", app["socket"]) is None
            ):
                raise ValueError("chat_host_socket_invalid")
            directory = str(Path(app["directory"]).resolve())
            if directory in apps or app["socket"] in sockets:
                raise ValueError("chat_host_duplicate_application")
            apps.add(directory)
            sockets.add(app["socket"])
    return value


def load_views(row: dict[str, Any], *, clock: Callable[[], int]) -> list[HostedRuntime]:
    """Caller holds the runtime lock until every serving thread has drained.

    A runtime with no messaging application is hosted for presence only: its own
    ledger, operator surface, peer transport and `/we` sync, with closed egress and
    therefore no messaging and no echo obligation. That is how one being keeps an
    embodiment in another harness or on another host without inventing a
    relationship just to give it a socket.
    """
    applications = row["applications"]
    if not applications:
        return [
            load_runtime(
                Path(row["state_root"]),
                "runtime.json",
                lambda: bytearray(protected_read(Path(row["password_file"]))),
                clock=clock,
                egress=closed_visibility(clock=clock, catalog_mode="migrate"),
            )
        ]
    first, *others = applications
    base = load_runtime(
        Path(row["state_root"]),
        "runtime.json",
        lambda: bytearray(protected_read(Path(row["password_file"]))),
        clock=clock,
        egress_factory=host_visibility_factory(
            first["directory"], first["visibility"], clock=clock
        ),
    )
    views = [load_application(base, first["directory"])]
    views.extend(
        application_view(base, Path(app["directory"]), Path(app["visibility"]))
        for app in others
    )
    return [
        replace(view, socket_path=base.state_root / app["socket"])
        for view, app in zip(views, row["applications"], strict=True)
    ]


def serve_views(views: list[HostedRuntime], stop: threading.Event) -> None:
    """Any link failure stops the host; never leave a silently partial service."""
    listeners = [v.messaging_http.listen for v in views if v.messaging_http]
    listeners.extend(
        v.peer_listen for v in views if v.peer_dispatcher and v.peer_listen
    )
    if len(listeners) != len(set(listeners)) or len(
        {v.socket_path for v in views}
    ) != len(views):
        raise ValueError("chat_host_listener_collision")
    errors: list[BaseException] = []

    def run(view: HostedRuntime) -> None:
        try:
            daemon.serve_forever(view, stop=stop)
        except BaseException as error:
            errors.append(error)
            stop.set()

    threads = [threading.Thread(target=run, args=(v,)) for v in views]
    try:
        for thread in threads:
            thread.start()
        while not stop.wait(0.25):
            if any(not thread.is_alive() for thread in threads):
                stop.set()
    finally:
        stop.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join()
    if errors:
        raise ValueError("chat_host_link_failed") from errors[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    locks = []
    stop = threading.Event()
    try:
        _directory(args.config.parent)
        config = validate_config(read_document(args.config))
        for row in sorted(config["runtimes"], key=lambda row: row["state_root"]):
            locks.append(
                daemon.acquire_lock(daemon._state_root(Path(row["state_root"])))
            )
        views = [
            view
            for row in config["runtimes"]
            for view in load_views(row, clock=lambda: time.time_ns() // 1_000_000)
        ]
        # Verify every registry before any listener or visibility worker starts.
        for view in views:
            view.egress.validate_registry(daemon._enabled_egress_paths(view))
        if args.check:
            return 0
        for number in (signal.SIGTERM, signal.SIGINT):
            signal.signal(number, lambda _number, _frame: stop.set())
        serve_views(views, stop)
        return 0
    except Exception:
        daemon._log("chat_host_failed")
        return 1
    finally:
        for descriptor in reversed(locks):
            os.close(descriptor)


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
