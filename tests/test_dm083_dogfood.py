"""Fast Forward regressions found while preparing the real two-host dogfood."""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path

from daimon_matrix.daemon import _bind_private_socket


class DM083SocketPublicationTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux AF_UNIX boundary")
    def test_private_staging_fits_when_public_socket_fits(self) -> None:
        # Linux sockaddr_un allows 107 non-NUL path bytes.  Exercise a public
        # path at that boundary; the atomic private staging name must not make
        # the effective path longer.
        with tempfile.TemporaryDirectory(prefix="dm083-") as directory:
            root = Path(directory)
            remaining = 107 - len(os.fsencode(root)) - 2 - len("matrix.sock")
            nested = root / ("x" * remaining)
            nested.mkdir(mode=0o700)
            target = nested / "matrix.sock"
            self.assertEqual(len(os.fsencode(target)), 107)

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                _bind_private_socket(listener, target)
                self.assertTrue(target.is_socket())
                self.assertFalse(
                    any(path.name.startswith(".s-") for path in nested.iterdir())
                )
            finally:
                listener.close()
                target.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
