"""Run one deterministic module shard of ordinary unittest discovery.

Collect the original suite first, including imported TestCases and discovery
errors. Keep every module's fixtures together and retain suite ordering. The
qualification parent supplies its existing isolated environment.
"""

from __future__ import annotations

import argparse
import hashlib
import unittest


def select(suite: unittest.TestSuite, index: int, count: int) -> unittest.TestSuite:
    if not 1 <= count <= 32 or not 0 <= index < count:
        raise ValueError("shard index must be within a count of 1..32")
    result = unittest.TestSuite()
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            result.addTest(select(test, index, count))
        elif test is not None:
            module = type(test).__module__.encode()
            assigned = int.from_bytes(hashlib.sha256(module).digest(), "big") % count
            if assigned == index:
                result.addTest(test)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=int)
    parser.add_argument("count", type=int)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover("tests")
    if not suite.countTestCases():
        parser.error("qualification discovered no tests")
    try:
        selected = select(suite, args.index, args.count)
    except ValueError as error:
        parser.error(str(error))
    print(
        f"Qualification shard {args.index + 1}/{args.count}: "
        f"{selected.countTestCases()} of {suite.countTestCases()} cases",
        flush=True,
    )
    return int(not unittest.TextTestRunner(verbosity=2).run(selected).wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
