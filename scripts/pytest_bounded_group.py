from __future__ import annotations

"""Run one pytest group and exit with pytest's real result without teardown hangs.

Some public tests create many application instances and third-party libraries may
leave non-daemon resources alive after pytest has already completed its session.
The wrapper calls ``pytest.main`` in-process, verifies the exact collected count,
flushes output, and uses ``os._exit`` with the real result code.  It never infers
success from human-readable pytest output.
"""

import argparse
import os
import sys
from typing import Any

import pytest


class CollectionRecorder:
    def __init__(self) -> None:
        self.collected = -1

    def pytest_collection_finish(self, session: Any) -> None:
        self.collected = len(session.items)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-count", type=int, required=True)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    pytest_args = list(args.pytest_args)
    if pytest_args and pytest_args[0] == "--":
        pytest_args = pytest_args[1:]
    recorder = CollectionRecorder()
    exit_code = int(pytest.main(pytest_args, plugins=[recorder]))
    if exit_code == 0 and recorder.collected != int(args.expected_count):
        print(
            f"bounded pytest collection mismatch: expected={args.expected_count}, "
            f"actual={recorder.collected}",
            file=sys.stderr,
            flush=True,
        )
        exit_code = 3
    else:
        print(
            f"bounded pytest result: exit={exit_code}, collected={recorder.collected}",
            flush=True,
        )
    sys.stdout.flush()
    sys.stderr.flush()
    return exit_code


if __name__ == "__main__":
    code = main()
    # Avoid waiting on leaked non-daemon test resources after pytest has returned.
    os._exit(code)
