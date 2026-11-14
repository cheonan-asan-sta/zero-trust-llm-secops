"""Opt-in same-process measurement; preserve the original worker's exit and output."""

import runpy
import sys

from scripts.systemd_resources import KINDS, emit


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in KINDS:
        raise SystemExit(2)
    original = sys.argv
    succeeded = False
    try:
        sys.argv = argv
        try:
            runpy.run_module(argv[0], run_name="__main__", alter_sys=True)
            succeeded = True
        except SystemExit as error:
            succeeded = error.code is None or (isinstance(error.code, int) and error.code == 0)
            raise
    finally:
        sys.argv = original
        try:
            emit(KINDS[argv[0]], succeeded)
        except Exception:  # noqa: BLE001, S110 -- preserve worker status; missing receipt fails parent acceptance.
            pass


if __name__ == "__main__":
    main()
