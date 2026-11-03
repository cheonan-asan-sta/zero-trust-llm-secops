"""Run Prometheus/Alertmanager and reload their config when certificate files change."""

import argparse
import hashlib
import signal
import subprocess
import time
from pathlib import Path

from scripts.certificate_controller import atomic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", type=Path, action="append", required=True)
    parser.add_argument("--ack", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    child = subprocess.Popen(command)
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    previous = None
    try:
        while not stopping and child.poll() is None:
            digest = hashlib.sha256(b"".join(p.read_bytes() for p in args.watch)).hexdigest()
            if digest != previous:
                if previous is not None:
                    child.send_signal(signal.SIGHUP)
                time.sleep(.2)
                if child.poll() is None:
                    atomic(args.ack, digest + "\n")
                    previous = digest
            time.sleep(.2)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    raise SystemExit(child.returncode)


if __name__ == "__main__":
    main()
