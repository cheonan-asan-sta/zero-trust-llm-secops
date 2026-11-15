"""Run Prometheus/Alertmanager and reload their config when certificate files change."""

import argparse
import hashlib
import re
import signal
import subprocess
import time
from pathlib import Path

from scripts.certificate_controller import atomic


def watch_digest(paths, resolve_tls=False):
    bodies = [Path(p).read_bytes() for p in paths]
    if resolve_tls:
        for path, body in zip(paths, bodies[:], strict=True):
            names = sorted(set(re.findall(rb"/service-tls/([A-Za-z0-9_-]+\.(?:pem|key))", body)))
            bodies.extend((Path(path).parent / name.decode()).read_bytes() for name in names)
    return hashlib.sha256(b"".join(bodies)).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", type=Path, action="append", required=True)
    parser.add_argument("--ack", type=Path, required=True)
    parser.add_argument("--resolve-tls", action="store_true")
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
            digest = watch_digest(args.watch, args.resolve_tls)
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
