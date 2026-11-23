"""Send already queued login observations for the selected local recovery generation."""

import argparse
import os
import signal
import sys
from pathlib import Path
from threading import Event

import httpx

from scripts.login_queue_activation import ActivationConflict, managed_collector


class SenderIdentityMismatch(ValueError):
    """The configured API does not authenticate this queue's sender."""


def _credential(directory):
    fd = os.open(directory / "analysis-key", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        key = stream.read(513).strip(b"\r\n")
    if not 1 <= len(key) <= 512 or any(byte < 33 or byte > 126 for byte in key):
        raise ValueError("Invalid analysis-key systemd credential")
    return key.decode("ascii")


def serve(control, origin, credentials, stop, *, status_file=None):
    with (
        httpx.Client(
            base_url=origin, headers={"X-API-Key": _credential(credentials)},
            timeout=5, trust_env=False, follow_redirects=False,
        ) as client,
        managed_collector(
            control, client, settings=None, authority=None, registry=None,
            gateway_id=None, source_id=None, key_id=None, signing_key=None,
        ) as collector,
    ):
        # A wrong deployment key or tenant must never park queued observations.
        response = client.get("/auth/me")
        if not response.is_success:
            raise SenderIdentityMismatch("Analysis API did not authenticate the registered sender")
        identity = response.json()
        if (
            identity["auth_method"] != "api_key" or identity["subject"] != collector.spool.collector_subject
            or identity["tenant_id"] != collector.spool.tenant_id
            or "analyst" not in identity["roles"]
        ):
            raise SenderIdentityMismatch("Analysis API identity differs from the selected queue binding")
        collector.replay_until_stopped(stop, status_path=status_file, batch_size=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--status-file", type=Path)
    args = parser.parse_args()
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory or not Path(directory).is_absolute():
        parser.error("systemd CREDENTIALS_DIRECTORY is required")
    stop = Event()

    def shutdown(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        serve(args.control, args.origin, Path(directory), stop, status_file=args.status_file)
    except (ActivationConflict, SenderIdentityMismatch) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except (httpx.HTTPError, OSError, ValueError, KeyError, TypeError):
        print("Login queue sender could not start or continue", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
