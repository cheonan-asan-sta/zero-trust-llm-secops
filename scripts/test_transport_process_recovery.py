"""Test-only host fault worker; never used by the production scheduler.

The parent acceptance driver kills this process at an acknowledged checkpoint.
No fault switch, arbitrary executable or secret material is added to runtime APIs.
"""

import argparse
import os
import re
import subprocess
import time
import traceback
from pathlib import Path

from scripts.certificate_controller import PUBLIC_FAILURE_REASONS, failure_reason, save
from scripts.continuous_mtls_runtime import ROOT, RuntimeFailure
from scripts.database_transport_runtime import (
    TransportCoordinator,
    management_lease,
    runtime_type,
)

CHECKPOINTS = {'stopped': 'after', 'installed': 'before', 'resuming': 'before', 'idle': 'before'}


def public_failure(error):
    """Fixed reason codes and repository line numbers; no payload/locals/stderr."""
    allowed = {*("authority_child_" + code for code in PUBLIC_FAILURE_REASONS),
        'authority_docker_timeout', 'authority_docker_command_failed',
        'authority_child_retired_jwk_still_authorized', 'authority_child_authority_migration_incomplete',
        'authority_child_authority_requires_leaf_quiescence', 'authority_child_authority_replica_unhealthy'}
    reason = str(error) if str(error) in allowed else failure_reason(error)
    frames = []
    for frame in traceback.extract_tb(error.__traceback__):
        path = Path(frame.filename).resolve()
        if path.is_relative_to(ROOT / 'scripts') and path.is_file():
            frames.append({'file': path.relative_to(ROOT).as_posix(), 'line': frame.lineno})
    return {'reason': reason, 'frames': frames[-8:]}


def kill_worker(child):
    """Kill only our child tree (Windows venv Python may use a launcher)."""
    if child.poll() is None:
        if os.name == 'nt':
            result = subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'],
                capture_output=True, timeout=10, check=False)
            if result.returncode and child.poll() is None:
                raise RuntimeFailure('transport_test_worker_tree_kill_failed')
        else:
            child.kill()
    child.wait(timeout=10)


def checkpoint_worker(directory, target, token):
    if target not in CHECKPOINTS or re.fullmatch('[a-f0-9]{24}', token) is None:
        raise RuntimeFailure('transport_test_checkpoint_scope')
    r = runtime_type(directory)(directory)
    with management_lease(r.directory):
        r.load()
        worker = TransportCoordinator(r)
        persist = worker.persist

        def checkpoint():
            reached = worker.state['phase'] == target
            if not reached or CHECKPOINTS[target] == 'after':
                persist()
            if reached:
                save(r.directory / ('transport-fault-' + token + '.json'),
                     {'token': token, 'phase': target, 'boundary': CHECKPOINTS[target]})
                # A missing parent cannot leave this test worker running forever.
                time.sleep(45)
                raise RuntimeFailure('transport_test_parent_did_not_kill_worker')

        worker.persist = checkpoint
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            worker.tick()
            time.sleep(.2)
        raise RuntimeFailure('transport_test_checkpoint_timeout')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--checkpoint', choices=CHECKPOINTS, required=True)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    checkpoint_worker(args.directory, args.checkpoint, args.token)


if __name__ == '__main__':
    main()
