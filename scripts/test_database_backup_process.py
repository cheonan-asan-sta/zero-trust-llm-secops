"""Test-only lost publication acknowledgement worker, killed by its test parent."""

import argparse
import re
import time
from pathlib import Path

from scripts.ca_recovery_state import save
from scripts.certificate_controller import LifecycleError
from scripts.database_backup_runtime import BackupCoordinator, management_lease
from scripts.database_transport_runtime import runtime_type


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    if re.fullmatch('[a-f0-9]{24}', args.token) is None:
        raise LifecycleError('backup_test_token_invalid')
    r = runtime_type(args.directory)(args.directory)
    with management_lease(r.directory):
        r.load()
        worker = BackupCoordinator(r)
        persist = worker.persist

        def checkpoint():
            if worker.state['phase'] != 'sealed':
                return persist()
            save(r.directory / ('backup-fault-' + args.token + '.json'),
                 {'token': args.token, 'phase': 'sealed', 'boundary': 'before'})
            time.sleep(45)
            raise LifecycleError('backup_test_parent_did_not_kill_worker')

        worker.persist = checkpoint
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            worker.tick()
        raise LifecycleError('backup_test_timeout')


if __name__ == '__main__':
    main()
