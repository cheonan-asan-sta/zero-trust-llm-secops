"""Actual restore process loss cannot admit a partial directory."""

import os
import subprocess

import pytest
from test_witness_observer_backup import KEY, fixture, restore

from app.services import audit_witness_observer as observer
from app.services.audit_transfer import AuditTransferError
from scripts.local_process_runtime import direct_python


@pytest.mark.parametrize("point,code", [("marker", 81), ("files", 82), ("receipt", 83), ("admitted", 84)])
def test_actual_process_exit_preserves_source_and_denies_partial_restore(tmp_path, point, code):
    source, signer, _, original, pin, last, package, report = fixture(tmp_path)
    before = {path: path.read_bytes() for path in (source.path, signer / "journal.sqlite3",
                                                  original / "observer.sqlite3")}
    target = tmp_path / "killed"
    script = r'''
import os,sys
from pathlib import Path
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
package,target,package_pin,profile_pin,minimum,point=sys.argv[1:]
target=Path(target)
write=observer._write
sync=backup._sync
sync_count=0
def injected(path,raw):
    result=write(path,raw)
    if point=='marker' and path==target/'restore.pending':os._exit(81)
    if point=='files' and path==target/'lease.sqlite3':os._exit(82)
    if point=='receipt' and path==target/'restore.receipt.json':os._exit(83)
    return result
def synchronized(path):
    global sync_count
    result=sync(path)
    if path==target:
        sync_count+=1
        if point=='admitted' and sync_count==3:os._exit(84)
    return result
observer._write=injected
backup._sync=synchronized
backup.restore(package,target,package_pin,profile_pin,minimum,bytes(range(32)))
raise SystemExit('requested loss boundary was not reached')
'''
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    child = subprocess.run([binary, "-c", script, str(package), str(target), report["backup_sha256"],
                            pin, last["receipt_sha256"], point], env=env, capture_output=True,
                           text=True, timeout=30, check=False)
    assert child.returncode == code, child.stdout + child.stderr
    for path, raw in before.items():
        assert path.read_bytes() == raw
    if point == "admitted":
        assert not (target / "restore.pending").exists()
        assert observer.status(target, pin, minimum_receipt=last["receipt_sha256"])["healthy"]
        assert (target / "restore.receipt.json").is_file()
    else:
        assert (target / "restore.pending").is_file()
        with pytest.raises(AuditTransferError, match="restore is incomplete"):
            observer.cycle(target, pin, minimum_receipt=last["receipt_sha256"])
        # Recovery is an explicit fresh candidate; never delete the marker or
        # overwrite an interrupted directory to claim it was complete.
        restore(tmp_path, pin, last, package, report, name="fresh-after-loss", key=KEY)
        assert observer.status(tmp_path / "fresh-after-loss", pin,
                               minimum_receipt=last["receipt_sha256"])["healthy"]
