"""Explicit restore resume never overwrites partial bytes or adopts new pins."""

import json
import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_witness_observer_backup import KEY, fixture

from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError, sha
from scripts.local_process_runtime import direct_python


def interrupted(tmp_path, point="files"):
    source, signer, _, original, pin, last, package, saved = fixture(tmp_path)
    target = tmp_path / "candidate"
    script = r'''
import os,sys
from pathlib import Path
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
package,target,package_pin,profile_pin,minimum,point=sys.argv[1:]
target=Path(target)
write=observer._write
def injected(path,raw):
    result=write(path,raw)
    if point=='marker' and path==target/'restore.pending':os._exit(91)
    if point=='files' and path==target/'lease.sqlite3':os._exit(92)
    if point=='receipt' and path==target/'restore.receipt.json':os._exit(93)
    return result
observer._write=injected
backup.restore(package,target,package_pin,profile_pin,minimum,bytes(range(32)))
raise SystemExit('requested loss boundary not reached')
'''
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    child = subprocess.run([binary, "-c", script, str(package), str(target), saved["backup_sha256"],
                            pin, last["receipt_sha256"], point], env=env, capture_output=True,
                           text=True, timeout=30, check=False)
    assert child.returncode == {"marker": 91, "files": 92, "receipt": 93}[point], child.stdout + child.stderr
    return source, signer, original, pin, last, package, saved, target


def resume(target, pin, minimum, package, saved, *, key=KEY):
    return backup.restore(package, target, saved["backup_sha256"], pin,
                          minimum["receipt_sha256"], key, resume=True)


@pytest.mark.parametrize("point", ["marker", "files", "receipt"])
def test_real_cli_resumes_exact_interrupted_candidate_and_preserves_start_and_existing_bytes(tmp_path, point):
    source, signer, original, pin, last, package, saved, target = interrupted(tmp_path, point)
    marker = json.loads((target / "restore.pending").read_bytes())
    before = {path: path.read_bytes() for path in target.iterdir() if path.is_file()}
    sources = {p: p.read_bytes() for p in (source.path, signer / "journal.sqlite3", original / "observer.sqlite3")}
    key = tmp_path / "recovery.key"
    key.write_bytes(KEY)
    key.chmod(0o600)
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    argv = [binary, "-m", "scripts.audit_witness_observer_backup", "resume-restore",
            "--package", str(package), "--destination", str(target), "--profile-sha256", pin,
            "--minimum-receipt", last["receipt_sha256"], "--backup-sha256", saved["backup_sha256"],
            "--key-file", str(key), "--key-sha256", sha(KEY)]
    child = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert result["resumed"] and not result["automatic_activation_allowed"]
    assert not (target / "restore.pending").exists()
    receipt = json.loads((target / "restore.receipt.json").read_bytes())
    assert receipt["started_at"] == marker["started_at"]
    for path, raw in before.items():
        if path.name != "restore.pending":
            assert path.read_bytes() == raw
    for path, raw in sources.items():
        assert path.read_bytes() == raw
    assert observer.status(target, pin, minimum_receipt=last["receipt_sha256"])["healthy"]
    checked = backup.inspect_restore(package, target, saved["backup_sha256"],
                                     result["restore_receipt_sha256"], pin, last["receipt_sha256"])
    assert checked["restore_started_at"] == marker["started_at"]
    # Completed candidates cannot be resumed again to refresh their start time.
    again = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert again.returncode == 1 and "refused" in again.stderr
    assert sha((target / "restore.receipt.json").read_bytes()) == result["restore_receipt_sha256"]


@pytest.mark.parametrize("change", ["profile_file", "partial_database", "extra_file", "bad_receipt",
                                     "marker_package", "marker_profile", "future_start", "old_start",
                                     "weak_minimum", "different_package", "wrong_key"])
def test_changed_or_partial_candidates_or_new_scope_are_never_repaired_by_overwriting(tmp_path, change):
    _, _, original, pin, last, package, saved, target = interrupted(
        tmp_path, "receipt" if change == "bad_receipt" else "files")
    key = KEY
    if change == "profile_file":
        (target / "profile.json").write_bytes(b"changed")
    elif change == "partial_database":
        path = target / "observer.sqlite3"
        path.write_bytes(path.read_bytes()[:10])
    elif change == "extra_file":
        (target / "unexpected").write_bytes(b"unowned")
    elif change == "bad_receipt":
        (target / "restore.receipt.json").write_bytes(b"changed")
    elif change in {"marker_package", "marker_profile", "future_start", "old_start"}:
        path = target / "restore.pending"
        marker = json.loads(path.read_bytes())
        if change == "marker_package":
            marker["backup_sha256"] = "f" * 64
        elif change == "marker_profile":
            marker["profile_sha256"] = "f" * 64
        else:
            marker["started_at"] = "2099-01-01T00:00:00+00:00" if change == "future_start" else "2000-01-01T00:00:00+00:00"
        path.write_text(json.dumps(marker))
    elif change == "weak_minimum":
        last["receipt_sha256"] = json.loads((original / "profile.json").read_bytes())["bootstrap_sha256"]
    elif change == "different_package":
        package = tmp_path / "new-package.aesgcm"
        saved = backup.backup(original, pin, last["receipt_sha256"], package, KEY)
    else:
        key = b"z" * 32
    before = {path: path.read_bytes() for path in target.iterdir() if path.is_file()}
    with pytest.raises((AuditTransferError, sqlite3.Error)):
        resume(target, pin, last, package, saved, key=key)
    for path, raw in before.items():
        assert path.read_bytes() == raw
    assert (target / "restore.pending").exists()
    with pytest.raises(AuditTransferError, match="restore is incomplete"):
        observer.cycle(target, pin, minimum_receipt=last["receipt_sha256"])


def test_active_finalize_lease_refuses_resume_without_removing_marker(tmp_path):
    _, _, _, pin, last, package, saved, target = interrupted(tmp_path)
    marker = (target / "restore.pending").read_bytes()
    with observer._database(target, lease=True, profile_pin=pin), pytest.raises(observer.ObserverBusy):
        resume(target, pin, last, package, saved)
    assert (target / "restore.pending").read_bytes() == marker
    assert resume(target, pin, last, package, saved)["resumed"]


def test_two_explicit_resumers_have_one_completion_and_do_not_overwrite_receipt(tmp_path):
    _, _, _, pin, last, package, saved, target = interrupted(tmp_path)

    def attempt(_index):
        try:
            return resume(target, pin, last, package, saved)
        except (AuditTransferError, OSError, sqlite3.Error):
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    successes = [r for r in results if r is not None]
    assert len(successes) == 1
    assert sha((target / "restore.receipt.json").read_bytes()) == successes[0]["restore_receipt_sha256"]
    assert observer.status(target, pin, minimum_receipt=last["receipt_sha256"])["healthy"]


@pytest.mark.parametrize("point,code", [("profile.json", 98), ("restore.receipt.json", 99)])
def test_another_actual_process_loss_during_resume_keeps_original_start_and_can_retry(tmp_path, point, code):
    _, signer, _, pin, last, package, saved, target = interrupted(tmp_path, "marker")
    marker = (target / "restore.pending").read_bytes()
    journal = (signer / "journal.sqlite3").read_bytes()
    script = r'''
import os,sys
from pathlib import Path
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
package,target,package_pin,profile_pin,minimum,point,code=sys.argv[1:]
target=Path(target)
write=observer._write
def injected(path,raw):
    result=write(path,raw)
    if path==target/point:os._exit(int(code))
    return result
observer._write=injected
backup.restore(package,target,package_pin,profile_pin,minimum,bytes(range(32)),resume=True)
raise SystemExit('resume loss boundary not reached')
'''
    binary, env = direct_python(dict(os.environ, AWS_EC2_METADATA_DISABLED="true"))
    child = subprocess.run([binary, "-c", script, str(package), str(target), saved["backup_sha256"], pin,
                            last["receipt_sha256"], point, str(code)], env=env, capture_output=True,
                           text=True, timeout=30, check=False)
    assert child.returncode == code, child.stdout + child.stderr
    assert (target / "restore.pending").read_bytes() == marker
    with pytest.raises(AuditTransferError, match="restore is incomplete"):
        observer.cycle(target, pin, minimum_receipt=last["receipt_sha256"])
    result = resume(target, pin, last, package, saved)
    receipt = json.loads((target / "restore.receipt.json").read_bytes())
    assert receipt["started_at"] == json.loads(marker)["started_at"]
    assert (signer / "journal.sqlite3").read_bytes() == journal
    assert result["resumed"] and not result["automatic_activation_allowed"]


@pytest.mark.skipif(os.name != "posix", reason="POSIX private file and nofollow contract")
@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public_mode", "lease_profile"])
def test_unsafe_existing_objects_do_not_get_replaced_to_finish_resume(tmp_path, kind):
    _, _, original, pin, last, package, saved, target = interrupted(tmp_path)
    path = target / "profile.json"
    if kind == "symlink":
        path.unlink()
        path.symlink_to(original / "profile.json")
    elif kind == "hardlink":
        os.link(path, tmp_path / "other-profile")
    elif kind == "public_mode":
        path.chmod(0o644)
    else:
        with sqlite3.connect(target / "lease.sqlite3") as con:
            con.execute("UPDATE lease SET profile_sha256=?", ("f" * 64,))
    marker = (target / "restore.pending").read_bytes()
    with pytest.raises(AuditTransferError):
        resume(target, pin, last, package, saved)
    assert (target / "restore.pending").read_bytes() == marker
