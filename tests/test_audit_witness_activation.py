"""Manual restore activation controls the operational witness entry point."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest
from test_witness_observer_backup import KEY, fixture, restore

from app.services import audit_witness as witness
from app.services import audit_witness_activation as activation
from app.services import audit_witness_observer as observer
from app.services import audit_witness_observer_backup as backup
from app.services.audit_transfer import AuditTransferError


def prepared(tmp_path):
    source, signer, _, original, profile, last, package, report = fixture(tmp_path)
    candidate = tmp_path / "restored"
    recovered = restore(tmp_path, profile, last, package, report)
    journal = tmp_path / "activation.sqlite3"
    activation.initialize(journal)
    params = (journal, candidate, package, report["backup_sha256"],
              recovered["restore_receipt_sha256"], profile, last["receipt_sha256"], witness.GENESIS)
    return source, signer, original, params


def approve(params):
    reviewed = activation.plan(*params)
    return activation.activate(*params, reviewed["approval_sha256"], "operator-1")["activation_sha256"]


def cli(module, *args):
    return subprocess.run([sys.executable, "-m", module, *map(str, args)], capture_output=True,
                          text=True, encoding="utf-8", timeout=60, check=False)


def test_real_cli_watch_requires_approval_and_resumes_after_restart(tmp_path):
    source, signer, original, params = prepared(tmp_path)
    journal, candidate, _, _, receipt, profile, minimum, _ = params
    flags = ("--directory", candidate, "--profile-sha256", profile, "--minimum-receipt", minimum)
    before = (signer / "journal.sqlite3").read_bytes()
    for action in ("watch", "cycle"):
        assert cli("scripts.audit_witness_observer", action, *flags).returncode == 1
    assert (signer / "journal.sqlite3").read_bytes() == before
    pin = approve(params)
    old = (original / "observer.sqlite3").read_bytes()
    source_bytes = source.path.read_bytes()
    for anchors in (2, 3):
        output = cli("scripts.audit_witness_activation", "watch", "--journal", journal,
                     "--activation-sha256", pin, "--minimum-receipt", minimum, "--cycles", 1)
        assert output.returncode == 0, output.stderr
        result = json.loads(output.stdout)
        assert result["cycle_success"] and result["anchor_count"] == anchors
    assert (original / "observer.sqlite3").read_bytes() == old
    assert source.path.read_bytes() == source_bytes
    assert backup.inspect_restore(params[2], candidate, params[3], receipt, profile,
                                  minimum)["current_scope"]["anchor_count"] == 3
    history = activation.history(journal, pin)
    assert history["active_sha256"] == pin
    assert [row["kind"] for row in history["events"]] == [
        "approval_submitted", "approved", "activated",
    ]


@pytest.mark.parametrize("fault", ["approval", "stale", "receipt", "signer"])
def test_refused_switch_is_recorded_and_does_not_change_selection(tmp_path, fault):
    _, signer, original, params = prepared(tmp_path)
    journal, candidate, _, _, _, profile, minimum, _ = params
    approval = activation.plan(*params)["approval_sha256"]
    if fault == "approval":
        approval = "a" * 64
    elif fault == "stale":
        observer.cycle(original, profile, minimum_receipt=minimum)
    elif fault == "receipt":
        (candidate / "restore.receipt.json").write_bytes(b"damaged")
    else:
        (signer / "private.key").unlink()
    before = (signer / "journal.sqlite3").read_bytes()
    with pytest.raises((AuditTransferError, OSError)):
        activation.activate(*params, approval, "operator-1")
    assert (signer / "journal.sqlite3").read_bytes() == before
    audited = activation.history(journal)
    assert audited["active_sha256"] == witness.GENESIS
    assert [row["kind"] for row in audited["events"]] == ["approval_submitted", "activation_failed"]
    assert len({row["attempt"] for row in audited["events"]}) == 1


def test_new_selection_fences_old_managed_cycles(tmp_path):
    _, signer, _, params = prepared(tmp_path)
    journal, candidate, _, _, _, profile, minimum, _ = params
    first = approve(params)
    new_package = tmp_path / "next.aesgcm"
    saved = backup.backup(candidate, profile, minimum, new_package, KEY)
    next_control = tmp_path / "next"
    recovered = backup.restore(new_package, next_control, saved["backup_sha256"], profile,
                               minimum, KEY)
    new_params = (journal, next_control, new_package, saved["backup_sha256"],
                  recovered["restore_receipt_sha256"], profile, minimum, first)
    second = approve(new_params)
    before = (signer / "journal.sqlite3").read_bytes()
    with pytest.raises(AuditTransferError, match="approved active restore"):
        activation.cycle(journal, first, minimum)
    assert (signer / "journal.sqlite3").read_bytes() == before
    assert activation.cycle(journal, second, minimum)["receipt_sha256"] != minimum
    result = activation.history(journal, first)
    assert result["active_sha256"] == second
    assert result["events"][-1]["kind"] == "collection_failed"


def test_failed_publication_rolls_back_approval_and_preserves_prior_selection(tmp_path, monkeypatch):
    _, _, _, params = prepared(tmp_path)
    journal = params[0]
    plan = activation.plan(*params)
    append = activation._append

    def refuse(con, head, count, kind, **fields):
        if kind == "activated":
            raise OSError("simulated selection write failure")
        return append(con, head, count, kind, **fields)

    monkeypatch.setattr(activation, "_append", refuse)
    with pytest.raises(OSError, match="selection write failure"):
        activation.activate(*params, plan["approval_sha256"], "operator-1")
    result = activation.history(journal)
    assert result["active_sha256"] == witness.GENESIS
    assert [row["kind"] for row in result["events"]] == ["approval_submitted", "activation_failed"]


def test_managed_cycle_and_candidate_revalidation_are_serialized(tmp_path, monkeypatch):
    _, _, _, params = prepared(tmp_path)
    journal, candidate, package, _, _, profile, minimum, _ = params
    active = approve(params)
    next_candidate = tmp_path / "same-head-copy"
    next_package = package.with_name("concurrent.aesgcm")
    saved = backup.backup(candidate, profile, minimum, next_package, KEY)
    restored = backup.restore(next_package, next_candidate, saved["backup_sha256"], profile,
                              minimum, KEY)
    competing = (journal, next_candidate, next_package, saved["backup_sha256"],
                 restored["restore_receipt_sha256"], profile, minimum, active)
    review = activation.plan(*competing)["approval_sha256"]
    entered, release = Event(), Event()
    original = observer.cycle

    def held_cycle(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(observer, "cycle", held_cycle)
    with ThreadPoolExecutor(max_workers=2) as workers:
        collection = workers.submit(activation.cycle, journal, active, minimum)
        assert entered.wait(5)
        selection = workers.submit(activation.activate, *competing, review, "operator-2")
        release.set()
        assert collection.result(timeout=10)["receipt_sha256"] != minimum
        with pytest.raises(AuditTransferError, match="disagrees with live witness"):
            selection.result(timeout=10)
    assert activation.history(journal)["active_sha256"] == active
