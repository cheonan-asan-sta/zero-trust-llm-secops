import json
import os
import secrets
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_observation_backup import FLAGS, PamObservationBackup, sha
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from tests.test_pam_journal import build
from tests.test_pam_journal import configured as configuration_fixture
from tests.test_pam_observation_ledger import admit, newer

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='private Linux observation ledger')


@pytest.fixture
def fixture(tmp_path):
    f = configuration_fixture.__wrapped__(tmp_path)
    ledger = PamObservationLedger(tmp_path/'source', f.scope)
    ledger.initialize()
    admit(ledger, f, build(f))
    for name in ('packages', 'checkpoints', 'reviews'):
        (tmp_path/name).mkdir(mode=0o700)
    return SimpleNamespace(f=f, ledger=ledger, manager=PamObservationBackup(ledger),
        package=tmp_path/'packages/one', checkpoint=tmp_path/'checkpoints/one.json',
        review=tmp_path/'reviews/one', key=secrets.token_bytes(32), key_id='pam-recovery-1')


def backup(f):
    return f.manager.backup(f.package, f.checkpoint,
        f.ledger.checkpoint()['checkpoint_sha256'], f.key, f.key_id)


def restore(f, backed):
    return f.manager.restore(f.package, f.review, f.checkpoint,
        backed['checkpoint_sha256'], f.key, f.key_id)


def status(f, backed, restored):
    return f.manager.status(f.package, f.review, f.checkpoint,
        backed['checkpoint_sha256'], restored['review_receipt_sha256'])


def test_encrypted_copy_survives_source_loss_without_recreating_live_store(fixture):
    f = fixture
    original = f.ledger.path.read_bytes()
    checkpoint = f.ledger.checkpoint()
    backed = backup(f)
    ciphertext = (f.package/'payload.aesgcm').read_bytes()
    assert original not in ciphertext and not ciphertext.startswith(b'SQLite format 3')
    assert f.key not in ciphertext
    shutil.rmtree(f.ledger.directory)
    restored = restore(f, backed)
    assert not f.ledger.directory.exists()
    assert (f.review/'review.sqlite3').read_bytes() == original
    assert not (f.review/'observations.sqlite3').exists()
    checked = status(f, backed, restored)
    assert checked['completed'] and checked['unique_events'] == 2
    assert f.manager.inspect_database(original, checkpoint['checkpoint_sha256'])['external_pin_matched']
    for result in (backed, restored, checked):
        assert all(result[k] is False for k in FLAGS)
    for path in (f.package/'payload.aesgcm', f.package/'manifest.json',
                 f.checkpoint, f.review/'review.sqlite3', f.review/'restore.json'):
        assert path.stat().st_mode & 0o777 == 0o600
        assert f.key not in path.read_bytes()


def test_wrong_observation_pin_creates_no_package_or_checkpoint(fixture):
    f = fixture
    with pytest.raises(ValueError, match='checkpoint_mismatch'):
        f.manager.backup(f.package, f.checkpoint, 'f'*64, f.key, f.key_id)
    assert not f.package.exists() and not f.checkpoint.exists()


@pytest.mark.parametrize('damage', ['key', 'key_id', 'outer_pin', 'checkpoint', 'manifest', 'payload'])
def test_wrong_keys_or_pins_and_damaged_bytes_refuse_before_destination_exists(fixture, damage):
    f = fixture
    backed = backup(f)
    key, key_id, pin = f.key, f.key_id, backed['checkpoint_sha256']
    if damage == 'key':
        key = secrets.token_bytes(32)
    elif damage == 'key_id':
        key_id = 'different-key'
    elif damage == 'outer_pin':
        pin = 'f'*64
    else:
        path = {'checkpoint': f.checkpoint, 'manifest': f.package/'manifest.json',
                'payload': f.package/'payload.aesgcm'}[damage]
        path.write_bytes(path.read_bytes()+b'!')
    with pytest.raises(ValueError):
        f.manager.restore(f.package, f.review, f.checkpoint, pin, key, key_id)
    assert not f.review.exists()


@pytest.mark.parametrize('damage', ['ciphertext', 'review_db', 'receipt', 'extra_package', 'extra_review', 'missing_review'])
def test_keyless_monitor_drops_all_cached_counts_after_any_evidence_loss(fixture, damage):
    f = fixture
    backed = backup(f)
    restored = restore(f, backed)
    assert status(f, backed, restored)['unique_events'] == 2
    if damage == 'missing_review':
        shutil.rmtree(f.review)
    elif damage == 'extra_package':
        (f.package/'unexpected').write_bytes(b'foreign')
    elif damage == 'extra_review':
        (f.review/'unexpected').write_bytes(b'foreign')
    else:
        path = {'ciphertext': f.package/'payload.aesgcm', 'review_db': f.review/'review.sqlite3',
                'receipt': f.review/'restore.json'}[damage]
        path.write_bytes(path.read_bytes()+b'!')
    failed = status(f, backed, restored)
    assert not failed['completed'] and failed['state'] == 'unavailable'
    assert failed['captures'] is failed['unique_events'] is None
    assert all(failed[k] is False for k in FLAGS)


def test_repair_of_exact_bytes_preserves_original_restore_time_without_key(fixture):
    f = fixture
    backed = backup(f)
    restored = restore(f, backed)
    receipt = (f.review/'restore.json').read_bytes()
    original = (f.package/'payload.aesgcm').read_bytes()
    (f.package/'payload.aesgcm').write_bytes(original+b'!')
    assert not status(f, backed, restored)['completed']
    (f.package/'payload.aesgcm').write_bytes(original)
    f.key = None  # No decryption/signing key input is part of status().
    assert status(f, backed, restored)['completed']
    assert (f.review/'restore.json').read_bytes() == receipt


@pytest.mark.parametrize('operation', ['backup_source', 'backup_child', 'checkpoint_source', 'restore_source', 'restore_package'])
def test_original_store_and_overlapping_paths_are_never_destinations(fixture, operation):
    f = fixture
    if operation.startswith('restore'):
        backed = backup(f)
        destination = f.ledger.directory if operation == 'restore_source' else f.package/'nested'
        with pytest.raises(ValueError, match='overlap'):
            f.manager.restore(f.package, destination, f.checkpoint,
                backed['checkpoint_sha256'], f.key, f.key_id)
    else:
        output = f.ledger.directory if operation == 'backup_source' else f.package
        if operation == 'backup_child':
            output = f.ledger.directory/'nested'
        checkpoint = f.ledger.directory/'witness' if operation == 'checkpoint_source' else f.checkpoint
        with pytest.raises(ValueError, match='overlap'):
            f.manager.backup(output, checkpoint, f.ledger.checkpoint()['checkpoint_sha256'], f.key, f.key_id)
    assert f.ledger.inventory()['unique_events'] == 2


def test_existing_package_checkpoint_and_review_are_never_overwritten(fixture):
    f = fixture
    backed = backup(f)
    original_pin = f.checkpoint.read_bytes()
    with pytest.raises(ValueError, match='fresh_checkpoint'):
        backup(f)
    restored = restore(f, backed)
    before = (f.review/'restore.json').read_bytes()
    with pytest.raises(FileExistsError):
        restore(f, backed)
    assert (f.review/'restore.json').read_bytes() == before and f.checkpoint.read_bytes() == original_pin
    assert status(f, backed, restored)['completed']


@pytest.mark.parametrize('damage', ['symlink', 'hardlink', 'permissions'])
def test_unsafe_package_files_are_refused(fixture, tmp_path, damage):
    f = fixture
    backed = backup(f)
    path = f.package/'payload.aesgcm'
    if damage == 'permissions':
        path.chmod(0o644)
    elif damage == 'hardlink':
        os.link(path, tmp_path/'second-link')
    else:
        path.rename(tmp_path/'real-payload')
        path.symlink_to(tmp_path/'real-payload')
    with pytest.raises((OSError, ValueError)):
        restore(f, backed)
    assert not f.review.exists()


def test_future_manifest_is_refused_even_with_new_operator_byte_pin(fixture):
    f = fixture
    backup(f)
    path = f.package/'manifest.json'
    manifest = json.loads(path.read_bytes())
    manifest['created_at'] = (datetime.now(UTC)+timedelta(days=1)).isoformat()
    path.write_bytes(canonical(manifest)+b'\n')
    pin = json.loads(f.checkpoint.read_bytes())
    pin['manifest_sha256'] = sha(path.read_bytes())
    f.checkpoint.write_bytes(canonical(pin)+b'\n')
    with pytest.raises(ValueError, match='future_package'):
        f.manager.restore(f.package, f.review, f.checkpoint, sha(f.checkpoint.read_bytes()), f.key, f.key_id)
    assert not f.review.exists()


def test_new_live_admissions_do_not_renew_or_expand_the_older_review(fixture):
    f = fixture
    backed = backup(f)
    admit(f.ledger, f.f, newer(f.f))
    assert f.ledger.inventory()['captures'] == 2
    restored = restore(f, backed)
    assert status(f, backed, restored)['captures'] == 1


def test_damaged_source_cannot_be_packaged_as_valid_history(fixture):
    f = fixture
    old_pin = f.ledger.checkpoint()['checkpoint_sha256']
    with sqlite3.connect(f.ledger.path) as con:
        con.execute('DELETE FROM events')
    with pytest.raises(ValueError):
        f.manager.backup(f.package, f.checkpoint, old_pin, f.key, f.key_id)
    assert not f.package.exists() and not f.checkpoint.exists()
