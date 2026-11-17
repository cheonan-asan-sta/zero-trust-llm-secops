import hashlib
import json
import os
import sqlite3
from datetime import timedelta

import pytest

from scripts import checkpoint_pam_observations as cli
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from tests.test_pam_journal import build, row
from tests.test_pam_journal import configured as configuration_fixture
from tests.test_pam_observation_ledger import admit, newer

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='private Linux observation ledger')


@pytest.fixture
def configured(tmp_path):
    return configuration_fixture.__wrapped__(tmp_path)


@pytest.fixture
def ledger(tmp_path, configured):
    result = PamObservationLedger(tmp_path/'ledger', configured.scope)
    result.initialize()
    return result


def test_empty_checkpoint_is_stable_and_has_no_freshness_or_identity_claim(ledger):
    first = ledger.checkpoint()
    assert first['captures'] == first['unique_events'] == 0
    assert not first['external_pin_matched']
    assert first == ledger.checkpoint()
    assert first['checkpoint_sha256'] == hashlib.sha256(canonical({
        k: v for k, v in first.items() if k not in {'checkpoint_sha256', 'external_pin_matched'}
    })).hexdigest()
    for field in ('current_freshness_verified', 'human_authenticated',
                  'authorization_asserted', 'automatic_enforcement_allowed', 'goal_qualified'):
        assert first[field] is False


def test_reopened_checkpoint_matches_external_pin_without_touching_database(ledger, configured):
    admit(ledger, configured, build(configured))
    before = ledger.path.read_bytes()
    first = ledger.checkpoint()
    reopened = PamObservationLedger(ledger.directory, configured.scope)
    checked = reopened.checkpoint(first['checkpoint_sha256'])
    assert checked['external_pin_matched'] and checked['contents_sha256'] == first['contents_sha256']
    assert ledger.path.read_bytes() == before


def test_detects_whole_database_rollback_with_a_separately_retained_new_pin(ledger, configured):
    f = configured
    admit(ledger, f, build(f))
    old_database = ledger.path.read_bytes()
    old = ledger.checkpoint()
    admit(ledger, f, newer(f, [row(f, 3)]))
    latest = ledger.checkpoint()
    ledger.path.write_bytes(old_database)
    assert ledger.inventory()['unique_events'] == 2  # Internally consistent older DB.
    with pytest.raises(ValueError, match='pam_checkpoint_mismatch'):
        ledger.checkpoint(latest['checkpoint_sha256'])
    # If the external witness is also rolled back, there is no protection.
    assert ledger.checkpoint(old['checkpoint_sha256'])['external_pin_matched']


def test_equal_counts_with_different_valid_observations_have_different_pins(ledger, configured, tmp_path):
    f = configured
    admit(ledger, f, build(f))
    pin = ledger.checkpoint()
    other = PamObservationLedger(tmp_path/'other', f.scope)
    other.initialize()
    admit(other, f, build(f, [row(f, 3), row(f, 4, close=True)]))
    changed = other.checkpoint()
    assert (pin['captures'], pin['unique_events']) == (changed['captures'], changed['unique_events'])
    assert pin['contents_sha256'] != changed['contents_sha256']
    ledger.path.write_bytes(other.path.read_bytes())
    with pytest.raises(ValueError, match='pam_checkpoint_mismatch'):
        ledger.checkpoint(pin['checkpoint_sha256'])


def test_overlapping_capture_and_duplicate_admission_metadata_remain_bound(ledger, configured):
    f = configured
    capture = build(f)
    admit(ledger, f, capture)
    initial = ledger.checkpoint()
    admit(ledger, f, capture, now=f.now+timedelta(seconds=1))
    duplicate = ledger.checkpoint()
    assert duplicate['unique_events'] == initial['unique_events']
    assert duplicate['contents_sha256'] != initial['contents_sha256']
    admit(ledger, f, newer(f, seconds=2))
    overlapping = ledger.checkpoint()
    assert overlapping['captures'] == 2 and overlapping['unique_events'] == 2
    assert overlapping['contents_sha256'] != duplicate['contents_sha256']


def test_explicit_signer_selection_does_not_reset_logical_checkpoint(ledger, configured):
    admit(ledger, configured, build(configured))
    changed_key = configured.scope.model_copy(update={'key_id': 'explicit-other-key'})
    # Historical storage inspection does not grant authority to this key.
    reopened = PamObservationLedger(ledger.directory, changed_key)
    assert reopened.checkpoint() == ledger.checkpoint()


@pytest.mark.parametrize('bad', ['', 'A'*64, 'f'*63, 'f'*65, None, True, 7])
def test_malformed_external_pin_is_not_silently_adopted(ledger, bad):
    if bad is None:
        assert ledger.checkpoint(bad)['external_pin_matched'] is False
    else:
        with pytest.raises(ValueError, match='pam_checkpoint_pin'):
            ledger.checkpoint(bad)


@pytest.mark.parametrize('sql', [
    "UPDATE events SET sha='altered'",
    "UPDATE captures SET body=X'7b7d'",
    "DELETE FROM events",
    "CREATE VIEW surprise AS SELECT * FROM events",
])
def test_no_checkpoint_is_issued_for_invalid_internal_inventory(ledger, configured, sql):
    admit(ledger, configured, build(configured))
    with sqlite3.connect(ledger.path) as con:
        con.execute(sql)
    with pytest.raises((ValueError, KeyError)):
        ledger.checkpoint()


def test_individually_valid_metadata_change_invalidates_old_external_pin(ledger, configured):
    admit(ledger, configured, build(configured))
    original = ledger.checkpoint()
    with sqlite3.connect(ledger.path) as con:
        con.execute('UPDATE metadata SET checked=?', ((configured.now+timedelta(seconds=2)).isoformat(),))
    assert ledger.inventory()['captures'] == 1
    with pytest.raises(ValueError, match='pam_checkpoint_mismatch'):
        ledger.checkpoint(original['checkpoint_sha256'])


def test_inventory_and_hash_share_one_writer_fence(ledger, configured, monkeypatch):
    admit(ledger, configured, build(configured))
    original = ledger._inventory
    attempts = []

    def fenced(con):
        result = original(con)
        with sqlite3.connect(ledger.path, timeout=0) as other:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                other.execute('BEGIN IMMEDIATE')
            attempts.append(True)
        return result

    monkeypatch.setattr(ledger, '_inventory', fenced)
    assert ledger.checkpoint()['completed'] and attempts == [True]


def test_physical_database_repacking_keeps_logical_pin(ledger, configured):
    admit(ledger, configured, build(configured))
    checkpoint = ledger.checkpoint()
    with sqlite3.connect(ledger.path) as con:
        con.execute('VACUUM')
    assert ledger.checkpoint(checkpoint['checkpoint_sha256'])['external_pin_matched']


def test_cli_fails_closed_without_echoing_paths_or_creating_missing_storage(ledger, configured, capsys, tmp_path):
    f = configured
    admit(ledger, f, build(f))
    args = ['--tenant', f.scope.tenant_id, '--server', f.scope.server_id, '--unit', f.scope.unit,
        '--source', f.scope.source_id, '--key-id', f.scope.key_id, '--ledger-directory', str(ledger.directory)]
    assert cli.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert cli.main([*args, '--expected-sha256', result['checkpoint_sha256']]) == 0
    assert json.loads(capsys.readouterr().out)['external_pin_matched']
    assert cli.main([*args, '--expected-sha256', 'f'*64]) == 2
    failure = capsys.readouterr().out
    assert json.loads(failure)['completed'] is False
    assert 'pam_unix(' not in failure and str(ledger.directory) not in failure
    absent = tmp_path/'PRIVATE_PATH_CANARY'
    assert cli.main([*args[:-1], str(absent)]) == 2
    assert 'PRIVATE_PATH_CANARY' not in capsys.readouterr().out and not absent.exists()
