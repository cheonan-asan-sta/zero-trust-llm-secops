import base64
import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import admit_pam_journal as cli
from scripts.f1_lab import pam_journal as pam
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from scripts.f1_lab.shared_execution_evidence import PinnedServiceRegistry
from tests.test_pam_journal import build, row
from tests.test_pam_journal import configured as configuration_fixture

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='private Linux observation ledger')


@pytest.fixture
def configured(tmp_path):
    return configuration_fixture.__wrapped__(tmp_path)


@pytest.fixture
def ledger(configured, tmp_path):
    result = PamObservationLedger(tmp_path/'ledger', configured.scope)
    result.initialize()
    return result


def admit(ledger, f, capture, **changes):
    args = {'boot': f.boot, 'invocation': f.invocation, 'now': capture.issued_at}
    args.update(changes)
    return ledger.admit(capture, f.pinned, **args)


def newer(f, rows=None, seconds=1):
    return build(f, rows, now=f.now+timedelta(seconds=seconds),
                 window_end_us=pam.micros(f.now)+seconds*1000000)


def test_repeated_capture_is_idempotent_after_reopening(ledger, configured):
    f = configured
    capture = build(f)
    first = admit(ledger, f, capture)
    reopened = PamObservationLedger(ledger.directory, f.scope)
    second = admit(reopened, f, capture, now=f.now+timedelta(seconds=1))
    assert first['new_events'] == 2 and not first['duplicate_capture']
    assert second['new_events'] == 0 and second['duplicate_capture']
    assert reopened.inventory()['unique_events'] == 2
    assert second['original_window_end_us'] == first['original_window_end_us']


def test_overlapping_new_capture_keeps_original_events_and_times(ledger, configured):
    f = configured
    first = admit(ledger, f, build(f))
    second = admit(ledger, f, newer(f))
    assert second['new_events'] == 0 and second['overlapping_events'] == 2
    assert second['capture_sha256'] != first['capture_sha256']
    assert ledger.inventory()['captures'] == 2 and ledger.inventory()['unique_events'] == 2


def test_another_export_serialization_is_not_another_event(ledger, configured):
    f = configured
    admit(ledger, f, build(f))
    # Same trusted fields/cursor/message/time, different byte order of JSON.
    import json
    reserialized = [json.dumps(json.loads(row(f)), sort_keys=False, indent=1).encode(),
                    json.dumps(json.loads(row(f, 2, close=True)), sort_keys=False, indent=1).encode()]
    result = admit(ledger, f, newer(f, reserialized))
    assert result['new_events'] == 0 and result['overlapping_events'] == 2
    assert ledger.inventory()['unique_events'] == 2


@pytest.mark.parametrize('field,value', [('_PID', '999'), ('_UID', '1'),
    ('__REALTIME_TIMESTAMP', None), ('MESSAGE', 'pam_unix(sudo:session): session opened for user root by (uid=1)')])
def test_same_cursor_conflicting_authenticated_fields_roll_back(ledger, configured, field, value):
    f = configured
    admit(ledger, f, build(f))
    if value is None:
        value = str(pam.micros(f.now)-1000000)
    collision = newer(f, [row(f, **{field: value})])
    with pytest.raises(ValueError, match='cursor_conflict'):
        admit(ledger, f, collision)
    assert ledger.inventory()['captures'] == 1 and ledger.inventory()['unique_events'] == 2


def test_new_cursor_with_same_message_and_pid_is_retained(ledger, configured):
    f = configured
    admit(ledger, f, build(f))
    result = admit(ledger, f, newer(f, [row(f, 3)]))
    assert result['new_events'] == 1 and ledger.inventory()['unique_events'] == 3


def test_verified_empty_is_never_normal_or_human_authenticated(ledger, configured):
    f = configured
    result = admit(ledger, f, build(f, []))
    assert result['new_events'] == result['unique_events_retained'] == 0
    assert not result['human_authenticated'] and not result['authorization_asserted']
    assert not result['automatic_enforcement_allowed'] and not result['goal_qualified']
    assert 'normal' not in result
    assert ledger.inventory()['captures'] == 1


def test_clock_regression_and_capture_expiry_never_refresh_old_event(ledger, configured):
    f = configured
    capture = build(f)
    admit(ledger, f, capture, now=f.now+timedelta(seconds=2))
    with pytest.raises(ValueError, match='clock_regression'):
        admit(ledger, f, capture, now=f.now+timedelta(seconds=1))
    with pytest.raises(ValueError, match='expiry'):
        admit(ledger, f, capture, now=capture.expires_at)
    assert ledger.inventory()['unique_events'] == 2


def test_older_unseen_capture_cannot_replace_latest(ledger, configured):
    f = configured
    admit(ledger, f, newer(f, seconds=2))
    with pytest.raises(ValueError, match='capture_regression'):
        admit(ledger, f, newer(f), now=f.now+timedelta(seconds=3))
    assert ledger.inventory()['captures'] == 1


def test_duplicate_old_capture_never_replaces_newest_or_adds_events(ledger, configured):
    f = configured
    original = build(f)
    admit(ledger, f, original)
    newest = admit(ledger, f, newer(f, [row(f, 3)]))
    result = admit(ledger, f, original, now=f.now+timedelta(seconds=2))
    assert result['duplicate_capture'] and result['new_events'] == 0
    with sqlite3.connect(ledger.path) as con:
        assert con.execute('SELECT latest FROM metadata').fetchone()[0] == newest['capture_sha256']
    assert ledger.inventory()['unique_events'] == 3


def test_explicit_new_key_does_not_reset_dedup_or_reenable_revoked_key(ledger, configured):
    f = configured
    admit(ledger, f, build(f))
    key = Ed25519PrivateKey.generate()
    new_auth = next(a for a in f.registry.authorities if a.kind == 'authentication').model_copy(update={
        'key_id': 'auth-2', 'issued_at': f.now+timedelta(seconds=1),
        'public_key': base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip('=')})
    registry = f.registry.model_copy(update={'version': 2, 'authorities': [
        a.model_copy(update={'enabled': False}) if a.kind == 'authentication' else a for a in f.registry.authorities]+[new_auth]})
    f.path.write_bytes(canonical(registry.model_dump(mode='json')))
    pinned = PinnedServiceRegistry(f.path, hashlib.sha256(f.path.read_bytes()).hexdigest())
    scope = f.scope.model_copy(update={'key_id': 'auth-2'})
    capture = pam.build([row(f),row(f,2,close=True)],scope,pinned,key,boot=f.boot,invocation=f.invocation,
        window_start_us=pam.micros(f.now)-5000000,window_end_us=pam.micros(f.now)+1000000,
        now=f.now+timedelta(seconds=1))
    reopened = PamObservationLedger(ledger.directory,scope)
    result = reopened.admit(capture,pinned,boot=f.boot,invocation=f.invocation,now=capture.issued_at)
    assert result['new_events'] == 0 and result['overlapping_events'] == 2
    assert reopened.inventory()['captures'] == 2 and reopened.inventory()['unique_events'] == 2
    assert not next(a for a in registry.authorities if a.key_id == 'auth-1').enabled


@pytest.mark.parametrize('option', ['captures', 'events'])
def test_capacity_failure_keeps_all_original_observations(tmp_path,configured,option):
    f=configured
    ledger=PamObservationLedger(tmp_path/'bounded',f.scope,capacity=1 if option=='captures' else 1000,event_capacity=2)
    ledger.initialize()
    admit(ledger,f,build(f))
    with pytest.raises(ValueError,match='capacity'):
        admit(ledger,f,newer(f,[row(f,3)]))
    assert ledger.inventory()['captures']==1 and ledger.inventory()['unique_events']==2


@pytest.mark.parametrize('sql', [
    "UPDATE events SET sha='broken'",
    "UPDATE captures SET body=X'7b7d'",
    "UPDATE captures SET new_events=0",
    "UPDATE events SET first_capture='missing'",
    "UPDATE metadata SET latest='missing'",
    "DELETE FROM events",
    "CREATE TRIGGER surprise AFTER INSERT ON captures BEGIN SELECT 1; END",
])
def test_damaged_or_foreign_store_is_not_reused_for_new_admission(ledger,configured,sql):
    f=configured
    admit(ledger,f,build(f))
    with sqlite3.connect(ledger.path) as con:con.execute(sql)
    with pytest.raises((ValueError,KeyError)):
        admit(ledger,f,newer(f))


@pytest.mark.parametrize('damage',['symlink','hardlink','permissions','wal_link'])
def test_unsafe_database_files_fail_without_following_links(ledger,configured,tmp_path,damage):
    f=configured
    if damage=='permissions':ledger.path.chmod(0o644)
    elif damage=='hardlink':os.link(ledger.path,tmp_path/'other')
    elif damage=='symlink':
        ledger.path.rename(tmp_path/'original')
        ledger.path.symlink_to(tmp_path/'original')
    else:ledger.path.with_name(ledger.path.name+'-wal').symlink_to(tmp_path/'missing')
    with pytest.raises(ValueError):admit(ledger,f,build(f))


def test_concurrent_same_capture_is_stored_once(ledger,configured):
    f=configured
    capture=build(f)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:admit(ledger,f,capture),range(2)))
    assert sorted(r['new_events'] for r in results)==[0,2]
    assert ledger.inventory()['captures']==1 and ledger.inventory()['unique_events']==2


def test_scope_and_capacity_changes_need_new_explicit_storage(ledger,configured):
    f=configured
    for modified in [PamObservationLedger(ledger.directory,f.scope,capacity=999),
                     PamObservationLedger(ledger.directory,f.scope.model_copy(update={'server_id':'another'}))]:
        with pytest.raises(ValueError,match='scope_or_config'):modified.inventory()
    with pytest.raises(ValueError,match='fresh_directory'):ledger.initialize()


def test_cli_uses_real_pin_and_exposes_no_key_or_raw_message(tmp_path,configured,capsys):
    f=configured
    capture=build(f)
    path=tmp_path/'capture.json';path.write_bytes(canonical(capture.model_dump(mode='json'))+b'\n');path.chmod(0o600)
    args=['--tenant',f.scope.tenant_id,'--server',f.scope.server_id,'--unit',f.scope.unit,
        '--source',f.scope.source_id,'--key-id',f.scope.key_id,'--registry',str(f.path),
        '--registry-sha256',f.pinned.expected_sha256,'--capture',str(path),
        '--capture-sha256',hashlib.sha256(path.read_bytes()).hexdigest(),'--boot-id',f.boot,
        '--invocation-id',f.invocation,'--ledger-directory',str(tmp_path/'cli-ledger')]
    assert cli.main([*args,'--initialize'])==0
    assert cli.main(args)==0
    output=capsys.readouterr().out
    assert 'PRIVATE KEY' not in output and 'pam_unix(' not in output
    ledger=PamObservationLedger(tmp_path/'cli-ledger',f.scope)
    assert ledger.inventory()['unique_events']==2
    assert b'PRIVATE KEY' not in ledger.path.read_bytes() and b'pam_unix(' not in ledger.path.read_bytes()
    path.write_bytes(path.read_bytes()+b' ')
    assert cli.main(args)==2
    assert 'unavailable' in capsys.readouterr().out
