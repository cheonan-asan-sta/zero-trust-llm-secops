"""Interrupted work cannot regain authorization or cause another command."""

import json
import sys
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature

from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.exec_intent import ExecIntentJournal
from scripts.f1_lab.operation_context import canonical
from tests.test_managed_exec_retention import fixture

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='private POSIX intent contracts')


def journal(f):
    return ExecIntentJournal(f.intents,f.lab.broker.joiner.registry,f.lab.broker.registry)


def reconcile(f, request_id, **kwargs):
    return journal(f).reconcile(request_id,f.lab.broker,f.lab.operations,f.root,f.outbox,**kwargs)


def test_normal_dispatch_persists_intent_and_same_original_before_outbox(tmp_path):
    f = fixture(tmp_path)
    gate, _, _, raw = f.execute()
    run = f.intents/gate.request.request_id
    value = journal(f).load(gate.request.request_id)
    assert value.request == gate.request
    assert (run/'capture.json').read_bytes() == raw
    body = (run/'intent.json').read_bytes()
    assert gate.token.encode() not in body and gate.access.grant_token.encode() not in body
    assert gate.principal.subject.encode() not in body and gate.access.session_id.encode() not in body
    report = reconcile(f,gate.request.request_id)
    assert report['state'] == 'sealed_original_verified' and report['app_grant_consumed']
    assert report['publication_resumed'] is report['authorization_asserted'] is False
    assert len(f.launches) == 1


def test_completed_bytes_recover_before_outbox_without_any_command_or_grant_retry(tmp_path):
    f = fixture(tmp_path)
    gate = f.lab.gate(f.lab.new_request(),f.lab.new_access())
    with (patch.object(retention,'fresh_file',side_effect=OSError('owned pre-outbox fault')),
          pytest.raises(OSError)):
        retention.dispatch_and_retain(gate,f.launcher,f.lab.permission,f.root,f.outbox,intent_root=f.intents)
    original = (f.intents/gate.request.request_id/'capture.json').read_bytes()
    assert not list(f.outbox.glob('*.json')) and not (f.root/'latest.json').exists()
    with (patch.object(f.lab.broker,'dispatch',side_effect=AssertionError('no dispatch')),
          patch.object(f.lab.broker,'issue',side_effect=AssertionError('no issue')),
          patch.object(f.lab.operations,'access',side_effect=AssertionError('no access'))):
        for _ in range(2):
            report = reconcile(f,gate.request.request_id,resume=True)
            assert report['publication_resumed']
    assert (f.outbox/(gate.request.request_id+'.json')).read_bytes() == original
    assert (f.root/'latest.json').read_bytes() == original
    assert len(f.launches) == 1 and not report['command_reexecuted'] and not report['grant_refunded']


def test_post_exec_pre_seal_failure_remains_indeterminate_even_with_worker_and_used_grant(tmp_path):
    f = fixture(tmp_path)
    gate = f.lab.gate(f.lab.new_request(),f.lab.new_access())
    with (patch.object(retention,'seal_completed',side_effect=OSError('owned pre-seal fault')),
          pytest.raises(OSError)):
        retention.dispatch_and_retain(gate,f.launcher,f.lab.permission,f.root,f.outbox,intent_root=f.intents)
    assert len(f.launches) == 1
    for resume in (False,True):
        report = reconcile(f,gate.request.request_id,resume=resume)
        assert report['state'] == 'indeterminate' and report['worker_artifact_present']
        assert report['app_grant_consumed'] and report['broker_state'] == 'bound'
        assert not report['sealed_original_available'] and not report['publication_resumed']
    assert not (f.root/'latest.json').exists() and not list(f.outbox.glob('*.json'))
    assert not (f.intents/gate.request.request_id/'capture.json').exists()


def test_pre_dispatch_intent_is_only_a_proposal_and_does_not_consume_or_launch(tmp_path):
    f = fixture(tmp_path)
    gate = f.lab.gate(f.lab.new_request(),f.lab.new_access())
    journal(f).prepare(gate,f.launcher,f.root,f.outbox)
    report = reconcile(f,gate.request.request_id,resume=True)
    assert report['state'] == 'indeterminate' and report['broker_state'] == 'pending'
    assert not report['app_grant_consumed'] and not report['worker_artifact_present']
    assert not report['publication_resumed'] and not f.launches


@pytest.mark.parametrize('field', ['signature','policy_sha256','proposed_caller_ref_sha256',
                                  'session_ref_sha256','worker_directory','resource_id'])
def test_modified_signed_intent_never_resumes(field,tmp_path):
    f = fixture(tmp_path)
    gate,_,_,_ = f.execute()
    p = f.intents/gate.request.request_id/'intent.json'
    value = json.loads(p.read_bytes())
    value[field] = 'B'*86 if field == 'signature' else '/tmp/other' if field == 'worker_directory' else 'f'*64
    p.write_bytes(canonical(value))
    with pytest.raises((ValueError,InvalidSignature)):
        reconcile(f,gate.request.request_id,resume=True)
    assert len(f.launches) == 1


@pytest.mark.parametrize('part', ['intent_link','intent_hardlink','capture_link','capture_damage','unknown_file'])
def test_linked_damaged_or_partial_private_inventory_is_not_silently_reused(part,tmp_path):
    import os

    f = fixture(tmp_path)
    gate,_,_,_ = f.execute()
    run = f.intents/gate.request.request_id
    if part in {'intent_link','capture_link'}:
        p = run/('intent.json' if part == 'intent_link' else 'capture.json')
        backup = tmp_path/'owned-copy'
        backup.write_bytes(p.read_bytes())
        backup.chmod(0o600)
        p.unlink()
        p.symlink_to(backup)
    elif part == 'intent_hardlink':
        os.link(run/'intent.json',tmp_path/'owned-link')
    elif part == 'capture_damage':
        (run/'capture.json').write_bytes(b'{}')
    else:
        (run/'unknown.tmp').write_bytes(b'interrupted')
    with pytest.raises((ValueError,OSError,InvalidSignature)):
        reconcile(f,gate.request.request_id,resume=True)
    assert len(f.launches) == 1


def test_app_record_or_broker_receipt_loss_cannot_be_replaced_by_intent(tmp_path):
    f = fixture(tmp_path)
    gate,_,_,_ = f.execute()
    with f.lab.broker.connect() as con:
        con.execute('UPDATE requests SET receipt=NULL WHERE id=?',(gate.request.request_id,))
    with pytest.raises(ValueError,match='exec_intent_reconciliation_incomplete'):
        reconcile(f,gate.request.request_id,resume=True)
    assert len(f.launches) == 1


def test_other_request_worker_file_cannot_explain_unsealed_intent(tmp_path):
    f = fixture(tmp_path)
    gate = f.lab.gate(f.lab.new_request(),f.lab.new_access())
    journal(f).prepare(gate,f.launcher,f.root,f.outbox)
    (f.launcher.directory/'capture.json').write_bytes(canonical({'request_sha256':'f'*64}))
    (f.launcher.directory/'capture.json').chmod(0o600)
    with pytest.raises(ValueError,match='exec_intent_worker_request'):
        reconcile(f,gate.request.request_id,resume=True)
    assert not f.launches


def test_current_policy_or_pin_change_prevents_automatic_republication(tmp_path):
    f = fixture(tmp_path)
    gate,_,_,_ = f.execute()
    f.lab.broker.registry.path.write_bytes(b'{}')
    with pytest.raises(ValueError):
        reconcile(f,gate.request.request_id,resume=True)
    assert len(f.launches) == 1


def test_invalid_and_overlapping_intent_root_is_rejected_before_launch(tmp_path):
    f = fixture(tmp_path)
    gate = f.lab.gate(f.lab.new_request(),f.lab.new_access())
    with pytest.raises(ValueError,match='outbox_path_overlap'):
        retention.dispatch_and_retain(gate,f.launcher,f.lab.permission,f.root,f.outbox,intent_root=f.outbox)
    assert not f.launches and not gate.used
