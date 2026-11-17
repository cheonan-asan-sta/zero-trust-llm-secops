"""A successful later request cannot hide a pre-seal interrupted request."""

import json
import shutil
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature

from scripts.f1_lab import exec_recovery_inventory as mod
from scripts.f1_lab import managed_exec_retention as retention
from scripts.f1_lab.capture_archive import ArchivePolicy, CaptureArchive
from scripts.f1_lab.exec_intent import ExecIntentJournal
from scripts.f1_lab.operation_context import canonical
from tests.test_managed_exec_retention import fixture

pytestmark=pytest.mark.skipif(sys.platform!='linux',reason='private POSIX recovery inventory')


def inspect(f,**kwargs):
    return mod.inspect_recovery(f.intents,f.root,f.archive_scope,f.lab.broker.joiner.registry,
                                f.lab.broker.registry,**kwargs)


def interrupted(f,phase):
    gate=f.lab.gate(f.lab.new_request(),f.lab.new_access())
    target='seal_completed' if phase=='preseal' else 'fresh_file'
    with (patch.object(retention,target,side_effect=OSError('owned publication fault')),
          pytest.raises(OSError)):
        retention.dispatch_and_retain(gate,f.launcher,f.lab.permission,f.root,f.outbox,intent_root=f.intents)
    return gate


def test_published_sealed_and_empty_inventory_are_checked_without_grants(tmp_path):
    f=fixture(tmp_path)
    assert inspect(f)['intents']==0
    f.execute()
    result=inspect(f)
    assert result['intents']==result['sealed']==result['published']==1
    assert result['indeterminate']==result['unpublished']==0
    assert result['oldest_indeterminate_at'] is result['oldest_unpublished_at'] is None
    assert len(f.launches)==1


def test_preseal_gap_is_visible_even_when_sealed_outbox_is_empty(tmp_path):
    f=fixture(tmp_path)
    gate=interrupted(f,'preseal')
    result=inspect(f)
    assert result['indeterminate']==result['intents']==1
    assert result['sealed']==result['published']==result['unpublished']==0
    original=ExecIntentJournal(f.intents,f.lab.broker.joiner.registry,f.lab.broker.registry).load(gate.request.request_id)
    assert result['oldest_indeterminate_at']==original.created_at
    assert not list(f.outbox.glob('*.json')) and len(f.launches)==1


def test_durable_capture_before_outbox_is_pending_publication(tmp_path):
    f=fixture(tmp_path)
    interrupted(f,'preoutbox')
    result=inspect(f)
    assert result['intents']==result['sealed']==result['unpublished']==1
    assert result['indeterminate']==result['published']==0
    assert result['oldest_unpublished_at'] is not None
    assert not list(f.outbox.glob('*.json')) and len(f.launches)==1


def test_later_recovery_resolves_publication_but_preserves_original_indeterminate_request(tmp_path):
    f=fixture(tmp_path)
    interrupted(f,'preseal')
    original=inspect(f)['oldest_indeterminate_at']
    gate=interrupted(f,'preoutbox')
    value=inspect(f)
    assert value['indeterminate']==value['unpublished']==1 and value['intents']==2
    ExecIntentJournal(f.intents,f.lab.broker.joiner.registry,f.lab.broker.registry).reconcile(
        gate.request.request_id,f.lab.broker,f.lab.operations,f.root,f.outbox,resume=True)
    result=inspect(f)
    assert result['published']==1 and result['unpublished']==0 and result['indeterminate']==1
    assert result['oldest_indeterminate_at']==original and len(f.launches)==2


def test_cold_and_hot_publications_are_both_exactly_counted(tmp_path):
    f=fixture(tmp_path)
    for _ in range(2):f.execute()
    result=CaptureArchive(f.root,f.archive_scope,policy=ArchivePolicy(max_hot_records=1)).compact(apply=True)
    assert result['archive_records']==1
    observed=inspect(f)
    assert observed['intents']==observed['published']==observed['sealed']==2
    assert observed['indeterminate']==observed['unpublished']==0


@pytest.mark.parametrize('damage',['unknown_root','unknown_run','intent_damage','intent_link','capture_damage','capture_link','hot_collision'])
def test_missing_malformed_or_linked_evidence_is_unavailable_not_zero(damage,tmp_path):
    f=fixture(tmp_path)
    gate,_,_,_=f.execute()
    run=f.intents/gate.request.request_id
    if damage=='unknown_root':(f.intents/'interrupted.tmp').write_bytes(b'partial')
    elif damage=='unknown_run':(run/'interrupted.tmp').write_bytes(b'partial')
    elif damage in {'intent_damage','capture_damage'}:
        (run/('intent.json' if damage=='intent_damage' else 'capture.json')).write_bytes(b'{}')
    elif damage in {'intent_link','capture_link'}:
        p=run/('intent.json' if damage=='intent_link' else 'capture.json')
        target=tmp_path/'owned-original'
        target.write_bytes(p.read_bytes())
        target.chmod(0o600)
        p.unlink()
        p.symlink_to(target)
    else:
        (f.root/gate.request.request_id/'capture.json').write_bytes(b'{}')
    with pytest.raises((ValueError,OSError,InvalidSignature)):
        inspect(f)
    assert len(f.launches)==1


@pytest.mark.parametrize('field',['signature','proposed_caller_ref_sha256','session_ref_sha256','worker_directory'])
def test_intent_signatures_are_rechecked_for_every_inventory(field,tmp_path):
    f=fixture(tmp_path)
    gate=interrupted(f,'preseal')
    p=f.intents/gate.request.request_id/'intent.json'
    value=json.loads(p.read_bytes())
    value[field]='B'*86 if field=='signature' else '/other' if field=='worker_directory' else 'f'*64
    p.write_bytes(canonical(value))
    with pytest.raises((ValueError,InvalidSignature)):
        inspect(f)


def test_worker_broker_and_app_directories_are_not_required_by_keyless_inventory(tmp_path):
    f=fixture(tmp_path)
    f.execute()
    assert f.launcher.directory.parent==tmp_path
    shutil.rmtree(f.launcher.directory)
    # The inspector accepts only public pins and the two artifact stores; it
    # has no broker or app access API and cannot read the signed worker path.
    result=inspect(f)
    assert result['published']==1 and result['indeterminate']==0


def test_wrong_unit_or_current_pin_cannot_return_a_healthy_inventory(tmp_path):
    f=fixture(tmp_path)
    f.execute()
    other=f.archive_scope.model_copy(update={'unit':'other.service'})
    with pytest.raises(ValueError,match='exec_recovery_proposed_scope'):
        mod.inspect_recovery(f.intents,f.root,other,f.lab.broker.joiner.registry,f.lab.broker.registry)
    f.lab.broker.registry.path.write_bytes(b'{}')
    with pytest.raises(ValueError):inspect(f)


def test_capacity_and_deadline_failure_do_not_emit_partial_counts(tmp_path,monkeypatch):
    f=fixture(tmp_path)
    for _ in range(2):f.execute()
    monkeypatch.setattr(mod,'MAX_RECORDS',1)
    with pytest.raises(ValueError,match='exec_recovery_'):
        inspect(f)
    monkeypatch.setattr(mod,'MAX_RECORDS',10000)
    ticks=iter([1,17])
    monkeypatch.setattr(mod,'time',SimpleNamespace(monotonic=lambda:next(ticks)))
    with pytest.raises(ValueError,match='exec_recovery_inspection_deadline'):
        inspect(f)
