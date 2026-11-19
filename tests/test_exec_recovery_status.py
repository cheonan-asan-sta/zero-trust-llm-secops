"""Operational recovery health is separate from identity and detection F1."""

import json
import os
import sys
from datetime import UTC, datetime, timedelta

import pytest

from scripts.f1_lab import exec_recovery_status as mod
from scripts.f1_lab.capture_archive import ArchiveScope
from scripts.f1_lab.operation_context import canonical

SCOPE=ArchiveScope(tenant_id='fixture',server_id='fixture-server',unit='fixture.service',source_id='fixture-source')
NOW=datetime(2026,11,16,tzinfo=UTC)


def values():
    return {'intents':5,'sealed':4,'indeterminate':1,'published':3,'unpublished':1,'raw_bytes':1024,
            'oldest_indeterminate_at':NOW-timedelta(seconds=10),'oldest_unpublished_at':NOW-timedelta(seconds=8)}


def profile(tmp_path):
    return {'schema':'zt-exec-recovery-metrics-profile-1','scope_sha256':mod.scope_hash(SCOPE),
            'status_file':str(tmp_path/'status.json'),'max_indeterminate_age_seconds':5,
            'max_unpublished_age_seconds':5,'max_intents':5}


def write(path,value):
    path.write_bytes(canonical(value)+b'\n')
    path.chmod(0o644)


def test_public_report_contains_only_counts_scope_and_original_pending_times():
    result=mod.report(SCOPE,values(),now=NOW)
    assert result['state']=='pending' and result['values']['indeterminate']==1
    assert not result['authorization_asserted'] and not result['automatic_execution_allowed']
    text=json.dumps(result)
    assert all(v not in text for v in ('fixture-server','fixture.service','fixture-source','worker_directory',
                                       'caller_ref_sha256','request_id','grant_token','signature'))


def test_no_sealed_gap_can_be_reported_ready_after_a_different_publication_succeeds():
    v=values()
    v.update(published=4,unpublished=0,oldest_unpublished_at=None)
    assert mod.report(SCOPE,v,now=NOW)['state']=='pending'
    v.update(indeterminate=0,intents=4,oldest_indeterminate_at=None)
    assert mod.report(SCOPE,v,now=NOW)['state']=='ready'


@pytest.mark.parametrize('field',['intents','sealed','indeterminate','published','unpublished','raw_bytes'])
@pytest.mark.parametrize('bad',[True,-1,1.5])
def test_invalid_counters_cannot_be_published(field,bad):
    v=values()
    v[field]=bad
    with pytest.raises(ValueError,match='exec_recovery_status_counts'):
        mod.report(SCOPE,v,now=NOW)


@pytest.mark.parametrize('damage',['unknown','wrong_scope','permit','authorize','false_ready','missing_age','future_age','unavailable_counts'])
def test_report_shape_binding_and_uncertainty_are_strict(damage):
    value=mod.report(SCOPE,values(),now=NOW)
    if damage=='unknown':value['token']='not-allowed'
    elif damage=='wrong_scope':value['scope_sha256']='f'*64
    elif damage=='permit':value['automatic_execution_allowed']=True
    elif damage=='authorize':value['authorization_asserted']=True
    elif damage=='false_ready':value['state']='ready'
    elif damage=='missing_age':value['oldest_indeterminate_at']=None
    elif damage=='future_age':value['oldest_indeterminate_at']=(NOW+timedelta(seconds=1)).isoformat()
    else:value['state']='unavailable'
    with pytest.raises(ValueError,match='exec_recovery_'):
        mod.validate(value,mod.scope_hash(SCOPE))


@pytest.mark.skipif(os.name != 'posix', reason='Actual POSIX protected public status file')
def test_metrics_show_original_age_both_pending_types_and_capacity(tmp_path):
    p=profile(tmp_path)
    write(tmp_path/'status.json',mod.report(SCOPE,values(),now=NOW))
    result=mod.metrics(p,now=NOW)
    assert 'secops_exec_recovery_status_success 1' in result
    assert 'secops_exec_recovery_indeterminate 1' in result
    assert 'secops_exec_recovery_unpublished 1' in result
    assert 'secops_exec_recovery_indeterminate_overdue 1' in result
    assert 'secops_exec_recovery_unpublished_overdue 1' in result
    assert 'secops_exec_recovery_capacity_pressure 1' in result
    before=(tmp_path/'status.json').read_bytes()
    mod.metrics(p,now=NOW+timedelta(seconds=1))
    assert (tmp_path/'status.json').read_bytes()==before


@pytest.mark.parametrize('condition',['expired','future','unavailable','missing','wrong_binding','damage'])
def test_unavailable_or_expired_status_omits_all_cached_counts(condition,tmp_path):
    p=profile(tmp_path)
    value=mod.report(SCOPE,values(),now=NOW)
    now=NOW
    if condition=='expired':now+=timedelta(seconds=60)
    elif condition=='future':now-=timedelta(seconds=1)
    elif condition=='unavailable':value=mod.report(SCOPE,now=NOW)
    elif condition=='wrong_binding':p['scope_sha256']='f'*64
    if condition!='missing':write(tmp_path/'status.json',value if condition!='damage' else {})
    result=mod.metrics(p,now=now)
    assert 'secops_exec_recovery_status_success 0' in result
    assert 'secops_exec_recovery_intents ' not in result
    assert 'secops_exec_recovery_indeterminate ' not in result
    assert 'secops_exec_recovery_unpublished ' not in result


@pytest.mark.parametrize('field,bad',[('max_intents',0),('max_intents',True),('max_indeterminate_age_seconds',0),
                                   ('max_unpublished_age_seconds',86401),('status_file','relative.json'),
                                   ('scope_sha256','bad'),('schema','old')])
def test_profile_does_not_accept_invalid_limits_or_remote_paths(field,bad,tmp_path,monkeypatch):
    # Profile-shape unit coverage is independent of the POSIX file admission
    # tested above and by test_collector_status_bridge on Linux.
    monkeypatch.setattr(mod, 'read_public', lambda path: json.loads(path.read_bytes()))
    value=profile(tmp_path)
    value[field]=bad
    write(tmp_path/'profile.json',value)
    with pytest.raises(ValueError,match='exec_recovery_profile'):
        mod.load_profile(tmp_path/'profile.json')


@pytest.mark.skipif(sys.platform!='linux',reason='POSIX publisher contracts')
def test_atomic_publication_and_clock_regression_denial(tmp_path):
    path=tmp_path/'status.json'
    mod.publish(path,mod.report(SCOPE,values(),now=NOW))
    assert path.stat().st_mode&0o777==0o644
    original=path.read_bytes()
    with pytest.raises(ValueError,match='exec_recovery_status_publication_clock'):
        mod.publish(path,mod.report(SCOPE,values(),now=NOW-timedelta(seconds=1)))
    assert path.read_bytes()==original


@pytest.mark.skipif(sys.platform!='linux',reason='POSIX publisher contracts')
@pytest.mark.parametrize('damage',['symlink','hardlink','writable_parent'])
def test_publisher_refuses_redirected_or_writable_output(damage,tmp_path):
    p=tmp_path/'status.json'
    other=tmp_path/'owned-other'
    value=mod.report(SCOPE,values(),now=NOW)
    if damage=='symlink':
        write(other,value)
        p.symlink_to(other)
    elif damage=='hardlink':
        write(other,value)
        os.link(other,p)
    else:tmp_path.chmod(0o777)
    with pytest.raises((ValueError,OSError)):
        mod.publish(p,value)


def test_empty_inventory_is_ready_with_no_invented_original_age():
    v={k:0 for k in mod.COUNTERS}
    v.update(oldest_indeterminate_at=None,oldest_unpublished_at=None)
    result=mod.report(SCOPE,v,now=NOW)
    assert result['state']=='ready' and result['oldest_indeterminate_at'] is None
