"""Explicit, evidence-bound replacement of removed operator containers."""

import copy
import json

import pytest
from test_executor_transition import actor_snapshot, original, record

from scripts import executor_transition as op
from scripts.certificate_controller import LifecycleError
from scripts.executor_cluster import Cluster


def proof(r):
    return {'schema':'executor-actor-recovery-1','previous_actor':r['actor']['id'],'record_sha256':op.digest(r),
        'request_sha256':op.digest(op.record_request(r)),'nonce':'7'*32}


@pytest.mark.parametrize('phase',op.PHASES[:-1])
def test_rebinding_preserves_operation_phase_plan_and_fencing(phase):
    r=record(phase);before=copy.deepcopy(r);new=op.rebind_record(r,'9'*64,proof(r))
    assert r==before and new['actor']['predecessors']==[before['actor']['id']]
    assert new['actor']['id']=='9'*64 and new['schema']=='executor-transition-2'
    for field in op.FIELDS-{'schema','actor'}:assert new[field]==before[field]
    assert op.read_record(op.envelope(new))==new


def test_multiple_losses_form_a_bounded_unique_identity_history():
    r=record('copied')
    for ident in ['7'*64,'8'*64,'9'*64]:r=op.rebind_record(r,ident,proof(r))
    assert r['actor']['predecessors']==['c'*64,'7'*64,'8'*64]
    assert r['planned']==record('copied')['planned'] and r['id']=='d'*32


@pytest.mark.parametrize('fault',['stale_digest','other_actor','other_request','nonce','same_id','prior_id','overflow','complete'])
def test_invalid_replacement_cannot_change_the_trusted_identity(fault):
    r=record('copied');p=proof(r);ident='9'*64
    if fault=='stale_digest':p['record_sha256']='0'*64
    elif fault=='other_actor':p['previous_actor']='1'*64
    elif fault=='other_request':p['request_sha256']='0'*64
    elif fault=='nonce':p['nonce']='bad'
    elif fault=='same_id':ident=r['actor']['id']
    elif fault=='prior_id':
        r=op.rebind_record(r,'8'*64,p);p=proof(r);ident='c'*64
    elif fault=='overflow':
        r['schema']='executor-transition-2';r['actor']['predecessors']=[f'{i:064x}' for i in range(16)];p=proof(r)
    else:r=record();p=proof(r)
    with pytest.raises(LifecycleError):op.rebind_record(r,ident,p)


def evidence(monkeypatch,phase='copied'):
    r=record(phase)
    if phase=='owners':
        for host in r['planned']['hosts'].values():host['worker']=None
    old=Cluster(r['original']);new=Cluster(r['planned']);source=old.d['active'];target=r['target']
    core={'profile.json':{'version':1},'cluster.json':copy.deepcopy(old.d)}
    if phase!='intent':r['profile_hashes']=op.tree_hashes(core)
    pair_new=op.PHASES.index(phase)>=3
    peer=(new if pair_new else old).d['hosts'][source]['journal']
    disks={old.d['hosts'][target]['journal']:{**core,op.NAME:op.envelope(r)},peer:{**core,op.NAME:op.envelope(r)}}
    for site in ['a','b']:
        owner_volume=(new if pair_new else old).d['hosts'][site]['owner']
        disks[owner_volume]=({'owner.json':new.role()} if phase=='owners' else
            {'owner.json':old.role()} if site==target or not pair_new else {})
    monkeypatch.setattr(Cluster,'verify_volume',lambda *a:None)
    monkeypatch.setattr(Cluster,'disk',lambda self,name,operation,**kwargs:copy.deepcopy(disks[name]))
    monkeypatch.setattr(Cluster,'raw',lambda self,args,**k:json.dumps([{'Labels':{op.LABEL:r['id']}}]) if args[:2]==['volume','inspect'] else '')
    monkeypatch.setattr(op,'lookup',lambda *a:None)
    return old,r,disks,peer


@pytest.mark.parametrize('phase',['intent','fenced','volumes','copied','owners'])
def test_consistent_surviving_evidence_allows_only_read_only_preflight(monkeypatch,phase):
    old,r,_,_=evidence(monkeypatch,phase)
    before=copy.deepcopy(r);op.recovery_evidence(old,r);assert r==before


@pytest.mark.parametrize('fault',['peer_missing','peer_diverged','source_changed','owner_empty','owner_foreign','profile_changed','cluster_changed'])
def test_ambiguous_or_inconsistent_survivors_refuse_replacement(monkeypatch,fault):
    c,r,disks,peer=evidence(monkeypatch);target=c.d['hosts'][r['target']]
    if fault=='peer_missing':disks[peer].pop(op.NAME)
    elif fault=='peer_diverged':
        other=copy.deepcopy(r);other['id']='e'*32;disks[peer][op.NAME]=op.envelope(other)
    elif fault=='source_changed':
        other=copy.deepcopy(r);other['id']='e'*32;disks[target['journal']][op.NAME]=op.envelope(other)
    elif fault=='owner_empty':disks[target['owner']]={}
    elif fault=='owner_foreign':disks[target['owner']]={'owner.json':c.role()|{'epoch':99}}
    elif fault=='profile_changed':disks[target['journal']]['profile.json']['version']=2
    else:disks[target['journal']]['cluster.json']={'epoch':99}
    with pytest.raises(LifecycleError):op.recovery_evidence(c,r)


def test_existing_predecessor_under_any_name_refuses_before_disk_mutation(monkeypatch):
    c,r,_,_=evidence(monkeypatch)
    monkeypatch.setattr(Cluster,'raw',lambda *a,**k:r['actor']['id'])
    monkeypatch.setattr(Cluster,'disk',lambda *a,**k:pytest.fail('read past live predecessor'))
    with pytest.raises(LifecycleError,match='predecessor_present'):op.recovery_evidence(c,r)


def test_partial_volume_from_another_operation_cannot_be_adopted(monkeypatch):
    c,r,_,_=evidence(monkeypatch)
    monkeypatch.setattr(Cluster,'raw',lambda self,args,**k:json.dumps([{'Labels':{op.LABEL:'e'*32}}]) if args[:2]==['volume','inspect'] else '')
    with pytest.raises(LifecycleError,match='volume_conflict'):op.recovery_evidence(c,r)


def test_exact_peer_only_identity_write_is_resumable_for_same_pinned_candidate(monkeypatch):
    c,r,disks,peer=evidence(monkeypatch);bound=op.rebind_record(r,'9'*64,proof(r))
    disks[peer][op.NAME]=op.envelope(bound)
    op.recovery_evidence(c,r,bound=bound)
    other=op.rebind_record(r,'8'*64,proof(r))
    with pytest.raises(LifecycleError,match='replica_disagreement'):op.recovery_evidence(c,r,bound=other)


def test_recovery_actor_environment_and_label_are_bound_to_checkpoint(monkeypatch):
    c=Cluster(original());r=record('copied');p=proof(r);found=actor_snapshot(c)
    found['Config']['Env'].append(op.RECOVERY_ENV+'='+json.dumps(p,sort_keys=True,separators=(',',':')))
    found['Config']['Labels'][op.RECOVERY_LABEL]=p['nonce'];found['Config']['Cmd'][-1]='recover-actor'
    monkeypatch.setattr(c,'raw',lambda _:json.dumps([{'Config':{'Env':['BASE=1']}}]))
    op.verify_actor(c,found,op.record_request(r))
    found['Config']['Labels'][op.RECOVERY_LABEL]='6'*32
    with pytest.raises(LifecycleError,match='operator_replaced'):op.verify_actor(c,found,op.record_request(r))


def test_recovered_completion_receipt_retains_all_previous_actor_ids():
    r=op.rebind_record(record('retired'),'9'*64,proof(record('retired')))
    r['phase']='complete';r['receipt']=op.receipt(r)
    assert r['receipt']['operator_actor_predecessors']==['c'*64]
    assert op.read_record(op.envelope(r))==r
