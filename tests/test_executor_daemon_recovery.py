"""Daemon identity, paired-state validation and restart reply-loss safety."""

import copy
import json

import pytest
from test_executor_actor_loss import evidence
from test_executor_transition import actor_snapshot, original, record

from scripts import executor_daemon_recovery as recovery
from scripts import executor_transition as op
from scripts.certificate_controller import LifecycleError
from scripts.executor_cluster import Cluster


def seal():
    value={'schema':'executor-daemon-seal-1','anchor':Cluster(original()).anchor(),'daemon_id':'12345678-1234-1234-1234-123456789abc'}
    return {**value,'sha256':op.digest(value)}


@pytest.mark.parametrize('fault',['checksum','schema','anchor','identity','extra'])
def test_invalid_seal_refuses_before_contacting_docker(monkeypatch,fault):
    value=seal()
    if fault=='checksum':value['sha256']='0'*64
    elif fault=='schema':value['schema']='new'
    elif fault=='anchor':value['anchor']['graph_image']='unknown'
    elif fault=='identity':value['daemon_id']=''
    else:value['extra']=True
    if fault!='checksum':value['sha256']=op.digest({k:v for k,v in value.items() if k!='sha256'})
    monkeypatch.setattr(Cluster,'raw',lambda *a,**k:pytest.fail('contacted Docker'))
    with pytest.raises(LifecycleError):recovery.verify_daemon(value,Cluster(original()).anchor())


def test_wrong_daemon_refuses_before_volume_reads_or_starts(monkeypatch):
    calls=[]
    def raw(self,args,*a,**k):calls.append(args);return json.dumps('different-daemon-id-1234')
    monkeypatch.setattr(Cluster,'raw',raw)
    with pytest.raises(LifecycleError,match='identity_changed'):recovery.verify_daemon(seal(),Cluster(original()).anchor())
    assert len(calls)==1 and calls[0][0]=='info'


@pytest.mark.parametrize('state',['running','paused','restarting','dead','removing','exec'])
def test_unsettled_processes_are_never_started_or_fenced_by_recovery(state):
    found={'State':{'Status':'exited','Running':False},'ExecIDs':[]}
    if state=='exec':found['ExecIDs']=['x']
    else:
        found['State']['Status']=state
        found['State'][{'running':'Running','paused':'Paused','restarting':'Restarting','dead':'Dead','removing':'RemovalInProgress'}[state]]=True
    with pytest.raises(LifecycleError,match='not_quiescent'):op.require_stopped(found)


@pytest.mark.parametrize('phase',['intent','fenced','volumes','copied'])
def test_same_stopped_actor_can_validate_paired_restart_checkpoint(monkeypatch,phase):
    c,r,_,_=evidence(monkeypatch,phase);found=actor_snapshot(c)
    found.update(Id=r['actor']['id'],State={'Status':'exited','Running':False},ExecIDs=[])
    previous=Cluster.raw
    monkeypatch.setattr(Cluster,'raw',lambda self,args,**k:json.dumps([{'Config':{'Env':['BASE=1']}}]) if args[:2]==['image','inspect'] else previous(self,args,**k))
    op.recovery_evidence(c,r,present_actor=found)


def completed(monkeypatch):
    r=record();c=Cluster(r['planned']);calls=[]
    disks={c.d['hosts'][s]['journal']:{op.NAME:op.envelope(r),'cluster.json':c.d,'profile.json':{'consumed':'new'}} for s in ['a','b']}
    disks.update({c.d['hosts'][s]['owner']:{'owner.json':c.role()} for s in ['a','b']})
    workers={s:{'Id':c.d['hosts'][s]['worker']['id'],'State':{'Status':'exited','Running':False},'ExecIDs':[]} for s in ['a','b']}
    monkeypatch.setattr(Cluster,'verify_volume',lambda *a:None)
    monkeypatch.setattr(Cluster,'disk',lambda self,v,operation,**k:copy.deepcopy(disks[v]))
    monkeypatch.setattr(Cluster,'inspect_worker',lambda self,s:copy.deepcopy(workers[s]))
    monkeypatch.setattr(Cluster,'raw',lambda self,args,**k:calls.append(args) or '')
    monkeypatch.setattr(Cluster,'rpc',lambda *a,**k:calls.append(['probe']) or {})
    monkeypatch.setattr(op,'complete_result',lambda value:{'receipt':value['receipt'],'descriptor':value['planned']})
    return r,c,disks,workers,calls


@pytest.mark.parametrize('fault',['peer_record','cluster','owner','worker_missing','worker_paused','worker_running_paused'])
def test_entire_completed_pair_checked_before_first_worker_start(monkeypatch,fault):
    r,c,disks,workers,calls=completed(monkeypatch)
    if fault=='peer_record':disks[c.d['hosts']['b']['journal']].pop(op.NAME)
    elif fault=='cluster':disks[c.d['hosts']['b']['journal']]['cluster.json']={}
    elif fault=='owner':disks[c.d['hosts']['b']['owner']]={}
    elif fault=='worker_missing':monkeypatch.setattr(Cluster,'inspect_worker',lambda *a:(_ for _ in ()).throw(LifecycleError('missing')))
    else:
        workers['b']['State']['Status']='paused'
        if fault=='worker_running_paused':workers['b']['State'].update(Running=True,Paused=True)
    with pytest.raises(LifecycleError):recovery.restore_complete(r)
    assert not any(args[0]=='start' for args in calls)


def test_completed_retry_preserves_new_profile_and_starts_only_stopped_peer(monkeypatch):
    r,_c,disks,workers,calls=completed(monkeypatch);workers['a']['State']={'Status':'running','Running':True}
    before=copy.deepcopy(disks);value=recovery.restore_complete(r)
    assert disks==before and value['receipt']==r['receipt']
    assert [a for a in calls if a[0]=='start']==[['start',workers['b']['Id']]]
    assert calls[-1]==['probe']


def test_test_wait_is_not_accepted_without_the_existing_test_cut_plan():
    request=op.record_request(record('intent'))
    with pytest.raises(LifecycleError,match='test_wait_scope'):op.actor_args(request,wait=True)
    assert op.WAIT_ENV+'=1' in op.actor_args(request,op.CUTS,wait=True)


def test_late_phase_actor_checks_both_workers_before_any_restart(monkeypatch):
    r,c,_disks,workers,calls=completed(monkeypatch);r['phase']='published';r['receipt']=None
    actor=op.Actor.__new__(op.Actor);actor.new=c;actor.r=r
    for w in workers.values():w['Config']={'Labels':{op.LABEL:r['id']}}
    workers['b']['Config']['Labels'][op.LABEL]='other'
    with pytest.raises(LifecycleError,match='worker_replaced'):actor.resume_workers()
    assert not any(args[0]=='start' for args in calls)


@pytest.mark.parametrize('live_site',['a','b'])
def test_incomplete_live_worker_is_refused_without_stop_or_mutation(monkeypatch,live_site):
    r=record('intent');before=copy.deepcopy(r);calls=[]
    def lookup(c,name):
        for site,host in r['original']['hosts'].items():
            if host['worker']['name']==name:
                return {'Id':host['worker']['id'],'State':{'Status':'running' if site==live_site else 'exited','Running':site==live_site},'ExecIDs':[]}
        return None
    monkeypatch.setattr(op,'lookup',lookup)
    monkeypatch.setattr(Cluster,'verify_worker',lambda *a:None)
    monkeypatch.setattr(Cluster,'raw',lambda self,args,**k:calls.append(args) or '')
    with pytest.raises(LifecycleError,match='not_quiescent'):recovery.incomplete_workers(r)
    assert calls==[] and r==before
