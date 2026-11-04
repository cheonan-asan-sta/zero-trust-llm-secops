"""Pinned operator restart, pending-work barriers and partial public copy recovery."""

import copy
import json

import pytest

from scripts import executor_transition as op
from scripts.certificate_controller import LifecycleError
from scripts.executor_cluster import Cluster
from scripts.executor_disk import copy_resume


def original():
    p='c02-'+'a'*12
    return {'schema':'executor-cluster-1','project':p,'graph_image':'sha256:'+'a'*64,'executor_image':'sha256:'+'b'*64,
        'directory':'/app/runtime/c02/'+p+'-executor','docker_group':0,'active':'a','epoch':1,
        'hosts':{s:{'generation':1,'journal':p+f'-executor-{s}-g1-journal','owner':p+f'-executor-{s}-g1-owner',
            'worker':{'name':p+f'-executor-{s}-e1','id':s*64}} for s in ['a','b']}}


def record(phase='complete'):
    old=original();new=op.planned(old,'b')
    if op.PHASES.index(phase)>=4:
        for site,ident in [('a','e'),('b','f')]:new['hosts'][site]['worker']={'name':old['project']+f'-executor-{site}-e2','id':ident*64}
    value={'schema':'executor-transition-1','id':'d'*32,'phase':phase,'original':old,'planned':new,'target':'b','discard':True,
        'actor':{'id':'c'*64,'name':old['project']+'-executor-takeover-lock'},'profile_hashes':None,'fenced':[],'settled':None,'receipt':None}
    if phase!='intent':
        value.update(profile_hashes={'profile.json':'a'*64,'cluster.json':'b'*64},
            fenced=[{**old['hosts'][s]['worker'],'removed':True} for s in ['a','b']],
            settled={'execs_remaining':0,'jobs_remaining':0,'pinned_services_inspected':2})
    if phase=='complete':value['receipt']=op.receipt(value)
    return value


@pytest.mark.parametrize('phase',op.PHASES)
def test_operator_record_roundtrip_all_durable_phases(phase):
    r=record(phase);assert op.read_record(op.envelope(r))==r


@pytest.mark.parametrize('field',['id','phase','target','discard','actor','original','planned','profile_hashes','fenced','receipt'])
def test_corrupt_public_record_refuses_even_when_json_is_parseable(field):
    value=op.envelope(record());value[field]=None
    with pytest.raises(LifecycleError,match='transition_invalid'):op.read_record(value)


@pytest.mark.parametrize('fault',['epoch','target','generation','shared_volume','image','actor_id','actor_name','fence','busy','receipt'])
def test_semantically_invalid_record_with_recomputed_checksum_refuses(fault):
    r=record()
    if fault=='epoch':r['planned']['epoch']=4
    elif fault=='target':r['target']='a'
    elif fault=='generation':r['planned']['hosts']['a']['generation']=3
    elif fault=='shared_volume':r['planned']['hosts']['a']['journal']=r['planned']['hosts']['b']['journal']
    elif fault=='image':r['planned']['graph_image']='sha256:'+'f'*64
    elif fault=='actor_id':r['actor']['id']='not-an-id'
    elif fault=='actor_name':r['actor']['name']='foreign-actor'
    elif fault=='fence':r['fenced'][0]['id']='e'*64
    elif fault=='busy':r['settled']['execs_remaining']=1
    else:r['receipt']['executor_epoch']=9
    with pytest.raises(LifecycleError):op.read_record({**r,'sha256':op.digest(r)})


@pytest.mark.parametrize('phase',op.PHASES[:-1])
def test_pending_operator_records_block_normal_work_even_with_matching_roles(tmp_path,phase):
    a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir();r=record(phase)
    for root in [a,b]:op.write_path(root/op.NAME,op.envelope(r))
    with pytest.raises(LifecycleError,match='operator_resume_required'):op.guard_pair(a,b,Cluster(r['planned']).role())


def test_complete_pair_allows_current_owner_and_rejects_old_owner(tmp_path):
    a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir();r=record()
    for root in [a,b]:op.write_path(root/op.NAME,op.envelope(r))
    op.guard_pair(a,b,Cluster(r['planned']).role())
    with pytest.raises(LifecycleError):op.guard_pair(a,b,Cluster(r['original']).role())
    (b/op.NAME).unlink()
    with pytest.raises(LifecycleError):op.guard_pair(a,b,Cluster(r['planned']).role())


def test_partial_copy_is_idempotent_and_never_overwrites_conflicting_public_state(tmp_path):
    source=tmp_path/'source';target=tmp_path/'target';source.mkdir();target.mkdir()
    files={'profile.json':{'version':1},'cluster.json':{'epoch':1}}
    for name,value in files.items():op.write_path(source/name,value)
    op.write_path(target/'profile.json',files['profile.json'])
    assert copy_resume(target,source,op.tree_hashes(files))=={'copied':True}
    assert copy_resume(target,source,op.tree_hashes(files))=={'copied':True}
    op.write_path(target/'profile.json',{'version':2})
    with pytest.raises(LifecycleError,match='copy_conflict'):copy_resume(target,source,op.tree_hashes(files))
    assert json.loads((target/'profile.json').read_bytes())=={'version':2}


def test_changed_source_cannot_be_reinterpreted_as_the_old_copy_checkpoint(tmp_path):
    a=tmp_path/'a';b=tmp_path/'b';a.mkdir();b.mkdir();op.write_path(a/'profile.json',{'version':2})
    with pytest.raises(LifecycleError,match='source_changed'):copy_resume(b,a,op.tree_hashes({'profile.json':{'version':1}}))
    assert not list(b.iterdir())


def request():return {'schema':'executor-operator-request-1','id':'d'*32,'original':original(),'target':'b','discard':True}


def actor_snapshot(c):
    req=request();p=c.project
    return {'Id':'c'*64,'Name':'/'+p+'-executor-takeover-lock','Image':c.d['executor_image'],'ExecIDs':None,
        'State':{'Running':False,'ExitCode':73},'NetworkSettings':{'Networks':{'none':{}}},
        'Mounts':[{'Type':'volume','Name':c.d['hosts']['b']['journal'],'Destination':'/data','RW':True},
            {'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock','RW':True}],
        'Config':{'User':'10001:10001','Entrypoint':['python'],'Cmd':['-m','scripts.executor_transition','actor'],
            'Env':['BASE=1','DOCKER_HOST=unix:///var/run/docker.sock',op.ENV+'='+json.dumps(req,sort_keys=True,separators=(',',':'))],
            'Labels':{'secops.executor-cluster':p,'secops.executor-kind':'operator',op.LABEL:req['id']}},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapAdd':None,'CapDrop':['ALL'],
            'SecurityOpt':['no-new-privileges:true'],'GroupAdd':['0'],'Memory':512*1024**2,'PidsLimit':128,'NanoCpus':1_000_000_000,
            'Tmpfs':{'/tmp':'rw,size=32m'},'RestartPolicy':{'Name':'no'}}}


@pytest.fixture
def actor(monkeypatch):
    c=Cluster(original());monkeypatch.setattr(c,'raw',lambda _:json.dumps([{'Config':{'Env':['BASE=1']}}]))
    return c,actor_snapshot(c)


def test_expected_stopped_operator_spec_matches(actor):
    c,found=actor;op.verify_actor(c,found,request())


@pytest.mark.parametrize('fault',['image','name','uid','command','env','nonce','socket','volume','network','privileged','cap','security','memory','pid','cpu','group','tmpfs','restart'])
def test_replaced_or_weakened_operator_cannot_be_restarted(actor,fault):
    c,found=actor;r=copy.deepcopy(found)
    if fault=='image':r['Image']='different'
    elif fault=='name':r['Name']='/foreign'
    elif fault=='uid':r['Config']['User']='0'
    elif fault=='command':r['Config']['Cmd']=['-c','different']
    elif fault=='env':r['Config']['Env'].append('PYTHONPATH=/tmp')
    elif fault=='nonce':r['Config']['Labels'][op.LABEL]='e'*32
    elif fault=='socket':r['Mounts'][1]['Source']='/different'
    elif fault=='volume':r['Mounts'][0]['Name']='foreign'
    elif fault=='network':r['HostConfig']['NetworkMode']='bridge'
    elif fault=='privileged':r['HostConfig']['Privileged']=True
    elif fault=='cap':r['HostConfig']['CapAdd']=['SYS_ADMIN']
    elif fault=='security':r['HostConfig']['SecurityOpt']=[]
    elif fault=='memory':r['HostConfig']['Memory']=0
    elif fault=='pid':r['HostConfig']['PidsLimit']=0
    elif fault=='cpu':r['HostConfig']['NanoCpus']=0
    elif fault=='group':r['HostConfig']['GroupAdd']=[]
    elif fault=='tmpfs':r['HostConfig']['Tmpfs']={}
    else:r['HostConfig']['RestartPolicy']['Name']='always'
    with pytest.raises(LifecycleError,match='operator_replaced'):op.verify_actor(c,r,request())


@pytest.mark.parametrize('busy',['running','exec'])
def test_live_operator_is_never_killed_or_started_again(actor,monkeypatch,busy):
    c,found=actor
    if busy=='running':found['State']['Running']=True
    else:found['ExecIDs']=['still-executing']
    monkeypatch.setattr(op.subprocess,'run',lambda *a,**k:pytest.fail('started live operator'))
    with pytest.raises(LifecycleError,match='still_running'):op.run_actor(c,found,request())


def test_completed_operator_fast_path_never_replays_copy_fence_or_owner_writes(monkeypatch):
    value=record();actor=object.__new__(op.Actor);actor.r=value
    for name in ['orphans','save','cut','volume','worker']:setattr(actor,name,lambda *a,**k:pytest.fail('replayed completed operator'))
    wanted={'descriptor':value['planned'],'receipt':value['receipt']}
    monkeypatch.setattr(op,'complete_result',lambda r:wanted)
    assert actor.run()==wanted


def test_existing_operator_requires_explicit_resume_without_creating_a_second_actor(monkeypatch):
    c=Cluster(original());monkeypatch.setattr(op,'lookup',lambda *_:{'Id':'c'*64})
    monkeypatch.setattr(c,'raw',lambda *_:pytest.fail('created concurrent actor'))
    with pytest.raises(LifecycleError,match='resume_required'):op.launch(c,'b')


@pytest.mark.skipif(__import__('os').name=='nt',reason='Windows symlink creation needs separate OS privileges')
def test_dangling_transition_symlink_is_not_treated_as_absent_intent(tmp_path):
    path=tmp_path/op.NAME;path.symlink_to(tmp_path/'missing')
    with pytest.raises(LifecycleError,match='transition_invalid'):op.read_path(path)


def test_recorded_operator_id_cannot_be_replaced_even_with_identical_specs(monkeypatch):
    c=Cluster(original());found=actor_snapshot(c);found['Id']='e'*64;r=record()
    monkeypatch.setattr(op,'lookup',lambda *_:found)
    monkeypatch.setattr(Cluster,'disk',lambda *a,**k:{op.NAME:op.envelope(r)})
    monkeypatch.setattr(Cluster,'raw',lambda *_:json.dumps([{'Config':{'Env':['BASE=1']}}]))
    h=c.d['hosts']['b']
    with pytest.raises(LifecycleError,match='identity_changed'):op.resume_operator(c.anchor(),'b',h['journal'],h['owner'])


def test_lost_incomplete_actor_is_never_silently_recreated(monkeypatch):
    c=Cluster(original());r=record('fenced')
    monkeypatch.setattr(op,'lookup',lambda *_:None)
    monkeypatch.setattr(Cluster,'disk',lambda *a,**k:{op.NAME:op.envelope(r)})
    monkeypatch.setattr(Cluster,'raw',lambda *_:pytest.fail('recreated lost actor'))
    h=c.d['hosts']['b']
    with pytest.raises(LifecycleError,match='operator_missing'):op.resume_operator(c.anchor(),'b',h['journal'],h['owner'])
