"""Executor ownership, independent replica persistence and dispatch fencing."""

import copy
import json
from types import SimpleNamespace

import pytest

from scripts import executor_fence as fence
from scripts import executor_store as storage
from scripts.certificate_controller import LifecycleError
from scripts.control_executor import ExecutorManagement
from scripts.control_plane_ha import Management
from scripts.control_transition import Transition, available, read
from scripts.executor_cluster import Cluster


def role():
    return {'schema':'executor-owner-1','project':'c02-'+'a'*12,'epoch':1,'active':'a',
        'graph_image':'sha256:'+'a'*64,'executor_image':'sha256:'+'b'*64,'generations':{'a':1,'b':1}}


def record():
    return {'schema':'control-transition-1','id':'c'*32,'phase':'prepared','project':role()['project'],
        'image':role()['graph_image'],'source':'a','target':'b','primary':'a','original':{},'profile':{},
        'proof':{},'state':None,'fenced':[],'processes':{},'receipt':None}


@pytest.fixture
def pair(tmp_path):
    a=tmp_path/'host-a';b=tmp_path/'host-b';a.mkdir();b.mkdir()
    roles=[tmp_path/'owner-a.json',tmp_path/'owner-b.json']
    for p in roles:p.write_text(json.dumps(role()))
    cfg={'site':'a','expected':role(),'root':str(a),'peer':str(b),'roles':[str(p) for p in roles]}
    return storage.Store(cfg),roles


def test_journal_peer_is_fsynced_before_active_acknowledgement(pair,monkeypatch):
    store,_=pair;events=[];original=storage.write
    def write(path,value):events.append(path);original(path,value)
    monkeypatch.setattr(storage,'write',write);store.save_record(store.root/'management-transition.json',record())
    assert events==[store.peer/'management-transition.json',store.root/'management-transition.json']
    assert store.record(store.root/'management-transition.json')==record()


def test_peer_failure_does_not_advance_active_journal(pair,monkeypatch):
    store,_=pair;store.save_record(store.root/'management-transition.json',record());original=storage.write
    def write(path,value):
        if path.parent==store.peer:raise OSError('unavailable replica')
        original(path,value)
    monkeypatch.setattr(storage,'write',write)
    with pytest.raises(OSError):store.save_record(store.root/'management-transition.json',record()|{'phase':'fenced'})
    assert read(store.root/'management-transition.json')['phase']=='prepared'


def test_peer_only_prefix_survives_old_host_loss_but_active_cannot_ignore_divergence(pair):
    store,_=pair;store.save_record(store.root/'management-transition.json',record())
    def die(*_):raise SystemExit(73)
    store.hook=die
    with pytest.raises(SystemExit):store.save_record(store.root/'management-transition.json',record()|{'phase':'fenced'})
    assert read(store.peer/'management-transition.json')['phase']=='fenced'
    assert read(store.root/'management-transition.json')['phase']=='prepared'
    with pytest.raises(LifecycleError,match='divergence_requires_fence'):store.record(store.root/'management-transition.json')


@pytest.mark.parametrize('fault',['missing','changed_epoch','different_project','invalid_json'])
@pytest.mark.parametrize('index',[0,1])
def test_incomplete_owner_blocks_replication_before_either_copy_changes(pair,index,fault):
    store,roles=pair
    if fault=='missing':roles[index].unlink()
    elif fault=='invalid_json':roles[index].write_text('{')
    else:roles[index].write_text(json.dumps(role()|({'epoch':2} if fault=='changed_epoch' else {'project':'foreign'})))
    with pytest.raises(LifecycleError,match='owner'):store.save_record(store.root/'management-transition.json',record())
    assert not (store.root/'management-transition.json').exists() and not (store.peer/'management-transition.json').exists()


def test_passive_cannot_dispatch_even_with_consistent_owner_files(pair):
    store,_=pair;store.context['site']='b'
    b=object.__new__(ExecutorManagement);b.executor=store;b.profile={'image':role()['graph_image']};b.project=role()['project']
    with pytest.raises(LifecycleError,match='passive_host'):b.raw(['version'])


@pytest.mark.parametrize('name',['escape.json','../profile.json','authority-coordinator.json'])
def test_only_replicated_public_executor_files_can_be_written(pair,name):
    store,_=pair
    with pytest.raises(LifecycleError,match='scope'):store.save_json(name,{})


@pytest.mark.parametrize('field',['project','image'])
def test_foreign_journal_never_replaces_either_copy(pair,field):
    store,_=pair
    with pytest.raises(LifecycleError,match='project_or_image'):store.save_record(store.root/'management-transition.json',record()|{field:'foreign'})
    assert not (store.peer/'management-transition.json').exists()


@pytest.mark.parametrize('raw',['null','[]','{}','{'])
def test_malformed_executor_context_never_falls_back_to_single_host(monkeypatch,raw):
    monkeypatch.setenv(storage.ENV,raw)
    with pytest.raises(LifecycleError):storage.Store.environment()


def test_transition_storage_hook_is_used_instead_of_local_files(tmp_path):
    events=[];b=SimpleNamespace(directory=lambda:tmp_path,transition_write=lambda p,r:events.append((p,r.copy())))
    t=Transition(b);t.record=record();t.save('fenced')
    assert events[0][1]['phase']=='fenced' and not t.path.exists()


def test_control_availability_reads_replicated_store(tmp_path):
    b=SimpleNamespace(directory=lambda:tmp_path,project=role()['project'],profile={'image':role()['graph_image']},
        transition_read=lambda _p:record())
    with pytest.raises(LifecycleError,match='resume_required'):available(b)


@pytest.mark.parametrize('fault',['shared','nested','relative','traversal'])
def test_executor_replica_roots_cannot_alias_or_escape(pair,fault):
    store,_=pair;cfg=copy.deepcopy(store.context)
    if fault=='shared':cfg['peer']=cfg['root']
    elif fault=='nested':cfg['peer']=str(store.root/'nested')
    elif fault=='relative':cfg['peer']='relative'
    else:cfg['peer']=str(store.root/'..'/'escape')
    with pytest.raises(LifecycleError):storage.Store(cfg)


def test_late_job_old_epoch_cannot_run_after_owner_changes(pair,monkeypatch):
    _,roles=pair
    monkeypatch.setenv(fence.ENV,json.dumps({'expected':role(),'roles':list(map(str,roles))}))
    fence.guard()
    for p in roles:p.write_text(json.dumps(role()|{'epoch':2,'active':'b'}))
    with pytest.raises(LifecycleError,match='stale'):fence.guard()


@pytest.mark.parametrize('raw',['null','[]','{}','{'])
def test_malformed_job_fence_is_not_optional(monkeypatch,raw):
    monkeypatch.setenv(fence.ENV,raw)
    with pytest.raises(LifecycleError):fence.guard()


def test_ordinary_legacy_jobs_retain_behavior_without_executor_flag(monkeypatch):
    monkeypatch.delenv(fence.ENV,raising=False);fence.guard()


def test_all_temporary_dispatches_receive_readonly_epoch_guard(pair,monkeypatch):
    store,_=pair;b=object.__new__(ExecutorManagement);b.executor=store;b.project=role()['project'];b.profile={'image':role()['graph_image']}
    calls=[];monkeypatch.setattr(Management,'raw',lambda _self,args,payload,timeout:calls.append(args) or '')
    b.raw(['run','--rm','--network','none','--entrypoint','python',b.profile['image'],'-c','print(1)'])
    args=calls[0];assert 'scripts.executor_fence' in args and args[-3:]==['python','-c','print(1)']
    assert sum('/executor-fence-' in x and x.endswith(',readonly') for x in args)==2
    assert any(x.startswith(fence.ENV+'=') for x in args)


@pytest.mark.parametrize('args',[['run','different-image'],['run','--entrypoint','python','wrong-image'],
    ['run','--entrypoint','python','--network','none',role()['graph_image']]])
def test_unapproved_ephemeral_image_or_layout_cannot_bypass_wrapper(pair,args):
    store,_=pair;b=object.__new__(ExecutorManagement);b.executor=store;b.project=role()['project'];b.profile={'image':role()['graph_image']}
    with pytest.raises(LifecycleError,match='scope|layout'):b.raw(args)


def descriptor():
    p=role()['project']
    return {'schema':'executor-cluster-1','project':p,'graph_image':role()['graph_image'],'executor_image':role()['executor_image'],
        'active':'a','epoch':1,'directory':'/app/runtime/c02/'+p+'-executor','docker_group':0,
        'hosts':{s:{'generation':1,'journal':p+f'-executor-{s}-g1-journal','owner':p+f'-executor-{s}-g1-owner',
        'worker':{'name':p+f'-executor-{s}-e1','id':s*64}} for s in ['a','b']}}


@pytest.mark.parametrize('fault',['project','image','active','epoch','group','directory','generation','volume','worker','members','duplicate_worker'])
def test_invalid_host_identity_or_volume_plan_refuses_before_docker(fault):
    d=descriptor()
    if fault=='project':d['project']='foreign'
    elif fault=='image':d['executor_image']='latest'
    elif fault=='active':d['active']='c'
    elif fault=='epoch':d['epoch']=0
    elif fault=='group':d['docker_group']=True
    elif fault=='directory':d['directory']='/outside'
    elif fault=='generation':d['hosts']['a']['generation']=False
    elif fault=='volume':d['hosts']['a']['owner']=d['hosts']['b']['owner']
    elif fault=='worker':d['hosts']['a']['worker']['name']='foreign'
    elif fault=='members':d['hosts']['c']=d['hosts'].pop('b')
    else:d['hosts']['b']['worker']['id']=d['hosts']['a']['worker']['id']
    with pytest.raises(LifecycleError):Cluster(d)


def worker_snapshot(cluster,site='a'):
    expected={dest:(v,not ro) for v,dest,ro in cluster.mounts(site)}
    mounts=[{'Type':'volume','Name':v,'Destination':dest,'RW':rw} for dest,(v,rw) in expected.items()]
    mounts.append({'Type':'bind','Source':'/var/run/docker.sock','Destination':'/var/run/docker.sock','RW':True})
    from scripts.control_executor import JOB_EPOCH, JOB_SITE
    from scripts.executor_cluster import CLUSTER, KIND
    return {'Id':cluster.d['hosts'][site]['worker']['id'],'Name':'/'+cluster.d['hosts'][site]['worker']['name'],
        'Image':cluster.d['executor_image'],'Mounts':mounts,'NetworkSettings':{'Networks':{'none':{}}},
        'Config':{'User':'10001:10001','Entrypoint':['python'],'Cmd':['-m','scripts.control_executor','daemon'],
        'Labels':{CLUSTER:cluster.project,JOB_SITE:site,JOB_EPOCH:'1',KIND:'worker'},
        'Env':[storage.ENV+'='+json.dumps(cluster.context(site),sort_keys=True,separators=(',',':')),'DOCKER_HOST=unix:///var/run/docker.sock']},
        'HostConfig':{'NetworkMode':'none','ReadonlyRootfs':True,'Privileged':False,'CapAdd':None,'CapDrop':['ALL'],
        'SecurityOpt':['no-new-privileges:true'],'RestartPolicy':{'Name':'no'},'Memory':512*1024**2,'PidsLimit':128,
        'NanoCpus':1_000_000_000,'GroupAdd':['0'],'Tmpfs':{'/tmp':'rw,size=32m','/data':'rw,uid=10001,gid=10001,size=1m'}}}


def test_expected_maintenance_host_spec_is_valid():
    c=Cluster(descriptor());c.verify_worker('a',worker_snapshot(c))


@pytest.mark.parametrize('fault',['id','image','uid','socket','owner_rw','command','env','privileged','cap','security','network','memory','pid','cpu','group','tmpfs'])
def test_replaced_or_weakened_management_host_cannot_be_fenced_as_owned(fault):
    c=Cluster(descriptor());r=worker_snapshot(c)
    if fault=='id':r['Id']='f'*64
    elif fault=='image':r['Image']='foreign'
    elif fault=='uid':r['Config']['User']='0'
    elif fault=='socket':r['Mounts'][-1]['Source']='/unexpected.sock'
    elif fault=='owner_rw':r['Mounts'][2]['RW']=True
    elif fault=='command':r['Config']['Cmd']=['changed']
    elif fault=='env':r['Config']['Env']=[]
    elif fault=='privileged':r['HostConfig']['Privileged']=True
    elif fault=='cap':r['HostConfig']['CapAdd']=['SYS_ADMIN']
    elif fault=='security':r['HostConfig']['SecurityOpt']=[]
    elif fault=='network':r['NetworkSettings']['Networks']['unexpected']={}
    elif fault=='memory':r['HostConfig']['Memory']=0
    elif fault=='pid':r['HostConfig']['PidsLimit']=0
    elif fault=='cpu':r['HostConfig']['NanoCpus']=0
    elif fault=='group':r['HostConfig']['GroupAdd']=[]
    else:r['HostConfig']['Tmpfs']={}
    with pytest.raises(LifecycleError,match='worker_replaced'):c.verify_worker('a',r)


def test_same_owner_takeover_is_rejected_without_operator_lock():
    c=Cluster(descriptor());c.operator_lock=lambda:pytest.fail('operator lock created for invalid target')
    with pytest.raises(LifecycleError,match='takeover_scope'):c.takeover('a')


@pytest.mark.parametrize('busy',[False,True])
def test_pinned_unlabelled_service_exec_is_included_in_drain_barrier(monkeypatch,busy):
    from scripts import executor_cluster as module
    c=Cluster(descriptor());pinned='e'*64;calls=[]
    monkeypatch.setattr(c,'service_ids',lambda _: [pinned])
    def raw(args):
        calls.append(args)
        return json.dumps([{'Id':pinned,'ExecIDs':['running-exec'] if busy else None}]) if args[0]=='inspect' else ''
    monkeypatch.setattr(c,'raw',raw);ticks=iter([0,31])
    monkeypatch.setattr(module.time,'monotonic',lambda:next(ticks))
    if busy:
        with pytest.raises(LifecycleError,match='inflight_work_requires_investigation'):c.settle({})
    else:assert c.settle({})['pinned_services_inspected']==1
    assert ['inspect',pinned] in calls
