"""Coordinator-death recovery must preserve identity, phase and security state."""

import copy
import json

import pytest

from scripts import control_store
from scripts import control_transition as tr
from scripts.certificate_controller import LifecycleError
from scripts.control_plane_ha import Management
from scripts.control_store import COMPONENTS


@pytest.fixture
def transition(tmp_path,monkeypatch):
    project='c02-'+'a'*12;image='sha256:'+'a'*64
    old={'project':project,'image':image,'ca':{'name':project+'-ca','id':'a'*64},
        'leaf':{'name':project+'-leaf','id':'b'*64},'volumes':{k:project+'-a-'+k for k in ['ca','vault','leaf','renewal']},
        'service_hosts':{n:{'name':project+'-host-'+n,'id':n*64,'image':'sha256:'+'c'*64} for n in ['a','b']},
        'control_directory':str(tmp_path),'initial_root':'public-fixture','client_network':project+'-client',
        'cluster_network':project+'-cluster','gateways':[project+'-gate-a',project+'-gate-b'],'gateway_ids':['e'*64,'f'*64]}
    old['management']={'active':'a','epoch':1,'workload_mounts':[],
        'standby':{'name':project+'-standby','id':'d'*64},'cells':{n:{'generation':1,
        'volumes':{k:project+'-'+n+'-'+k.replace('_','-') for k in COMPONENTS}} for n in ['a','b']}}
    b=Management(old);b.directory=lambda:tmp_path;t=tr.Transition(b);t.lookup=lambda *_:None
    original=t.run;t.run=lambda:None
    t.begin('b','a',{'database_incarnation':'db-current','tree_sha256':'a'*64,'phase':'prepared','epoch':0,'plan_hash':'b'*64})
    t.run=original
    monkeypatch.delenv('SECOPS_CONTROL_MIRROR',raising=False)
    return t


@pytest.mark.parametrize('raw',['{','[]','null','{}','42'])
def test_invalid_journal_cannot_be_treated_as_no_transition(tmp_path,raw):
    p=tmp_path/'journal';p.write_text(raw)
    with pytest.raises(LifecycleError,match='journal_invalid'):tr.read(p)


@pytest.mark.parametrize('field,value',[('phase','complete'),('target','a'),('id','f'*32),('image','foreign')])
def test_modified_journal_fails_checksum(transition,field,value):
    t=transition;r=json.loads(t.path.read_bytes());r[field]=value;t.path.write_text(json.dumps(r))
    with pytest.raises(LifecycleError,match='journal_invalid'):tr.read(t.path)


@pytest.mark.parametrize('phase',tr.PHASES[:-1])
def test_pending_transition_blocks_ordinary_control_jobs(transition,phase):
    t=transition;t.record['phase']=phase;t.save();t.b.job=lambda *_a,**_k:pytest.fail('Docker job ran before transition refusal')
    with pytest.raises(LifecycleError,match='resume_required'):t.b.load_control()


def test_own_resume_token_allows_internal_recovery_only(transition):
    t=transition;t.b._transition_id=t.record['id'];tr.available(t.b)
    t.b._transition_id='f'*32
    with pytest.raises(LifecycleError,match='resume_required'):tr.available(t.b)


@pytest.mark.parametrize('field',['project','image'])
def test_foreign_journal_blocks_even_with_valid_checksum(transition,field):
    t=transition;t.record[field]='foreign';t.save()
    with pytest.raises(LifecycleError,match='journal_scope'):tr.available(t.b)


@pytest.mark.parametrize('fault',['epoch','active','candidate','replica','directory','database','network','root','workloads','checkpoint'])
def test_changed_transition_plan_refuses_before_any_docker_side_effect(transition,fault):
    t=transition;r=t.record;p=r['profile'];m=p['management']
    if fault=='epoch':m['epoch']+=1
    elif fault=='active':m['active']='a'
    elif fault=='candidate':m['cells']['b']['generation']+=1
    elif fault=='replica':m['cells']['a']['volumes']['ca']=p['project']+'-wrong'
    elif fault=='directory':p['control_directory']='elsewhere'
    elif fault=='database':p['service_hosts']['a']['id']='9'*64
    elif fault=='network':p['cluster_network']=p['project']+'-wrong'
    elif fault=='root':p['initial_root']='different'
    elif fault=='workloads':m['workload_mounts']=['unexpected']
    else:r['phase']='opening'
    t.b.raw=lambda *_a,**_k:pytest.fail('Docker inspected before invalid plan rejection')
    with pytest.raises(LifecycleError,match='control_transition_'):t.validate()


@pytest.fixture
def trees(tmp_path):
    sources={};targets={}
    for name in ['vault','control']:
        sources[name]=tmp_path/'source'/name;targets[name]=tmp_path/'target'/name
        sources[name].mkdir(parents=True);targets[name].mkdir(parents=True)
    (sources['vault']/'secret').write_bytes(b'generated-unit-only')
    (sources['control']/'state').write_text('prepared-checkpoint')
    return sources,targets


def test_copy_resumes_identical_prefix_after_interrupted_atomic_write(trees,monkeypatch):
    sources,targets=trees;expected=control_store.tree_digest(sources);original=control_store.replace_file;count=0
    def interrupted(path,body):
        nonlocal count
        count+=1
        if count==2:raise SystemExit(73)
        original(path,body)
    monkeypatch.setattr(control_store,'replace_file',interrupted)
    with pytest.raises(SystemExit):control_store.copy_replica(sources,targets,expected=expected)
    monkeypatch.setattr(control_store,'replace_file',original)
    control_store.copy_replica(sources,targets,expected=expected)
    assert control_store.tree_digest(targets)==expected


@pytest.mark.parametrize('fault',['source_changed','partial_conflict','unexpected_file'])
def test_copy_never_overwrites_an_unproven_source_or_partial_replica(trees,fault):
    sources,targets=trees;expected=control_store.tree_digest(sources)
    if fault=='source_changed':(sources['vault']/'secret').write_bytes(b'changed')
    elif fault=='partial_conflict':(targets['vault']/'secret').write_bytes(b'conflict')
    else:(targets['vault']/'unknown').write_bytes(b'unexpected')
    before={str(p):p.read_bytes() for p in targets['vault'].iterdir()}
    with pytest.raises(LifecycleError,match='control_replica_'):control_store.copy_replica(sources,targets,expected=expected)
    assert before=={str(p):p.read_bytes() for p in targets['vault'].iterdir()}


def process(t):
    name=t.b.project+'-planned';image=t.record['image']
    args=['create','--name',name,'--network','none','--restart','no','--read-only','--user','10001:10001',
        '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--pids-limit','128',
        '--tmpfs','/tmp:rw,size=32m','--tmpfs','/data:rw,uid=10001,gid=10001,size=1m',
        '--entrypoint','python',image,'-m','scripts.control_store','standby']
    spec={'args':args,'extra_network':None,'start':True}
    entry={'name':name,'args':args,'extra_network':None,'start':True,'spec':spec,'id':None}
    found={'Id':'9'*64,'Name':'/'+name,'Image':image,'State':{'Running':True},'Mounts':[],
        'NetworkSettings':{'Networks':{'none':{}}},'Config':{'User':'10001:10001','Entrypoint':['python'],
        'Cmd':['-m','scripts.control_store','standby'],'Env':['BASE=value'],
        'Labels':{tr.LABEL:t.record['id'],tr.SPEC:tr.digest(spec)}},
        'HostConfig':{'ReadonlyRootfs':True,'RestartPolicy':{'Name':'no'},'Privileged':False,'Binds':None,'CapAdd':None,
        'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges:true'],'Memory':512*1024**2,'PidsLimit':128,
        'NetworkMode':'none','Tmpfs':{'/tmp':'rw,size=32m','/data':'rw,uid=10001,gid=10001,size=1m'}}}
    t.image_env=['BASE=value']
    return entry,found


@pytest.mark.parametrize('fault',['id','image','label','spec','command','env','uid','privileged','rootfs','bind',
    'cap','security','memory','pid','mount','network','tmpfs','missing'])
def test_recreated_or_weakened_process_is_never_adopted(transition,fault):
    t=transition;entry,found=process(t)
    if fault=='id':entry['id']='8'*64
    elif fault=='image':found['Image']='foreign'
    elif fault=='label':found['Config']['Labels'][tr.LABEL]='f'*32
    elif fault=='spec':found['Config']['Labels'][tr.SPEC]='wrong'
    elif fault=='command':found['Config']['Cmd']=['different']
    elif fault=='env':found['Config']['Env'].append('LD_PRELOAD=unexpected')
    elif fault=='uid':found['Config']['User']='0'
    elif fault=='privileged':found['HostConfig']['Privileged']=True
    elif fault=='rootfs':found['HostConfig']['ReadonlyRootfs']=False
    elif fault=='bind':found['HostConfig']['Binds']=['/var/run/docker.sock:/var/run/docker.sock']
    elif fault=='cap':found['HostConfig']['CapAdd']=['SYS_ADMIN']
    elif fault=='security':found['HostConfig']['SecurityOpt']=[]
    elif fault=='memory':found['HostConfig']['Memory']=0
    elif fault=='pid':found['HostConfig']['PidsLimit']=0
    elif fault=='mount':found['Mounts']=[{'Type':'volume','Destination':'/vault','Name':'unexpected','RW':True}]
    elif fault=='network':found['NetworkSettings']['Networks']['unapproved']={}
    elif fault=='tmpfs':found['HostConfig']['Tmpfs']={}
    else:found=None
    with pytest.raises(LifecycleError,match='control_transition_process_'):t.verify_process(found,entry)


def test_created_process_with_lost_cli_reply_is_adopted_without_second_create(transition):
    t=transition;entry,found=process(t);t.record['processes'][entry['name']]=entry
    t.lookup=lambda *_:copy.deepcopy(found)
    t.b.raw=lambda *_a,**_k:pytest.fail('Docker create/start repeated for already running planned process')
    result=t.create_process(entry['name'],entry['args'],None,True)
    assert result['id']==found['Id'] and tr.read(t.path)['processes'][entry['name']]['id']==found['Id']


@pytest.mark.parametrize('frozen',[True,False])
def test_opening_resume_never_reconciles_or_resets_post_open_security_state(transition,frozen):
    t=transition;r=t.record;r['phase']='opening';r['state']={'phase':'idle'};r['fenced']=[{'stopped':True}]
    t.validate=lambda:None;t.primary=lambda:None;t.no_jobs=lambda:None;t.check_services=lambda:None
    t.fence=lambda:pytest.fail('post-open writer fence/reconcile repeated');t.replica=lambda:pytest.fail('post-open copy repeated')
    t.b.guard=lambda:None;calls=[]
    def witness(operation):
        calls.append(operation)
        return {'frozen':frozen,'pending':{} if frozen else {'new-client':1}} if operation=='status' else {}
    t.b.witness=witness
    first=t.run();second=t.run()
    assert first==second and first['management_epoch']==2 and r['phase']=='complete'
    assert calls==(['status','unfreeze'] if frozen else ['status'])


def test_post_open_csr_is_captured_while_publisher_is_still_running():
    from scripts.test_control_transition import CrashLab
    lab=object.__new__(CrashLab);lab.report={'control_checks':[]};lab.save=lambda:None
    csr='unit-fixture-csr';calls=[]
    lab.current_request=lambda:pytest.fail('JWT minted before CA restart')
    lab.private_rpc=lambda _program:calls.append('publisher-running') or csr
    lab.add('post_backup_token_consumption_and_revocation_established')
    assert lab.post_open_csr is csr and calls==['publisher-running']


def test_second_takeover_never_queries_already_stopped_publisher():
    from types import SimpleNamespace

    from scripts.test_control_transition import CrashLab
    class WorkerReached(Exception):
        pass
    lab=object.__new__(CrashLab);lab.takeovers=1;lab.post_open_csr='unit-csr'
    lab.backend=SimpleNamespace(profile={'management':{'epoch':2}})
    lab.current_request=lambda:pytest.fail('stopped publisher queried to prepare fixture')
    def worker(*_a,**_k):raise WorkerReached
    lab.worker=worker
    with pytest.raises(WorkerReached):lab.interrupted_promote('a','a')


def test_post_open_probe_mints_only_in_network_none_readonly_vault_job():
    from types import SimpleNamespace

    from scripts.test_control_transition import CrashLab
    lab=object.__new__(CrashLab);events=[];calls=[]
    lab.backend=SimpleNamespace(profile={'image':'sha256:'+'a'*64},volumes=lambda:{'vault':'owned-vault'},
        ensure_volumes=lambda values:events.append(values),
        command=lambda *_a,**_k:pytest.fail('normal management control bypassed'))
    def raw(args,payload):calls.append((args,payload));return json.dumps({'csr':payload,'ott':'fixture-only'})
    lab.backend.raw=raw
    result=lab.post_open_probe('prepared-csr')
    args,payload=calls[0]
    assert events==[['owned-vault']] and args[args.index('--network')+1]=='none'
    assert args[args.index('--mount')+1]=='type=volume,src=owned-vault,dst=/vault,readonly'
    assert '--read-only' in args and payload=='prepared-csr' and result['csr']=='prepared-csr'
