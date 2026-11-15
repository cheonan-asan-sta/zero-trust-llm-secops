"""Service graph identity, ordered admission, and no security-state rollback."""

import copy
import json
from types import SimpleNamespace

import pytest
from test_executor_transition import original

from scripts import executor_transition as op
from scripts import service_daemon_recovery as recovery
from scripts.certificate_controller import LifecycleError
from scripts.executor_cluster import Cluster
from scripts.service_recovery_store import read_record, write_record
from scripts.test_service_daemon_restart import ServiceLab


def found(index=1,running=False):
    ident=f'{index:064x}'
    return {'Id':ident,'Name':'/c02-'+'a'*12+f'-service-{index}','Image':'sha256:'+'b'*64,
        'Config':{'Env':['SECRET=not-published'],'User':'10001:10001','Cmd':['server']},
        'HostConfig':{'ReadonlyRootfs':True},'Mounts':[{'Type':'volume','Name':'v','Source':'/vol/v','Destination':'/state','RW':True}],
        'NetworkSettings':{'Networks':{'n':{'NetworkID':'net','Aliases':['two','one'],'IPAMConfig':None}}},
        'State':{'Status':'running' if running else 'exited','Running':running,'Paused':False},'ExecIDs':[]}


def manifest():
    c=Cluster(original());d={'schema':'executor-daemon-seal-1','anchor':c.anchor(),'daemon_id':'12345678-1234-1234-1234-123456789abc'}
    d={**d,'sha256':op.digest(d)}
    roles=['host','host','gateway','gateway','leaf','standby','worker','worker']
    pins={found(i)['Name'][1:]:recovery.pin(found(i),r) for i,r in enumerate(roles,1)}
    m={'schema':'service-daemon-seal-1','id':'d'*32,'daemon':d,'descriptor':original(),'profile_sha256':'a'*64,
        'management_role':{},'primary':'a','incarnation':'123456789012345','outer':pins,'inner':{'a':{},'b':{}},'volumes':{},
        'journal':c.project+'-services-'+'d'*32+'-journal'}
    return {**m,'sha256':op.digest(m)}


def record(phase='ready'):
    return {'manifest':manifest(),'actor':'e'*64,'phase':phase,'cycle':1,'was_frozen':None if phase=='ready' else False,'receipt':None,'history':[]}


@pytest.mark.parametrize('fault',['checksum','schema','id','journal','missing_host','missing_gateway','duplicate_id','primary','inner'])
def test_invalid_graph_refuses_before_any_docker_operation(monkeypatch,fault):
    m=manifest()
    if fault=='checksum':m['sha256']='0'*64
    elif fault=='schema':m['schema']='bad'
    elif fault=='id':m['id']='bad'
    elif fault=='journal':m['journal']='foreign'
    elif fault.startswith('missing_'):
        role=fault.removeprefix('missing_');key=next(k for k,v in m['outer'].items() if v['role']==role);del m['outer'][key]
    elif fault=='duplicate_id':list(m['outer'].values())[1]['id']=next(iter(m['outer'].values()))['id']
    elif fault=='primary':m['primary']='c'
    else:m['inner'].pop('b')
    if fault!='checksum':m['sha256']=op.digest({k:v for k,v in m.items() if k!='sha256'})
    monkeypatch.setattr(recovery.daemon,'verify_daemon',lambda *a:pytest.fail('contacted daemon'))
    with pytest.raises(LifecycleError):recovery.recover_services(m)


@pytest.mark.parametrize('field',['Id','Name','Image','Config','HostConfig','Mounts'])
def test_full_object_pin_rejects_changed_spec_even_when_stopped(field):
    item=found();expected=recovery.pin(item,'leaf');changed=copy.deepcopy(item)
    changed[field]={'changed':True} if isinstance(item[field],dict) else [] if isinstance(item[field],list) else 'changed'
    with pytest.raises(LifecycleError):recovery.check_pin(changed,expected)


def test_secret_environment_is_hashed_and_alias_order_is_not_identity():
    item=found();signature=recovery.spec(item);item['NetworkSettings']['Networks']['n']['Aliases'].reverse()
    assert recovery.spec(item)==signature
    assert 'not-published' not in json.dumps(recovery.pin(item,'leaf'))
    item['Config']['Env']=['SECRET=other'];assert recovery.spec(item)!=signature


@pytest.mark.parametrize('mode',['default','bridge'])
def test_builtin_bridge_runtime_network_id_can_change_on_same_daemon_restart(mode):
    item=found();item['HostConfig']['NetworkMode']=mode
    item['NetworkSettings']['Networks']={'bridge':item['NetworkSettings']['Networks']['n']}
    expected=recovery.pin(item,'ca');item['NetworkSettings']['Networks']['bridge']['NetworkID']='new-builtin-id'
    recovery.check_pin(item,expected)
    item['HostConfig']['NetworkMode']='other'
    with pytest.raises(LifecycleError):recovery.check_pin(item,expected)


def test_custom_network_replacement_still_refuses_even_when_name_and_aliases_match():
    item=found();item['HostConfig']['NetworkMode']='n';expected=recovery.pin(item,'gateway')
    item['NetworkSettings']['Networks']['n']['NetworkID']='replacement-network'
    with pytest.raises(LifecycleError):recovery.check_pin(item,expected)


def test_inherited_dns_null_and_empty_survive_reload_but_explicit_resolver_change_refuses():
    item=found();item['HostConfig']['Dns']=None;expected=recovery.pin(item,'worker')
    item['HostConfig']['Dns']=[];recovery.check_pin(item,expected)
    item['HostConfig']['Dns']=['192.0.2.53']
    with pytest.raises(LifecycleError):recovery.check_pin(item,expected)


def test_fixture_does_not_accept_expected_code_appearing_only_in_traceback_source(tmp_path,monkeypatch):
    lab=ServiceLab.__new__(ServiceLab);lab.directory=tmp_path
    result=SimpleNamespace(returncode=1,stderr="raise LifecycleError('services_recovery_result_unknown')\nLifecycleError: services_object_replaced\n")
    from scripts import test_service_daemon_restart as fixture
    monkeypatch.setattr(fixture.subprocess,'run',lambda *args,**kwargs:result)
    with pytest.raises(fixture.flow.CheckFailed,match='wrong_cut'):
        lab.recover_services(expected='services_recovery_result_unknown')


@pytest.mark.parametrize('fault',['phase','cycle','actor','history','frozen','receipt','extra'])
def test_invalid_recovery_record_is_not_a_resume_authority(fault):
    value=record('intent')
    if fault=='phase':value['phase']='unknown'
    elif fault=='cycle':value['cycle']=False
    elif fault=='actor':value['actor']='bad'
    elif fault=='history':value['history']=[{}]
    elif fault=='frozen':value['was_frozen']=None
    elif fault=='receipt':value['receipt']={}
    else:value['extra']='x'
    with pytest.raises(LifecycleError):recovery.validate_record(value)


def test_public_journal_checksum_and_same_content_survive_read_retry(tmp_path):
    path=tmp_path/'services.json';value=record();write_record(path,value)
    assert recovery.validate_record(read_record(path))==value
    payload=json.loads(path.read_bytes());payload['cycle']=2;path.write_text(json.dumps(payload),encoding='utf-8')
    with pytest.raises(LifecycleError,match='journal_invalid'):read_record(path)


@pytest.mark.parametrize('fault',['other_id','paused','exec','running_exec'])
def test_entire_start_group_validated_before_any_start(monkeypatch,fault):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();calls=[]
    items={entry['id']:found(i) for i,entry in enumerate(actor.m['outer'].values(),1)}
    targets=[v for v in actor.m['outer'].values() if v['role']=='host'];bad=items[targets[1]['id']]
    if fault=='other_id':bad['Id']='f'*64
    elif fault=='paused':bad['State'].update(Running=True,Status='paused',Paused=True)
    else:
        bad['ExecIDs']=['unknown']
        if fault=='running_exec':bad['State'].update(Running=True,Status='running')
    class Backend:
        def raw(self,args):calls.append(args)
    actor.c=Backend();monkeypatch.setattr(recovery,'inspect',lambda c,i:items[i])
    with pytest.raises(LifecycleError):actor.start({'host'})
    assert calls==[]


@pytest.mark.parametrize('fault',['dual_primary','dual_standby','wrong_primary','incarnation','unsynced'])
def test_database_checks_never_promote_or_restore(fault):
    calls=[]
    class Backend:
        def sql(self,site,statement):
            calls.append(statement)
            if 'pg_is_in_recovery' in statement:
                return 'f' if fault=='dual_primary' else 't' if fault=='dual_standby' else ('t' if site=='a' else 'f') if fault=='wrong_primary' else 'f' if site=='a' else 't'
            if 'system_identifier' in statement:return 'wrong' if fault=='incarnation' else '123'
            return '0' if fault=='unsynced' else '1'
    with pytest.raises(LifecycleError):recovery.database_proof(Backend(),'a','123')
    assert all(s.startswith('SELECT ') for s in calls)


def test_completed_online_retry_does_not_reclose_or_validate_an_old_snapshot(monkeypatch):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.r=record('complete')
    actor.r['receipt']={'id':actor.m['id'],'cycle':1,'accepted_after_open':True}
    actor.outer=lambda:{k:found(i,True) for i,k in enumerate(actor.m['outer'],1)}
    host_checks=[]
    actor.hosts_ready=lambda **kwargs:host_checks.append(kwargs['allow_start']) or True
    actor.healthy_databases=lambda:True;actor.wait=lambda f:f()
    class Backend:
        def node_health(self,s):return True
    actor.b=Backend();monkeypatch.setattr(recovery,'storage_proof',lambda b:pytest.fail('replayed old security snapshot'))
    actor.advance=lambda phase:pytest.fail('changed completed phase')
    assert actor.run()==actor.r['receipt']
    assert host_checks==[False]


def test_opened_resume_preserves_new_consumption_without_freeze_or_checkpoint(monkeypatch):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.r=record('leaf');actor.c=Cluster(original())
    actor.outer=lambda:{k:found(i,True) for i,k in enumerate(actor.m['outer'],1)}
    host_checks=[]
    actor.hosts_ready=lambda **kwargs:host_checks.append(kwargs['allow_start']) or True
    actor.healthy_databases=lambda:True;actor.wait=lambda f:f();calls=[]
    actor.start=lambda roles:calls.append(roles)
    actor.advance=lambda phase:actor.r.update(phase=phase)
    class Backend:
        def offline_witness(self,operation):
            assert operation=='status'
            return {'frozen':False,'sequence':100,'pending':3}
        def role(self):return {}
    actor.b=Backend();monkeypatch.setattr(recovery,'storage_proof',lambda b:pytest.fail('new security state was compared to old baseline'))
    assert actor.run()['cycle']==1
    assert calls==[{'leaf','worker'}]
    assert host_checks==[False]


@pytest.mark.parametrize('closed',[False,True])
def test_database_proof_precedes_admission_and_existing_closed_intent_survives(tmp_path,monkeypatch,closed):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.r=record();actor.path=tmp_path/'services.json'
    actor.c=Cluster(original());events=[]
    items={k:found(i) for i,k in enumerate(actor.m['outer'],1)}
    actor.outer=lambda:items;actor.wait=lambda call:call()
    def hosts():events.append('hosts-verified');return True
    def database(checkpoint=None):
        assert checkpoint=={'frozen':closed}
        events.append('database-verified');return True
    def start(roles):
        events.append('start:'+','.join(sorted(roles)))
        for name,entry in actor.m['outer'].items():
            if entry['role'] in roles:items[name]['State'].update(Running=True,Status='running')
    actor.hosts_ready=hosts;actor.healthy_databases=database;actor.start=start
    class Backend:
        def offline_witness(self,operation):events.append(operation);return {'frozen':closed}
        def node_health(self,site):events.append('ca-verified:'+site)
        def role(self):return {}
    actor.b=Backend()
    monkeypatch.setattr(recovery,'storage_proof',lambda b:{'witness':{'frozen':closed}})
    receipt=actor.run()
    assert receipt['admission_preserved_closed']==closed
    assert events.index('freeze')<events.index('start:host')<events.index('database-verified')<events.index('start:gateway')<events.index('start:leaf,worker')
    assert ('unfreeze' in events)==(not closed)
    if not closed:assert events.index('start:gateway')<events.index('unfreeze')<events.index('start:leaf,worker')
    assert read_record(actor.path)['phase']=='complete'


def test_private_checkpoint_refusal_never_starts_services_or_clears_pending(tmp_path,monkeypatch):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.r=record();actor.path=tmp_path/'services.json'
    actor.outer=lambda:{k:found(i) for i,k in enumerate(actor.m['outer'],1)}
    operations=[]
    class Backend:
        def offline_witness(self,operation):operations.append(operation);return {'frozen':False}
    actor.b=Backend();actor.start=lambda roles:pytest.fail('started services without current security proof')
    def refuse(b):raise LifecycleError('services_security_checkpoint_uncertain')
    monkeypatch.setattr(recovery,'storage_proof',refuse)
    with pytest.raises(LifecycleError,match='checkpoint_uncertain'):actor.run()
    assert operations==['status'] and not actor.path.exists()


def test_completed_online_retry_restores_only_stopped_fixed_workers(monkeypatch):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.r=record('complete')
    actor.r['receipt']={'id':actor.m['id'],'cycle':1}
    items={k:found(i,entry['role']!='worker') for i,(k,entry) in enumerate(actor.m['outer'].items(),1)}
    actor.outer=lambda:items;actor.wait=lambda call:call();actor.hosts_ready=lambda **kwargs:True;actor.healthy_databases=lambda:True
    calls=[]
    def start(roles):
        calls.append(roles)
        for name,entry in actor.m['outer'].items():
            if entry['role'] in roles:items[name]['State'].update(Running=True,Status='running')
    actor.start=start
    class Backend:
        def node_health(self,site):return True
    actor.b=Backend();monkeypatch.setattr(recovery,'storage_proof',lambda b:pytest.fail('rechecked old snapshot'))
    assert actor.run()==actor.r['receipt']
    assert calls==[{'worker'}]


@pytest.mark.parametrize('stopped_role',['database','ca'])
def test_open_admission_inner_health_check_never_starts_a_newly_stopped_service(monkeypatch,stopped_role):
    actor=recovery.Actor.__new__(recovery.Actor);actor.m=manifest();actor.c=object()
    actor.m['inner']={};items={};hosts={}
    for index,site in enumerate(['a','b'],1):
        host=found(index,True);host['NetworkSettings']['Networks']['n']['IPAddress']=f'172.20.0.{index}'
        hosts[site]={'id':host['Id'],'address':f'172.20.0.{index}'};items[host['Id']]=host
        inner={}
        for offset,role in enumerate(['database','ca'],10):
            item=found(index*100+offset,not (site=='a' and role==stopped_role));items[item['Id']]=item
            inner[role]=recovery.pin(item,role)
        actor.m['inner'][site]={'daemon_id':'engine-'+site,'volumes':{},'containers':inner}
    class Backend:
        def __init__(self):self.profile={'cluster_network':'n'}
        def inner(self,site,args):
            if args[0]=='info':return 'engine-'+site
            if args[0]=='inspect':return json.dumps([items[args[1]]])
            pytest.fail('started an inner service while admission was open')
    actor.b=Backend();actor.b.hosts=hosts
    monkeypatch.setattr(recovery,'inspect',lambda c,ident:items[ident])
    with pytest.raises(LifecycleError,match='live_inner_outage_requires_quiescence'):
        actor.hosts_ready(allow_start=False)
