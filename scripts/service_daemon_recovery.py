"""Identity-pinned, admission-first C04 service recovery on the same Docker store.

No database promotion, backup restore, key regeneration or business POST retries.
"""

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scripts import executor_daemon_recovery as daemon
from scripts import executor_transition as op
from scripts.authority_rotation_coordinator import lease
from scripts.certificate_controller import LifecycleError, save
from scripts.control_executor import ExecutorManagement
from scripts.executor_cluster import Cluster
from scripts.executor_store import ENV, Store
from scripts.service_recovery_store import read_record, write_record

PHASES=('ready','intent','frozen','hosts','database','workloads','gateways','opening','leaf','complete')
STAGES={'host':'hosts','workload':'workloads','standby':'workloads','gateway':'gateways','leaf':'leaf','worker':'leaf'}
MANIFEST_ENV='SECOPS_SERVICE_MANIFEST'
FAULT_ENV='SECOPS_SERVICE_TEST_CUTS'
CUTS={'after_hosts','after_leaf'}


def spec(found):
    cfg=copy.deepcopy(found['Config']);cfg['Env']=op.digest(cfg.get('Env') or [])
    networks={n:{'NetworkID':None if n=='bridge' and found['HostConfig'].get('NetworkMode') in {'default','bridge'} else v.get('NetworkID'),
        'Aliases':sorted(v.get('Aliases') or []),'IPAMConfig':v.get('IPAMConfig')} for n,v in found['NetworkSettings']['Networks'].items()}
    return op.digest({'id':found['Id'],'name':found['Name'],'image':found['Image'],'config':cfg,
        'host':found['HostConfig'],'mounts':found['Mounts'],'networks':networks})


def pin(found,role):return {'id':found['Id'],'name':found['Name'][1:],'image':found['Image'],'spec':spec(found),'role':role}


def volume_spec(value):return op.digest({k:value.get(k) for k in ['Name','Driver','Options','Labels','Scope']})


def inspect(c,ident):return json.loads(c.raw(['inspect',ident]))[0]


def check_pin(found,expected):
    if found['Id']!=expected['id'] or found['Name']!='/'+expected['name'] or found['Image']!=expected['image'] or spec(found)!=expected['spec']:
        raise LifecycleError('services_object_replaced')
    op.require_worker_state(found)
    if found.get('ExecIDs'):raise LifecycleError('services_unfinished_exec')


def profile(c):
    values=[]
    for site in ['a','b']:
        for kind in ['journal','owner']:c.verify_volume(site,kind)
        files=c.disk(c.d['hosts'][site]['journal'],'read')
        if files.get('cluster.json')!=c.d or c.disk(c.d['hosts'][site]['owner'],'read')!={'owner.json':c.role()}:
            raise LifecycleError('services_executor_state_changed')
        marker=op.read_record(files[op.NAME]) if op.NAME in files else None
        if marker is not None and (marker['phase']!='complete' or marker['planned']!=c.d):
            raise LifecycleError('services_executor_transition_pending')
        values.append((files['profile.json'],marker))
    if values[0]!=values[1]:raise LifecycleError('services_executor_replicas_diverged')
    return values[0][0]


def storage_proof(b):
    mounts=[(v,f'/source/{s}/{k}',True) for s in ['a','b'] for k,v in b.volumes(s).items()]
    args=['run','--rm','-i','--network','none','--read-only','--user','10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges:true']
    for v,d,_ in mounts:args+=['--mount',f'type=volume,src={v},dst={d},readonly']
    return json.loads(b.raw([*args,'--entrypoint','python',b.profile['image'],'-m','scripts.service_recovery_store'],
        {'operation':'private-proof','expected':b.role()}))


def database_proof(b,primary,incarnation,*,checkpoint=None):
    roles={s:b.sql(s,'SELECT pg_is_in_recovery();') for s in ['a','b']}
    if roles!={s:'f' if s==primary else 't' for s in ['a','b']}:
        raise LifecycleError('services_database_role_changed')
    for s in ['a','b']:
        if b.sql(s,'SELECT system_identifier FROM pg_control_system();')!=incarnation:
            raise LifecycleError('services_database_incarnation_changed')
    standby='b' if primary=='a' else 'a'
    if b.sql(primary,"SELECT count(*) FROM pg_stat_replication WHERE state='streaming' AND sync_state='sync';")!='1':
        raise LifecycleError('services_database_replica_not_sync')
    if checkpoint is not None:
        from scripts.ca_host_recovery import lsn
        if lsn(b.sql(standby,'SELECT pg_last_wal_replay_lsn();'))<lsn(checkpoint['checkpoint_lsn']):
            raise LifecycleError('services_database_replica_behind')
        # Read only the current security tables; never reconcile/replace them.
        program="import json;from scripts.ca_recovery_state import snapshot;from pathlib import Path;print(json.dumps({'sha256':snapshot(json.loads(Path('/witness/config.json').read_bytes())['dsn'])['sha256']}))"
        a=b.volumes();args=['run','--rm','--network',b.profile['cluster_network'],'--read-only','--user','10001:10001','--cap-drop=ALL',
            '--mount',f"type=volume,src={a['witness']},dst=/witness,readonly",'--mount',f"type=volume,src={a['reader']},dst=/reader,readonly",
            '--entrypoint','python',b.profile['image'],'-c',program]
        if json.loads(b.raw(args))['sha256']!=checkpoint['checkpoint_hash']:
            raise LifecycleError('services_database_security_checkpoint_mismatch')
    return {'primary':primary,'incarnation':incarnation,'synchronous':True}


def journal(c,volume,operation,**fields):
    return json.loads(c.raw(['run','--rm','-i','--network','none','--read-only','--user','10001:10001',
        '--mount',f'type=volume,src={volume},dst=/data'+(',readonly' if operation=='read' else ''),
        '--entrypoint','python',c.d['graph_image'],'-m','scripts.service_recovery_store'],{'operation':operation,**fields}))


def validate_manifest(value):
    try:
        m=copy.deepcopy(value);checksum=m.pop('sha256')
        if (m['schema']!='service-daemon-seal-1' or checksum!=op.digest(m) or not re.fullmatch(r'[a-f0-9]{32}',m['id'])
                or m['journal']!=m['descriptor']['project']+'-services-'+m['id']+'-journal'):raise ValueError
        Cluster(m['descriptor']);daemon.validate_seal(m['daemon'])
        if m['daemon']['anchor']!=Cluster(m['descriptor']).anchor():raise ValueError
        for entry in m['outer'].values():
            if (entry['role'] not in STAGES or not re.fullmatch(re.escape(m['descriptor']['project'])+r'-[a-zA-Z0-9_.-]+',entry['name'])
                    or not re.fullmatch(r'[a-f0-9]{64}',entry['id'])):raise ValueError
        roles=[e['role'] for e in m['outer'].values()]
        if (any(roles.count(role)!=count for role,count in {'host':2,'gateway':2,'leaf':1,'standby':1,'worker':2}.items())
                or len({e['id'] for e in m['outer'].values()})!=len(roles) or roles.count('workload')>32
                or set(m['inner'])!={'a','b'} or m['primary'] not in {'a','b'}):raise ValueError
    except (ValueError,KeyError,TypeError):raise LifecycleError('services_manifest_invalid') from None
    return m


def seal_services(c,extras=()):
    # The profile's control directory belongs to the Linux maintenance host,
    # never to a Windows console. Keep existing path/lease guards intact.
    return c.rpc('service-seal',(list(extras),),timeout=300)['result']


def seal_services_local(c,extras=()):
    p=profile(c)
    # Healthy worker RPC already enforces paired public profile and owner guards.
    c.rpc('view');public_daemon=daemon.seal_daemon(c)
    from scripts.control_plane_ha import Management
    b=Management(p);proof=storage_proof(b)
    hosts=p['service_hosts'];primary=[s for s in ['a','b'] if b.sql(s,'SELECT pg_is_in_recovery();')=='f']
    if len(primary)!=1:raise LifecycleError('services_database_role_changed')
    database_proof(b,primary[0],proof['database_incarnation'],checkpoint=proof['witness'])
    outer={}
    expected=[(n,'host') for n in hosts.values()]+[(p['leaf'],'leaf'),(p['management']['standby'],'standby')]
    expected += [({'name':n,'id':i},'gateway') for n,i in zip(p['gateways'],p['gateway_ids'],strict=True)]
    expected += [(h['worker'],'worker') for h in c.d['hosts'].values()]
    expected += [(entry,'workload') for entry in extras]
    for item,role in expected:
        found=inspect(c,item['id'])
        if found['Name']!='/'+item['name'] or not found['State']['Running']:raise LifecycleError('services_seal_not_healthy')
        if role!='host' and any(m['Destination']=='/vault' or m['Destination'].endswith('docker.sock') for m in found['Mounts']) and role!='worker':
            raise LifecycleError('services_online_privileged_mount')
        op.require_worker_state(found);outer[item['name']]=pin(found,role)
    inner={}
    for s,node in hosts.items():
        if b.inner(s,['info','--format','{{.ID}}']).strip()!=node['daemon_id']:raise LifecycleError('services_inner_daemon_changed')
        containers={}
        for name,role in [(node['database'],'database'),(node['ca']['name'],'ca')]:
            found=json.loads(b.inner(s,['inspect',name]))[0]
            if not found['State']['Running']:raise LifecycleError('services_seal_not_healthy')
            h=found['HostConfig'];cfg=found['Config']
            if (cfg['User']!='10001:10001' or not h['ReadonlyRootfs'] or h.get('Privileged') or h.get('CapAdd')
                    or h.get('CapDrop')!=['ALL'] or any(x['Destination']=='/vault' or x['Destination'].endswith('docker.sock') for x in found['Mounts'])):
                raise LifecycleError('services_inner_privileged_mount')
            if role=='ca':b.owned_ca(s)
            containers[role]=pin(found,role)
        volumes={v:volume_spec(json.loads(b.inner(s,['volume','inspect',v]))[0]) for v in [node['data_volume'],node['tls_volume'],node['ca_volume']]}
        inner[s]={'daemon_id':node['daemon_id'],'containers':containers,'volumes':volumes}
    volumes={m['Name'] for e in outer.values() for m in inspect(c,e['id'])['Mounts'] if m['Type']=='volume'}
    volumes.update(v for cell in p['management']['cells'].values() for v in cell['volumes'].values())
    volumes={v:volume_spec(json.loads(c.raw(['volume','inspect',v]))[0]) for v in volumes}
    ident=uuid.uuid4().hex;volume=c.project+'-services-'+ident+'-journal'
    m={'schema':'service-daemon-seal-1','id':ident,'daemon':public_daemon,'descriptor':copy.deepcopy(c.d),'profile_sha256':op.digest(p),
        'management_role':b.role(),'primary':primary[0],'incarnation':proof['database_incarnation'],'outer':outer,'inner':inner,'volumes':volumes,'journal':volume}
    m={**m,'sha256':op.digest(m)};validate_manifest(m)
    c.raw(['volume','create','--label','secops.c02='+c.project,'--label','secops.services-seal='+ident,volume])
    journal(c,volume,'initialize',value={'manifest':m,'actor':None,'phase':'ready','cycle':1,'was_frozen':None,'receipt':None,'history':[]})
    return m


def validate_record(record):
    try:
        if (set(record)!={'manifest','actor','phase','cycle','was_frozen','receipt','history'}
                or record['phase'] not in PHASES or type(record['cycle']) is not int or not 1<=record['cycle']<=17
                or len(record['history'])!=record['cycle']-1
                or record['actor'] is not None and not re.fullmatch(r'[a-f0-9]{64}',record['actor'])
                or record['phase']!='ready' and type(record['was_frozen']) is not bool
                or record['phase']!='complete' and record['receipt'] is not None):raise ValueError
        validate_manifest(record['manifest'])
        if record['phase']=='complete' and (record['receipt']['id']!=record['manifest']['id'] or record['receipt']['cycle']!=record['cycle']):raise ValueError
    except (ValueError,KeyError,TypeError):raise LifecycleError('services_journal_invalid') from None
    return record


def actor_args(m,cuts=()):
    c=Cluster(m['descriptor']);args=['create','--name',c.project+'-services-recovery','--label','secops.c02='+c.project,
        '--label','secops.services-seal='+m['id'],'--network','none','--restart','no','--read-only','--user','10001:10001',
        '--group-add',str(c.d['docker_group']),'--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--pids-limit','128',
        '--tmpfs','/tmp:rw,size=32m','--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
        '--mount',f"type=volume,src={m['journal']},dst=/data",'--env','DOCKER_HOST=unix:///var/run/docker.sock',
        '--env',MANIFEST_ENV+'='+m['sha256'],'--env',ENV+'='+json.dumps(c.context(c.d['active']),sort_keys=True,separators=(',',':'))]
    for v,d,r in c.mounts(c.d['active']):args+=['--mount',f'type=volume,src={v},dst={d}'+(',readonly' if r else '')]
    if cuts:
        if not set(cuts)<=CUTS or len(set(cuts))!=len(cuts):raise LifecycleError('services_test_cut_scope')
        args+=['--env',FAULT_ENV+'='+json.dumps(list(cuts),separators=(',',':'))]
    return [*args,'--entrypoint','python',c.d['executor_image'],'-m','scripts.service_daemon_recovery','test-actor' if cuts else 'actor']


def verify_actor(c,m,found):
    h=found['HostConfig'];cfg=found['Config'];env=cfg.get('Env') or []
    base=json.loads(c.raw(['image','inspect',c.d['executor_image']]))[0]['Config'].get('Env') or []
    expected=dict(v.split('=',1) for v in base);expected.update({'DOCKER_HOST':'unix:///var/run/docker.sock',MANIFEST_ENV:m['sha256'],ENV:json.dumps(c.context(c.d['active']),sort_keys=True,separators=(',',':'))})
    values=dict(v.split('=',1) for v in env);mode='actor'
    if FAULT_ENV in values:
        try:cuts=json.loads(values[FAULT_ENV])
        except ValueError:raise LifecycleError('services_actor_replaced') from None
        if not isinstance(cuts,list) or not cuts or not set(cuts)<=CUTS or len(set(cuts))!=len(cuts):raise LifecycleError('services_actor_replaced')
        expected[FAULT_ENV]=json.dumps(cuts,separators=(',',':'));mode='test-actor'
    mounts={d:(v,not r) for v,d,r in c.mounts(c.d['active'])};mounts.update({'/data':(m['journal'],True),'/var/run/docker.sock':('/var/run/docker.sock',True)})
    actual={x['Destination']:(x.get('Name') if x['Type']=='volume' else x.get('Source'),x['RW']) for x in found['Mounts'] if x['Type']!='tmpfs'}
    if (found['Name']!='/'+c.project+'-services-recovery' or found['Image']!=c.d['executor_image'] or cfg['User']!='10001:10001'
            or cfg['Entrypoint']!=['python'] or cfg['Cmd']!=['-m','scripts.service_daemon_recovery',mode]
            or cfg['Labels'].get('secops.services-seal')!=m['id'] or actual!=mounts or len(env)!=len(expected) or dict(v.split('=',1) for v in env)!=expected
            or h['NetworkMode']!='none' or not h['ReadonlyRootfs'] or h.get('Privileged') or h.get('CapAdd') or h.get('CapDrop')!=['ALL']
            or h.get('SecurityOpt')!=['no-new-privileges:true'] or h.get('GroupAdd')!=[str(c.d['docker_group'])]
            or h['Memory']!=512*1024**2 or h['PidsLimit']!=128 or h.get('Tmpfs')!={'/tmp':'rw,size=32m'} or h['RestartPolicy']['Name'] not in {'','no'}):
        raise LifecycleError('services_actor_replaced')


def recover_services(manifest,*,test_cuts=()):
    validate_manifest(manifest);c=Cluster(manifest['descriptor']);daemon.verify_daemon(manifest['daemon'],c.anchor())
    data=json.loads(c.raw(['volume','inspect',manifest['journal']]))[0]
    if data.get('Labels',{}).get('secops.services-seal')!=manifest['id']:raise LifecycleError('services_journal_identity')
    record=validate_record(journal(c,manifest['journal'],'read'))
    if record['manifest']!=manifest:raise LifecycleError('services_journal_manifest_changed')
    found=op.lookup(c,c.project+'-services-recovery')
    if found is None:
        if record['actor'] is not None:
            op.require_absent(c,[record['actor']])
            if record['phase']!='complete':raise LifecycleError('services_incomplete_actor_missing')
        ident=c.raw(actor_args(manifest,test_cuts)).strip();found=op.lookup(c,c.project+'-services-recovery')
        if found is None or found['Id']!=ident:raise LifecycleError('services_actor_create_unknown')
    verify_actor(c,manifest,found);op.require_stopped(found)
    if record['actor']!=found['Id']:journal(c,manifest['journal'],'bind',actor=found['Id'])
    result=subprocess.run(['docker','start','--attach',found['Id']],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=900,check=False)
    after=inspect(c,found['Id']);verify_actor(c,manifest,after);op.require_stopped(after)
    if result.returncode or after['State']['ExitCode']:
        codes=re.findall(r'LifecycleError: ([a-z0-9_]+)',result.stderr)
        raise LifecycleError(codes[-1] if codes else 'services_recovery_result_unknown')
    record=journal(c,manifest['journal'],'read')
    if record['phase']!='complete':raise LifecycleError('services_recovery_incomplete')
    c.raw(['rm','--volumes',found['Id']]);return record['receipt']


class Actor:
    def __init__(self):
        self.path=Path('/data/services.json');self.r=validate_record(read_record(self.path));self.m=self.r['manifest'];validate_manifest(self.m)
        if os.environ.get(MANIFEST_ENV)!=self.m['sha256']:raise LifecycleError('services_actor_manifest_changed')
        self.c=Cluster(self.m['descriptor']);daemon.verify_daemon(self.m['daemon'],self.c.anchor())
        found=op.lookup(self.c,self.c.project+'-services-recovery');verify_actor(self.c,self.m,found)
        if self.r['actor']!=found['Id'] or self.r['phase'] not in PHASES:raise LifecycleError('services_actor_identity_changed')
        self.store=Store.environment();self.store.guard();p=self.store.load_json('profile.json')
        if op.digest(p)!=self.m['profile_sha256']:raise LifecycleError('services_profile_changed')
        self.b=ExecutorManagement(p,self.store)
        if self.b.role()!=self.m['management_role']:raise LifecycleError('services_management_role_changed')

    def advance(self,phase):
        if PHASES.index(self.r['phase'])<PHASES.index(phase):self.r['phase']=phase;write_record(self.path,self.r)

    def outer(self):
        found={}
        for name,expected in self.m['outer'].items():
            item=inspect(self.c,expected['id']);check_pin(item,expected);found[name]=item
        for name,digest in self.m['volumes'].items():
            if volume_spec(json.loads(self.c.raw(['volume','inspect',name]))[0])!=digest:raise LifecycleError('services_volume_replaced')
        protected={v for cell in self.b.profile['management']['cells'].values() for v in cell['volumes'].values()}
        ids=self.c.raw(['ps','--quiet','--no-trunc']).split()
        if ids:
            for item in json.loads(self.c.raw(['inspect',*ids])):
                if item['Id'] not in {v['id'] for v in self.m['outer'].values()} and any(x.get('Name') in protected and x['RW'] for x in item['Mounts']):
                    raise LifecycleError('services_unknown_private_writer')
        return found

    def start(self,roles):
        items=[(e,inspect(self.c,e['id'])) for e in self.m['outer'].values() if e['role'] in roles]
        for expected,item in items:check_pin(item,expected)
        for _,item in items:
            if not item['State']['Running']:self.c.raw(['start',item['Id']])

    def wait(self,call):
        deadline=time.monotonic()+75
        while True:
            try:return call()
            except LifecycleError:
                if time.monotonic()>=deadline:raise
                time.sleep(.5)

    def hosts_ready(self,*,allow_start=True):
        pending=[]
        for s,node in self.b.hosts.items():
            if self.b.inner(s,['info','--format','{{.ID}}']).strip()!=self.m['inner'][s]['daemon_id']:raise LifecycleError('services_inner_daemon_changed')
            actual=inspect(self.c,node['id'])['NetworkSettings']['Networks'][self.b.profile['cluster_network']]['IPAddress']
            if actual!=node['address']:raise LifecycleError('services_host_address_changed')
            for name,digest in self.m['inner'][s]['volumes'].items():
                if volume_spec(json.loads(self.b.inner(s,['volume','inspect',name]))[0])!=digest:raise LifecycleError('services_inner_volume_changed')
            for expected in self.m['inner'][s]['containers'].values():
                item=json.loads(self.b.inner(s,['inspect',expected['id']]))[0];check_pin(item,expected)
                pending.append((s,item))
        if not allow_start and any(not item['State']['Running'] for _,item in pending):
            raise LifecycleError('services_live_inner_outage_requires_quiescence')
        for s,item in pending:
            if not item['State']['Running']:self.b.inner(s,['start',item['Id']])
        return True

    def healthy_databases(self,checkpoint=None):return database_proof(self.b,self.m['primary'],self.m['incarnation'],checkpoint=checkpoint)

    def cut(self,point):
        if sys.argv[-1]!='test-actor' or point not in json.loads(os.environ.get(FAULT_ENV,'[]')):return
        path=Path('/data/faults.json');used=json.loads(path.read_bytes()) if path.exists() else []
        key=f"{self.r['cycle']}:{point}"
        if key not in used:op.write_path(path,[*used,key]);os._exit(73)

    def run(self):
        found=self.outer();services=[v for k,v in found.items() if self.m['outer'][k]['role']!='worker']
        online=all(i['State']['Running'] for i in services)
        if self.r['phase']=='complete' and online:
            self.wait(lambda:self.hosts_ready(allow_start=False));self.wait(self.healthy_databases)
            for s in ['a','b']:self.b.node_health(s)
            if any(not found[k]['State']['Running'] for k,v in self.m['outer'].items() if v['role']=='worker'):
                self.start({'worker'})
                if not all(i['State']['Running'] for i in self.outer().values()):raise LifecycleError('services_not_running')
            return self.r['receipt']
        if self.r['phase']=='complete':
            if any(i['State']['Running'] for i in services):raise LifecycleError('services_live_partial_outage_requires_quiescence')
            if len(self.r['history'])>=16:raise LifecycleError('services_recovery_history_limit')
            self.r['history'].append(self.r['receipt']);self.r.update(phase='ready',cycle=self.r['cycle']+1,receipt=None,was_frozen=None)
        for name,item in found.items():
            role=self.m['outer'][name]['role']
            if role=='worker':
                if item.get('ExecIDs'):raise LifecycleError('services_executor_work_pending')
            elif item['State']['Running'] and PHASES.index(self.r['phase'])<PHASES.index(STAGES[role]):
                raise LifecycleError('services_live_writer_requires_quiescence')
        gateways=[found[k] for k,v in self.m['outer'].items() if v['role']=='gateway']
        current=self.b.offline_witness('status')
        opening=PHASES.index(self.r['phase'])>=PHASES.index('opening')
        if opening and all(g['State']['Running'] for g in gateways) and not current['frozen']:
            self.wait(lambda:self.hosts_ready(allow_start=False));self.wait(self.healthy_databases)
        else:
            if any(g['State']['Running'] for g in gateways) and not current['frozen']:raise LifecycleError('services_admission_not_closed')
            proof=storage_proof(self.b)
            if self.r['phase']=='ready':self.r['was_frozen']=proof['witness']['frozen'];self.advance('intent')
            self.b.offline_witness('freeze');self.advance('frozen')
            self.advance('hosts');self.start({'host'});self.wait(self.hosts_ready)
            self.cut('after_hosts')
            self.wait(lambda:self.healthy_databases(proof['witness']));self.advance('database')
            for s in ['a','b']:self.wait(lambda s=s:self.b.node_health(s))
            self.advance('workloads');self.start({'workload','standby'})
            self.advance('gateways');self.start({'gateway'})
            self.advance('opening')
            if not self.r['was_frozen']:self.b.offline_witness('unfreeze')
        self.advance('leaf');self.start({'leaf','worker'})
        self.cut('after_leaf')
        final=self.outer()
        if not all(i['State']['Running'] for i in final.values()):raise LifecycleError('services_not_running')
        self.r['receipt']={'schema':'service-daemon-receipt-1','id':self.m['id'],'cycle':self.r['cycle'],'executor_epoch':self.c.d['epoch'],
            'management_role':self.b.role(),'primary':self.m['primary'],'incarnation':self.m['incarnation'],
            'services':{k:v['id'] for k,v in self.m['outer'].items()},'admission_preserved_closed':bool(self.r['was_frozen'])}
        self.advance('complete');return self.r['receipt']


def main():
    if len(sys.argv)>1 and sys.argv[1] in {'actor','test-actor'}:
        actor=Actor()
        with lease(actor.b.directory()):print(json.dumps(actor.run()))
        return
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['seal','recover']);p.add_argument('--descriptor',type=Path)
    p.add_argument('--seal',type=Path,required=True);p.add_argument('--extras',type=Path);args=p.parse_args()
    if args.operation=='seal':
        value=seal_services(Cluster(json.loads(args.descriptor.read_bytes())),json.loads(args.extras.read_bytes()) if args.extras else ())
        save(args.seal,value);result={'sealed':True,'id':value['id'],'services':len(value['outer'])}
    else:result=recover_services(json.loads(args.seal.read_bytes()))
    print(json.dumps(result))


if __name__=='__main__':main()
