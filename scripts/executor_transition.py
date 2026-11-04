"""Explicit resume of a pinned stopped maintenance actor; no automatic election.

The same single PID-1 container and survivor-volume flock serialize every restart.
Its public intent is mirrored before mutations; online work refuses pending intent.
"""

import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

from scripts.certificate_controller import LifecycleError, replace_file
from scripts.control_mirror import durable_parent

NAME='executor-transition.json'
FAULTS='executor-transition-faults.json'
ENV='SECOPS_EXECUTOR_TRANSITION'
CUT_ENV='SECOPS_EXECUTOR_TRANSITION_CUTS'
LABEL='secops.executor-transition'
PHASES=('intent','fenced','volumes','copied','owners','workers','published','retired','complete')
CUTS=('after_intent','after_fence','volume_created','after_copy','owner_a_written','worker_created','after_publish','after_complete')
FIELDS={'schema','id','phase','original','planned','target','discard','actor','profile_hashes','fenced','settled','receipt'}
CORE={'profile.json','cluster.json','management-transition.json','authority-coordinator.json'}


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def planned(original,target):
    d=copy.deepcopy(original);source=d['active'];d['active']=target;d['epoch']+=1
    d['hosts'][source]['generation']+=1
    for kind in ['journal','owner']:
        d['hosts'][source][kind]=d['project']+f"-executor-{source}-g{d['hosts'][source]['generation']}-"+kind
    for host in d['hosts'].values():host['worker']=None
    return d


def validate(record):
    from scripts.executor_cluster import Cluster
    try:
        if (set(record)!=FIELDS or record['schema']!='executor-transition-1'
                or not re.fullmatch(r'[a-f0-9]{32}',record['id']) or record['phase'] not in PHASES
                or type(record['discard']) is not bool):raise ValueError
        old=Cluster(record['original']);new=Cluster(record['planned']);target=record['target']
        if target not in {'a','b'} or target==old.d['active']:raise ValueError
        expected=planned(old.d,target)
        for site in ['a','b']:
            if old.d['hosts'][site]['worker'] is None:raise ValueError
            expected['hosts'][site]['worker']=new.d['hosts'][site]['worker']
        if expected!=new.d:raise ValueError
        if (set(record['actor'])!={'name','id'} or record['actor']['name']!=old.project+'-executor-takeover-lock'
                or not re.fullmatch(r'[a-f0-9]{64}',record['actor']['id'])):raise ValueError
        if PHASES.index(record['phase'])>=1:
            if (not isinstance(record['profile_hashes'],dict) or not {'profile.json','cluster.json'}<=set(record['profile_hashes'])
                    or not set(record['profile_hashes'])<=CORE
                    or any(not re.fullmatch(r'[a-f0-9]{64}',h) for h in record['profile_hashes'].values())
                    or len(record['fenced'])!=2 or record['settled']['execs_remaining']!=0 or record['settled']['jobs_remaining']!=0):raise ValueError
            if record['fenced']!=[{**old.d['hosts'][s]['worker'],'removed':True} for s in [old.d['active'],target]]:raise ValueError
        if PHASES.index(record['phase'])>=5 and any(h['worker'] is None for h in new.d['hosts'].values()):raise ValueError
        if record['phase']!='complete' and record['receipt'] is not None:raise ValueError
        if record['phase']=='complete' and record['receipt']!=receipt(record):raise ValueError
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        raise LifecycleError('executor_transition_invalid') from None
    return record


def read_record(value):
    try:
        value=copy.deepcopy(value);checksum=value.pop('sha256')
        if checksum!=digest(value):raise ValueError
        return validate(value)
    except (ValueError,KeyError,TypeError,AttributeError):raise LifecycleError('executor_transition_invalid') from None


def read_path(path):
    if path.is_symlink():raise LifecycleError('executor_transition_invalid')
    if not path.exists():return None
    try:
        if path.is_symlink() or path.stat().st_size>4*1024**2:raise ValueError
        return read_record(json.loads(path.read_bytes()))
    except (OSError,ValueError,TypeError):raise LifecycleError('executor_transition_invalid') from None


def envelope(record):validate(record);return {**record,'sha256':digest(record)}


def write_path(path,value):
    replace_file(path,json.dumps(value,sort_keys=True));durable_parent(path)


def guard_pair(root,peer,expected):
    from scripts.executor_cluster import Cluster
    a,b=read_path(root/NAME),read_path(peer/NAME)
    if a is None and b is None:return
    if a is None or a!=b or a['phase']!='complete' or Cluster(a['planned']).role()!=expected:
        raise LifecycleError('executor_operator_resume_required')


def core_files(value):
    if set(value)-CORE-{NAME,FAULTS}:raise LifecycleError('executor_transition_public_files')
    return {k:v for k,v in value.items() if k in CORE}


def tree_hashes(value):return {k:digest(v) for k,v in value.items()}


def receipt(record):
    old=record['original'];source=old['active']
    return {'active':record['target'],'executor_epoch':record['planned']['epoch'],'fenced':record['fenced'],
        'settled':record['settled'],'retired_storage':{k:old['hosts'][source][k] for k in ['journal','owner']},
        'discarded':record['discard'],'operator_transition_id':record['id'],'operator_actor_id':record['actor']['id']}


def request_cluster(request):
    from scripts.executor_cluster import Cluster
    try:
        if (set(request)!={'schema','id','original','target','discard'} or request['schema']!='executor-operator-request-1'
                or not re.fullmatch(r'[a-f0-9]{32}',request['id']) or type(request['discard']) is not bool):raise ValueError
        cluster=Cluster(request['original'])
        if request['target'] not in {'a','b'} or request['target']==cluster.d['active']:raise ValueError
        if any(h['worker'] is None for h in cluster.d['hosts'].values()):raise ValueError
        return cluster
    except (ValueError,TypeError,KeyError):raise LifecycleError('executor_operator_request_invalid') from None


def actor_args(request,cuts=()):
    c=request_cluster(request);target=request['target'];volume=c.d['hosts'][target]['journal']
    args=['create','--name',c.project+'-executor-takeover-lock','--label','secops.c02='+c.project,
        '--label','secops.executor-cluster='+c.project,'--label','secops.executor-kind=operator','--label',LABEL+'='+request['id'],
        '--network','none','--restart','no','--read-only','--user','10001:10001','--group-add',str(c.d['docker_group']),
        '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--cpus','1','--pids-limit','128',
        '--tmpfs','/tmp:rw,size=32m','--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
        '--mount',f'type=volume,src={volume},dst=/data','--env','DOCKER_HOST=unix:///var/run/docker.sock',
        '--env',ENV+'='+json.dumps(request,sort_keys=True,separators=(',',':'))]
    if cuts:
        if len(set(cuts))!=len(cuts) or not set(cuts)<=set(CUTS):raise LifecycleError('executor_operator_test_cut_scope')
        args+=['--env',CUT_ENV+'='+json.dumps(list(cuts),separators=(',',':'))]
    return [*args,'--entrypoint','python',c.d['executor_image'],'-m','scripts.executor_transition','test-actor' if cuts else 'actor']


def lookup(c,name):
    ids=c.raw(['ps','--all','--no-trunc','--filter','name=^/'+re.escape(name)+'$','--format','{{.ID}}']).split()
    if not ids:return None
    if len(ids)!=1:raise LifecycleError('executor_operator_ambiguous')
    return json.loads(c.raw(['inspect',ids[0]]))[0]


def verify_actor(c,found,request):
    h=found['HostConfig'];cfg=found['Config'];labels=cfg.get('Labels') or {};env=cfg.get('Env') or []
    values=dict(v.split('=',1) for v in env);cuts=()
    if CUT_ENV in values:
        try:cuts=json.loads(values[CUT_ENV])
        except ValueError:raise LifecycleError('executor_operator_replaced') from None
        if not isinstance(cuts,list) or not cuts or len(set(cuts))!=len(cuts) or not set(cuts)<=set(CUTS):
            raise LifecycleError('executor_operator_replaced')
    expected=dict(v.split('=',1) for v in json.loads(c.raw(['image','inspect',c.d['executor_image']]))[0]['Config'].get('Env') or [])
    expected.update({'DOCKER_HOST':'unix:///var/run/docker.sock',ENV:json.dumps(request,sort_keys=True,separators=(',',':'))})
    if cuts:expected[CUT_ENV]=json.dumps(cuts,separators=(',',':'))
    mounts={m['Destination']:(m.get('Name') if m['Type']=='volume' else m.get('Source'),m['RW']) for m in found['Mounts'] if m['Type']!='tmpfs'}
    if (found['Name']!='/'+c.project+'-executor-takeover-lock' or found['Image']!=c.d['executor_image']
            or labels.get('secops.executor-cluster')!=c.project or labels.get('secops.executor-kind')!='operator'
            or labels.get(LABEL)!=request['id'] or cfg['User']!='10001:10001' or cfg['Entrypoint']!=['python']
            or cfg['Cmd']!=['-m','scripts.executor_transition','test-actor' if cuts else 'actor']
            or len(env)!=len(expected) or values!=expected
            or mounts!={'/data':(c.d['hosts'][request['target']]['journal'],True),'/var/run/docker.sock':('/var/run/docker.sock',True)}
            or h['NetworkMode']!='none' or not h['ReadonlyRootfs'] or h.get('Privileged') or h.get('CapAdd')
            or h.get('CapDrop')!=['ALL'] or h.get('SecurityOpt')!=['no-new-privileges:true'] or h.get('GroupAdd')!=[str(c.d['docker_group'])]
            or h['Memory']!=512*1024**2 or h['PidsLimit']!=128 or h.get('NanoCpus')!=1_000_000_000
            or h.get('Tmpfs')!={'/tmp':'rw,size=32m'} or h['RestartPolicy']['Name'] not in {'','no'}
            or not set(found['NetworkSettings']['Networks']).issubset({'none'})):
        raise LifecycleError('executor_operator_replaced')


def complete_result(record):
    from scripts.executor_cluster import Cluster
    c=Cluster(record['planned'])
    for site in ['a','b']:
        files=c.disk(c.d['hosts'][site]['journal'],'read')
        if files.get(NAME)!=envelope(record) or files.get('cluster.json')!=c.d:
            raise LifecycleError('executor_operator_complete_mismatch')
        if c.disk(c.d['hosts'][site]['owner'],'read').get('owner.json')!=c.role():
            raise LifecycleError('executor_operator_complete_owner')
        if not c.inspect_worker(site)['State']['Running']:raise LifecycleError('executor_operator_new_worker_not_running')
    return {'descriptor':c.d,'receipt':record['receipt']}


def run_actor(c,found,request):
    verify_actor(c,found,request)
    if found['State']['Running'] or found.get('ExecIDs'):raise LifecycleError('executor_operator_still_running')
    try:
        result=subprocess.run(['docker','start','--attach',found['Id']],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=600,check=False)
    except subprocess.SubprocessError:raise LifecycleError('executor_operator_running_or_result_unknown') from None
    after=json.loads(c.raw(['inspect',found['Id']]))[0];verify_actor(c,after,request)
    if after['Id']!=found['Id'] or after['State']['Running'] or after.get('ExecIDs'):
        raise LifecycleError('executor_operator_still_running')
    if result.returncode or after['State']['ExitCode']:
        codes=re.findall(r'LifecycleError: ([a-z0-9_]+)\s*$',result.stderr)
        raise LifecycleError('executor_operator_'+codes[-1] if codes else 'executor_operator_resume_required')
    files=c.disk(c.d['hosts'][request['target']]['journal'],'read');record=read_record(files[NAME])
    if record['actor']['id']!=found['Id'] or record['phase']!='complete':raise LifecycleError('executor_operator_result_incomplete')
    value=complete_result(record)
    # Remove only the verified stopped pinned PID-1 actor; no force/lease deletion.
    c.raw(['rm','--volumes',found['Id']]);return value


def launch(c,target,*,discard=False,cuts=()):
    if target not in {'a','b'} or target==c.d['active']:raise LifecycleError('executor_takeover_scope')
    if lookup(c,c.project+'-executor-takeover-lock') is not None:raise LifecycleError('executor_operator_resume_required')
    for kind in ['journal','owner']:c.verify_volume(target,kind)
    files=c.disk(c.d['hosts'][target]['journal'],'read')
    if (files.get('cluster.json')!=c.d or c.disk(c.d['hosts'][target]['owner'],'read').get('owner.json')!=c.role()):
        raise LifecycleError('executor_survivor_not_current')
    if NAME in files:
        r=read_record(files[NAME])
        if r['phase']!='complete' or r['planned']!=c.d:raise LifecycleError('executor_operator_resume_required')
    request={'schema':'executor-operator-request-1','id':uuid.uuid4().hex,'original':copy.deepcopy(c.d),'target':target,'discard':discard}
    ident=c.raw(actor_args(request,cuts)).strip();found=lookup(c,c.project+'-executor-takeover-lock')
    if found is None or found['Id']!=ident:raise LifecycleError('executor_operator_create_unconfirmed')
    return run_actor(c,found,request)


def resume_operator(anchor,site,journal,owner):
    from scripts.executor_cluster import Cluster
    proto={**anchor,'active':site,'epoch':1,'hosts':{s:{'generation':1,'worker':None,
        'journal':anchor['project']+f'-executor-{s}-g1-journal','owner':anchor['project']+f'-executor-{s}-g1-owner'} for s in ['a','b']}}
    c=Cluster(proto)
    if not re.fullmatch(re.escape(c.project)+r'-executor-'+re.escape(site)+r'-g[0-9]+-journal',journal):
        raise LifecycleError('executor_operator_recovery_scope')
    found=lookup(c,c.project+'-executor-takeover-lock');files=c.disk(journal,'read')
    record=read_record(files[NAME]) if NAME in files else None
    if found is None:
        if record is None or record['phase']!='complete':raise LifecycleError('executor_operator_missing')
        request={'schema':'executor-operator-request-1','id':record['id'],'original':record['original'],'target':record['target'],'discard':record['discard']}
        if c.raw(['ps','--all','--quiet','--filter','id='+record['actor']['id']]).split():
            raise LifecycleError('executor_operator_identity_changed')
        value=True
    else:
        try:request=json.loads(dict(v.split('=',1) for v in found['Config']['Env'])[ENV])
        except (ValueError,KeyError,TypeError):raise LifecycleError('executor_operator_replaced') from None
        original=request_cluster(request);verify_actor(original,found,request)
        if record and record['id']==request['id'] and record['actor']['id']!=found['Id']:
            raise LifecycleError('executor_operator_identity_changed')
        value=None
    original=request_cluster(request)
    if (original.anchor()!=anchor or request['target']!=site or original.d['hosts'][site]['journal']!=journal
            or original.d['hosts'][site]['owner']!=owner):raise LifecycleError('executor_operator_recovery_anchor')
    for kind in ['journal','owner']:original.verify_volume(site,kind)
    return complete_result(record) if value is not None else run_actor(original,found,request)


class Actor:
    def __init__(self,request,found):
        from scripts.executor_cluster import Cluster
        self.request=request;self.old=request_cluster(request);self.old.operator_id=request['id'];self.root=Path('/data')
        verify_actor(self.old,found,request);self.found=found
        current=read_path(self.root/NAME)
        if current is None or (current['id']!=request['id'] and current['phase']=='complete' and current['planned']==self.old.d):
            source=self.old.d['hosts'][request['target']]
            if (self.old.disk(source['journal'],'read').get('cluster.json')!=self.old.d
                    or self.old.disk(source['owner'],'read').get('owner.json')!=self.old.role()):
                raise LifecycleError('executor_operator_initial_owner_changed')
            current={'schema':'executor-transition-1','id':request['id'],'phase':'intent','original':copy.deepcopy(self.old.d),
                'planned':planned(self.old.d,request['target']),'target':request['target'],'discard':request['discard'],
                'actor':{'id':found['Id'],'name':found['Name'][1:]},'profile_hashes':None,'fenced':[],'settled':None,'receipt':None}
        if (current['id']!=request['id'] or current['original']!=request['original'] or current['target']!=request['target']
                or current['discard']!=request['discard'] or current['actor']['id']!=found['Id']):
            raise LifecycleError('executor_operator_identity_changed')
        self.r=validate(current);self.new=Cluster(self.r['planned']);self.new.operator_id=request['id']

    def save(self,phase=None):
        if phase:self.r['phase']=phase
        value=envelope(self.r);source=self.old.d['active']
        peer=self.new.d['hosts'][source]['journal'] if PHASES.index(self.r['phase'])>=3 else self.old.d['hosts'][source]['journal']
        self.old.disk(peer,'write',files={NAME:value});write_path(self.root/NAME,value)

    def cut(self,point):
        if sys.argv[-1]!='test-actor' or point not in json.loads(os.environ.get(CUT_ENV,'[]')):return
        path=self.root/FAULTS;used=json.loads(path.read_bytes()) if path.exists() else {}
        if point in used.get(self.r['id'],[]):return
        used.setdefault(self.r['id'],[]).append(point);write_path(path,used);os._exit(73)

    def orphans(self):
        ids=self.old.raw(['ps','--all','--quiet','--filter','label='+LABEL+'='+self.r['id'],
            '--filter','label=secops.executor-operator-job=1']).split()
        for ident in ids:
            found=json.loads(self.old.raw(['inspect',ident]))[0]
            if found['Image']!=self.old.d['graph_image']:raise LifecycleError('executor_operator_orphan_image')
            self.old.raw(['rm','--force','--volumes',ident])

    def volume(self,site,kind):
        from scripts.executor_cluster import CLUSTER, KIND
        h=self.new.d['hosts'][site];name=h[kind]
        names=self.old.raw(['volume','ls','--filter','name='+name,'--format','{{.Name}}']).split()
        if name not in names:
            self.old.raw(['volume','create','--label','secops.c02='+self.old.project,'--label',CLUSTER+'='+self.old.project,
                '--label',KIND+'='+kind,'--label','secops.executor-site='+site,'--label','secops.executor-generation='+str(h['generation']),
                '--label',LABEL+'='+self.r['id'],name]);self.cut('volume_created')
        self.new.verify_volume(site,kind)
        found=json.loads(self.old.raw(['volume','inspect',name]))[0]
        if found['Labels'].get(LABEL)!=self.r['id']:raise LifecycleError('executor_operator_reserved_volume')
        self.old.raw(['run','--rm','--network','none','--read-only','--user','10001:10001','--mount',f'type=volume,src={name},dst=/data',
            '--entrypoint','python',self.old.d['graph_image'],'-c',"from pathlib import Path;Path('/data').chmod(0o700)"])

    def worker(self,site):
        h=self.new.d['hosts'][site];name=self.new.project+f'-executor-{site}-e{self.new.d["epoch"]}'
        found=lookup(self.new,name)
        if found is None:
            if h['worker'] is not None:raise LifecycleError('executor_operator_worker_missing')
            ident=self.new.raw(self.new.worker_args(site,self.r['id'])).strip();self.cut('worker_created')
            found=lookup(self.new,name)
            if found is None or found['Id']!=ident:raise LifecycleError('executor_operator_worker_unconfirmed')
        if (h['worker'] and h['worker']['id']!=found['Id']) or found['Config']['Labels'].get(LABEL)!=self.r['id']:
            raise LifecycleError('executor_operator_worker_replaced')
        h['worker']={'name':name,'id':found['Id']};self.new.verify_worker(site,found);self.save()
        if not found['State']['Running']:self.new.raw(['start',found['Id']])

    def run(self):
        if self.r['phase']=='complete':return complete_result(self.r)
        self.orphans();self.save();self.cut('after_intent')
        fenced=[self.old.fence_worker(s) for s in [self.old.d['active'],self.r['target']]]
        files=self.old.disk(self.old.d['hosts'][self.r['target']]['journal'],'read')
        settled=self.old.settle(files['profile.json'])
        if self.r['phase']=='intent':
            self.r.update(fenced=fenced,settled=settled,profile_hashes=tree_hashes(core_files(files)))
            self.save('fenced');self.cut('after_fence')
        if self.r['phase']=='fenced':
            for kind in ['journal','owner']:self.volume(self.old.d['active'],kind)
            self.save('volumes')
        if self.r['phase']=='volumes':
            self.old.disk(self.new.d['hosts'][self.old.d['active']]['journal'],'copy_resume',
                source=self.old.d['hosts'][self.r['target']]['journal'],expected=self.r['profile_hashes'])
            self.save('copied');self.cut('after_copy')
        if self.r['phase']=='copied':
            for site in ['a','b']:
                values=self.new.disk(self.new.d['hosts'][site]['owner'],'read')
                allowed=[{'owner.json':self.old.role()},{'owner.json':self.new.role()}] if site==self.r['target'] else [{},{'owner.json':self.new.role()}]
                if values not in allowed:
                    raise LifecycleError('executor_operator_owner_conflict')
                self.new.disk(self.new.d['hosts'][site]['owner'],'write',files={'owner.json':self.new.role()})
                if site=='a':self.cut('owner_a_written')
            self.save('owners')
        if self.r['phase']=='owners':
            for site in [self.r['target'],self.old.d['active']]:self.worker(site)
            self.save('workers')
        if self.r['phase']=='workers':self.new.publish();self.save('published');self.cut('after_publish')
        if self.r['phase']=='published':
            if self.r['discard']:
                for kind in ['journal','owner']:
                    name=self.old.d['hosts'][self.old.d['active']][kind]
                    names=self.old.raw(['volume','ls','--filter','name='+name,'--format','{{.Name}}']).split()
                    if name in names:self.old.verify_volume(self.old.d['active'],kind);self.old.raw(['volume','rm',name])
            self.save('retired')
        if self.r['phase']=='retired':
            self.r['receipt']=receipt(self.r);self.save('complete');self.cut('after_complete')
        return complete_result(self.r)


def main():
    import fcntl
    request=json.loads(os.environ[ENV]);c=request_cluster(request);found=lookup(c,c.project+'-executor-takeover-lock')
    if found is None:raise LifecycleError('executor_operator_missing')
    path=Path('/data/executor-transition.lock')
    if path.is_symlink():raise LifecycleError('executor_operator_lease_symlink')
    with path.open('a+b') as stream:
        fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(Actor(request,found).run()))


if __name__=='__main__':main()
