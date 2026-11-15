"""Explicitly fenced paired maintenance hosts on a local trusted Docker kernel.

No shared journal filesystem, automatic election or physical-host guarantee.
A public anchor plus a surviving journal/owner pair can replace a lost console
cache. The operator's Docker-name lock serializes takeover across consoles.
"""

import argparse
import copy
import json
import re
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from scripts.authority_rotation_coordinator import DockerBackend
from scripts.certificate_controller import LifecycleError, save
from scripts.control_executor import JOB_EPOCH, JOB_MODE, JOB_SITE
from scripts.executor_store import ENV

CLUSTER='secops.executor-cluster'
KIND='secops.executor-kind'


class Cluster:
    def __init__(self,descriptor):
        self.d=descriptor;self.project=descriptor['project']
        if (descriptor.get('schema')!='executor-cluster-1' or not re.fullmatch(r'c02-[a-f0-9]{12}',self.project)
                or descriptor['active'] not in {'a','b'} or type(descriptor['epoch']) is not int or descriptor['epoch']<1
                or set(descriptor['hosts'])!={'a','b'}):
            raise LifecycleError('executor_cluster_shape')
        for key in ['graph_image','executor_image']:
            if not re.fullmatch(r'sha256:[a-f0-9]{64}',descriptor[key]):raise LifecycleError('executor_image_scope')
        if descriptor['directory']!='/app/runtime/c02/'+self.project+'-executor':raise LifecycleError('executor_directory_scope')
        if type(descriptor.get('docker_group')) is not int or descriptor['docker_group']<0:
            raise LifecycleError('executor_socket_group_scope')
        volumes=[];workers=[]
        for site,h in descriptor['hosts'].items():
            if type(h['generation']) is not int or h['generation']<1:raise LifecycleError('executor_generation_scope')
            for kind in ['journal','owner']:
                if h[kind]!=self.volume_name(site,h['generation'],kind):raise LifecycleError('executor_volume_scope')
                volumes.append(h[kind])
            w=h.get('worker')
            if w is not None and (w['name']!=self.project+f'-executor-{site}-e{descriptor["epoch"]}'
                    or not re.fullmatch(r'[a-f0-9]{64}',w['id'])):raise LifecycleError('executor_worker_scope')
            if w is not None:workers.append(w['id'])
        if len(set(workers))!=len(workers):raise LifecycleError('executor_shared_worker')
        if len(set(volumes))!=4:raise LifecycleError('executor_shared_volumes')

    def raw(self,args,payload=None,timeout=60):
        if getattr(self,'operator_id',None) and args and args[0]=='run':
            args=['run','--label','secops.c02='+self.project,'--label','secops.executor-transition='+self.operator_id,
                '--label','secops.executor-operator-job=1',*args[1:]]
        return DockerBackend.command(self,args,payload,timeout)

    def volume_name(self,site,generation,kind):return self.project+f'-executor-{site}-g{generation}-'+kind

    def role(self):
        d=self.d
        return {'schema':'executor-owner-1','project':self.project,'epoch':d['epoch'],'active':d['active'],
            'graph_image':d['graph_image'],'executor_image':d['executor_image'],
            'generations':{s:h['generation'] for s,h in d['hosts'].items()}}

    def anchor(self):return {k:self.d[k] for k in ['schema','project','graph_image','executor_image','directory','docker_group']}

    def context(self,site):
        return {'site':site,'expected':self.role(),'root':self.d['directory'],'peer':'/executor-peer',
            'roles':['/executor-role-a/owner.json','/executor-role-b/owner.json']}

    def mounts(self,site):
        peer='b' if site=='a' else 'a'
        return [(self.d['hosts'][site]['journal'],self.d['directory'],False),
            (self.d['hosts'][peer]['journal'],'/executor-peer',False),
            (self.d['hosts']['a']['owner'],'/executor-role-a',True),
            (self.d['hosts']['b']['owner'],'/executor-role-b',True)]

    def disk(self,volume,operation,*,files=None,source=None,expected=None):
        self.raw(['volume','inspect',volume,*([source] if source else [])])
        args=['run','--rm','-i','--network','none','--read-only','--user','10001:10001','--cap-drop=ALL',
            '--security-opt=no-new-privileges:true','--mount',f'type=volume,src={volume},dst=/data'+(',readonly' if operation=='read' else '')]
        if source:args+=['--mount',f'type=volume,src={source},dst=/source,readonly']
        return json.loads(self.raw([*args,'--entrypoint','python',self.d['graph_image'],'-m','scripts.executor_disk'],
            {'operation':operation,**({'files':files} if files is not None else {}),**({'expected':expected} if expected is not None else {})}))

    def volume(self,site,generation,kind):
        name=self.volume_name(site,generation,kind)
        existing=self.raw(['volume','ls','--filter','name='+name,'--format','{{.Name}}']).splitlines()
        if name in existing:raise LifecycleError('executor_new_volume_exists')
        self.raw(['volume','create','--label','secops.c02='+self.project,'--label',CLUSTER+'='+self.project,
            '--label',KIND+'='+kind,'--label',JOB_SITE+'='+site,'--label','secops.executor-generation='+str(generation),name])
        self.raw(['run','--rm','--network','none','--read-only','--user','10001:10001',
            '--mount',f'type=volume,src={name},dst=/data','--entrypoint','python',self.d['graph_image'],'-c',
            "from pathlib import Path;Path('/data').chmod(0o700)"])
        return name

    def verify_volume(self,site,kind):
        h=self.d['hosts'][site];found=json.loads(self.raw(['volume','inspect',h[kind]]))[0];labels=found.get('Labels') or {}
        if (found['Name']!=h[kind] or labels.get(CLUSTER)!=self.project or labels.get(KIND)!=kind
                or labels.get(JOB_SITE)!=site or labels.get('secops.executor-generation')!=str(h['generation'])):
            raise LifecycleError('executor_volume_identity')

    def inspect_worker(self,site,missing_ok=False):
        w=self.d['hosts'][site]['worker']
        ids=self.raw(['ps','--all','--no-trunc','--filter','name=^/'+re.escape(w['name'])+'$','--format','{{.ID}}']).split()
        if not ids:
            if missing_ok and not self.raw(['ps','--all','--no-trunc','--filter','id='+w['id'],'--format','{{.ID}}']).split():return None
            raise LifecycleError('executor_worker_missing')
        if len(ids)!=1:raise LifecycleError('executor_worker_ambiguous')
        found=json.loads(self.raw(['inspect',ids[0]]))[0];self.verify_worker(site,found)
        return found

    def verify_worker(self,site,found):
        d=self.d;w=d['hosts'][site]['worker'];h=found['HostConfig'];c=found['Config'];labels=c.get('Labels') or {}
        actual={m['Destination']:(m.get('Name') if m['Type']=='volume' else m.get('Source'),m['RW']) for m in found['Mounts'] if m['Type']!='tmpfs'}
        expected={dest:(v,not ro) for v,dest,ro in self.mounts(site)}
        expected['/var/run/docker.sock']=('/var/run/docker.sock',True)
        context=ENV+'='+json.dumps(self.context(site),sort_keys=True,separators=(',',':'))
        if (found['Id']!=w['id'] or found['Name']!='/'+w['name'] or found['Image']!=d['executor_image']
                or labels.get(CLUSTER)!=self.project or labels.get(JOB_SITE)!=site or labels.get(JOB_EPOCH)!=str(d['epoch'])
                or labels.get(KIND)!='worker' or c['User']!='10001:10001'
                or c['Entrypoint']!=['python'] or c['Cmd']!=['-m','scripts.control_executor','daemon']
                or h['NetworkMode']!='none' or not h['ReadonlyRootfs'] or h.get('Privileged') or h.get('CapAdd')
                or h.get('CapDrop')!=['ALL'] or h.get('SecurityOpt')!=['no-new-privileges:true']
                or h['RestartPolicy']['Name'] not in {'','no'} or h['Memory']!=512*1024**2 or h['PidsLimit']!=128
                or h.get('NanoCpus')!=1_000_000_000
                or h.get('Tmpfs')!={'/tmp':'rw,size=32m','/data':'rw,uid=10001,gid=10001,size=1m'}
                or not set(found['NetworkSettings']['Networks']).issubset({'none'})
                or h.get('GroupAdd')!=[str(d['docker_group'])] or actual!=expected
                or context not in c.get('Env',[]) or 'DOCKER_HOST=unix:///var/run/docker.sock' not in c.get('Env',[])):
            raise LifecycleError('executor_worker_replaced')

    def worker_args(self,site,operation=None):
        name=self.project+f"-executor-{site}-e{self.d['epoch']}"
        args=['create','--name',name,'--label','secops.c02='+self.project,'--label',CLUSTER+'='+self.project,
            '--label',KIND+'=worker','--label',JOB_SITE+'='+site,'--label',JOB_EPOCH+'='+str(self.d['epoch']),
            '--network','none','--restart','no','--read-only','--user','10001:10001','--group-add',str(self.d['docker_group']),
            '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--cpus','1','--pids-limit','128',
            '--tmpfs','/tmp:rw,size=32m','--tmpfs','/data:rw,uid=10001,gid=10001,size=1m',
            '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
            '--env','DOCKER_HOST=unix:///var/run/docker.sock',
            '--env',ENV+'='+json.dumps(self.context(site),sort_keys=True,separators=(',',':'))]
        for volume,dest,ro in self.mounts(site):args+=['--mount',f'type=volume,src={volume},dst={dest}'+(',readonly' if ro else '')]
        if operation:args+=['--label','secops.executor-transition='+operation]
        return [*args,'--entrypoint','python',self.d['executor_image'],'-m','scripts.control_executor','daemon']

    def create_worker(self,site):
        name=self.project+f"-executor-{site}-e{self.d['epoch']}"
        ident=self.raw(self.worker_args(site)).strip()
        self.d['hosts'][site]['worker']={'name':name,'id':ident};self.raw(['start',ident]);self.inspect_worker(site)

    def publish(self):
        for site in ['a','b']:self.disk(self.d['hosts'][site]['journal'],'write',files={'cluster.json':self.d})

    def rpc(self,operation,args=(),kwargs=None,*,site=None,fault=None,expect_exit=None,timeout=240):
        site=site or self.d['active'];found=self.inspect_worker(site)
        if not found['State']['Running']:raise LifecycleError('executor_host_not_running')
        request={'operation':operation,'args':list(args),'kwargs':kwargs or {}}
        if fault:request['fault']=fault
        command=['docker','exec','-i',found['Id'],'python','-m','scripts.control_executor','test-rpc' if fault else 'rpc']
        import subprocess
        result=subprocess.run(command,input=json.dumps(request),capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout,check=False)
        if expect_exit is not None:
            if result.returncode!=expect_exit:raise LifecycleError('executor_expected_exit_'+str(result.returncode))
            return None
        if result.returncode:
            codes=re.findall(r'LifecycleError: ([a-z0-9_]+)\s*$',result.stderr)
            raise LifecycleError('executor_rpc_'+codes[-1] if codes else 'executor_rpc_failed')
        return json.loads(result.stdout)

    def fence_worker(self,site):
        found=self.inspect_worker(site,missing_ok=True)
        if found is not None:
            self.raw(['stop','--time','2',found['Id']])
            if json.loads(self.raw(['inspect',found['Id']]))[0]['State']['Running']:raise LifecycleError('executor_fence_unconfirmed')
            self.raw(['rm','--volumes',found['Id']])
        return {**self.d['hosts'][site]['worker'],'removed':True}

    def service_ids(self,profile):
        from scripts.control_plane_ha import Management
        Management(profile)
        if profile['project']!=self.project or profile['image']!=self.d['graph_image']:
            raise LifecycleError('executor_service_profile_scope')
        pinned=[*profile['service_hosts'].values(),profile['leaf']]
        if profile['management'].get('standby'):pinned.append(profile['management']['standby'])
        pinned.extend({'name':n,'id':i} for n,i in zip(profile.get('gateways',[]),profile.get('gateway_ids',[]),strict=True))
        result=[]
        for expected in pinned:
            if not re.fullmatch(r'[a-f0-9]{64}',expected['id']):raise LifecycleError('executor_service_id_scope')
            ids=self.raw(['ps','--all','--no-trunc','--filter','name=^/'+re.escape(expected['name'])+'$','--format','{{.ID}}']).split()
            if not ids:
                if self.raw(['ps','--all','--quiet','--filter','id='+expected['id']]).split():
                    raise LifecycleError('executor_service_renamed')
                continue
            if ids!=[expected['id']]:raise LifecycleError('executor_service_replaced')
            found=json.loads(self.raw(['inspect',expected['id']]))[0]
            if found['Name']!='/'+expected['name'] or found['Image']!=expected.get('image',profile['image']):
                raise LifecycleError('executor_service_replaced')
            result.append(expected['id'])
        return result

    def settle(self,profile):
        # Old job containers are killed; execs inside existing managed services
        # must have finished. Queries failing is never proof of absence.
        filters=['--filter','label=secops.executor-project='+self.project,'--filter','label='+JOB_SITE+'='+self.d['active'],
            '--filter','label='+JOB_EPOCH+'='+str(self.d['epoch']),'--filter','label='+JOB_MODE+'=job']
        ids=self.raw(['ps','--all','--quiet',*filters]).split()
        for ident in ids:
            found=json.loads(self.raw(['inspect',ident]))[0]
            if found['Image']!=self.d['graph_image']:raise LifecycleError('executor_child_image_changed')
            self.raw(['rm','--force','--volumes',ident])
        # Initial DinD service hosts predate common Docker labels. Pin them
        # explicitly as well: an exec within their nested daemon can outlive
        # the removed executor's Docker client process.
        pinned=self.service_ids(profile)
        deadline=time.monotonic()+30
        while True:
            ids=self.raw(['ps','--all','--quiet','--filter','label=secops.c02='+self.project]).split()
            ids=sorted(set(ids+pinned))
            rows=json.loads(self.raw(['inspect',*ids])) if ids else []
            busy=[r['Id'] for r in rows if r.get('ExecIDs')]
            jobs=self.raw(['ps','--all','--quiet',*filters]).split()
            if not busy and not jobs:return {'execs_remaining':0,'jobs_remaining':0,'pinned_services_inspected':len(pinned)}
            if time.monotonic()>deadline:raise LifecycleError('executor_inflight_work_requires_investigation')
            time.sleep(.2)

    @contextmanager
    def operator_lock(self):
        name=self.project+'-executor-takeover-lock';token=uuid.uuid4().hex
        ident=self.raw(['create','--name',name,'--label','secops.c02='+self.project,'--label',CLUSTER+'='+self.project,
            '--label','secops.executor-lock='+token,'--network','none','--read-only','--user','10001:10001',
            '--tmpfs','/data:rw,size=1m','--entrypoint','python',self.d['graph_image'],'-c','pass']).strip()
        try:yield
        finally:
            found=json.loads(self.raw(['inspect',ident]))[0]
            if found['Id']!=ident or found['Image']!=self.d['graph_image'] or found['Config']['Labels'].get('secops.executor-lock')!=token:
                raise LifecycleError('executor_operator_lock_replaced')
            self.raw(['rm','--volumes',ident])

    def takeover(self,target,*,discard=False):
        if target==self.d['active'] or target not in {'a','b'}:raise LifecycleError('executor_takeover_scope')
        from scripts.executor_transition import launch
        result=launch(self,target,discard=discard);self.d=result['descriptor'];return result['receipt']

    @classmethod
    def bootstrap(cls,profile,executor_image,*,adopt=True):
        project=profile['project'];directory='/app/runtime/c02/'+project+'-executor'
        group=int(DockerBackend.command(None,['run','--rm','--network','none','--read-only','--mount',
            'type=bind,src=/var/run/docker.sock,dst=/sock,readonly','--entrypoint','python',profile['image'],'-c',
            "import os;print(os.stat('/sock').st_gid)"]))
        d={'schema':'executor-cluster-1','project':project,'graph_image':profile['image'],'executor_image':executor_image,
            'directory':directory,'docker_group':group,'active':'a','epoch':1,'hosts':{site:{'generation':1,
            'journal':project+f'-executor-{site}-g1-journal','owner':project+f'-executor-{site}-g1-owner','worker':None} for site in ['a','b']}}
        result=cls(d);p=copy.deepcopy(profile);p['control_directory']=directory
        for site in ['a','b']:
            for kind in ['journal','owner']:result.volume(site,1,kind)
            result.disk(d['hosts'][site]['journal'],'write',files={'profile.json':p})
            result.disk(d['hosts'][site]['owner'],'write',files={'owner.json':result.role()})
        for site in ['a','b']:result.create_worker(site)
        result.publish()
        if adopt:result.rpc('persist_profile')
        return result

    @classmethod
    def recover(cls,anchor,site,journal,owner):
        # Discovery is explicit; do not elect by whichever counter is largest.
        prototype={**anchor,'active':site,'epoch':1,'hosts':{s:{'generation':1,
            'journal':anchor['project']+f'-executor-{s}-g1-journal','owner':anchor['project']+f'-executor-{s}-g1-owner',
            'worker':None} for s in ['a','b']}}
        reader=cls(prototype)
        for name in [journal,owner]:
            if not re.fullmatch(re.escape(anchor['project'])+r'-executor-[ab]-g[0-9]+-(journal|owner)',name):
                raise LifecycleError('executor_recovery_volume_scope')
        files=reader.disk(journal,'read');d=files['cluster.json'];result=cls(d)
        if result.anchor()!=anchor or result.d['hosts'][site]['journal']!=journal or result.d['hosts'][site]['owner']!=owner:
            raise LifecycleError('executor_recovery_anchor_mismatch')
        for kind in ['journal','owner']:result.verify_volume(site,kind)
        if result.disk(owner,'read').get('owner.json')!=result.role():raise LifecycleError('executor_recovery_owner_mismatch')
        return result


class Remote:
    def __init__(self,cluster):self.cluster=cluster;self.refresh()
    def refresh(self):self.profile=self.cluster.rpc('view')['result'];return self.profile
    @property
    def active(self):return self.profile['management']['active']
    @property
    def peer(self):return 'b' if self.active=='a' else 'a'
    def volumes(self,label=None):return self.profile['management']['cells'][label or self.active]['volumes']
    def role(self):
        from scripts.control_plane_ha import Management
        return Management(self.profile).role()
    def __getattr__(self,name):
        from scripts.control_executor import METHODS
        if name not in METHODS:raise AttributeError(name)
        def invoke(*args,**kwargs):
            value=self.cluster.rpc(name,args,kwargs);self.profile=value['profile'];return value['result']
        return invoke


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=['status','takeover','recover','journal','resume','tick','resume-takeover','recover-takeover','seal-daemon','recover-daemon'])
    p.add_argument('--descriptor',type=Path);p.add_argument('--anchor',type=Path);p.add_argument('--site',choices=['a','b'])
    p.add_argument('--journal');p.add_argument('--owner');p.add_argument('--daemon-seal',type=Path);args=p.parse_args()
    if args.operation=='seal-daemon':
        from scripts.executor_daemon_recovery import seal_daemon
        result=seal_daemon(Cluster(json.loads(args.descriptor.read_bytes())));save(args.daemon_seal,result)
        print(json.dumps(result));return
    if args.operation=='recover-daemon':
        from scripts.executor_daemon_recovery import recover_daemon
        value=recover_daemon(json.loads(args.daemon_seal.read_bytes()),json.loads(args.anchor.read_bytes()),args.site,args.journal,args.owner)
        cluster=Cluster(value['descriptor']);result=value['receipt']
    elif args.operation in {'resume-takeover','recover-takeover'}:
        from scripts.executor_transition import recover_operator, resume_operator
        method=recover_operator if args.operation=='recover-takeover' else resume_operator
        value=method(json.loads(args.anchor.read_bytes()),args.site,args.journal,args.owner)
        cluster=Cluster(value['descriptor']);result=value['receipt']
    elif args.operation=='recover':
        cluster=Cluster.recover(json.loads(args.anchor.read_bytes()),args.site,args.journal,args.owner)
        result=cluster.takeover(args.site)
    else:
        cluster=Cluster(json.loads(args.descriptor.read_bytes()))
        result=(cluster.takeover(args.site) if args.operation=='takeover' else cluster.d if args.operation=='status'
            else cluster.rpc(args.operation)['result'])
    if args.descriptor:save(args.descriptor,cluster.d)
    print(json.dumps(result))


if __name__=='__main__':main()
