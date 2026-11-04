"""Fenced active/passive local management cells with peer-first durable state.

The trusted host executor/file lease remains a common physical control boundary.
There is no automatic election, remote filesystem, quorum or Byzantine guarantee.
"""

import argparse
import copy
import json
import re
import time
from contextlib import contextmanager
from pathlib import Path

from scripts.authority_rotation_coordinator import DockerBackend, lease
from scripts.ca_host_recovery import Hosts
from scripts.certificate_controller import LifecycleError
from scripts.control_mirror import ENV
from scripts.control_store import COMPONENTS

DESTINATIONS = {'/ca':'ca','/vault':'vault','/state':'leaf','/controller':'leaf','/renewal':'renewal',
    '/managed/renewal':'renewal','/witness':'witness','/backups':'backups','/backup-key':'backup_key','/reader':'reader','/control':'control'}


class Management(Hosts):
    def __init__(self, profile):
        super().__init__(profile)
        m = profile['management']
        if set(m['cells']) != {'a','b'} or m['active'] not in m['cells'] or type(m['epoch']) is not int or m['epoch'] < 1:
            raise LifecycleError('control_profile_shape')
        for cell in m['cells'].values():
            if set(cell['volumes']) != set(COMPONENTS) or type(cell['generation']) is not int or cell['generation'] < 1:
                raise LifecycleError('control_cell_shape')
            for name in cell['volumes'].values():
                if not re.fullmatch(re.escape(self.project)+r'-[a-z0-9-]+',name):
                    raise LifecycleError('control_volume_scope')
        all_volumes=[v for c in m['cells'].values() for v in c['volumes'].values()]
        if len(set(all_volumes)) != len(all_volumes):
            raise LifecycleError('control_shared_replica_volume')
        self.depth=0

    @property
    def active(self):
        return self.profile['management']['active']

    @property
    def peer(self):
        return 'b' if self.active=='a' else 'a'

    def volumes(self, label=None):
        return self.profile['management']['cells'][label or self.active]['volumes']

    def role(self):
        m=self.profile['management']
        return {'schema':'control-role-1','project':self.project,'image':self.profile['image'],'epoch':m['epoch'],
            'active':m['active'],'generations':{k:v['generation'] for k,v in m['cells'].items()}}

    def ensure_volumes(self, names):
        self.raw(['volume','inspect',*names])

    def raw(self, args, payload=None, timeout=60):
        return DockerBackend.command(self,args,payload,timeout)

    def mirror(self, mappings, shared=()):
        return json.dumps({'expected':self.role(),'roles':['/ha-active/role.json','/ha-peer/role.json'],
            'mirrors':mappings,'shared':list(shared)},separators=(',',':'))

    def meta_mounts(self):
        return [(self.volumes()['control'],'/ha-active',True),(self.volumes(self.peer)['control'],'/ha-peer',True)]

    def job(self, req, mounts, *, env=None, network='none'):
        names=[v for v,_,_ in mounts];self.ensure_volumes(names)
        args=['run','--rm','-i','--network',network,'--read-only','--user','10001:10001','--cap-drop=ALL',
            '--security-opt=no-new-privileges:true','--memory','512m','--cpus','1']
        for volume,dest,readonly in mounts:
            args+=['--mount',f'type=volume,src={volume},dst={dest}'+(',readonly' if readonly else '')]
        if env is not None:args+=['--env',ENV+'='+env]
        return json.loads(self.raw([*args,'--entrypoint','python',self.profile['image'],'-m','scripts.control_store'],req))

    def guard(self):
        mounts=[*self.meta_mounts(),(self.volumes()['control'],'/control',True),
            (self.volumes(self.peer)['control'],'/replica/control',True)]
        return self.job({'operation':'guard'},mounts,env=self.mirror({'/control':'/replica/control'}))

    def control_job(self, req):
        return self.job(req,[*self.meta_mounts(),(self.volumes()['control'],'/control',False),
            (self.volumes(self.peer)['control'],'/replica/control',False)],env=self.mirror({'/control':'/replica/control'}))

    def load_control(self):
        return self.control_job({'operation':'read_control'})

    def save_control(self, state):
        self.control_job({'operation':'write_control','state':state})

    @contextmanager
    def management_operation(self):
        if self.depth:
            yield;return
        self.guard()
        self._operation(True)
        self.depth+=1
        try:
            yield
            # Exceptions leave the durable busy marker for explicit investigation.
            self._operation(False)
        finally:
            self.depth-=1

    def _operation(self, busy):
        self.control_job({'operation':'operation','busy':busy})

    def control_tick(self):
        return self.management_operation()

    def command(self, args, payload=None, timeout=30):
        # Add peer writes only to known management-volume jobs. CA service-host
        # volumes and application workload volumes keep their existing behavior.
        if args and args[0]=='run':
            additions=[];mapping={};touched=False
            active=self.volumes();peer=self.volumes(self.peer)
            for index,arg in enumerate(args):
                if arg!='--mount':continue
                fields=args[index+1].split(',');values=dict(p.split('=',1) for p in fields if '=' in p)
                component=next((k for k,v in active.items() if v==values.get('src')),None)
                if component is not None:
                    touched=True
                    if values.get('dst') not in DESTINATIONS or DESTINATIONS[values['dst']]!=component:
                        raise LifecycleError('control_job_mount_scope')
                    if 'readonly' not in fields:
                        target='/replica/'+component;mapping[values['dst']]=target
                        additions+=['--mount',f'type=volume,src={peer[component]},dst={target}']
            if touched:
                self.ensure_volumes([*active.values(),*peer.values()])
                for v,d,r in self.meta_mounts():additions+=['--mount',f'type=volume,src={v},dst={d},readonly']
                # Read-only jobs still verify the role, with an unused RO mirror.
                if not mapping:
                    additions+=['--mount',f"type=volume,src={peer['control']},dst=/replica/control,readonly"]
                    mapping={'/ha-active':'/replica/control'}
                additions+=['--env',ENV+'='+self.mirror(mapping)]
                args=[*args[:1],*additions,*args[1:]]
        return self.raw(args,payload,timeout)

    def leaf(self, operation, plan=None, **fields):
        self.guard();return super().leaf(operation,plan,**fields)

    def custodian(self, operation, payload=None):
        self.guard();return super().custodian(operation,payload)

    def witness(self, operation, **fields):
        self.guard()
        # A dead first gateway is not a reason to lose the management RPC path.
        for name,ident in zip(self.profile['gateways'],self.profile['gateway_ids'],strict=True):
            record=json.loads(self.raw(['inspect',name]))[0]
            if record['Id']!=ident or record['Image']!=self.profile['image']:
                raise LifecycleError('control_gateway_replaced')
            if record['State']['Running']:
                return json.loads(self.raw(['exec','-i',name,'python','-m','scripts.ca_recovery_state','rpc'],{'operation':operation,**fields}))
        raise LifecycleError('control_no_live_gateway')

    def new_volume(self, name):
        self.raw(['volume','create','--label','secops.c02='+self.project,name])
        self.profile.setdefault('additional_volumes',[]).append(name)
        self.raw(['run','--rm','--network','none','--read-only','--user','10001:10001','--mount',f'type=volume,src={name},dst=/data',
            '--entrypoint','python',self.profile['image'],'-c',"from pathlib import Path;Path('/data').chmod(0o700)"])
        return name

    def new_cell(self,label,generation):
        return {'generation':generation,'volumes':{k:self.new_volume(self.project+f'-mgmt-{label}-g{generation}-'+k.replace('_','-')) for k in COMPONENTS}}

    def seed(self, source, target):
        mounts=[(v,'/source/'+k,True) for k,v in source.items()]+[(v,'/target/'+k,False) for k,v in target.items()]
        return self.job({'operation':'copy'},mounts)

    def initialize_control(self, state):
        return self.job({'operation':'initialize','files':{'role.json':self.role(),'coordinator.json':state,
            'operation.json':{'busy':False},'profile.json':self.profile}},
            [(self.volumes()['control'],'/active',False),(self.volumes(self.peer)['control'],'/peer',False)])

    def persist_profile(self):
        self.control_job({'operation':'write_profile','profile':self.profile})
        super().persist_profile()

    def container(self, expected, *, stop=False, remove=False):
        record=json.loads(self.raw(['inspect',expected['name']]))[0]
        if (record['Id']!=expected['id'] or record['Image']!=self.profile['image'] or record['Name']!='/'+expected['name']
                or record['HostConfig']['RestartPolicy']['Name'] not in {'','no'}
                or any(m['Destination'].endswith('docker.sock') or m['Destination']=='/vault' for m in record['Mounts'])):
            raise LifecycleError('control_container_replaced')
        if stop:self.raw(['stop','--time','2',record['Id']])
        if stop and json.loads(self.raw(['inspect',record['Id']]))[0]['State']['Running']:
            raise LifecycleError('control_fence_unconfirmed')
        if remove:self.raw(['rm','--volumes',record['Id']])
        return {'id':record['Id'],'name':expected['name'],'stopped':stop}

    def start_process(self,name,argv,mounts, *, network, aliases=(), extra_network=None, env=None, start=True):
        self.ensure_volumes([v for v,_,_ in mounts])
        args=['create','--name',name,'--network',network,'--restart','no','--read-only','--user','10001:10001',
            '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--pids-limit','128','--tmpfs','/tmp:rw,size=32m']
        for alias in aliases:args+=['--network-alias',alias]
        for v,d,r in mounts:args+=['--mount',f'type=volume,src={v},dst={d}'+(',readonly' if r else '')]
        if env:args+=['--env',ENV+'='+env]
        ident=self.raw([*args,'--entrypoint',argv[0],self.profile['image'],*argv[1:]]).strip()
        self.profile.setdefault('additional_containers',[]).append(name)
        if extra_network:self.raw(['network','connect',extra_network,name])
        if start:self.raw(['start',name])
        return {'name':name,'id':ident}

    def select_active_storage(self):
        a=self.volumes()
        self.profile.update(volumes={k:a[k] for k in ['ca','vault','leaf','renewal']},
            witness_volume=a['witness'],backup_volume=a['backups'],backup_key_volume=a['backup_key'])

    def install_processes(self):
        self.select_active_storage()
        a=self.volumes();b=self.volumes(self.peer)
        mounts=[(a['leaf'],'/state',False),(b['leaf'],'/replica/leaf',False),
            (a['renewal'],'/managed/renewal',False),(b['renewal'],'/replica/renewal',False),*self.meta_mounts()]
        shared=[]
        for value in self.profile['management']['workload_mounts']:
            parts=value.split(',');data=dict(p.split('=',1) for p in parts if '=' in p)
            mounts.append((data['src'],data['dst'],'readonly' in parts));shared.append(data['dst'])
        epoch=self.profile['management']['epoch']
        self.profile['leaf']=self.start_process(self.project+f'-mgmt-{self.active}-e{epoch}-leaf',
            ['python','-m','scripts.certificate_controller','run'],mounts,network=self.profile['client_network'],
            env=self.mirror({'/state':'/replica/leaf','/managed/renewal':'/replica/renewal'},shared))
        passive=self.start_process(self.project+f'-mgmt-{self.peer}-e{epoch}-standby',
            ['python','-m','scripts.control_store','standby'],[(b['leaf'],'/state',True),(b['control'],'/role',True)],network='none')
        self.profile['management']['standby']=passive
        names=[];ids=[]
        for label in ['a','b']:
            name=self.profile['gateways'][0 if label=='a' else 1]
            gateway=self.start_process(name,['python','-m','scripts.ca_recovery_state','gateway','--node',label,'--backend','host-'+label],
                [(a['witness'],'/witness',False),(b['witness'],'/replica/witness',False),(a['reader'],'/reader',True),*self.meta_mounts()],
                network=self.profile['client_network'],aliases=['ca-'+label]+(['ca'] if label=='a' else []),
                extra_network=self.profile['cluster_network'],env=self.mirror({'/witness':'/replica/witness'}))
            names.append(name);ids.append(gateway['id'])
        self.profile.update(gateways=names,gateway_ids=ids)

    def offline_witness(self,operation,**fields):
        a=self.volumes();b=self.volumes(self.peer)
        mounts=[(a['witness'],'/witness',False),(b['witness'],'/replica/witness',False),(a['reader'],'/reader',True),*self.meta_mounts()]
        args=['run','--rm','-i','--network',self.profile['cluster_network'],'--read-only','--user','10001:10001','--cap-drop=ALL']
        for v,d,r in mounts:args+=['--mount',f'type=volume,src={v},dst={d}'+(',readonly' if r else '')]
        args+=['--env',ENV+'='+self.mirror({'/witness':'/replica/witness'}),'--entrypoint','python',self.profile['image'],'-m','scripts.ca_recovery_state','rpc']
        return json.loads(self.raw(args,{'operation':operation,**fields}))

    def node_tls_probe(self,program,request):
        # Admission gateways are deliberately absent during management takeover.
        # This probe receives only public trust material, with no state/key mount.
        self.guard()
        self.raw(['run','--rm','-i','--network',self.profile['cluster_network'],'--read-only',
            '--user','10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges:true',
            '--memory','256m','--pids-limit','64','--entrypoint','python',self.profile['image'],'-c',program],request,timeout=10)

    def promote(self, target, primary):
        with lease(self.directory()):
            return self._promote(target,primary)

    def _promote(self,target,primary):
        if target!=self.peer:raise LifecycleError('control_promotion_scope')
        candidate=self.volumes(target)
        validation={'operation':'validate','expected':self.role()}
        proof=self.job(validation,[(v,'/source/'+k,True) for k,v in candidate.items()])
        if (self.sql(primary,'SELECT pg_is_in_recovery();')!='f'
                or self.sql(primary,'SELECT system_identifier FROM pg_control_system();')!=proof['database_incarnation']):
            raise LifecycleError('control_primary_identity')
        # Host lease excludes live dispatchers; unfinished durable operations and
        # any unknown orphan job remain a refusal, never an election timeout.
        self.ensure_no_jobs()
        receipts=[self.container(self.profile['leaf'],stop=True,remove=True)]
        receipts.append(self.container(self.profile['management']['standby'],stop=True,remove=True))
        for name,ident in zip(self.profile['gateways'],self.profile['gateway_ids'],strict=True):
            receipts.append(self.container({'name':name,'id':ident},stop=True,remove=True))
        proof=self.job(validation,[(v,'/source/'+k,True) for k,v in candidate.items()])
        ca=[]
        for label in self.hosts:
            record=self.owned_ca(label);self.inner(label,['stop','--time','2',record['Id']]);ca.append((label,record['Id']))
        deadline=time.monotonic()+15
        while self.sql(primary,"SELECT count(*) FROM pg_stat_activity WHERE usename='secops_ca';")!='0':
            if time.monotonic()>deadline:raise LifecycleError('control_writer_drain_timeout')
            time.sleep(.2)
        source=self.active;old=copy.deepcopy(self.profile['management']['cells'][source])
        replacement=self.new_cell(source,old['generation']+1)
        self.seed(candidate,replacement['volumes'])
        m=self.profile['management'];m['active']=target;m['epoch']+=1;m['cells'][source]=replacement
        self.select_active_storage()
        # Coordinator state is public; loading it from the candidate never reads
        # private key bytes through the host filesystem.
        state=json.loads(self.raw(['run','--rm','--network','none','--read-only','--user','10001:10001','--mount',
            f"type=volume,src={candidate['control']},dst=/data,readonly",'--entrypoint','python',self.profile['image'],'-c',
            "from pathlib import Path;print(Path('/data/coordinator.json').read_text())"]))
        self.initialize_control(state)
        self.offline_witness('management_reconcile',verified_writers_stopped=True,verified_gateways_stopped=True)
        # Keep publishers paused until the interrupted authority ceremony resumes.
        a=self.volumes();b=self.volumes(self.peer)
        self.job({'operation':'pause_leaf'},[(a['leaf'],'/state',False),(b['leaf'],'/replica/leaf',False),*self.meta_mounts()],
            env=self.mirror({'/state':'/replica/leaf'}))
        for label,ident in ca:self.inner(label,['start',ident]);self.node_health(label)
        self.install_processes();self.initialize_control(state);self.persist_profile()
        self.witness('unfreeze')
        return {'active':target,'management_epoch':m['epoch'],'coordinator_phase':proof['phase'],
            'coordinator_epoch':proof['epoch'],'plan_hash':proof['plan_hash'],'fenced':receipts,
            'retired_volumes':old['volumes'],'candidate_sha256':proof['tree_sha256']}

    def ensure_no_jobs(self):
        ids=self.raw(['ps','--quiet','--filter','ancestor='+self.profile['image']]).split()
        known={self.profile['leaf']['id'],self.profile['management']['standby']['id'],*self.profile['gateway_ids']}
        volumes={v for c in self.profile['management']['cells'].values() for v in c['volumes'].values()}
        if ids:
            for record in json.loads(self.raw(['inspect',*ids])):
                if record['Id'] not in known and any(m.get('Name') in volumes and m['RW'] for m in record['Mounts']):
                    raise LifecycleError('control_orphan_job_requires_fence')

    @classmethod
    def bootstrap(cls, profile, reader_volume, workload_mounts):
        p=copy.deepcopy(profile);project=p['project']
        av={**p['volumes'],'witness':p['witness_volume'],'backups':p['backup_volume'],
            'backup_key':p['backup_key_volume'],'reader':reader_volume,'control':project+'-mgmt-a-g1-control'}
        bv={k:project+'-mgmt-b-g1-'+k.replace('_','-') for k in COMPONENTS}
        p['management']={'active':'a','epoch':1,'cells':{'a':{'generation':1,'volumes':av},'b':{'generation':1,'volumes':bv}},
            'workload_mounts':workload_mounts}
        result=cls(p)
        with lease(result.directory()):
            old=Hosts(profile);old.leaf('pause',value=True)
            deadline=time.monotonic()+30
            while not old.leaf('status')['paused']:
                if time.monotonic()>deadline:raise LifecycleError('control_bootstrap_pause_timeout')
                time.sleep(.2)
            old.wait_quiet()
            result.container(p['leaf'],stop=True,remove=True)
            for name,ident in zip(p['gateways'],p['gateway_ids'],strict=True):result.container({'name':name,'id':ident},stop=True,remove=True)
            state=json.loads((result.directory()/'authority-coordinator.json').read_bytes())
            result.new_volume(av['control'])
            for name in bv.values():result.new_volume(name)
            result.seed(av,bv);result.initialize_control(state)
            result.install_processes();result.initialize_control(state);result.persist_profile();result.witness('unfreeze')
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=['status','promote'])
    parser.add_argument('--profile',type=Path,required=True);parser.add_argument('--target',choices=['a','b']);parser.add_argument('--primary',choices=['a','b'],default='a')
    args=parser.parse_args();b=Management(json.loads(args.profile.read_bytes()))
    print(json.dumps(b.promote(args.target,args.primary) if args.operation=='promote' else b.load_control()))


if __name__=='__main__':main()
