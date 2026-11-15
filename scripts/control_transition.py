"""Resumable, explicit local management takeover under the trusted host lease.

The public host journal survives coordinator process death, not host/disk loss.
No business POST is retried. Once opening starts, reconciliation is never rerun.
"""

import copy
import hashlib
import json
import re
import time
import uuid

from scripts.certificate_controller import LifecycleError, replace_file
from scripts.control_mirror import durable_parent
from scripts.control_store import COMPONENTS

PHASES = ('prepared', 'fenced', 'copied', 'roles', 'reconciled', 'services', 'published', 'opening', 'complete')
LABEL = 'secops.control-transition'
SPEC = 'secops.control-spec'
FIELDS = {'schema','id','phase','project','image','source','target','primary','original',
    'profile','proof','state','fenced','processes','receipt'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read(path):
    if not path.exists():
        return None
    try:
        if path.is_symlink() or path.stat().st_size > 4 * 1024**2:
            raise ValueError
        record = json.loads(path.read_bytes())
        if not isinstance(record, dict):
            raise TypeError
        checksum = record.pop('sha256')
        if set(record) != FIELDS or checksum != digest(record) or record['schema'] != 'control-transition-1':
            raise ValueError
        if record['phase'] not in PHASES or not re.fullmatch(r'[a-f0-9]{32}', record['id']):
            raise ValueError
        return record
    except (OSError, ValueError, TypeError, KeyError):
        raise LifecycleError('control_transition_journal_invalid') from None


def write(path, record):
    replace_file(path, json.dumps({**record, 'sha256': digest(record)}, sort_keys=True))
    durable_parent(path)


def available(backend):
    path = backend.directory() / 'management-transition.json'
    record = backend.transition_read(path) if hasattr(backend, 'transition_read') else read(path)
    if record is not None:
        if record['project'] != backend.project or record['image'] != backend.profile['image']:
            raise LifecycleError('control_transition_journal_scope')
        if record['phase'] != 'complete' and getattr(backend, '_transition_id', None) != record['id']:
            raise LifecycleError('control_transition_resume_required')


class Transition:
    def __init__(self, backend):
        self.b = backend
        self.path = backend.directory() / 'management-transition.json'
        self.record = None

    def save(self, phase=None):
        if phase is not None:
            self.record['phase'] = phase
        if hasattr(self.b, "transition_write"):
            self.b.transition_write(self.path,self.record)
        else:
            write(self.path, self.record)

    def cut(self, point):
        hook = getattr(self.b, '_transition_hook', None)
        if hook is not None:
            hook(point)

    def begin(self, target, primary, proof):
        available(self.b)
        old = copy.deepcopy(self.b.profile)
        planned = copy.deepcopy(old)
        m = planned['management']; source = m['active']
        generation = m['cells'][source]['generation'] + 1
        replacement = {'generation': generation, 'volumes': {
            k:self.b.project+f'-mgmt-{source}-g{generation}-'+k.replace('_','-') for k in COMPONENTS}}
        for name in replacement['volumes'].values():
            if self.lookup('volume', name) is not None:
                raise LifecycleError('control_transition_reserved_volume_exists')
        m['cells'][source] = replacement; m['active'] = target; m['epoch'] += 1
        planned.setdefault('additional_volumes',[]).extend(replacement['volumes'].values())
        planned['gateways'] = [self.b.project+f"-mgmt-e{m['epoch']}-admission-"+label for label in ['a','b']]
        self.record = {'schema':'control-transition-1', 'id':uuid.uuid4().hex, 'phase':'prepared',
            'project':self.b.project, 'image':old['image'], 'source':source, 'target':target, 'primary':primary,
            'original':old, 'profile':planned, 'proof':proof, 'state':None, 'fenced':[], 'processes':{}, 'receipt':None}
        self.save(); self.cut('after_intent')
        return self.run()

    def validate(self):
        r = self.record; old = r['original']; new = r['profile']
        from scripts.control_plane_ha import Management
        Management(old); Management(new)
        source = r['source']; target = r['target']
        a = old['management']; n = new['management']
        if (r['project'] != self.b.project or r['image'] != self.b.profile['image']
                or old['project'] != r['project'] or new['project'] != r['project']
                or old['image'] != r['image'] or new['image'] != r['image']
                or source != a['active'] or target not in {'a','b'} or target == source or n['active'] != target
                or r['primary'] not in {'a','b'} or n['epoch'] != a['epoch']+1
                or n['cells'][target] != a['cells'][target]
                or n['cells'][source]['generation'] != a['cells'][source]['generation']+1
                or old['control_directory'] != str(self.path.parent)
                or new['control_directory'] != old['control_directory']
                or any(new[k] != old[k] for k in ['service_hosts','client_network','cluster_network','initial_root'])
                or n['workload_mounts'] != a['workload_mounts']):
            raise LifecycleError('control_transition_plan_scope')
        generation = n['cells'][source]['generation']
        expected = {k:r['project']+f'-mgmt-{source}-g{generation}-'+k.replace('_','-') for k in COMPONENTS}
        if n['cells'][source]['volumes'] != expected:
            raise LifecycleError('control_transition_replica_scope')
        if PHASES.index(r['phase']) >= PHASES.index('fenced') and (not r['state'] or not r['fenced']):
            raise LifecycleError('control_transition_checkpoint_missing')

    def resume(self):
        self.record = self.b.transition_read(self.path) if hasattr(self.b, "transition_read") else read(self.path)
        if self.record is None:
            raise LifecycleError('control_transition_missing')
        self.validate()
        return self.run()

    def lookup(self, kind, name):
        if kind == 'volume':
            names = self.b.raw(['volume','ls','--filter','name='+name,'--format','{{.Name}}']).splitlines()
            if name not in names:
                return None
            return json.loads(self.b.raw(['volume','inspect',name]))[0]
        ids = self.b.raw(['ps','--all','--no-trunc','--filter','name=^/'+re.escape(name)+'$','--format','{{.ID}}']).split()
        if not ids:
            return None
        if len(ids) != 1:
            raise LifecycleError('control_transition_container_ambiguous')
        return json.loads(self.b.raw(['inspect',ids[0]]))[0]

    def select(self, profile):
        self.b.profile = copy.deepcopy(profile)
        self.b.hosts = self.b.profile['service_hosts']
        self.b.select_active_storage()

    def fence(self):
        old = self.record['original']
        expected = [old['leaf'],old['management']['standby'],
            *[{'name':name,'id':ident} for name,ident in zip(old['gateways'],old['gateway_ids'],strict=True)]]
        receipts = []
        for item in expected:
            found = self.lookup('container', item['name'])
            if found is not None:
                self.b.container(item, stop=True, remove=True)
            else:
                # A missing name is insufficient if its pinned ID still exists elsewhere.
                ids = self.b.raw(['ps','--all','--no-trunc','--filter','id='+item['id'],'--format','{{.ID}}']).split()
                if ids:
                    raise LifecycleError('control_transition_fence_identity')
            receipts.append({**item,'stopped':True})
        self.stop_writers()
        return receipts

    def primary(self):
        p = self.record['primary']; incarnation = self.record['proof']['database_incarnation']
        if (self.b.sql(p,'SELECT pg_is_in_recovery();') != 'f'
                or self.b.sql(p,'SELECT system_identifier FROM pg_control_system();') != incarnation):
            raise LifecycleError('control_transition_database_identity')

    def stop_writers(self):
        self.primary()
        for label in self.b.hosts:
            found = self.b.owned_ca(label)
            if found['State']['Running']:
                self.b.inner(label,['stop','--time','2',found['Id']])
            if self.b.owned_ca(label)['State']['Running']:
                raise LifecycleError('control_transition_writer_fence')
        deadline = time.monotonic()+15
        while self.b.sql(self.record['primary'],"SELECT count(*) FROM pg_stat_activity WHERE usename='secops_ca';") != '0':
            if time.monotonic() > deadline:
                raise LifecycleError('control_transition_writer_drain')
            time.sleep(.2)

    def replica(self):
        b = self.b; r = self.record
        source = r['profile']['management']['cells'][r['source']]['volumes']
        for name in source.values():
            self.b.profile.setdefault('additional_volumes',[])
            if name not in self.b.profile['additional_volumes']:
                self.b.profile['additional_volumes'].append(name)
            found = self.lookup('volume', name)
            if found is None:
                b.raw(['volume','create','--label','secops.c02='+b.project,'--label',LABEL+'='+r['id'],name])
                self.cut('volume_created')
                found = self.lookup('volume', name)
            if found is None or found.get('Labels',{}).get(LABEL) != r['id']:
                raise LifecycleError('control_transition_volume_replaced')
            b.raw(['run','--rm','--network','none','--read-only','--user','10001:10001','--mount',
                f'type=volume,src={name},dst=/data','--entrypoint','python',r['image'],'-c',"from pathlib import Path;Path('/data').chmod(0o700)"])
        original = r['original']['management']['cells'][r['target']]['volumes']
        mounts = [(v,'/source/'+k,True) for k,v in original.items()]+[(v,'/target/'+k,False) for k,v in source.items()]
        b.job({'operation':'copy_resume','expected':r['proof']['tree_sha256']},mounts)

    def no_jobs(self):
        b = self.b; r = self.record
        known = {r['original']['leaf']['id'],r['original']['management']['standby']['id'],*r['original']['gateway_ids']}
        for entry in r['processes'].values():
            found = self.lookup('container', entry['name'])
            if found is not None:
                self.verify_process(found,entry)
                known.add(found['Id'])
        volumes = {v for p in [r['original'],r['profile']] for cell in p['management']['cells'].values() for v in cell['volumes'].values()}
        ids = b.raw(['ps','--quiet','--filter','ancestor='+r['image']]).split()
        if ids:
            for found in json.loads(b.raw(['inspect',*ids])):
                if found['Id'] not in known and any(m.get('Name') in volumes and m['RW'] for m in found['Mounts']):
                    raise LifecycleError('control_orphan_job_requires_fence')

    def verify_process(self, found, entry):
        if found is None:
            raise LifecycleError('control_transition_process_missing')
        args = entry['args']; labels = found['Config'].get('Labels') or {}
        mounts = {}
        for index,value in enumerate(args):
            if value == '--mount':
                parts=args[index+1].split(',');data=dict(x.split('=',1) for x in parts if '=' in x)
                mounts[data['dst']] = (data['src'],'readonly' not in parts)
        actual = {m['Destination']:(m.get('Name'),m['RW']) for m in found['Mounts'] if m['Type']=='volume'}
        boundary = args.index('--entrypoint'); command=args[boundary+3:]
        networks = set(found['NetworkSettings']['Networks'])
        allowed = {args[args.index('--network')+1],entry['extra_network']} - {None}
        h = found['HostConfig']; config = found['Config']
        expected_env = next((args[i+1] for i,v in enumerate(args) if v=='--env'),None)
        if not hasattr(self, 'image_env'):
            self.image_env = json.loads(self.b.raw(['image','inspect',self.record['image']]))[0]['Config'].get('Env') or []
        env = dict(v.split('=',1) for v in self.image_env)
        if expected_env:
            key,value = expected_env.split('=',1);env[key]=value
        actual_env = config.get('Env') or []
        tmpfs = dict(args[i+1].split(':',1) for i,v in enumerate(args) if v=='--tmpfs')
        if (found['Name'] != '/'+entry['name'] or found['Image'] != self.record['image']
                or (entry['id'] is not None and found['Id'] != entry['id'])
                or labels.get(LABEL) != self.record['id'] or labels.get(SPEC) != digest(entry['spec'])
                or entry['spec'] != {'args':args,'extra_network':entry['extra_network'],'start':entry['start']}
                or config['User'] != '10001:10001' or config['Entrypoint'] != [args[boundary+1]] or config['Cmd'] != command
                or not h['ReadonlyRootfs'] or h['RestartPolicy']['Name'] not in {'','no'}
                or h.get('Privileged') or h.get('Binds') or h.get('CapAdd') or h.get('CapDrop') != ['ALL']
                or 'no-new-privileges:true' not in h.get('SecurityOpt',[])
                or h['Memory'] != 512*1024**2 or h['PidsLimit'] != 128
                or actual != mounts or not networks.issubset(allowed)
                or h['NetworkMode'] != args[args.index('--network')+1]
                or h.get('Tmpfs',{}) != tmpfs
                or any(m['Type'] not in {'volume','tmpfs'} for m in found['Mounts'])
                or len(actual_env) != len(env) or dict(v.split('=',1) for v in actual_env) != env):
            raise LifecycleError('control_transition_process_replaced')

    def create_process(self, name, args, extra_network, start):
        r = self.record
        spec = {'args':args,'extra_network':extra_network,'start':start}
        entry = r['processes'].get(name)
        if entry is None:
            entry = {'name':name,'id':None,'args':args,'extra_network':extra_network,'start':start,'spec':spec}
            r['processes'][name] = entry; self.save()
        elif entry['spec'] != spec:
            raise LifecycleError('control_transition_process_spec_changed')
        found = self.lookup('container',name)
        if found is None:
            if entry['id'] is not None:
                raise LifecycleError('control_transition_process_missing')
            ident = self.b.raw([*args[:1],'--label',LABEL+'='+r['id'],'--label',SPEC+'='+digest(spec),
                '--label','secops.c02='+self.b.project,*args[1:]]).strip()
            self.cut('process_created')
            found = self.lookup('container',name)
            if found is None or found['Id'] != ident:
                raise LifecycleError('control_transition_create_unconfirmed')
        self.verify_process(found,entry)
        entry['id'] = found['Id']; self.save()
        if extra_network and extra_network not in found['NetworkSettings']['Networks']:
            self.b.raw(['network','connect',extra_network,found['Id']])
        if start and not found['State']['Running']:
            self.b.raw(['start',found['Id']])
        self.verify_process(self.lookup('container',name),entry)
        if extra_network and extra_network not in self.lookup('container',name)['NetworkSettings']['Networks']:
            raise LifecycleError('control_transition_network_unconfirmed')
        self.b.profile.setdefault('additional_containers',[])
        if name not in self.b.profile['additional_containers']:
            self.b.profile['additional_containers'].append(name)
        return {'name':name,'id':entry['id']}

    def run(self):
        b = self.b; r = self.record
        self.validate(); b._transition_id=r['id']; b._transition=self
        try:
            self.select(r['original'] if PHASES.index(r['phase']) < PHASES.index('copied') else r['profile'])
            self.primary(); self.no_jobs()
            if r['phase']=='prepared':
                r['fenced']=self.fence()
                candidate=b.volumes(r['target'])
                proof=b.job({'operation':'validate','expected':b.role()},[(v,'/source/'+k,True) for k,v in candidate.items()])
                self.primary()
                r['proof']=proof
                r['state']=json.loads(b.raw(['run','--rm','--network','none','--read-only','--user','10001:10001',
                    '--mount',f"type=volume,src={candidate['control']},dst=/data,readonly",'--entrypoint','python',r['image'],'-c',
                    "from pathlib import Path;print(Path('/data/coordinator.json').read_text())"]))
                self.cut('after_fence'); self.save('fenced')
            if r['phase']=='fenced':
                self.fence(); self.replica(); self.cut('after_copy'); self.save('copied')
            self.select(r['profile'])
            if r['phase']=='copied':
                b.initialize_control(r['state']);self.cut('after_roles');self.save('roles')
            if r['phase']=='roles':
                self.fence()
                b.offline_witness('management_reconcile',verified_writers_stopped=True,verified_gateways_stopped=True)
                a=b.volumes();peer=b.volumes(b.peer)
                b.job({'operation':'pause_leaf'},[(a['leaf'],'/state',False),(peer['leaf'],'/replica/leaf',False),*b.meta_mounts()],
                    env=b.mirror({'/state':'/replica/leaf'}))
                self.cut('after_reconcile');self.save('reconciled')
            if r['phase']=='reconciled':
                for label in b.hosts:
                    found=b.owned_ca(label);b.inner(label,['start',found['Id']]);b.node_health(label)
                b.install_processes();r['profile']=copy.deepcopy(b.profile)
                self.cut('after_services');self.save('services')
            if r['phase']=='services':
                b.initialize_control(r['state']);b.persist_profile();self.cut('after_publish');self.save('published')
            if r['phase']=='published':
                b.guard();self.check_services();self.save('opening')
            if r['phase']=='opening':
                b.guard();self.check_services()
                if b.witness('status')['frozen']:
                    b.witness('unfreeze')
                self.cut('after_open')
                r['receipt']={'active':r['target'],'management_epoch':b.profile['management']['epoch'],
                    'coordinator_phase':r['proof']['phase'],'coordinator_epoch':r['proof']['epoch'],'plan_hash':r['proof']['plan_hash'],
                    'fenced':r['fenced'],'retired_volumes':r['original']['management']['cells'][r['source']]['volumes'],
                    'candidate_sha256':r['proof']['tree_sha256'],'transition_id':r['id']}
                self.save('complete')
            if r['phase']=='complete':
                b.guard();self.check_services()
                return r['receipt']
            raise LifecycleError('control_transition_phase')
        finally:
            b._transition=None;b._transition_id=None

    def check_services(self):
        p=self.b.profile
        required=[p['leaf'],p['management']['standby'],
            *[{'name':n,'id':i} for n,i in zip(p['gateways'],p['gateway_ids'],strict=True)]]
        if len(self.record['processes']) != len(required):
            raise LifecycleError('control_transition_service_coverage')
        for item in required:
            entry=self.record['processes'].get(item['name'])
            if entry is None or item['id'] != entry['id']:
                raise LifecycleError('control_transition_service_identity')
            found=self.lookup('container',item['name']);self.verify_process(found,entry)
            if not found['State']['Running']:
                raise LifecycleError('control_transition_service_stopped')
