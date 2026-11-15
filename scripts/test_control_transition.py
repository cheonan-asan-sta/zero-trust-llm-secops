"""Local process-death fault injection for resumable management takeover."""

import argparse
import copy
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

from scripts import test_signal_compose as flow
from scripts.authority_rotation_coordinator import DockerBackend
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.control_plane_ha import Management
from scripts.control_transition import LABEL, Transition, read
from scripts.test_control_plane_ha import ControlLab

SOURCES=['scripts/control_transition.py','scripts/test_control_transition.py']
IMPORTED={p:sha256(ROOT/p) for p in SOURCES}


class CrashLab(ControlLab):
    def prepare(self):
        self.fault_enabled=False;self.takeovers=0
        super().prepare()
        actual=json.loads(command(['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python',self.image,'-c',
            "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],input=json.dumps(SOURCES)))
        flow.require(actual==IMPORTED,'transition_image_attestation')
        self.report.update(schema='control-transition-recovery-1',transition_image_source_sha256=actual,transition_checks=[],
            authority_tick_deadline_seconds=180,authority_tick_observations=[])
        self.report['source_input_sha256'].update(IMPORTED);self.save()

    def authority_tick(self):
        path=self.authority_profile.with_name('authority-coordinator.json')
        before=json.loads(path.read_bytes())['phase'] if path.exists() else 'uncached'
        started=time.monotonic()
        result=json.loads(command([sys.executable,'-m','scripts.authority_rotation_coordinator','tick',
            '--profile',str(self.authority_profile)],timeout=180))
        self.report['authority_tick_observations'].append({'before':before,'after':result['phase'],
            'seconds':round(time.monotonic()-started,3),'error':result.get('error')})
        self.save()
        flow.require(not result.get('error'),'transition_authority_tick_'+str(result.get('error')))
        return result

    def add(self,label,**details):
        super().add(label,**details)
        if label=='post_backup_token_consumption_and_revocation_established':
            self.post_open_csr=self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        if label=='authority_candidate_keys_and_plan_replicated_before_install':
            self.fault_enabled=True;self.backend.promote=self.interrupted_promote

    def sync(self):
        super().sync()
        if getattr(self,'fault_enabled',False):self.backend.promote=self.interrupted_promote

    def check(self,label,**details):
        self.report['transition_checks'].append({'label':label,'passed':True,**details});self.save()

    def worker(self,operation,target,primary,cut=None):
        args=[sys.executable,'-m','scripts.test_control_transition','worker','--profile',str(self.authority_profile),
            '--operation',operation,'--target',target,'--primary',primary]
        if cut:args+=['--cut',cut]
        result=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=300,check=False)
        (self.directory/f'transition-{self.takeovers}-{operation}-{cut or "finish"}.private.log').write_text(result.stdout+result.stderr,encoding='utf-8')
        if cut:
            flow.require(result.returncode==73,'transition_expected_process_death_'+cut)
        else:
            flow.require(result.returncode==0,'transition_resume_failed')
            return json.loads(result.stdout)
        return None

    def post_open_probe(self,csr):
        # step-ca rejects JWTs minted before its restart. Mint after admission
        # opens; only a prepared CSR crosses this test-only boundary beforehand.
        b=self.backend;vault=b.volumes()['vault'];b.ensure_volumes([vault])
        program="""import json,sys
from pathlib import Path
from scripts.authority_custodian import unseal,load_key
from scripts.certificate_authority import bootstrap_token
v=Path('/vault');s=json.loads((v/'state.json').read_bytes());bundle=unseal((v/s['bundle']).read_bytes(),(v/'password').read_bytes())
p=next(p for p in bundle['providers'] if p['name']=='collector-clientAuth');csr=json.load(sys.stdin)
print(json.dumps({'csr':csr,'ott':bootstrap_token(p,load_key(bundle['keys'][p['name']]),csr,seconds=900),'notAfter':'20m'}))"""
        return json.loads(b.raw(['run','--rm','-i','--network','none','--read-only','--user','10001:10001',
            '--cap-drop=ALL','--security-opt=no-new-privileges:true','--mount',f'type=volume,src={vault},dst=/vault,readonly',
            '--entrypoint','python',b.profile['image'],'-c',program],csr))

    def interrupted_promote(self,target,primary):
        self.takeovers+=1
        first=self.takeovers==1
        probe_csr=None if first else self.post_open_csr
        pending_request=None
        original_epoch=self.backend.profile['management']['epoch']
        cuts=['after_fence','volume_created','after_copy','after_roles','process_created','after_services','after_publish','after_open'] if first else ['after_open']
        transition_id=None;old_created=None
        for index,cut in enumerate(cuts):
            self.worker('promote' if index==0 else 'resume',target,primary,cut)
            record=read(self.authority_profile.parent/'management-transition.json')
            self.last_transition_record=copy.deepcopy(record)
            transition_id=transition_id or record['id']
            flow.require(record['id']==transition_id and record['profile']['management']['epoch']==original_epoch+1,'transition_identity_regenerated')
            try:Management(json.loads(self.authority_profile.read_bytes())).load_control()
            except LifecycleError as exc:flow.require(str(exc)=='control_transition_resume_required','transition_wrong_pending_refusal')
            else:raise flow.CheckFailed('transition_pending_controller_allowed')
            self.check(f'takeover_{self.takeovers}_process_death_{cut}',transition_id=record['id'],durable_phase=record['phase'])
            if cut=='process_created':
                entry=next(e for e in record['processes'].values() if e['id'] is None)
                found=json.loads(command(['docker','inspect',entry['name']]))[0]
                old_created=(entry['name'],found['Id'])
                flow.require(found['Config']['Labels'][LABEL]==transition_id,'transition_unrecorded_create_label')
            if cut=='after_roles':
                # Corrupt the public journal; ordinary control and resume must
                # refuse before touching the pinned Docker service identities.
                path=self.authority_profile.parent/'management-transition.json';raw=path.read_bytes()
                bad=json.loads(raw);bad['target']='a' if target=='b' else 'b';path.write_text(json.dumps(bad),encoding='utf-8')
                try:
                    attempt=subprocess.run([sys.executable,'-m','scripts.control_plane_ha','resume','--profile',str(self.authority_profile)],capture_output=True,timeout=30,check=False)
                    flow.require(attempt.returncode!=0 and b'control_transition_journal_invalid' in attempt.stderr,'transition_corrupt_journal_accepted')
                finally:
                    path.write_bytes(raw)
                self.check('corrupt_journal_resume_refused_with_checksum')
            if cut=='after_open' and probe_csr is not None:
                self.backend=Management(json.loads(self.authority_profile.read_bytes()));self.sync()
                pending_request=self.post_open_probe(probe_csr)
                issued=self.ca_call(pending_request,endpoint='ca-a')
                flow.require(issued['status']==201,'transition_post_open_issue_'+str(issued['status']))
                self.check('new_token_consumption_after_gate_open_before_commit')
        result=self.worker('resume',target,primary)
        self.backend=Management(json.loads(self.authority_profile.read_bytes()));self.sync()
        record=read(self.authority_profile.parent/'management-transition.json')
        flow.require(record['phase']=='complete' and record['id']==transition_id,'transition_not_committed')
        again=self.worker('resume',target,primary)
        flow.require(again==result,'transition_complete_resume_changed_receipt')
        self.check(f'takeover_{self.takeovers}_complete_resume_is_idempotent',management_epoch=result['management_epoch'])
        if old_created:
            flow.require(record['processes'][old_created[0]]['id']==old_created[1],'transition_created_container_not_adopted')
            self.check('created_container_with_lost_reply_reused_by_same_id',container_id=old_created[1])
        if pending_request is not None:
            flow.require(self.ca_call(pending_request,endpoint='ca-b')['status'] in {400,401,403},'transition_post_open_consumption_rolled_back')
            self.check('post_open_security_write_survives_final_resume')
        return result

    def cleanup(self):
        if hasattr(self,'authority_profile'):
            try:record=read(self.authority_profile.parent/'management-transition.json')
            except LifecycleError:record=getattr(self,'last_transition_record',None)
            if record is not None and record['project']==self.ident:
                for entry in record['processes'].values():
                    if entry['name'].startswith(self.ident+'-') and entry['name'] not in self.containers:self.containers.append(entry['name'])
                names=[v for c in record['profile']['management']['cells'].values() for v in c['volumes'].values()]
                self.backend.profile.setdefault('additional_volumes',[]).extend(n for n in names if n not in self.backend.profile.get('additional_volumes',[]))
        super().cleanup()


def worker(args):
    b=Management(json.loads(args.profile.read_bytes()))
    def kill(point):
        if point==args.cut:os._exit(73)
    b._transition_hook=kill
    print(json.dumps(b.promote(args.target,args.primary) if args.operation=='promote' else b.resume()))


def spec_check(directory):
    if not directory.resolve().is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('transition_spec_directory_scope')
    directory.mkdir(parents=True,exist_ok=True)
    project='c02-'+uuid.uuid4().hex[:12];name=project+'-contract'
    image=command(['docker','image','inspect','python:3.12-slim','--format','{{.Id}}']).strip()
    b=SimpleNamespace(project=project,profile={'image':image},directory=lambda:directory)
    b.raw=lambda args,payload=None,timeout=60:DockerBackend.command(b,args,payload,timeout)
    t=Transition(b);t.record={'id':uuid.uuid4().hex,'image':image,'processes':{}};t.save=lambda:None
    args=['create','--name',name,'--network','none','--restart','no','--read-only','--user','10001:10001',
        '--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory','512m','--pids-limit','128',
        '--tmpfs','/tmp:rw,size=32m','--tmpfs','/data:rw,uid=10001,gid=10001,size=1m',
        '--entrypoint','python',image,'-c','pass']
    try:
        first=t.create_process(name,args,None,False)
        second=t.create_process(name,args,None,False)
        flow.require(first==second,'transition_spec_adoption')
        print(json.dumps({'passed':True,'same_id_adopted':True,'container_id':first['id']}))
    finally:
        found=t.lookup('container',name)
        if found and found['Config']['Labels'].get(LABEL)==t.record['id'] and found['Image']==image:
            b.raw(['rm','--force','--volumes',found['Id']])


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',nargs='?',choices=['run','worker','spec-check'],default='run')
    p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/transition-reproduce');p.add_argument('--profile',type=Path)
    p.add_argument('--operation',choices=['promote','resume'],default='resume');p.add_argument('--target',choices=['a','b'],default='b')
    p.add_argument('--primary',choices=['a','b'],default='a');p.add_argument('--cut')
    args=p.parse_args()
    if args.mode=='worker':worker(args);return
    if args.mode=='spec-check':spec_check(args.directory);return
    lab=CrashLab(args.directory);lab.key_smoke=True
    try:
        lab.prepare();lab.smoke()
        flow.require(all(sha256(ROOT/n)==h for n,h in lab.report['source_input_sha256'].items()),'transition_sources_changed')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:
        lab.report['finished_at']=flow.timestamp();lab.cleanup()


if __name__=='__main__':main()
