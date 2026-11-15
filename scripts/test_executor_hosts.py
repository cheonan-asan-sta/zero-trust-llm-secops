"""Real local maintenance-host loss with independent replicated transition logs.

Only disposable c02 namespaces are touched. This is a single-PC Docker pilot,
not physical-host availability, quorum, or automatic operator-ceremony recovery.
"""

import argparse
import base64
import copy
import json
import os
import subprocess
import time
import uuid
from pathlib import Path

from scripts import test_signal_compose as flow
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.control_plane_ha import Management
from scripts.control_store import COMPONENTS
from scripts.executor_cluster import Cluster, Remote
from scripts.executor_store import Store
from scripts.test_authority_key_rotation import AuthorityLab
from scripts.test_ca_host_recovery import RecoveryLab
from scripts.test_control_plane_ha import ControlLab
from scripts.test_control_transition import CrashLab

SOURCES=['scripts/control_executor.py','scripts/executor_cluster.py','scripts/executor_disk.py','scripts/executor_transition.py',
    'scripts/executor_fence.py','scripts/executor_store.py','scripts/test_executor_hosts.py',
    'scripts/test_control_transition.py']
IMPORTED={p:sha256(ROOT/p) for p in SOURCES}


def build_executor(project,graph_image,directory):
    lock=json.loads((ROOT/'infra/mtls/ca-recovery-tools.lock.json').read_bytes())
    build=directory/'executor-build';build.mkdir(parents=True,exist_ok=True)
    refs=json.loads(command(['docker','image','inspect',graph_image,'--format','{{json .RepoTags}}']))
    ref=next(t for t in refs if t.startswith(project+'-'))
    dockerfile=f"FROM {lock['docker_host']['image']} AS cli\nFROM {ref}\nCOPY --from=cli /usr/local/bin/docker /usr/local/bin/docker\nHEALTHCHECK NONE\n"
    (build/'Dockerfile').write_text(dockerfile,encoding='utf-8')
    tag=project+'-executor-tools'
    result=subprocess.run(['docker','build','--tag',tag,str(build)],capture_output=True,timeout=300,check=False)
    (directory/'executor-build.private.log').write_bytes(result.stdout+result.stderr)
    flow.require(result.returncode==0,'executor_tools_build')
    return tag,command(['docker','image','inspect',tag,'--format','{{.Id}}']).strip()


def owned_cleanup(project,tags):
    # Exact generated project prefix, never global prune or a foreign workload.
    for kind,listing,remove in [('containers',['ps','--all','--format','{{.Names}}'],['rm','--force','--volumes']),
            ('volumes',['volume','ls','--format','{{.Name}}'],['volume','rm']),
            ('networks',['network','ls','--format','{{.Name}}'],['network','rm'])]:
        names=[n for n in command(['docker',*listing]).splitlines() if n.startswith(project+'-')]
        for name in names:command(['docker',*remove,name])
    for tag in tags:command(['docker','image','rm',tag])
    return {kind+'_remaining':len([n for n in command(['docker',*listing]).splitlines() if n.startswith(project+'-')])
        for kind,listing in [('containers',['ps','--all','--format','{{.Names}}']),
            ('volumes',['volume','ls','--format','{{.Name}}']),('networks',['network','ls','--format','{{.Name}}'])]}


def fixture():
    """Test-only raw public journal update; no CA or workload operations."""
    import sys
    request=json.load(sys.stdin);store=Store.environment();store.guard()
    if request.get('cut'):
        store.hook=lambda *_:os._exit(73)
    store.save_record(store.root/'management-transition.json',request['record'])
    print('{}')


def fixture_call(cluster,record,cut=False):
    ident=cluster.d['hosts'][cluster.d['active']]['worker']['id']
    result=subprocess.run(['docker','exec','-i',ident,'python','-m','scripts.test_executor_hosts','fixture'],
        input=json.dumps({'record':record,'cut':cut}),capture_output=True,text=True,timeout=30,check=False)
    flow.require(result.returncode==(73 if cut else 0),'executor_fixture_exit')


def spec_check(directory,takeover=None):
    project='c02-'+uuid.uuid4().hex[:12];tags=[];cluster=None
    directory.mkdir(parents=True,exist_ok=True)
    report={'schema':'executor-host-spec-1','project':project,'started_at':flow.timestamp(),'checks':[]}
    def check(label,**details):report['checks'].append({'label':label,'passed':True,**details})
    try:
        graph=project+'-app';tags.append(graph)
        result=subprocess.run(['docker','build','--tag',graph,'.'],cwd=ROOT,capture_output=True,timeout=300,check=False)
        (directory/'app-build.private.log').write_bytes(result.stdout+result.stderr)
        flow.require(result.returncode==0,'executor_spec_app_build')
        graph=command(['docker','image','inspect',graph,'--format','{{.Id}}']).strip()
        tag,image=build_executor(project,graph,directory);tags.append(tag)
        profile={'project':project,'image':graph,'ca':{'name':project+'-ca'},'leaf':{'name':project+'-leaf','id':'c'*64},'volumes':{},
            'service_hosts':{s:{'name':project+'-host-'+s,'id':s*64,'image':graph} for s in ['a','b']},
            'management':{'active':'a','epoch':1,'cells':{s:{'generation':1,
                'volumes':{k:project+'-mgmt-'+s+'-'+k.replace('_','-') for k in COMPONENTS}} for s in ['a','b']}}}
        # A real unlabelled service container models the original DinD hosts.
        service=command(['docker','run','--detach','--rm','--name',project+'-host-a','--network','none','--read-only',
            '--user','10001:10001','--cap-drop=ALL','--entrypoint','python',graph,'-c','import time;time.sleep(300)']).strip()
        profile['service_hosts']['a']['id']=service
        cluster=Cluster.bootstrap(profile,image,adopt=False)
        check('two_distinct_workers_and_four_independent_storage_volumes',workers={s:h['worker'] for s,h in cluster.d['hosts'].items()})
        version=cluster.rpc('raw',(['version','--format','{{.Client.Version}}'],))['result'].strip()
        check('pinned_docker_cli_works_from_nonroot_trusted_executor',version=version)
        try:cluster.rpc('view',site='b')
        except LifecycleError as exc:flow.require(str(exc)=='executor_rpc_executor_passive_host','executor_spec_passive_reason')
        else:raise flow.CheckFailed('executor_spec_passive_allowed')
        check('passive_host_refuses_dispatch')
        running=subprocess.Popen(['docker','exec',service,'python','-c','import time;time.sleep(300)'],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while not json.loads(command(['docker','inspect',service]))[0].get('ExecIDs'):
                flow.require(time.monotonic()<deadline,'executor_spec_exec_not_started');time.sleep(.1)
            try:cluster.settle(profile)
            except LifecycleError as exc:flow.require(str(exc)=='executor_inflight_work_requires_investigation','executor_spec_busy_wrong_refusal')
            else:raise flow.CheckFailed('executor_spec_unlabelled_busy_host_allowed')
            check('unlabelled_pinned_service_exec_blocks_owner_takeover')
        finally:
            command(['docker','stop','--time','1',service]);running.wait(timeout=10)
        record={'schema':'control-transition-1','id':uuid.uuid4().hex,'phase':'prepared','project':project,
            'image':graph,'source':'a','target':'b','primary':'a','original':{},'profile':{},'proof':{},
            'state':None,'fenced':[],'processes':{},'receipt':None}
        fixture_call(cluster,record)
        flow.require(cluster.rpc('journal')['result']==record,'executor_spec_initial_pair')
        job=project+'-old-epoch-job'
        job_id=cluster.rpc('raw',(['run','--detach','--rm','--name',job,'--network','none','--read-only',
            '--user','10001:10001','--cap-drop=ALL','--entrypoint','python',graph,'-c','import time;time.sleep(300)'],))['result'].strip()
        record['phase']='fenced';fixture_call(cluster,record,cut=True)
        try:cluster.rpc('journal')
        except LifecycleError as exc:flow.require('journal_divergence_requires_fence' in str(exc),'executor_spec_divergence_reason')
        else:raise flow.CheckFailed('executor_spec_divergence_allowed')
        check('real_process_exit_after_peer_fsync_refuses_divergent_local_prefix')
        anchor=cluster.anchor();survivor=copy.deepcopy(cluster.d['hosts']['b']);old=copy.deepcopy(cluster.d)
        cluster=Cluster.recover(anchor,'b',survivor['journal'],survivor['owner'])
        receipt=cluster.takeover('b',discard=True) if takeover is None else takeover(cluster,'b')
        flow.require(cluster.rpc('journal')['result']==record,'executor_spec_lost_peer_prefix')
        check('whole_active_worker_and_its_two_volumes_removed_surviving_peer_recovers_latest_record',**receipt)
        flow.require(subprocess.run(['docker','inspect',job_id],capture_output=True,check=False).returncode!=0,
            'executor_spec_old_job_not_settled')
        check('old_epoch_inflight_job_removed_before_new_owner_is_published')
        for kind in ['journal','owner']:
            flow.require(subprocess.run(['docker','volume','inspect',old['hosts']['a'][kind]],capture_output=True,check=False).returncode!=0,
                'executor_spec_old_volume_remains')
        expected=Cluster(old).role()
        fence={'expected':expected,'roles':['/executor-fence-a/owner.json','/executor-fence-b/owner.json']}
        args=['docker','run','--rm','--network','none','--read-only','--user','10001:10001','--cap-drop=ALL']
        for site in ['a','b']:args+=['--mount',f"type=volume,src={cluster.d['hosts'][site]['owner']},dst=/executor-fence-{site},readonly"]
        result=subprocess.run([*args,'--env','SECOPS_EXECUTOR_FENCE='+json.dumps(fence),'--entrypoint','python',graph,
            '-m','scripts.executor_fence','exec','python','-c',"print('forbidden_job_started')"],capture_output=True,timeout=30,check=False)
        flow.require(result.returncode!=0 and b'executor_job_stale_or_incomplete_owner' in result.stderr
            and b'forbidden_job_started' not in result.stdout,'executor_spec_old_job_allowed')
        check('late_old_epoch_job_refused_before_business_command')
        report['completed']=True
    finally:
        report['cleanup']=owned_cleanup(project,tags);report['finished_at']=flow.timestamp()
        (directory/'spec-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))


class ExecutorLab(ControlLab):
    def prepare(self):
        super().prepare();self.takeovers=0
        self.executor_tag,self.executor_image=build_executor(self.ident,self.report['certificate_execution_image_id'],self.directory)
        attest={}
        for label,image in [('graph',self.report['certificate_execution_image_id']),('executor',self.executor_image)]:
            attest[label]=json.loads(command(['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python',image,'-c',
                "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],input=json.dumps(SOURCES)))
            flow.require(attest[label]==IMPORTED,'executor_image_attestation_'+label)
        self.report.update(schema='executor-host-redundancy-1',executor_checks=[],executor_image_source_sha256=attest,
            executor_image_id=self.executor_image,authority_tick_observations=[],authority_tick_deadline_seconds=180,
            executor_scope={'hosts':'two trusted Docker-admin maintenance containers; independent rootfs, journal and owner volumes on one PC',
                'availability':'manual externally confirmed fencing; no quorum, automatic election, physical-host, power-loss or operator-ceremony crash guarantee',
                'online_services':'no Docker socket or offline root/backup-key mounts; executor socket is root-equivalent trusted maintenance access'})
        self.report['source_input_sha256'].update(IMPORTED);self.save()

    def check(self,label,**details):
        self.report['executor_checks'].append({'label':label,'passed':True,**details});self.save()

    def authority_tick(self):
        # Parent initialization still seeds the public coordinator before hosts exist.
        if not hasattr(self,'executors'):return super().authority_tick()
        started=time.monotonic();response=self.executors.rpc('tick',timeout=180)
        self.backend.profile=response['profile'];result=response['result']
        self.report['authority_tick_observations'].append({'after':result['phase'],'seconds':round(time.monotonic()-started,3),'error':result['error']})
        self.save();flow.require(not result['error'],'executor_authority_tick_failed');return result

    def coordinator_state(self):
        return self.backend.load_control() if hasattr(self,'executors') else super().coordinator_state()

    def drive_until(self,predicate,label,timeout=180):
        return AuthorityLab.drive_until(self,predicate,label,timeout=max(timeout,600))

    def lose_executor(self):
        cluster=self.executors;old=copy.deepcopy(cluster.d);target='b' if old['active']=='a' else 'a'
        anchor=cluster.anchor();survivor=old['hosts'][target]
        # These optional Windows console caches are deliberately destroyed.
        for name in ['profile.json','authority-coordinator.json','executor-descriptor.json']:
            self.authority_profile.with_name(name).unlink(missing_ok=True)
        cluster=Cluster.recover(anchor,target,survivor['journal'],survivor['owner'])
        receipt=cluster.takeover(target,discard=True)
        self.executors=cluster;self.backend=Remote(cluster);self.sync()
        for kind in ['journal','owner']:
            flow.require(subprocess.run(['docker','volume','inspect',old['hosts'][old['active']][kind]],capture_output=True,check=False).returncode!=0,
                'executor_failed_host_storage_survived')
        self.check('independent_executor_takeover_after_host_storage_and_console_cache_loss',**receipt)

    def interrupted_promote(self,target,primary,*,opening=False):
        self.takeovers+=1;old_epoch=self.backend.profile['management']['epoch']
        fault={'point':'after_open'} if opening else {'point':'journal_peer_saved','phase':'roles'}
        self.executors.rpc('promote',(target,primary),fault=fault,expect_exit=73,timeout=300)
        if not opening:
            try:self.executors.rpc('journal')
            except LifecycleError as exc:flow.require('journal_divergence_requires_fence' in str(exc),'executor_wrong_divergence_refusal')
            else:raise flow.CheckFailed('executor_divergent_journal_allowed')
            self.check('real_transition_peer_only_roles_checkpoint_blocks_old_executor_after_process_exit')
        self.lose_executor()
        before=self.executors.rpc('journal')['result'];identity=before['id']
        flow.require(before['phase']==('opening' if opening else 'roles'),'executor_wrong_survivor_phase')
        pending=None
        if opening:
            pending=CrashLab.post_open_probe(self,self.post_open_csr)
            flow.require(self.ca_call(pending,endpoint='ca-a')['status']==201,'executor_post_open_issue')
            self.check('new_security_write_after_open_and_executor_loss_before_resume')
        receipt=self.backend.resume();self.sync()
        record=self.executors.rpc('journal')['result']
        flow.require(record['phase']=='complete' and record['id']==identity,'executor_transition_identity_changed')
        flow.require(receipt==self.backend.resume() and receipt['management_epoch']==old_epoch+1,'executor_resume_not_idempotent')
        self.check('surviving_executor_resumes_exact_transition_once',transition_id=identity,management_epoch=receipt['management_epoch'],opening=opening)
        if pending is not None:
            flow.require(self.ca_call(pending,endpoint='ca-b')['status'] in {400,401,403},'executor_post_open_write_rolled_back')
            self.check('post_open_token_consumption_preserved_after_resume')
        return receipt

    def init_authority(self):
        providers=RecoveryLab.init_authority(self)
        mounts=json.loads(command(['docker','inspect',self.controller]))[0]['Mounts']
        workload=[f"type=volume,src={m['Name']},dst={m['Destination']}"+(',readonly' if not m['RW'] else '')
            for m in mounts if m['Destination'].startswith(('/managed/','/ack/')) and m['Destination']!='/managed/renewal']
        local=Management.bootstrap(self.backend.profile,self.reader_volume,workload)
        self.executors=Cluster.bootstrap(local.profile,self.executor_image);self.backend=Remote(self.executors);self.sync()
        self.check('two_executor_hosts_with_independent_journal_and_owner_volumes',hosts=self.executors.d['hosts'])
        state=self.drive_until(lambda s:s['phase']=='prepared','executor_prepared')
        plan_hash=state['plan']['root_public_key_sha256']
        receipt=self.interrupted_promote('b','a');self.retire(receipt['retired_volumes'])
        state=self.backend.load_control()
        flow.require(state['phase']=='prepared' and state['plan']['root_public_key_sha256']==plan_hash,'executor_prepared_key_changed')
        self.check('same_prepared_root_candidate_survives_management_and_executor_loss',root_public_key_sha256=plan_hash)
        return providers

    def smoke(self):
        AuthorityLab.smoke(self)
        control=self.backend.load_control()
        flow.require(control['epoch']==1 and control['phase']=='idle','executor_rotation_not_complete')
        flow.require(control['history'][0]['evidence']['old_jwks']['total_denied']==132,'executor_old_jwk_coverage')
        self.check('root_issuer_and_all_jwk_rotation_completed_on_surviving_executor',old_jwk_denials=132)
        uid=next(uid for uid,c in self.status()['credentials'].items() if c['name']=='collector')
        flow.require(self.rpc({'operation':'renew_attempt','id':uid})['allowed'],'executor_mtls_renewal_after_takeover')
        self.check('current_mtls_renewal_after_executor_takeover')
        self.check('encrypted_backup_and_separate_key_replicated',**self.backend.backup('backup-executor-current.sealed','a'))
        request=self.current_request();issued=self.ca_call(request,endpoint='ca-a')
        flow.require(issued['status']==201,'executor_baseline_issue')
        flow.require(self.ca_call({'serial':issued['serial'],'passive':True},endpoint='ca-a',mode='revoke')['status']==200,'executor_baseline_revoke')
        claims=request['ott'].split('.')[1];token_expiry=json.loads(base64.urlsafe_b64decode(claims+'='*(-len(claims)%4)))['exp']
        revoked_expiry=self.private_rpc("import json;from pathlib import Path;from scripts.certificate_controller import metadata;print(json.dumps(metadata(Path('/state/ha-revoked.pem').read_text())['not_after']))")
        self.post_open_csr=self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        self.backend.leaf('pause',value=True);self.wait(lambda:self.backend.leaf('status')['paused'],'executor_second_pause')
        self.backend.container(self.backend.profile['leaf'],stop=True)
        receipt=self.interrupted_promote('a','a',opening=True);self.retire(receipt['retired_volumes'])
        control=self.backend.load_control();flow.require(control['epoch']==1 and control['phase']=='idle','executor_committed_authority_rollback')
        now=time.time();flow.require(min(token_expiry,revoked_expiry)-now>30,'executor_security_fixture_expired')
        flow.require(self.ca_call(request,endpoint='ca-b')['status'] in {400,401,403},'executor_consumed_nonce_replayed')
        flow.require(self.ca_call({},endpoint='ca-b',mode='renew_revoked')['status'] in {401,403},'executor_revoked_certificate_renewed')
        self.check('unexpired_consumed_token_and_revoked_certificate_still_denied',remaining_token_seconds=round(token_expiry-now,3),remaining_certificate_seconds=round(revoked_expiry-now,3))
        flow.require(self.ca_call(self.current_request(),endpoint='ca-a')['status']==201,'executor_new_nonce_refused')
        self.check('fresh_nonce_works_after_both_management_and_executor_losses')
        self.check('surviving_backup_and_key_authenticate_against_latest_security_checkpoint',**self.backend.restore_check('backup-executor-current.sealed','a'))
        self.backend.witness('unfreeze')
        self.report.update(final_management_role=self.backend.role(),final_executor_role=self.executors.role(),authority_history=control['history'])

    def cleanup(self):
        if hasattr(self,'executors'):
            # Cleanup reads the surviving offline journal, even if a cut is pending.
            for site in ['a','b']:
                host=self.executors.d['hosts'][site]
                if host['worker'] and host['worker']['name'] not in self.containers:self.containers.append(host['worker']['name'])
                for kind in ['journal','owner']:
                    if host[kind] not in self.volumes:self.volumes.append(host[kind])
                try:
                    files=self.executors.disk(self.executors.d['hosts'][site]['journal'],'read')
                    record=files.get('management-transition.json')
                    if record:
                        for entry in record['processes'].values():
                            if entry['name'] not in self.containers:self.containers.append(entry['name'])
                        self.volumes.extend(v for c in record['profile']['management']['cells'].values() for v in c['volumes'].values() if v not in self.volumes)
                except (OSError,ValueError,KeyError):pass
            self.backend=Management(self.backend.profile)
        # Parent collection removes current cells plus known retired leftovers.
        super().cleanup()
        tags=[self.executor_tag] if hasattr(self,'executor_tag') else []
        self.report['executor_cleanup']=owned_cleanup(self.ident,tags);self.save()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',nargs='?',choices=['run','fixture','spec-check'],default='run')
    p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/executor-reproduce');args=p.parse_args()
    if args.mode=='fixture':fixture();return
    if not args.directory.resolve().is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('executor_test_directory_scope')
    if args.mode=='spec-check':spec_check(args.directory);return
    lab=ExecutorLab(args.directory);lab.key_smoke=True
    try:
        lab.prepare();lab.smoke()
        flow.require(all(sha256(ROOT/n)==h for n,h in lab.report['source_input_sha256'].items()),'executor_sources_changed_during_run')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:
        lab.report['finished_at']=flow.timestamp();lab.cleanup()


if __name__=='__main__':main()
