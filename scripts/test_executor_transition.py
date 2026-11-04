"""Local PID-1 actor death/restart campaign for explicit host handoff recovery."""

import argparse
import copy
import json
import subprocess
import sys
import uuid
from pathlib import Path

from scripts import executor_transition as op
from scripts import test_signal_compose as flow
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.executor_cluster import Cluster, Remote
from scripts.executor_store import Store
from scripts.test_control_transition import CrashLab
from scripts.test_executor_hosts import ExecutorLab, spec_check

SOURCES=['scripts/executor_transition.py','scripts/test_executor_transition.py']
IMPORTED={p:sha256(ROOT/p) for p in SOURCES}


def fixture_profile():
    store=Store.environment();value=store.load_json('profile.json');value['operator_post_complete_probe']='preserve-after-complete'
    store.save_json('profile.json',value);print('{}')


def exercise(cluster,target,check,after_complete=None,directory=None):
    old=copy.deepcopy(cluster.d);source=old['hosts'][target];anchor=cluster.anchor();actor_id=None;identity=None;lost_worker=None;points=[]
    value=None
    def resume():
        if directory is None:return op.resume_operator(anchor,target,source['journal'],source['owner'])
        anchor_path=directory/(cluster.project+'-operator-anchor.json');cache=directory/(cluster.project+'-operator-result.json')
        anchor_path.write_text(json.dumps(anchor),encoding='utf-8');cache.unlink(missing_ok=True)
        attempt=subprocess.run([sys.executable,'-m','scripts.executor_cluster','resume-takeover','--anchor',str(anchor_path),
            '--site',target,'--journal',source['journal'],'--owner',source['owner'],'--descriptor',str(cache)],
            capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=620,check=False)
        if attempt.returncode:
            if 'LifecycleError: executor_operator_resume_required' in attempt.stderr:raise LifecycleError('executor_operator_resume_required')
            raise LifecycleError('operator_fresh_console_failed')
        return {'descriptor':json.loads(cache.read_bytes()),'receipt':json.loads(attempt.stdout)}
    request={'schema':'executor-operator-request-1','id':uuid.uuid4().hex,'original':copy.deepcopy(old),'target':target,'discard':True}
    created=cluster.raw(op.actor_args(request,op.CUTS)).strip()
    flow.require(op.NAME not in cluster.disk(source['journal'],'read') or op.read_record(cluster.disk(source['journal'],'read')[op.NAME])['phase']=='complete',
        'operator_initial_journal_unexpected')
    check('created_actor_without_new_intent_is_resumable',actor_id=created)
    try:resume()
    except LifecycleError as exc:flow.require(str(exc)=='executor_operator_resume_required','operator_first_wrong_failure_'+str(exc))
    else:raise flow.CheckFailed('operator_first_cut_missing')
    for _ in range(len(op.CUTS)):
        found=op.lookup(cluster,cluster.project+'-executor-takeover-lock')
        flow.require(found is not None and not found['State']['Running'] and found['State']['ExitCode']==73,'operator_not_actual_pid1_death')
        files=cluster.disk(source['journal'],'read');r=op.read_record(files[op.NAME]);point=files[op.FAULTS][r['id']][-1]
        actor_id=actor_id or found['Id'];identity=identity or r['id']
        flow.require(found['Id']==actor_id==r['actor']['id'] and r['id']==identity,'operator_identity_regenerated')
        points.append(point);check('actual_same_actor_restart_checkpoint',point=point,phase=r['phase'],actor_id=actor_id,transition_id=identity)
        if point=='after_intent':
            try:cluster.rpc('view')
            except LifecycleError as exc:flow.require('operator_resume_required' in str(exc),'operator_pending_wrong_refusal')
            else:raise flow.CheckFailed('operator_pending_work_allowed')
            try:op.launch(cluster,target,discard=True)
            except LifecycleError as exc:flow.require(str(exc)=='executor_operator_resume_required','operator_second_actor_wrong_refusal')
            else:raise flow.CheckFailed('operator_second_actor_created')
            check('pending_intent_blocks_normal_work_and_second_operator')
        if point=='worker_created':
            name=cluster.project+f'-executor-{target}-e{r["planned"]["epoch"]}'
            created=op.lookup(cluster,name);flow.require(created is not None,'operator_lost_reply_worker_absent')
            flow.require(r['planned']['hosts'][target]['worker'] is None,'operator_lost_reply_already_recorded')
            lost_worker=created['Id']
        if point=='after_publish':
            current=Cluster(r['planned'])
            try:current.rpc('view')
            except LifecycleError as exc:flow.require('operator_resume_required' in str(exc),'operator_published_pending_wrong_refusal')
            else:raise flow.CheckFailed('operator_published_before_commit_allowed')
            check('new_matching_owner_workers_still_refuse_uncommitted_operator')
        if point=='after_complete':
            current=Cluster(r['planned'])
            if after_complete:after_complete(current)
            else:
                ident=current.d['hosts'][target]['worker']['id']
                command(['docker','exec',ident,'python','-m','scripts.test_executor_transition','fixture-profile'])
            check('fresh_state_written_after_operator_commit_before_final_reply')
        try:
            value=resume()
        except LifecycleError as exc:
            flow.require(str(exc)=='executor_operator_resume_required','operator_resume_wrong_failure_'+str(exc))
            continue
        break
    flow.require(points==list(op.CUTS) and value is not None,'operator_cut_coverage_incomplete')
    cluster.d=value['descriptor']
    flow.require(cluster.d['hosts'][target]['worker']['id']==lost_worker,'operator_lost_reply_worker_recreated')
    check('unrecorded_worker_adopted_by_same_id',worker_id=lost_worker)
    if after_complete is None:
        flow.require(cluster.rpc('view')['result']['operator_post_complete_probe']=='preserve-after-complete','operator_completed_profile_rolled_back')
    again=resume()
    flow.require(again==value,'operator_complete_retry_changed_receipt')
    flow.require(op.lookup(cluster,cluster.project+'-executor-takeover-lock') is None,'operator_actor_not_retired')
    check('completed_actor_reply_and_post_cleanup_retry_are_idempotent',transition_id=identity,actor_id=actor_id)
    return value['receipt']


class OperatorLab(ExecutorLab):
    def prepare(self):
        super().prepare();self.report.update(schema='executor-operator-recovery-1',operator_checks=[])
        self.report['executor_scope']['availability']='explicit restart of the same stopped pinned PID-1 actor and survivor-volume flock; no automatic election, physical-host or power-loss guarantee'
        actual={}
        for label,image in [('graph',self.report['certificate_execution_image_id']),('executor',self.executor_image)]:
            actual[label]=json.loads(command(['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python',image,'-c',
                "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],input=json.dumps(SOURCES)))
            flow.require(actual[label]==IMPORTED,'operator_image_attestation')
        self.report['operator_image_source_sha256']=actual;self.report['source_input_sha256'].update(IMPORTED);self.save()

    def operator_check(self,label,**details):
        self.report['operator_checks'].append({'label':label,'passed':True,**details});self.save()

    def lose_executor(self):
        cluster=self.executors;old=copy.deepcopy(cluster.d);target='b' if old['active']=='a' else 'a'
        for name in ['profile.json','authority-coordinator.json','executor-descriptor.json']:
            self.authority_profile.with_name(name).unlink(missing_ok=True)
        pending=None
        def probe(current):
            nonlocal pending
            self.executors=current;self.backend=Remote(current);self.sync()
            if self.takeovers==2:
                pending=CrashLab.post_open_probe(self,self.post_open_csr)
                flow.require(self.ca_call(pending,endpoint='ca-a')['status']==201,'operator_post_complete_issue')
                self.operator_check('new_token_consumed_after_operator_commit_before_actor_final_resume')
        receipt=exercise(cluster,target,self.operator_check,probe,self.directory)
        self.executors=cluster;self.backend=Remote(cluster);self.sync()
        if pending is not None:
            flow.require(self.ca_call(pending,endpoint='ca-b')['status'] in {400,401,403},'operator_completed_security_write_rolled_back')
            self.operator_check('operator_complete_fast_path_preserves_new_token_consumption')
        for kind in ['journal','owner']:
            flow.require(subprocess.run(['docker','volume','inspect',old['hosts'][old['active']][kind]],capture_output=True,check=False).returncode!=0,
                'operator_old_storage_remains')
        self.check('independent_executor_takeover_after_host_storage_and_console_cache_loss',**receipt)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',nargs='?',choices=['run','spec-check','fixture-profile'],default='run')
    p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/operator-reproduce');args=p.parse_args()
    if args.mode=='fixture-profile':fixture_profile();return
    if not args.directory.resolve().is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('operator_test_directory_scope')
    if args.mode=='spec-check':
        checks=[]
        def check(label,**details):checks.append({'label':label,'passed':True,**details})
        try:spec_check(args.directory,lambda c,t:exercise(c,t,check,directory=args.directory))
        finally:
            (args.directory/'operator-spec-results.json').write_text(json.dumps({'schema':'operator-spec-1','checks':checks},indent=2),encoding='utf-8')
        return
    lab=OperatorLab(args.directory);lab.key_smoke=True
    try:
        lab.prepare();lab.smoke()
        flow.require(all(sha256(ROOT/n)==h for n,h in lab.report['source_input_sha256'].items()),'operator_sources_changed_during_run')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:
        lab.report['finished_at']=flow.timestamp();lab.cleanup()


if __name__=='__main__':main()
