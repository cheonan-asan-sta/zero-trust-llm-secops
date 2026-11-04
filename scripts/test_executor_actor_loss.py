"""Real removed-container recovery; historical actor IDs remain fenced."""

import argparse
import copy
import json
import subprocess
import sys
import uuid
from pathlib import Path

from scripts import executor_transition as op
from scripts import test_signal_compose as flow
from scripts.certificate_controller import LifecycleError, save
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.executor_cluster import Cluster, Remote
from scripts.test_control_transition import CrashLab
from scripts.test_executor_hosts import spec_check
from scripts.test_executor_transition import OperatorLab

SOURCES=['scripts/test_executor_actor_loss.py']
IMPORTED={p:sha256(ROOT/p) for p in SOURCES}


def exercise(cluster,target,check,directory,after_complete=None):
    original=copy.deepcopy(cluster.d);survivor=original['hosts'][target];anchor=cluster.anchor()
    anchor_path=directory/(cluster.project+'-loss-anchor.json');result_path=directory/(cluster.project+'-loss-result.json')
    anchor_path.write_text(json.dumps(anchor),encoding='utf-8');deleted=[];points=[];identity=None;lost_worker=None;value=None
    def invoke(mode='recover',expected=None):
        result_path.unlink(missing_ok=True)
        args=[sys.executable,'-m','scripts.test_executor_actor_loss',mode,'--anchor',str(anchor_path),
            '--site',target,'--journal',survivor['journal'],'--owner',survivor['owner'],'--result',str(result_path)]
        attempt=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=620,check=False)
        if expected is not None:
            flow.require(attempt.returncode!=0 and 'LifecycleError: '+expected in attempt.stderr,'actor_loss_wrong_negative_result');return None
        if attempt.returncode:
            if 'LifecycleError: executor_operator_resume_required' in attempt.stderr:raise LifecycleError('executor_operator_resume_required')
            (directory/'actor-loss-console-failure.private.log').write_text(attempt.stderr,encoding='utf-8')
            raise LifecycleError('actor_loss_fresh_console_failed')
        return json.loads(result_path.read_bytes())
    request={'schema':'executor-operator-request-1','id':uuid.uuid4().hex,'original':original,'target':target,'discard':True}
    cluster.raw(op.actor_args(request,op.CUTS))
    try:invoke('resume')
    except LifecycleError as exc:flow.require(str(exc)=='executor_operator_resume_required','actor_loss_initial_cut_wrong')
    else:raise flow.CheckFailed('actor_loss_initial_cut_missing')
    for index in range(len(op.CUTS)):
        found=op.lookup(cluster,cluster.project+'-executor-takeover-lock')
        flow.require(found is not None and not found['State']['Running'] and found['State']['ExitCode']==73,'actor_loss_not_stopped')
        files=cluster.disk(survivor['journal'],'read');record=op.read_record(files[op.NAME]);point=files[op.FAULTS][record['id']][-1]
        identity=identity or record['id'];flow.require(record['id']==identity and record['actor']['id']==found['Id'],'actor_loss_identity_changed')
        points.append(point)
        if point=='worker_created':
            created=op.lookup(cluster,cluster.project+f'-executor-{target}-e{record["planned"]["epoch"]}')
            flow.require(created is not None and record['planned']['hosts'][target]['worker'] is None,'actor_loss_worker_intent_wrong')
            lost_worker=created['Id']
        if point=='after_complete':
            current=Cluster(record['planned'])
            if after_complete:after_complete(current)
            else:command(['docker','exec',current.d['hosts'][target]['worker']['id'],'python','-m','scripts.test_executor_transition','fixture-profile'])
            check('completed_state_callback_before_actor_removal')
        if index==0:
            cluster.raw(['rename',found['Id'],cluster.project+'-renamed-operator'])
            invoke(expected='executor_actor_predecessor_present')
            cluster.raw(['rename',found['Id'],found['Name'][1:]])
            check('renamed_old_actor_blocks_replacement_even_when_fixed_name_is_empty',actor_id=found['Id'])
        cluster.raw(['rm','--volumes',found['Id']]);deleted.append(found['Id'])
        flow.require(not cluster.raw(['ps','--all','--quiet','--filter','id='+found['Id']]).split(),'actor_loss_delete_unconfirmed')
        check('actual_actor_container_removed',point=point,phase=record['phase'],actor_id=found['Id'],transition_id=identity)
        if index==0:
            invoke('resume',expected='executor_operator_missing')
            prepared=invoke('prepare')
            candidate=op.lookup(cluster,cluster.project+'-executor-takeover-lock')
            flow.require(candidate is not None and candidate['Id']==prepared['created_actor'] and not candidate['State']['Running'],
                'actor_loss_prepared_candidate_missing')
            check('replacement_created_before_identity_ack_is_adopted_by_pinned_spec',actor_id=candidate['Id'])
            mode='resume'
        else:mode='recover'
        try:value=invoke(mode)
        except LifecycleError as exc:
            flow.require(str(exc)=='executor_operator_resume_required','actor_loss_wrong_cut');continue
        break
    flow.require(points==list(op.CUTS) and value is not None,'actor_loss_cut_coverage_incomplete')
    cluster.d=value['descriptor'];record=op.read_record(cluster.disk(survivor['journal'],'read')[op.NAME])
    flow.require(record['schema']=='executor-transition-2' and record['actor']['predecessors']==deleted[:-1], 'actor_loss_lineage_wrong')
    flow.require(record['actor']['id']==deleted[-1] and value['receipt']['operator_actor_id']==deleted[-1],'actor_loss_receipt_actor_wrong')
    flow.require(cluster.d['epoch']==original['epoch']+1 and cluster.d['hosts'][target]['worker']['id']==lost_worker,'actor_loss_epoch_or_worker_regenerated')
    if after_complete is None:
        flow.require(cluster.rpc('view')['result']['operator_post_complete_probe']=='preserve-after-complete','actor_loss_completed_state_rolled_back')
    flow.require(invoke()==value,'actor_loss_complete_retry_changed_result')
    flow.require(op.lookup(cluster,cluster.project+'-executor-takeover-lock') is None,'actor_loss_complete_created_another_actor')
    check('same_operation_and_epoch_complete_with_all_removed_ids_in_lineage',transition_id=identity,removed_actor_ids=deleted,
        predecessors=record['actor']['predecessors'],worker_id=lost_worker)
    return value['receipt']


class LossLab(OperatorLab):
    def prepare(self):
        super().prepare();self.report.update(schema='executor-actor-container-loss-1',actor_loss_checks=[])
        for label,image in [('graph',self.report['certificate_execution_image_id']),('executor',self.executor_image)]:
            actual=json.loads(command(['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python',image,'-c',
                "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],input=json.dumps(SOURCES)))
            flow.require(actual==IMPORTED,'actor_loss_image_source_mismatch')
            self.report.setdefault('actor_loss_image_source_sha256',{})[label]=actual
        self.report['source_input_sha256'].update(IMPORTED);self.save()

    def loss_check(self,label,**details):
        self.report['actor_loss_checks'].append({'label':label,'passed':True,**details});self.save()

    def lose_executor(self):
        cluster=self.executors;old=copy.deepcopy(cluster.d);target='b' if old['active']=='a' else 'a';pending=None
        for name in ['profile.json','authority-coordinator.json','executor-descriptor.json']:
            self.authority_profile.with_name(name).unlink(missing_ok=True)
        def probe(current):
            nonlocal pending
            self.executors=current;self.backend=Remote(current);self.sync()
            if self.takeovers==2:
                pending=CrashLab.post_open_probe(self,self.post_open_csr)
                flow.require(self.ca_call(pending,endpoint='ca-a')['status']==201,'actor_loss_post_complete_issue')
                self.loss_check('fresh_token_consumed_after_commit_before_actor_container_removal')
        receipt=exercise(cluster,target,self.loss_check,self.directory,probe)
        self.executors=cluster;self.backend=Remote(cluster);self.sync()
        if pending is not None:
            flow.require(self.ca_call(pending,endpoint='ca-b')['status'] in {400,401,403},'actor_loss_committed_token_rolled_back')
            self.loss_check('completed_missing_actor_fast_path_preserves_fresh_token_consumption')
        for kind in ['journal','owner']:
            flow.require(subprocess.run(['docker','volume','inspect',old['hosts'][old['active']][kind]],capture_output=True,check=False).returncode!=0,
                'actor_loss_old_storage_remains')
        self.check('independent_executor_takeover_after_host_storage_and_console_cache_loss',**receipt)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',nargs='?',choices=['run','spec-check','recover','prepare','resume'],default='run')
    p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/actor-loss-reproduce');p.add_argument('--anchor',type=Path)
    p.add_argument('--site',choices=['a','b']);p.add_argument('--journal');p.add_argument('--owner');p.add_argument('--result',type=Path)
    args=p.parse_args()
    if args.mode in {'recover','prepare','resume'}:
        anchor=json.loads(args.anchor.read_bytes())
        if args.mode=='resume':value=op.resume_operator(anchor,args.site,args.journal,args.owner)
        else:value=op.recover_operator(anchor,args.site,args.journal,args.owner,cuts=op.CUTS,create_only=args.mode=='prepare')
        save(args.result,value);return
    if not args.directory.resolve().is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('actor_loss_test_directory_scope')
    if args.mode=='spec-check':
        checks=[]
        def check(label,**details):checks.append({'label':label,'passed':True,**details})
        try:spec_check(args.directory,lambda c,t:exercise(c,t,check,args.directory))
        finally:(args.directory/'actor-loss-spec-results.json').write_text(json.dumps({'schema':'actor-loss-spec-1','checks':checks},indent=2),encoding='utf-8')
        return
    lab=LossLab(args.directory);lab.key_smoke=True
    try:
        lab.prepare();lab.smoke()
        flow.require(all(sha256(ROOT/n)==h for n,h in lab.report['source_input_sha256'].items()),'actor_loss_sources_changed')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:lab.report['finished_at']=flow.timestamp();lab.cleanup()


if __name__=='__main__':main()
