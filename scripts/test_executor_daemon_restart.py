"""Restart only an isolated nested dockerd, keeping its supervisor and data root.

Never restart the user's Docker Desktop. No AWS, paid models or real CA calls.
The durable post-completion security marker is synthetic public fixture data.
"""

import argparse
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from scripts import executor_transition as op
from scripts import test_signal_compose as flow
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT
from scripts.control_store import COMPONENTS
from scripts.executor_cluster import Cluster
from scripts.test_executor_hosts import build_executor

SOURCES=sorted(p.relative_to(ROOT).as_posix() for folder in ['app','scripts'] for p in (ROOT/folder).rglob('*.py'))


class Lab:
    def __init__(self,directory):
        self.directory=directory;directory.mkdir(parents=True,exist_ok=True)
        self.project='c02-'+uuid.uuid4().hex[:12];self.parent=self.project+'-parent';self.volume=self.parent+'-data'
        self.outer_env=dict(os.environ);self.inner_env=None;self.tags=[]
        self.report={'schema':'executor-daemon-restart-1','project':self.project,'started_at':flow.timestamp(),
            'completed':False,'checks':[],'restarts':[],'source_input_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES},
            'scope':'Isolated real parent dockerd process restart, persistent Docker data root and same supervisor. Synthetic public security marker; not a new CA issuance/replication campaign.'}
        self.save()

    def save(self):
        (self.directory/'summary.json').write_text(json.dumps(self.report,indent=2),encoding='utf-8')

    def check(self,label,**details):
        self.report['checks'].append({'label':label,'passed':True,**details});self.save()

    def call(self,args,*,inner=False,input=None,timeout=90):
        result=subprocess.run(['docker',*args],env=self.inner_env if inner else self.outer_env,input=input,
            capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout,check=False)
        if result.returncode:
            (self.directory/'command-failure.private.log').write_text(result.stderr,encoding='utf-8')
            raise LifecycleError('daemon_lab_docker_command_failed')
        return result.stdout.strip()

    def start_daemon(self,live=False):
        script='exec dockerd-entrypoint.sh dockerd --storage-driver=overlay2 --host=unix:///var/run/docker.sock --host=tcp://0.0.0.0:2375 --tls=false --pidfile=/tmp/lab-docker.pid --live-restore='+str(live).lower()+' >/tmp/lab-daemon.log 2>&1'
        self.call(['exec','--detach',self.parent,'sh','-c',script])
        end=time.monotonic()+70
        while time.monotonic()<end:
            result=subprocess.run(['docker','info','--format','{{.ID}}'],env=self.inner_env,capture_output=True,text=True,timeout=5,check=False)
            if result.returncode==0:return result.stdout.strip()
            time.sleep(.3)
        raise LifecycleError('daemon_lab_not_ready')

    def restart(self,live=False):
        before=self.call(['exec',self.parent,'cat','/tmp/lab-docker.pid'])
        parent=json.loads(self.call(['inspect',self.parent]))[0]
        # Verify the exact owned supervisor before signalling its own child daemon.
        flow.require(parent['Id']==self.report['parent_id'] and parent['Config']['Labels'].get('secops.c02')==self.project,'daemon_lab_parent_identity')
        self.call(['exec',self.parent,'sh','-c','kill -TERM "$(cat /tmp/lab-docker.pid)"'])
        end=time.monotonic()+65
        while self.call(['exec',self.parent,'sh','-c','if test -e /tmp/lab-docker.pid; then echo waiting; fi']):
            flow.require(time.monotonic()<end,'daemon_lab_shutdown_timeout');time.sleep(.3)
        ident=self.start_daemon(live)
        after=self.call(['exec',self.parent,'cat','/tmp/lab-docker.pid'])
        current=json.loads(self.call(['inspect',self.parent]))[0]
        flow.require(ident==self.report['daemon_id'] and before!=after and current['State']['Pid']==parent['State']['Pid'],
            'daemon_lab_restart_identity_wrong')
        self.report['restarts'].append({'old_pid':int(before),'new_pid':int(after),'daemon_id':ident,'same_supervisor_pid':True,'next_live_restore':live})
        self.save()

    def prepare(self):
        graph=self.project+'-app';self.tags.append(graph)
        result=subprocess.run(['docker','build','--tag',graph,'.'],env=self.outer_env,capture_output=True,timeout=300,check=False)
        (self.directory/'app-build.private.log').write_bytes(result.stdout+result.stderr)
        flow.require(result.returncode==0,'daemon_lab_build')
        tag,executor=build_executor(self.project,self.call(['image','inspect',graph,'--format','{{.Id}}']),self.directory);self.tags.append(tag)
        graph_id=self.call(['image','inspect',graph,'--format','{{.Id}}'])
        image=json.loads((ROOT/'infra/mtls/ca-recovery-tools.lock.json').read_bytes())['docker_host']['image']
        self.call(['volume','create','--label','secops.c02='+self.project,self.volume])
        ident=self.call(['run','--detach','--name',self.parent,'--privileged','--restart','no','--label','secops.c02='+self.project,
            '--env','DOCKER_TLS_CERTDIR=','--publish','127.0.0.1::2375','--mount',f'type=volume,src={self.volume},dst=/var/lib/docker',
            '--entrypoint','sh',image,'-c','exec sleep infinity'])
        self.report['parent_id']=ident
        bindings=json.loads(self.call(['inspect',self.parent]))[0]['NetworkSettings']['Ports']['2375/tcp']
        flow.require(len(bindings)==1 and bindings[0]['HostIp']=='127.0.0.1','daemon_lab_endpoint_not_loopback')
        self.inner_env={**self.outer_env,'DOCKER_HOST':'tcp://127.0.0.1:'+bindings[0]['HostPort']}
        for name in ['DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH']:self.inner_env.pop(name,None)
        self.report['daemon_id']=self.start_daemon();self.save()
        archive=self.directory/'images.private.tar'
        self.call(['save','--output',str(archive),graph,tag],timeout=240)
        self.call(['load','--input',str(archive)],inner=True,timeout=600)
        archive.unlink()
        self.report['outer_image_ids']={'graph':graph_id,'executor':executor}
        self.report.update(graph_image_id=self.call(['image','inspect',graph,'--format','{{.Id}}'],inner=True),
            executor_image_id=self.call(['image','inspect',tag,'--format','{{.Id}}'],inner=True))
        for key in ['graph_image_id','executor_image_id']:
            program="import hashlib,json,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"
            actual=json.loads(self.call(['run','--rm','-i','--network','none','--read-only','--entrypoint','python',self.report[key],'-c',program],
                inner=True,input=json.dumps(SOURCES)))
            flow.require(actual==self.report['source_input_sha256'],'daemon_lab_source_mismatch')
        self.save();self.check('isolated_daemon_loopback_and_both_image_sources_verified')

    def child(self,args,expected=None,timeout=620):
        result=subprocess.run([sys.executable,*args],env=self.inner_env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout,check=False)
        if expected:
            if result.returncode==0 or expected not in result.stderr:
                (self.directory/'negative-failure.private.log').write_text(result.stdout+'\n'+result.stderr,encoding='utf-8')
                codes=re.findall(r'LifecycleError: ([a-z0-9_]+)',result.stderr)
                raise LifecycleError('daemon_lab_wrong_refusal_'+(codes[-1] if codes else str(result.returncode)))
            return None
        if result.returncode:
            (self.directory/'console-failure.private.log').write_text(result.stderr,encoding='utf-8')
            raise LifecycleError('daemon_lab_console_failed')
        return json.loads(result.stdout)

    def recover(self,expected=None):
        return self.child(self.recovery_args(),expected)

    def recovery_args(self):
        s=self.survivor
        return ['-m','scripts.executor_cluster','recover-daemon','--anchor',str(self.directory/'anchor.json'),
            '--daemon-seal',str(self.directory/'seal.json'),'--site',self.target,'--journal',s['journal'],'--owner',s['owner'],
            '--descriptor',str(self.directory/'recovered.json')]

    def start_console(self):
        self.console_log=(self.directory/'recovery-console.private.log').open('ab')
        self.console=subprocess.Popen([sys.executable,*self.recovery_args()],env=self.inner_env,
            stdout=self.console_log,stderr=self.console_log)

    def finish_console(self):
        if hasattr(self,'console'):
            code=self.console.wait(timeout=60);self.console_log.close();del self.console
            flow.require(code!=0,'daemon_lab_interrupted_console_falsely_succeeded')

    def actor(self,cuts):
        old=copy.deepcopy(self.cluster.d);self.target='b' if old['active']=='a' else 'a';self.survivor=old['hosts'][self.target]
        self.request={'schema':'executor-operator-request-1','id':uuid.uuid4().hex,'original':old,'target':self.target,'discard':True}
        args=op.actor_args(self.request,cuts,wait=True)
        self.actor_id=self.call(args,inner=True);self.call(['start',self.actor_id],inner=True)

    def checkpoint(self,point):
        end=time.monotonic()+180
        while time.monotonic()<end:
            files=self.cluster.disk(self.survivor['journal'],'read')
            if point in files.get(op.FAULTS,{}).get(self.request['id'],[]):
                r=op.read_record(files[op.NAME]);found=op.lookup(self.cluster,r['actor']['name'])
                flow.require(found['Id']==self.actor_id and found['State']['Running'],'daemon_lab_actor_not_actually_running')
                return r
            time.sleep(.3)
        raise LifecycleError('daemon_lab_checkpoint_timeout')

    def run_inner(self):
        project=self.project;graph=self.report['graph_image_id']
        profile={'project':project,'image':graph,'ca':{'name':project+'-ca'},'leaf':{'name':project+'-leaf','id':'c'*64},'volumes':{},
            'service_hosts':{s:{'name':project+'-host-'+s,'id':s*64,'image':graph} for s in ['a','b']},
            'management':{'active':'a','epoch':1,'cells':{s:{'generation':1,'volumes':{k:project+'-mgmt-'+s+'-'+k.replace('_','-') for k in COMPONENTS}} for s in ['a','b']}}}
        self.cluster=Cluster.bootstrap(profile,self.report['executor_image_id'],adopt=False)
        (self.directory/'initial.json').write_text(json.dumps(self.cluster.d),encoding='utf-8')
        (self.directory/'anchor.json').write_text(json.dumps(self.cluster.anchor()),encoding='utf-8')
        self.child(['-m','scripts.executor_cluster','seal-daemon','--descriptor',str(self.directory/'initial.json'),
            '--daemon-seal',str(self.directory/'seal.json')])
        if getattr(self,'live_only',False):
            self.cluster.takeover('b',discard=True)
            self.exercise_live_restore()
            self.report['completed']=True;self.report['final_role']=self.cluster.role();self.save();return
        self.actor(op.CUTS);identity=self.request['id'];initial_epoch=self.cluster.d['epoch']
        for point in op.CUTS:
            r=self.checkpoint(point)
            if point=='worker_created':
                pending=op.lookup(self.cluster,project+f'-executor-{self.target}-e{r["planned"]["epoch"]}');reserved=pending['Id']
            if point=='after_complete':
                current=Cluster(r['planned']);worker=current.d['hosts'][self.target]['worker']['id']
                self.call(['exec',worker,'python','-m','scripts.test_executor_transition','fixture-profile'],inner=True)
            self.restart()
            self.finish_console()
            self.check('real_parent_dockerd_restart_at_live_actor_checkpoint',point=point,actor_id=self.actor_id,transition_id=identity,phase=r['phase'])
            if point!='after_complete':
                # Start without attach so the next test-only hold remains running.
                self.start_console()
            else:
                self.recover();self.cluster=Cluster(json.loads((self.directory/'recovered.json').read_bytes()))
        flow.require(self.cluster.d['epoch']==initial_epoch+1 and self.cluster.d['hosts'][self.target]['worker']['id']==reserved,
            'daemon_lab_epoch_or_worker_changed')
        self.check('same_actor_operation_epoch_and_unacknowledged_worker_id_preserved',transition_id=identity,actor_id=self.actor_id,worker_id=reserved)
        self.assert_marker()
        receipt=self.recover();self.restart();self.recover();self.assert_marker()
        self.check('completed_missing_actor_restores_only_pinned_workers_without_recopy')
        passive='b' if self.cluster.d['active']=='a' else 'a'
        paused=self.cluster.d['hosts'][passive]['worker']['id'];active=self.cluster.d['hosts'][self.cluster.d['active']]['worker']['id']
        self.call(['pause',paused],inner=True);self.call(['stop','--time','1',active],inner=True)
        self.recover('executor_daemon_process_not_quiescent')
        flow.require(not self.cluster.inspect_worker(self.cluster.d['active'])['State']['Running'],'daemon_lab_started_peer_before_paused_check')
        self.call(['unpause',paused],inner=True);self.recover();self.assert_marker()
        self.check('paused_running_worker_blocks_peer_start_before_any_recovery_start')
        self.restart();self.call(['start',self.cluster.d['hosts']['a']['worker']['id']],inner=True)
        flow.require(self.recover()==receipt,'daemon_lab_completed_receipt_changed');self.assert_marker()
        self.check('partial_worker_restart_reply_loss_is_idempotent')
        self.exercise_live_restore()
        self.report['final_role']=self.cluster.role()
        self.report['completed']=True;self.save()

    def exercise_live_restore(self):
        # live-restore is deliberately different: leave the actual actor alive.
        self.target=self.cluster.d['active'];self.survivor=copy.deepcopy(self.cluster.d['hosts'][self.target])
        self.restart(live=True)
        # The previous daemon had live-restore disabled, so that configuration
        # change stopped the completed workers. Restore them before the live test.
        self.recover()
        self.actor(('after_intent',));self.checkpoint('after_intent');self.restart(live=True)
        found=op.lookup(self.cluster,self.project+'-executor-takeover-lock')
        flow.require(found['State']['Running'] and all(self.cluster.inspect_worker(s)['State']['Running'] for s in ['a','b']),
            'daemon_lab_live_restore_did_not_preserve_processes')
        self.recover('executor_daemon_process_not_quiescent')
        self.check('live_restored_actor_refused_without_automatic_kill')
        self.call(['stop','--time','1',self.actor_id],inner=True)
        self.recover('executor_daemon_process_not_quiescent')
        self.check('live_restored_workers_refused_until_explicit_test_fencing')
        for host in self.cluster.d['hosts'].values():self.call(['stop','--time','1',host['worker']['id']],inner=True)
        self.recover();self.cluster=Cluster(json.loads((self.directory/'recovered.json').read_bytes()))
        self.check('explicitly_quiesced_live_restore_case_resumes_same_operation',transition_id=self.request['id'])

    def assert_marker(self):
        flow.require(self.cluster.rpc('view')['result']['operator_post_complete_probe']=='preserve-after-complete','daemon_lab_security_marker_rolled_back')
        ident=self.cluster.rpc('raw',(['info','--format','{{.ID}}'],))['result'].strip()
        flow.require(ident==self.report['daemon_id'],'daemon_lab_worker_socket_not_reconnected')

    def cleanup(self):
        # Only this generated parent and its named Docker data volume exist outside.
        found=subprocess.run(['docker','inspect',self.parent],env=self.outer_env,capture_output=True,text=True,check=False)
        if found.returncode==0:
            item=json.loads(found.stdout)[0]
            flow.require(item['Config']['Labels'].get('secops.c02')==self.project,'daemon_lab_cleanup_scope')
            self.call(['rm','--force','--volumes',item['Id']])
        for name in [self.volume]:
            found=subprocess.run(['docker','volume','inspect',name],env=self.outer_env,capture_output=True,text=True,check=False)
            if found.returncode==0:self.call(['volume','rm',name])
        for tag in self.tags:self.call(['image','rm',tag])
        inventory={}
        for kind,args in [('containers',['ps','--all','--format','{{.Names}}']),('volumes',['volume','ls','--format','{{.Name}}']),
            ('networks',['network','ls','--format','{{.Name}}']),('image_tags',['image','ls','--format','{{.Repository}}:{{.Tag}}'])]:
            inventory[kind]=[n for n in self.call(args).splitlines() if n.startswith(self.project+'-')]
        self.report['cleanup']=inventory;self.report['finished_at']=flow.timestamp();self.save()
        flow.require(not any(inventory.values()),'daemon_lab_cleanup_incomplete')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/daemon-reproduce')
    p.add_argument('--live-only',action='store_true',help='Narrow live-restore diagnostic, excluded from full campaign totals')
    args=p.parse_args();directory=args.directory.resolve()
    if not directory.is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('daemon_lab_directory_scope')
    lab=Lab(directory);lab.live_only=args.live_only;lab.report['live_only']=args.live_only
    try:
        lab.prepare()
        original=dict(os.environ)
        try:
            os.environ.clear();os.environ.update(lab.inner_env);lab.run_inner()
        finally:os.environ.clear();os.environ.update(original)
        flow.require(all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==h for p,h in lab.report['source_input_sha256'].items()),'daemon_lab_source_changed')
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['completed']=False;lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:lab.cleanup()


if __name__=='__main__':main()
