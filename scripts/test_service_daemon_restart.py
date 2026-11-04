"""Real C04 CA/PostgreSQL/leaf graph recovery inside an isolated parent daemon."""

import argparse
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from scripts import service_daemon_recovery as recovery
from scripts import test_signal_compose as flow
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT
from scripts.executor_cluster import Remote
from scripts.test_control_transition import CrashLab
from scripts.test_executor_daemon_restart import Lab as Parent
from scripts.test_executor_hosts import ExecutorLab

SOURCES=sorted(p.relative_to(ROOT).as_posix() for folder in ['app','scripts'] for p in (ROOT/folder).rglob('*.py'))


def prepare_parent(parent,lab):
    parent.project=lab.ident;parent.parent=lab.ident+'-parent';parent.volume=parent.parent+'-data'
    parent.report.update(project=lab.ident,schema='service-parent-fixture-1',scope='Real C04 service graph in an isolated child dockerd; Desktop untouched')
    image=lab.recovery_lock['docker_host']['image']
    alias=lab.ident+'-fixture-dind';parent.call(['tag',image,alias])
    tags=[n for n in parent.call(['image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines() if n.startswith(lab.ident+'-')]
    parent.tags=tags
    parent.call(['volume','create','--label','secops.c02='+lab.ident,parent.volume])
    ident=parent.call(['run','--detach','--name',parent.parent,'--privileged','--restart','no','--label','secops.c02='+lab.ident,
        '--env','DOCKER_TLS_CERTDIR=','--publish','127.0.0.1::2375','--mount',f'type=volume,src={parent.volume},dst=/var/lib/docker',
        '--entrypoint','sh',image,'-c','exec sleep infinity'])
    parent.report['parent_id']=ident
    item=json.loads(parent.call(['inspect',ident]))[0];binding=item['NetworkSettings']['Ports']['2375/tcp']
    flow.require(len(binding)==1 and binding[0]['HostIp']=='127.0.0.1','service_fixture_not_loopback')
    parent.inner_env={**parent.outer_env,'DOCKER_HOST':'tcp://127.0.0.1:'+binding[0]['HostPort']}
    for key in ['DOCKER_CONTEXT','DOCKER_CERT_PATH','DOCKER_TLS_VERIFY']:parent.inner_env.pop(key,None)
    parent.report['daemon_id']=parent.start_daemon();parent.save()
    archive=parent.directory/'service-images.private.tar'
    parent.call(['save','--output',str(archive),*tags],timeout=240)
    parent.call(['load','--input',str(archive)],inner=True,timeout=600);archive.unlink()
    lab.recovery_lock=copy.deepcopy(lab.recovery_lock)
    lab.recovery_lock['docker_host']['image']=parent.call(['image','inspect',alias,'--format','{{.Id}}'],inner=True)
    lab.report['isolated_parent']={'id':ident,'daemon_id':parent.report['daemon_id'],'requested_image':image,
        'inner_host_image_id':lab.recovery_lock['docker_host']['image'],'loopback_only':True}
    for image in [lab.image,lab.executor_image,lab.pg_image]:
        # Docker save/load must preserve this profile's pinned executable IDs.
        expected=parent.call(['image','inspect',image,'--format','{{.Id}}'])
        actual=parent.call(['image','inspect',image,'--format','{{.Id}}'],inner=True)
        flow.require(expected==actual,'service_fixture_image_identity_changed')
    return tags


class ServiceLab(ExecutorLab):
    def prepare(self):
        super().prepare();self.report.update(schema='service-daemon-recovery-1',service_checks=[])
        self.report['source_input_sha256'].update({p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in SOURCES})
        self.save()

    def service_check(self,label,**fields):
        self.report['service_checks'].append({'label':label,'passed':True,**fields});self.save()

    def recover_services(self,*,expected=None,cuts=True):
        result=subprocess.run([sys.executable,'-m','scripts.test_service_daemon_restart','recover',
            '--seal',str(self.directory/'services-seal.json'),*(['--no-cuts'] if not cuts else [])],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=940,check=False)
        if result.returncode:(self.directory/'service-console-failure.private.log').write_text(result.stderr,encoding='utf-8')
        if expected:
            flow.require(result.returncode!=0 and expected in result.stderr,'service_fixture_wrong_cut');return None
        if result.returncode:
            raise LifecycleError('service_fixture_recovery_failed')
        return json.loads(result.stdout)

    def service_smoke(self,parent):
        self.backend.leaf('pause',value=True)
        self.wait(lambda:self.backend.leaf('status')['paused'],'services_leaf_pause')
        request=self.current_request();issued=self.ca_call(request,endpoint='ca-a')
        flow.require(issued['status']==201,'services_baseline_issue')
        flow.require(self.ca_call({'serial':issued['serial'],'passive':True},endpoint='ca-a',mode='revoke')['status']==200,'services_baseline_revoke')
        revoked_expiry=self.private_rpc("import json;from pathlib import Path;from scripts.certificate_controller import metadata;print(json.dumps(metadata(Path('/state/ha-revoked.pem').read_text())['not_after']))")
        self.service_check('real_consumed_token_and_revoked_certificate_established_before_parent_fault')
        self.service_csr=self.private_rpc("import json;from pathlib import Path;s=json.loads(Path('/state/state.json').read_bytes());print(json.dumps(next(c['csr'] for c in s['credentials'].values() if c['name']=='collector' and c['purpose']=='clientAuth')))")
        p=self.backend.profile;known={*p['gateways'],p['leaf']['name'],p['management']['standby']['name'],
            *(n['name'] for n in p['service_hosts'].values()),*(h['worker']['name'] for h in self.executors.d['hosts'].values())}
        extras=[]
        for item in json.loads(parent.call(['inspect',*parent.call(['ps','--quiet'],inner=True).split()],inner=True)):
            name=item['Name'][1:]
            if name.startswith(self.ident+'-') and name not in known:extras.append({'name':name,'id':item['Id']})
        seal=recovery.seal_services(self.executors,extras)
        (self.directory/'services-seal.json').write_text(json.dumps(seal),encoding='utf-8')
        self.volumes.append(seal['journal']);self.containers.append(self.ident+'-services-recovery')
        self.report['service_seal_public']={'id':seal['id'],'outer_services':len(seal['outer']),'inner_services':4,
            'primary':seal['primary'],'incarnation':seal['incarnation'],'management_role':seal['management_role']};self.save()
        self.service_check('healthy_graph_and_current_authenticated_checkpoint_sealed_without_private_material',outer_services=len(seal['outer']))
        parent.restart();self.service_check('real_parent_daemon_restart_stops_service_graph',restart=parent.report['restarts'][-1])
        self.recover_services(expected='services_recovery_result_unknown')
        status=recovery.journal(self.executors,seal['journal'],'read')
        flow.require(status['phase']=='hosts','services_first_cut_phase')
        flow.require(not any(recovery.inspect(self.executors,entry['id'])['State']['Running'] for entry in seal['outer'].values() if entry['role']=='gateway'),
            'services_admission_open_during_database_proof')
        self.service_check('recovery_process_death_after_hosts_keeps_admission_closed')
        parent.restart();self.service_check('second_parent_restart_during_recovery_resumes_same_journal',restart=parent.report['restarts'][-1])
        self.recover_services(expected='services_recovery_result_unknown')
        status=recovery.journal(self.executors,seal['journal'],'read');flow.require(status['phase']=='leaf','services_second_cut_phase')
        self.backend=Remote(self.executors);self.sync()
        pending=CrashLab.post_open_probe(self,self.service_csr)
        flow.require(self.ca_call(pending,endpoint='ca-a')['status']==201,'services_fresh_post_open_issue')
        self.service_check('real_new_token_consumed_after_admission_open_before_recovery_reply')
        receipt=self.recover_services()
        flow.require(receipt==self.recover_services() and receipt['cycle']==1,'services_complete_retry_changed')
        claims=pending['ott'].split('.')[1];token_expiry=json.loads(base64.urlsafe_b64decode(claims+'='*(-len(claims)%4)))['exp']
        flow.require(min(token_expiry,revoked_expiry)-time.time()>30,'services_security_fixture_expired')
        flow.require(self.ca_call(pending,endpoint='ca-b')['status'] in {400,401,403},'services_new_token_rolled_back')
        flow.require(self.ca_call(request,endpoint='ca-b')['status'] in {400,401,403},'services_consumed_token_replayed')
        flow.require(self.ca_call({},endpoint='ca-b',mode='renew_revoked')['status'] in {401,403},'services_revocation_rolled_back')
        flow.require(self.ca_call(self.current_request(),endpoint='ca-a')['status']==201,'services_fresh_nonce_failed')
        flow.require(self.backend.leaf('status')['paused'],'services_leaf_intent_changed')
        self.service_check('completed_retry_preserves_new_and_old_consumption_revocation_and_leaf_pause')
        standby='b' if seal['primary']=='a' else 'a'
        host=self.backend.profile['service_hosts'][standby]['id'];database=seal['inner'][standby]['containers']['database']['id']
        self.executors.raw(['exec',host,'docker','stop','--time','2',database])
        try:
            self.recover_services(expected='services_live_inner_outage_requires_quiescence',cuts=False)
            item=json.loads(self.executors.raw(['exec',host,'docker','inspect',database]))[0]
            flow.require(not item['State']['Running'],'services_completed_retry_started_partial_database')
        finally:self.executors.raw(['exec',host,'docker','start',database])
        flow.require(self.recover_services(cuts=False)==receipt,'services_partial_outage_changed_receipt')
        self.service_check('completed_retry_refuses_new_inner_database_outage_without_start_or_state_reset')
        parent.restart();receipt2=self.recover_services(cuts=False)
        flow.require(receipt2['cycle']==2 and receipt2['services']==receipt['services'],'services_next_restart_recreated_objects')
        self.backend=Remote(self.executors);self.sync()
        flow.require(self.ca_call(pending,endpoint='ca-b')['status'] in {400,401,403},'services_second_cycle_token_rolled_back')
        flow.require(self.ca_call(self.current_request(),endpoint='ca-a')['status']==201,'services_second_cycle_fresh_nonce_failed')
        flow.require(self.executors.role()['epoch']==seal['descriptor']['epoch'] and self.backend.role()==seal['management_role'],'services_recovery_changed_role')
        self.service_check('subsequent_daemon_restart_uses_new_cycle_same_ids_and_roles',cycle=receipt2['cycle'])
        self.report['service_recovery_receipts']=[receipt,receipt2]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',nargs='?',choices=['run','recover'],default='run')
    p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/service-daemon-reproduce');p.add_argument('--seal',type=Path)
    p.add_argument('--no-cuts',action='store_true',help='Use the ordinary actor for a subsequent recovery cycle')
    args=p.parse_args()
    if args.mode=='recover':
        print(json.dumps(recovery.recover_services(json.loads(args.seal.read_bytes()),test_cuts=() if args.no_cuts else ('after_hosts','after_leaf'))));return
    directory=args.directory.resolve()
    if not directory.is_relative_to((ROOT/'runtime/c02').resolve()):raise LifecycleError('service_fixture_directory_scope')
    lab=ServiceLab(directory);lab.key_smoke=True;parent=Parent(directory/'parent');prepared=False;inner=False;original=dict(os.environ)
    try:
        lab.prepare();prepare_parent(parent,lab);prepared=True
        os.environ.clear();os.environ.update(parent.inner_env);inner=True
        lab.smoke();lab.service_smoke(parent)
        flow.require(all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in lab.report['source_input_sha256'].items()),'service_fixture_sources_changed')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:
        lab.report['finished_at']=flow.timestamp()
        try:
            if inner:lab.cleanup()
        finally:
            os.environ.clear();os.environ.update(original)
            if prepared or parent.tags:parent.cleanup()
            lab.report['parent_cleanup']=parent.report.get('cleanup');lab.save()


if __name__=='__main__':main()
