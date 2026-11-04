"""Local management-cell loss, standby takeover and authority continuation."""

import argparse
import base64
import copy
import json
import subprocess
import time
from pathlib import Path

from scripts import test_signal_compose as flow
from scripts.authority_rotation_coordinator import Coordinator
from scripts.certificate_controller import LifecycleError
from scripts.compare_pep import ROOT, command
from scripts.compare_supply_chain import sha256
from scripts.control_plane_ha import Management
from scripts.test_authority_key_rotation import AuthorityLab
from scripts.test_ca_host_recovery import RecoveryLab

SOURCES=['scripts/control_transition.py','scripts/control_mirror.py','scripts/control_store.py','scripts/control_plane_ha.py','scripts/test_control_plane_ha.py']
IMPORTED={p:sha256(ROOT/p) for p in SOURCES}


class ControlLab(RecoveryLab):
    def prepare(self):
        super().prepare()
        actual=json.loads(command(['docker','run','--rm','-i','--network','none','--read-only','--entrypoint','python',self.image,'-c',
            "import json,hashlib,sys;from pathlib import Path;print(json.dumps({p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in json.load(sys.stdin)}))"],input=json.dumps(SOURCES)))
        flow.require(actual==IMPORTED,'control_image_attestation')
        self.report.update(schema='control-plane-ha-1',control_image_source_sha256=actual,control_checks=[])
        self.report['source_input_sha256'].update(IMPORTED)
        self.save()

    def add(self,label,**details):
        self.report['control_checks'].append({'label':label,'passed':True,**details});self.save()

    def sync(self):
        p=self.backend.profile;v=self.backend.volumes()
        self.controller=p['leaf']['name'];self.controller_volume=v['leaf'];self.vault=v['vault'];self.ca_volume=v['ca']
        self.witness_volume=v['witness'];self.reader_volume=v['reader'];self.gateway_names=p['gateways']
        self.controller_mounts=[*p['management']['workload_mounts'],f"type=volume,src={v['renewal']},dst=/managed/renewal"]
        self.authority_profile.write_text(json.dumps(p),encoding='utf-8')

    def authority_tick(self):
        result=super().authority_tick()
        flow.require(not result.get('error'),'control_tick_'+str(result.get('error')))
        return result

    def raw_file(self,volume,name,value):
        program="""import json,sys
from pathlib import Path
from scripts.certificate_controller import replace_file
p=json.load(sys.stdin);f=Path('/data')/p['name'];assert f.name==p['name']
if p['value'] is None:f.unlink()
else:replace_file(f,json.dumps(p['value']))
print('{}')"""
        return self.backend.raw(['run','--rm','-i','--network','none','--read-only','--user','10001:10001','--mount',
            f'type=volume,src={volume},dst=/data','--entrypoint','python',self.backend.profile['image'],'-c',program],{'name':name,'value':value})

    def expected_rejection(self,callback,label):
        ids=[self.backend.profile['leaf']['id'],*self.backend.profile['gateway_ids']]
        try:callback()
        except LifecycleError as exc:
            flow.require(ids==[self.backend.profile['leaf']['id'],*self.backend.profile['gateway_ids']],'control_rejection_changed_identity')
            self.add(label,reason=str(exc))
        else:raise flow.CheckFailed('control_expected_rejection_'+label)

    def retire(self,volumes):
        current={v for c in self.backend.profile['management']['cells'].values() for v in c['volumes'].values()}
        flow.require(not current.intersection(volumes.values()),'control_retired_still_active')
        for name in volumes.values():
            command(['docker','volume','rm',name])
            if name in self.volumes:self.volumes.remove(name)
        self.add('retired_management_storage_removed_after_fencing_'+self.backend.active,count=len(volumes))

    def init_authority(self):
        providers=super().init_authority()
        mounts=json.loads(command(['docker','inspect',self.controller]))[0]['Mounts']
        workload=[f"type=volume,src={m['Name']},dst={m['Destination']}"+(',readonly' if not m['RW'] else '')
            for m in mounts if m['Destination'].startswith(('/managed/','/ack/')) and m['Destination']!='/managed/renewal']
        self.backend=Management.bootstrap(self.backend.profile,self.reader_volume,workload);self.sync()
        self.add('independent_management_volume_sets',cells={k:v['volumes'] for k,v in self.backend.profile['management']['cells'].items()})
        self.add('active_publisher_and_read_only_standby',active=self.backend.profile['leaf'],standby=self.backend.profile['management']['standby'])
        old=copy.deepcopy(self.backend.profile)
        role=self.backend.role();bad=role|{'epoch':role['epoch']+1}
        self.raw_file(self.backend.volumes(self.backend.peer)['control'],'role.json',bad)
        self.expected_rejection(lambda:self.backend.promote('b','a'),'mismatched_candidate_role_refuses_takeover')
        self.raw_file(self.backend.volumes(self.backend.peer)['control'],'role.json',role)
        self.backend.raw(['start',self.backend.profile['leaf']['name']])
        self.backend._operation(True)
        self.expected_rejection(lambda:self.backend.promote('b','a'),'unfinished_management_operation_refuses_takeover')
        self.backend._operation(False)
        state=self.drive_until(lambda s:s['phase']=='prepared','control_prepared',timeout=360)
        plan_hash=state['plan']['root_public_key_sha256']
        self.add('authority_candidate_keys_and_plan_replicated_before_install',root_public_key_sha256=plan_hash)
        self.backend.container(self.backend.profile['leaf'],stop=True)
        self.raw_file(self.backend.volumes()['control'],'role.json',None)
        self.raw_file(self.backend.volumes()['ca'],'ca.json',None)
        started=time.monotonic();receipt=self.backend.promote('b','a');self.sync()
        flow.require(receipt['coordinator_phase']=='prepared','control_prepared_phase_lost')
        self.add('lost_active_management_role_and_publisher_taken_over',elapsed_seconds=round(time.monotonic()-started,3),**receipt)
        self.retire(receipt['retired_volumes'])
        self.authority_profile.with_name('authority-coordinator.json').unlink()
        recovered=Coordinator(self.backend.profile,self.authority_profile.parent).state
        flow.require(recovered['phase']=='prepared' and recovered['plan']['root_public_key_sha256']==plan_hash,'control_candidate_changed')
        self.add('coordinator_cache_loss_recovers_same_private_candidate_and_plan')
        stale=Management(old)
        self.expected_rejection(lambda:stale.guard(),'stale_original_controller_profile_cannot_mutate')
        return providers

    def smoke(self):
        AuthorityLab.smoke(self)
        state=self.backend.load_control();flow.require(state['epoch']==1 and state['phase']=='idle','control_rotation_not_complete')
        flow.require(state['history'][0]['evidence']['old_jwks']['total_denied']==132,'control_old_jwk_coverage')
        self.add('authority_rotation_completed_from_replicated_prepared_checkpoint',old_jwk_denials=132)
        uid=next(uid for uid,c in self.status()['credentials'].items() if c['name']=='collector')
        flow.require(self.rpc({'operation':'renew_attempt','id':uid})['allowed'],'control_renewal_after_takeover')
        self.add('mtls_renewal_after_first_management_takeover')
        backup=self.backend.backup('backup-control-current.sealed','a')
        self.add('encrypted_backup_and_separate_backup_key_replicated',**backup)
        request=self.current_request();issued=self.ca_call(request,endpoint='ca-a')
        flow.require(issued['status']==201,'control_token_issue')
        flow.require(self.ca_call({'serial':issued['serial'],'passive':True},endpoint='ca-a',mode='revoke')['status']==200,'control_revoke')
        claims=request['ott'].split('.')[1]
        token_expiry=json.loads(base64.urlsafe_b64decode(claims+'='*(-len(claims)%4)))['exp']
        revoked_expiry=self.private_rpc("import json;from pathlib import Path;from scripts.certificate_controller import metadata;print(json.dumps(metadata(Path('/state/ha-revoked.pem').read_text())['not_after']))")
        self.add('post_backup_token_consumption_and_revocation_established',serial=issued['serial'])
        self.backend.leaf('pause',value=True)
        self.wait(lambda:self.backend.leaf('status')['paused'],'control_second_pause')
        before=self.backend.profile['management']['epoch']
        self.backend.container(self.backend.profile['leaf'],stop=True)
        receipt=self.backend.promote('a','a');self.sync()
        flow.require(receipt['management_epoch']==before+1,'control_management_epoch_not_advanced')
        self.add('second_management_cell_loss_uses_independent_surviving_copy',**receipt)
        self.retire(receipt['retired_volumes'])
        self.authority_profile.with_name('authority-coordinator.json').unlink()
        control=Coordinator(self.backend.profile,self.authority_profile.parent).state
        flow.require(control['epoch']==1 and control['phase']=='idle','control_committed_epoch_rollback')
        self.add('committed_authority_epoch_survives_cache_and_cell_loss')
        now=time.time()
        flow.require(min(token_expiry,revoked_expiry)-now>30,'control_security_fixture_expired')
        self.add('consumed_token_and_revoked_certificate_still_unexpired',remaining_token_seconds=round(token_expiry-now,3),
            remaining_certificate_seconds=round(revoked_expiry-now,3))
        flow.require(self.ca_call(request,endpoint='ca-b')['status'] in {400,401,403},'control_replay_after_loss')
        flow.require(self.ca_call({},endpoint='ca-b',mode='renew_revoked')['status'] in {401,403},'control_revocation_after_loss')
        self.add('consumed_token_and_revoked_certificate_remain_denied')
        flow.require(self.ca_call(self.current_request(),endpoint='ca-a')['status']==201,'control_fresh_nonce_after_loss')
        self.add('new_nonce_works_after_both_separate_management_losses')
        verify=self.backend.restore_check('backup-control-current.sealed','a')
        self.add('surviving_backup_key_and_archive_authenticate_with_latest_security_state',**verify)
        self.backend.witness('unfreeze')
        self.report['final_management_role']=self.backend.role();self.report['authority_history']=control['history']

    def cleanup(self):
        if isinstance(getattr(self,'backend',None),Management):
            self.backend.profile['additional_volumes']=[n for n in self.backend.profile.get('additional_volumes',[])
                if subprocess.run(['docker','volume','inspect',n],capture_output=True,check=False).returncode==0]
            for name in self.backend.profile.get('additional_containers',[]):
                if name not in self.containers:self.containers.append(name)
            for collection,args in [(self.containers,['inspect']),(self.volumes,['volume','inspect'])]:
                for name in list(collection):
                    if name.startswith(self.ident+'-') and subprocess.run(['docker',*args,name],capture_output=True,check=False).returncode:
                        collection.remove(name)
        super().cleanup()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--directory',type=Path,default=ROOT/'runtime/c02/c04/control-reproduce');args=p.parse_args()
    lab=ControlLab(args.directory);lab.key_smoke=True
    try:
        lab.prepare();lab.smoke()
        flow.require(all(sha256(ROOT/n)==h for n,h in lab.report['source_input_sha256'].items()),'control_source_changed_during_run')
        lab.report['completed']=True
    except (OSError,ValueError,KeyError,TypeError,StopIteration,subprocess.SubprocessError,flow.CheckFailed) as exc:
        lab.report['failure']=str(exc) if isinstance(exc,(ValueError,flow.CheckFailed)) else type(exc).__name__
        raise SystemExit(lab.report['failure']) from None
    finally:
        lab.report['finished_at']=flow.timestamp();lab.cleanup()


if __name__=='__main__':main()
