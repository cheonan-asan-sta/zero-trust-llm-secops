"""Run one staged package using an already cached Docker image, network none."""

import argparse
import json
import re
import subprocess
import uuid
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha

ROOT=Path(__file__).resolve().parents[1]
IMAGE_MASKS=('/workspace','/usr/local/lib/python3.12/site-packages/app',
    '/usr/local/lib/python3.12/site-packages/zero_trust_llm_secops-0.17.0.dist-info')
BOOTSTRAP="""import importlib.util,json,shutil,subprocess,sys,sysconfig,tarfile
from pathlib import Path
purelib=Path(sysconfig.get_path('purelib'))
assert str(purelib)=='/usr/local/lib/python3.12/site-packages'
masked=[Path('/workspace'),purelib/'app',purelib/'zero_trust_llm_secops-0.17.0.dist-info']
assert all(p.is_dir() and not list(p.iterdir()) for p in masked)
assert all(not list(p.iterdir()) for p in purelib.glob('zero_trust_llm_secops*.dist-info'))
tarfile.open('/inputs/code.tar').extractall('/work',filter='data')
assert importlib.util.find_spec('app').origin.startswith('/work/app/')
assert not Path('/work/docs').exists() and not Path('/work/tests').exists()
Path('/results/image-scope.json').write_text(json.dumps({'completed':True,
 'masked_project_paths':[str(p) for p in masked],'masked_paths_empty':True,
 'code_origin':importlib.util.find_spec('app').origin,'staged_documents_or_tests':False}))
shutil.copytree('/inputs/baseline','/tmp/baseline')
shutil.copytree('/inputs/raw','/tmp/raw')
if PIPELINE=='journal-service':
 args=[sys.executable,'-m','scripts.run_journal_service_review','--plan','/inputs/plan.json',
  '--sha256','PLAN','--journal-catalog','/inputs/journal-catalog.json','--journal-catalog-sha256','JOURNAL',
  '--output','/tmp/prediction-run']
elif PIPELINE in {'apparmor-causal','audit-native-normal','apparmor-status'}:
 args=[sys.executable,'-m','scripts.run_audit_intent_review','--plan','/inputs/plan.json',
  '--sha256','PLAN','--model','/inputs/models/head.json','--model-sha256','HEAD',
  '--output','/tmp/prediction-run',
  '--with-apparmor-status' if PIPELINE=='apparmor-status' else '--with-apparmor-causality',
  *(['--with-network-audit-context'] if NETWORK else [])]
 if PIPELINE=='audit-native-normal':
  args+=['--supplemental-intent-model','/inputs/models/supplemental.json',
   '--supplemental-intent-model-sha256','SUPPLEMENTAL']
else:
 args=[sys.executable,'-m','scripts.run_vpn_protocol_review','--plan','/inputs/plan.json',
 '--sha256','PLAN','--model','/inputs/models/head.json','--model-sha256','HEAD',
 '--legacy-models','/inputs/models/legacy.json','--legacy-models-sha256','LEGACY','--output','/tmp/prediction-run',
 *(['--with-attack-evidence'] if ATTACK else [])]
 if PIPELINE=='vpn-control':
  args+=['--control-model','/inputs/models/control.json','--control-model-sha256','CONTROL']
r=subprocess.run(args,cwd='/work',capture_output=True,text=True)
Path('/results/predict.log').write_text(r.stdout+'\\n'+r.stderr)
if r.returncode==0:shutil.copytree('/tmp/prediction-run','/results/prediction-run')
sys.exit(r.returncode)
"""


def command(args,timeout=1800):
    return subprocess.run(args,capture_output=True,text=True,encoding='utf8',errors='replace',timeout=timeout,check=False)


def run(package,stage_pin,image,*,with_attack_evidence=False,with_network_audit_context=False):
    require(type(with_attack_evidence) is bool,'protocol_attack_option')
    require(type(with_network_audit_context) is bool,'protocol_network_option')
    package=Path(package).resolve();inputs=package/'inputs';results=package/'results'
    require(sha(package/'stage.json')==stage_pin and re.fullmatch(r'sha256:[a-f0-9]{64}',image),'protocol_package_pin')
    stage=decode((package/'stage.json').read_bytes())
    require(stage['completed'] is True and stage['validation_labels_or_aggregates_staged'] is False
        and (stage['frozen_training_parameters_staged'] is True or stage.get('profile')=='journal-service'
             and stage['frozen_training_parameters_staged'] is False),'protocol_package_scope')
    require(not (package/'execution.json').exists() and results.is_dir() and not list(results.iterdir()),
        'protocol_package_already_run')
    require(sha(package/'source-manifest.json')==stage['source_manifest_sha256']
        and sha(inputs/'code.tar')==stage['source_archive_sha256']
        and sha(package/'projection-provenance.json')==stage['projection_provenance_sha256'],'protocol_package_receipt_pin')
    def inventory():
        require(all(not p.is_symlink() for p in inputs.rglob('*')),'protocol_package_symlink')
        return {p.relative_to(inputs).as_posix():sha(p) for p in inputs.rglob('*') if p.is_file()}
    require(inventory()==stage['input_pins'],'protocol_package_inventory')
    inspect=command(['docker','image','inspect',image],30)
    require(inspect.returncode==0 and json.loads(inspect.stdout)[0]['Id']==image,'protocol_image_not_cached')
    profile=stage.get('profile','vpn')
    require(profile in {'vpn','vpn-control','apparmor-causal','audit-native-normal','journal-service','apparmor-status'}
        and (profile in {'vpn','vpn-control'} or not with_attack_evidence),'protocol_execution_profile')
    require(not with_network_audit_context or profile in {'apparmor-causal','audit-native-normal'},'protocol_network_profile')
    extra=stage.get('supplemental_model_sha256')
    control=stage.get('control_model_sha256')
    journal=stage.get('journal_catalog_sha256')
    require(profile!='journal-service' or type(journal) is str and re.fullmatch('[a-f0-9]{64}',journal),'journal_catalog_pin')
    require(profile!='vpn-control' or type(control) is str and re.fullmatch('[a-f0-9]{64}',control),'control_model_pin')
    require(profile!='audit-native-normal' or type(extra) is str and re.fullmatch('[a-f0-9]{64}',extra),
        'protocol_supplemental_model_pin')
    program=BOOTSTRAP.replace('PLAN',stage['plan_sha256']).replace('HEAD',stage['model_sha256'] or '').replace('LEGACY',stage['legacy_models_sha256'] or '').replace('ATTACK',str(with_attack_evidence)).replace('PIPELINE',repr(profile)).replace('NETWORK',str(with_network_audit_context)).replace('SUPPLEMENTAL',extra or '').replace('CONTROL',control or '').replace('JOURNAL',journal or '')
    owner='zt-vpn-protocol-v109-'+uuid.uuid4().hex[:12];cid=None
    report={'completed':False,'stage_sha256':stage_pin,'goal_qualified':False,'new_independent_evaluation':False,
        'aws_calls':0,'paid_api_calls':0,'image':image,'validation_labels_in_predictor':False,
        'frozen_training_parameters_available':stage['frozen_training_parameters_staged']}
    report['with_attack_evidence']=with_attack_evidence
    report['profile']=profile
    report['with_network_audit_context']=with_network_audit_context
    report['supplemental_model_sha256']=extra
    report['control_model_sha256']=control
    report['journal_catalog_sha256']=journal
    try:
        created=command(['docker','create','--pull=never','--name',owner,'--label','secops.f1.owner='+owner,
            '--network','none','--read-only','--user','10001:10001','--cap-drop','ALL',
            '--security-opt','no-new-privileges:true','--memory','2g','--cpus','2','--pids-limit','128',
            '--tmpfs','/work:rw,nosuid,nodev,size=512m,mode=1777','--tmpfs','/tmp:rw,nosuid,nodev,size=1g,mode=1777',
            *[argument for path in IMAGE_MASKS for argument in ('--tmpfs',path+':ro,nosuid,nodev,size=1m,mode=0555')],
            '--mount','type=bind,source='+str(inputs)+',target=/inputs,readonly',
            '--mount','type=bind,source='+str(results)+',target=/results','--workdir','/work',
            '--env','PYTHONDONTWRITEBYTECODE=1','--env','AWS_EC2_METADATA_DISABLED=true',
            '--entrypoint','python',image,'-c',program],60)
        require(created.returncode==0,'protocol_container_create');cid=created.stdout.strip();report['owned_container']=cid
        execution=command(['docker','start','-a',cid]);(package/'container.log').write_text(execution.stdout+'\n'+execution.stderr,encoding='utf8')
        state=json.loads(command(['docker','inspect',cid],30).stdout)[0]
        require(state['Id']==cid and state['Config']['Labels']['secops.f1.owner']==owner,'protocol_container_owner')
        source=decode((package/'source-manifest.json').read_bytes())
        scope=decode((results/'image-scope.json').read_bytes())
        require(scope['completed'] is True and scope['masked_paths_empty'] is True
            and scope['staged_documents_or_tests'] is False
            and set(scope['masked_project_paths'])==set(IMAGE_MASKS),'protocol_image_project_scope')
        report.update(exit_code=execution.returncode,container_exit=state['State']['ExitCode'],oom_killed=state['State']['OOMKilled'],
            network_mode=state['HostConfig']['NetworkMode'],user=state['Config']['User'],read_only_root=state['HostConfig']['ReadonlyRootfs'],
            source_files_unchanged_after=({p.relative_to(ROOT).as_posix():sha(p) for name in ('app','scripts')
                for p in (ROOT/name).rglob('*.py')}=={r['path']:r['sha256'] for r in source}),
            original_inputs_unchanged_after=all(sha(p['path'])==p['sha256'] for p in stage['source_pins']),
            staged_inputs_unchanged_after=inventory()==stage['input_pins'])
        report['image_project_paths_masked']=True
        report['image_scope_sha256']=sha(results/'image-scope.json')
        report['completed']=(execution.returncode==state['State']['ExitCode']==0 and not report['oom_killed']
            and all(report[k] for k in ('source_files_unchanged_after','original_inputs_unchanged_after','staged_inputs_unchanged_after')))
    finally:
        if cid:
            state=json.loads(command(['docker','inspect',cid],30).stdout)[0]
            require(state['Id']==cid and state['Config']['Labels']['secops.f1.owner']==owner and state['Image']==image,
                'protocol_cleanup_owner')
            report['owned_container_removed']=command(['docker','rm','--force',cid],30).returncode==0
        (package/'execution.json').write_bytes(canonical(report)+b'\n')
    require(report['completed'] and report['owned_container_removed'],'protocol_batch_failed');return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('package','stage-sha256','image'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--with-attack-evidence',action='store_true')
    parser.add_argument('--with-network-audit-context',action='store_true')
    a=parser.parse_args();r=run(a.package,a.stage_sha256,a.image,with_attack_evidence=a.with_attack_evidence,
        with_network_audit_context=a.with_network_audit_context)
    print(json.dumps({'completed':r['completed'],'owned_container_removed':r['owned_container_removed'],'goal_qualified':False}));return 0


if __name__=='__main__':raise SystemExit(main())
