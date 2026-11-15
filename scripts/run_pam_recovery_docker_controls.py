"""Run six owned, local Docker PAM recovery controls without API calls.

Requires an approved frozen source tar and a cached Python3.12 test image with
repository test dependencies. Uses only uniquely labelled containers/volume.
Fixture observations are functional controls, never independent threat labels.
"""

import argparse
import hashlib
import json
import re
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path


def require(condition, message='pam_recovery_control_failed'):
    if not condition:
        raise ValueError(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--image-id', required=True, help='Cached local sha256 image ID; no pull/install')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    source, pin, image, out = args.source_archive, args.source_sha256, args.image_id, args.output
    require(re.fullmatch('[a-f0-9]{64}', pin) and re.fullmatch('sha256:[a-f0-9]{64}', image), 'pam_recovery_control_failed')
    require(source.is_absolute() and source.is_file() and not source.is_symlink(), 'pam_recovery_control_failed')
    require(source.stat().st_size <= 512*1024**2 and out.is_absolute(), 'pam_recovery_control_failed')
    require(hashlib.sha256(source.read_bytes()).hexdigest() == pin, 'pam_recovery_control_failed')
    out.mkdir(parents=True, exist_ok=False)
    owner = 'zt-pam-recovery-v99-'+uuid.uuid4().hex[:12]
    volume = owner+'-state'
    label = 'secops.pam.recovery.owner'
    created = []
    volume_created = False
    report = {'completed': False, 'source_archive_sha256': pin, 'owner': owner,
        'started_at': datetime.now(UTC).isoformat(), 'cases': [],
        'aws_calls': 0, 'paid_api_calls': 0, 'goal_qualified': False,
        'journal_source': 'synthetic functional fixture, not new independent performance data',
        'image_id': image}
    
    
    def run(args, timeout=120):
        return subprocess.run(args, capture_output=True, text=True, encoding='utf8', errors='replace', timeout=timeout, check=False)
    
    
    def save():
        (out/'run.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    
    
    def inspect(kind, name):
        r = run(['docker', kind, 'inspect', name] if kind == 'volume' else ['docker', 'inspect', name])
        require(r.returncode == 0, r.stderr)
        return json.loads(r.stdout)[0]
    
    
    def check(name, condition=True):
        require(condition, name)
        report['cases'].append(name)
        save()
    
    
    prefix = """import hashlib,tarfile
from pathlib import Path
assert hashlib.sha256(Path('/source/source.tar').read_bytes()).hexdigest()=='SOURCE_PIN'
tarfile.open('/source/source.tar').extractall('/work',filter='data')
import os,sys
os.chdir('/work');sys.path.insert(0,'/work');sys.dont_write_bytecode=True
""".replace('SOURCE_PIN', pin)
    
    
    def process(role, program, *, readonly=False, root_init=False):
        args = ['docker', 'create', '--name', owner+'-'+role, '--label', label+'='+owner,
            '--network', 'none', '--read-only', '--user', '0:0' if root_init else '10001:10001',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '512m',
            '--cpus', '1', '--pids-limit', '64', '--tmpfs', '/work:rw,nosuid,nodev,size=128m,mode=1777',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
            '--mount', 'type=volume,source='+volume+',target=/state'+(',readonly' if readonly else ''),
            '--mount', 'type=bind,source='+str(source)+',target=/source/source.tar,readonly',
            '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'AWS_EC2_METADATA_DISABLED=true']
        if root_init:
            args += ['--cap-add', 'CHOWN']
        r = run([*args, '--entrypoint', 'python', image, '-I', '-c', prefix+program])
        require(r.returncode == 0, r.stderr)
        identity = r.stdout.strip()
        created.append(identity)
        report['last_role'] = role
        save()
        r = run(['docker', 'start', '-a', identity])
        (out/(role+'.log')).write_text(r.stdout+'\n'+r.stderr, encoding='utf8')
        actual = inspect('container', identity)
        require(actual['Id'] == identity and actual['Config']['Labels'][label] == owner, 'pam_recovery_control_failed')
        require(actual['Image'] == image and actual['HostConfig']['NetworkMode'] == 'none', 'pam_recovery_control_failed')
        require(r.returncode == actual['State']['ExitCode'] == 0 and not actual['State']['OOMKilled'], role)
        return json.loads(r.stdout.strip().splitlines()[-1])
    
    
    save()
    started = time.monotonic()
    try:
        context = run(['docker','context','show'])
        require(context.returncode == 0, 'pam_recovery_control_failed')
        endpoints = run(['docker','context','inspect',context.stdout.strip()])
        require(endpoints.returncode == 0, 'pam_recovery_control_failed')
        endpoint = json.loads(endpoints.stdout)[0]['Endpoints']['docker']['Host']
        require(endpoint.startswith(('npipe://','unix://')), 'local_docker_endpoint_required')
        os_type = run(['docker','info','--format','{{.OSType}}'])
        require(os_type.returncode == 0 and os_type.stdout.strip() == 'linux', 'pam_recovery_control_failed')
        require(inspect('image', image)['Id'] == image, 'pam_recovery_control_failed')
        r = run(['docker', 'volume', 'create', '--label', label+'='+owner, volume])
        volume_created = r.returncode == 0
        require(volume_created and r.stdout.strip() == volume, 'pam_recovery_control_failed')
        require(inspect('volume', volume)['Labels'][label] == owner, 'pam_recovery_control_failed')
        process('initialize', "import os,json\nos.chmod('/state',0o700);os.chown('/state',10001,10001)\nprint(json.dumps({'initialized':True}))", root_init=True)
        written = process('writer', """
import json,secrets,shutil
from scripts.f1_lab.capture_backup import fresh_file,sha
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from scripts.f1_lab.pam_observation_backup import PamObservationBackup
from tests.test_pam_journal import configured,build
from tests.test_pam_observation_ledger import admit
f=configured.__wrapped__(Path('/state'))
ledger=PamObservationLedger(Path('/state/source'),f.scope);ledger.initialize()
admit(ledger,f,build(f));original=ledger.path.read_bytes()
for name in ('packages','checkpoints','reviews'):Path('/state',name).mkdir(mode=0o700)
manager=PamObservationBackup(ledger);key=secrets.token_bytes(32)
backed=manager.backup(Path('/state/packages/one'),Path('/state/checkpoints/one.json'),ledger.checkpoint()['checkpoint_sha256'],key,'pam-recovery-1')
shutil.rmtree(ledger.directory)
restored=manager.restore(Path('/state/packages/one'),Path('/state/reviews/one'),Path('/state/checkpoints/one.json'),backed['checkpoint_sha256'],key,'pam-recovery-1')
assert Path('/state/reviews/one/review.sqlite3').read_bytes()==original and not ledger.directory.exists()
control={'scope':f.scope.model_dump(mode='json'),'checkpoint_sha256':backed['checkpoint_sha256'],'review_receipt_sha256':restored['review_receipt_sha256']}
control_raw=canonical(control);fresh_file(Path('/state/control.json'),control_raw)
fresh_file(Path('/state/original-ciphertext'),Path('/state/packages/one/payload.aesgcm').read_bytes())
empty_ledger=PamObservationLedger(Path('/state/empty-source'),f.scope);empty_ledger.initialize()
empty_manager=PamObservationBackup(empty_ledger)
empty_backup=empty_manager.backup(Path('/state/packages/empty'),Path('/state/checkpoints/empty.json'),empty_ledger.checkpoint()['checkpoint_sha256'],key,'pam-recovery-1')
shutil.rmtree(empty_ledger.directory)
empty_restore=empty_manager.restore(Path('/state/packages/empty'),Path('/state/reviews/empty'),Path('/state/checkpoints/empty.json'),empty_backup['checkpoint_sha256'],key,'pam-recovery-1')
empty_status=empty_manager.status(Path('/state/packages/empty'),Path('/state/reviews/empty'),Path('/state/checkpoints/empty.json'),empty_backup['checkpoint_sha256'],empty_restore['review_receipt_sha256'])
assert empty_status['completed'] and empty_status['captures']==empty_status['unique_events']==0 and not empty_status['current_freshness_verified'] and not empty_status['human_authenticated']
for file in Path('/state').rglob('*'):
 if file.is_file():assert key not in file.read_bytes()
print(json.dumps({'empty_history_verified':True,'source_removed':True,'restored_bytes_identical':True,'control_sha256':sha(control_raw),'unique_events':restored['unique_events'],'restore_receipt_sha256':sha(Path('/state/reviews/one/restore.json').read_bytes())}))
"""
        )
        report['writer'] = written
        check('verified_empty_history_stays_historical_without_identity_or_freshness', written['empty_history_verified'])
        check('actual_unprivileged_networkless_writer_encrypts_and_restores_after_own_source_loss',
              written['source_removed'] and written['restored_bytes_identical'] and written['unique_events'] == 2)
        reader = """
import errno,json,os
from scripts.f1_lab.capture_backup import pinned
from scripts.f1_lab.collector_freshness import CollectorScope
from scripts.f1_lab.collector_security import current_security_status
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.pam_observation_ledger import PamObservationLedger
from scripts.f1_lab.pam_observation_backup import PamObservationBackup
control=decode(pinned(Path('/state/control.json'),'CONTROL_PIN',16384))
ledger=PamObservationLedger(Path('/state/source'),CollectorScope.model_validate(control['scope']))
manager=PamObservationBackup(ledger)
value=manager.status(Path('/state/packages/one'),Path('/state/reviews/one'),Path('/state/checkpoints/one.json'),control['checkpoint_sha256'],control['review_receipt_sha256'])
blocked=False
try:
 fd=os.open('/state/packages/one/payload.aesgcm',os.O_WRONLY);os.close(fd)
except OSError as error:blocked=error.errno in (errno.EROFS,errno.EACCES)
assert blocked and not Path('/state/source').exists()
value['readonly_write_denied']=blocked;value['worker_security']=current_security_status()
print(json.dumps(value))
""".replace('CONTROL_PIN', written['control_sha256'])
        checked = process('keyless-before', reader, readonly=True)
        security = checked['worker_security']
        check('separate_keyless_readonly_cap0_nnp_worker_validates_original_history',
              checked['completed'] and checked['unique_events'] == 2 and checked['readonly_write_denied']
              and security['effective_uid'] == 10001 and security['effective_capabilities'] == security['bounding_capabilities'] == 0
              and security['no_new_privileges'])
        process('damage', "import json\np=Path('/state/packages/one/payload.aesgcm');p.write_bytes(p.read_bytes()+b'!')\nprint(json.dumps({'damaged_owned_ciphertext':True}))")
        failed = process('keyless-damaged', reader, readonly=True)
        check('actual_ciphertext_damage_becomes_unavailable_without_stale_counts',
              not failed['completed'] and failed['captures'] is failed['unique_events'] is None)
        process('repair', "import json\np=Path('/state/packages/one/payload.aesgcm');p.write_bytes(Path('/state/original-ciphertext').read_bytes())\nprint(json.dumps({'restored_exact_ciphertext':True}))")
        repaired = process('keyless-repaired', reader, readonly=True)
        check('keyless_repair_rechecks_original_ciphertext_and_preserves_two_events',
              repaired['completed'] and repaired['unique_events'] == 2)
        last = process('final-evidence', "import json\nfrom scripts.f1_lab.capture_backup import sha\nprint(json.dumps({'receipt_sha256':sha(Path('/state/reviews/one/restore.json').read_bytes()),'source_missing':not Path('/state/source').exists()}))", readonly=True)
        check('recheck_does_not_renew_restore_time_or_recreate_live_store',
              last['receipt_sha256'] == written['restore_receipt_sha256'] and last['source_missing'])
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        report['failure_type'] = type(error).__name__
        report['failure'] = str(error)
    finally:
        removed = []
        for identity in created:
            actual = inspect('container', identity)
            require(actual['Id'] == identity and actual['Config']['Labels'][label] == owner and actual['Image'] == image, 'pam_recovery_control_failed')
            require(run(['docker', 'rm', '--force', identity]).returncode == 0, 'pam_recovery_control_failed')
            removed.append(identity)
        report['owned_containers_removed'] = len(removed) == len(created)
        if volume_created:
            require(inspect('volume', volume)['Labels'][label] == owner, 'pam_recovery_control_failed')
            report['owned_volume_removed'] = run(['docker', 'volume', 'rm', volume]).returncode == 0
        else:
            report['owned_volume_removed'] = True
        for kind, command in [('containers',['docker','ps','-aq']), ('volumes',['docker','volume','ls','-q'])]:
            remaining=run([*command,'--filter','label='+label+'='+owner])
            require(remaining.returncode == 0, 'cleanup_inventory_unavailable')
            report['remaining_owned_'+kind]=remaining.stdout.split()
            require(not report['remaining_owned_'+kind], 'owned_resource_cleanup_incomplete')
        report['completed'] = report['completed'] and report['owned_containers_removed'] and report['owned_volume_removed']
        report['source_archive_unchanged_after'] = hashlib.sha256(source.read_bytes()).hexdigest() == pin
        report['completed'] = report['completed'] and report['source_archive_unchanged_after']
        report['seconds'] = round(time.monotonic()-started, 3)
        report['finished_at'] = datetime.now(UTC).isoformat()
        save()
    print(json.dumps(report), flush=True)
    require(report['completed'], 'pam_recovery_control_failed')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
