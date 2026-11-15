import json
import os
import secrets
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.security import Principal, Role
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, arguments
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import LedgerUnavailable, WebEvidenceLedger
from scripts.f1_lab.web_ledger_backup import CheckpointedWebLedger, WebLedgerBackup, sha
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import VerifiedWebRisk, digest_raw

MAINTAINER = Principal('backup-maintainer','web-lab',frozenset({Role.ADMIN}),'api_key')
MAINTAINERS = frozenset({('web-lab','backup-maintainer')})


@pytest.fixture
def lab(tmp_path):
    c = WebControls(tmp_path/'controls')
    base = WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _:.02),
        SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))
    verified = VerifiedWebRisk(base,c.bridge)
    ledger = WebEvidenceLedger(tmp_path/'source/events.sqlite',tmp_path/'source/witness')
    ledger.initialize()
    empty = {ledger.database:ledger.database.read_bytes(), ledger.control/'witness.json':(ledger.control/'witness.json').read_bytes(),
             ledger.control/'witness.key':(ledger.control/'witness.key').read_bytes()}
    model = DurableWebRisk(verified,ledger)
    row = c.build(permission='deny')
    assert model.decide(row['challenge'].request,**arguments(row)).verified_adverse
    key = secrets.token_bytes(32)
    backup = WebLedgerBackup(ledger,key,'recovery-1',maintainers=MAINTAINERS)
    cp = tmp_path/'external/checkpoint-1.json'
    checkpoint = backup.checkpoint(cp,MAINTAINER,now=NOW)
    directory = tmp_path/'encrypted-backup'
    result = backup.backup(directory,cp,checkpoint['sha256'],MAINTAINER,now=NOW)
    return SimpleNamespace(c=c,model=model,ledger=ledger,row=row,key=key,backup=backup,checkpoint=cp,
        checkpoint_sha=checkpoint['sha256'],directory=directory,manifest_sha=result['manifest_sha256'],empty=empty)


def restore(lab, output, *, checkpoint=None, checkpoint_sha=None):
    return lab.backup.restore(lab.directory,lab.manifest_sha,checkpoint or lab.checkpoint,
        checkpoint_sha or lab.checkpoint_sha,output,MAINTAINER,now=NOW)


def test_encrypted_roundtrip_preserves_adverse_and_accepts_only_new_output(lab,tmp_path):
    output = tmp_path/'restored'
    result = restore(lab,output)
    assert not result['activated'] and result['head']['seq'] == 2
    ledger = lab.backup.open_restored(output,result['receipt_sha256'],lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
    assert isinstance(ledger,CheckpointedWebLedger)
    state = ledger.summary(lab.row['challenge'].request,OPERATOR,now=NOW)
    assert state['verified_adverse'] and state['alert'] and state['events'] == 2
    with pytest.raises(LedgerUnavailable,match='fresh_output'): restore(lab,output)
    assert ledger.summary(lab.row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']


def test_backup_does_not_publish_plain_database_or_local_witness_secret(lab):
    assert {p.name for p in lab.directory.iterdir()} == {'manifest.json','payload.aesgcm'}
    secret = (lab.ledger.control/'witness.key').read_bytes()
    payload = (lab.directory/'payload.aesgcm').read_bytes()
    assert secret not in payload and b'SQLite format 3' not in payload
    assert lab.key not in payload
    assert not list(lab.directory.glob('*.key'))


@pytest.mark.parametrize('principal', [OPERATOR,
    Principal('other-admin','web-lab',frozenset({Role.ADMIN}),'api_key'),
    Principal('backup-maintainer','other',frozenset({Role.ADMIN}),'oidc'),
    Principal('backup-maintainer','web-lab',frozenset({Role.ADMIN}),'disabled')])
def test_store_backup_requires_explicit_maintainer_and_admin(lab,tmp_path,principal):
    with pytest.raises(LedgerUnavailable,match='maintainer'):
        lab.backup.checkpoint(tmp_path/'not-created.json',principal,now=NOW)
    with pytest.raises(LedgerUnavailable,match='maintainer'):
        lab.backup.restore(lab.directory,lab.manifest_sha,lab.checkpoint,lab.checkpoint_sha,tmp_path/'not-created',principal,now=NOW)
    assert not (tmp_path/'not-created').exists()


@pytest.mark.parametrize('fault', ['key','key_id','manifest_pin','payload','rehashed_header','rehashed_payload','extra_file'])
def test_wrong_key_tampered_or_untrusted_packages_cannot_restore(lab,tmp_path,fault):
    manager = lab.backup
    manifest_sha = lab.manifest_sha
    if fault == 'key': manager = WebLedgerBackup(lab.ledger,secrets.token_bytes(32),'recovery-1',maintainers=MAINTAINERS)
    elif fault == 'key_id': manager = WebLedgerBackup(lab.ledger,lab.key,'other-key',maintainers=MAINTAINERS)
    elif fault == 'manifest_pin': manifest_sha = 'a'*64
    elif fault == 'payload':
        path = lab.directory/'payload.aesgcm'
        raw = bytearray(path.read_bytes()); raw[-1] ^= 1; path.write_bytes(raw)
    elif fault in {'rehashed_header','rehashed_payload'}:
        path = lab.directory/'manifest.json'
        data = json.loads(path.read_bytes())
        if fault == 'rehashed_header': data['nonce'] = 'A'*16
        else:
            payload = lab.directory/'payload.aesgcm'
            raw = bytearray(payload.read_bytes()); raw[-1] ^= 1; payload.write_bytes(raw)
            data['payload_sha256'] = sha(bytes(raw))
        path.write_text(json.dumps(data))
        manifest_sha = sha(path.read_bytes())
    else: (lab.directory/'unexpected.txt').write_text('not a declared member')
    with pytest.raises(LedgerUnavailable):
        manager.restore(lab.directory,manifest_sha,lab.checkpoint,lab.checkpoint_sha,tmp_path/'bad',MAINTAINER,now=NOW)
    assert not (tmp_path/'bad/restore.json').exists()


def test_old_backup_is_rejected_by_newer_checkpoint_and_fresh_backup_is_accepted(lab,tmp_path):
    row = lab.c.build(index=2)
    lab.model.decide(row['challenge'].request,**arguments(row))
    cp2 = tmp_path/'external/checkpoint-2.json'
    second = lab.backup.checkpoint(cp2,MAINTAINER,previous_path=lab.checkpoint,
        expected_previous_sha256=lab.checkpoint_sha,now=NOW)
    with pytest.raises(LedgerUnavailable,match='older_than_checkpoint'):
        restore(lab,tmp_path/'stale',checkpoint=cp2,checkpoint_sha=second['sha256'])
    assert not (tmp_path/'stale').exists()
    with pytest.raises(LedgerUnavailable,match='not_current_head'):
        lab.backup.backup(tmp_path/'outdated-anchor',lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
    current = lab.backup.backup(tmp_path/'current-backup',cp2,second['sha256'],MAINTAINER,now=NOW)
    result = lab.backup.restore(tmp_path/'current-backup',current['manifest_sha256'],cp2,second['sha256'],tmp_path/'current-restore',MAINTAINER,now=NOW)
    assert result['head']['seq'] == 4


def test_full_local_rollback_that_base_store_accepts_is_rejected_by_external_pin(lab):
    for path,body in lab.empty.items(): path.write_bytes(body)
    assert WebEvidenceLedger(lab.ledger.database,lab.ledger.control).summary(lab.row['challenge'].request,OPERATOR,now=NOW) is None
    anchored = CheckpointedWebLedger(lab.ledger.database,lab.ledger.control,lab.checkpoint,lab.checkpoint_sha)
    with pytest.raises(LedgerUnavailable,match='rollback'):
        anchored.summary(lab.row['challenge'].request,OPERATOR,now=NOW)


def test_anchor_is_rechecked_after_startup_and_cannot_be_silently_replaced(lab):
    anchored = CheckpointedWebLedger(lab.ledger.database,lab.ledger.control,lab.checkpoint,lab.checkpoint_sha)
    assert anchored.summary(lab.row['challenge'].request,OPERATOR,now=NOW)['alert']
    lab.checkpoint.write_text('{}')
    with pytest.raises(LedgerUnavailable,match='file_pin'):
        anchored.summary(lab.row['challenge'].request,OPERATOR,now=NOW)


def test_later_legitimate_appends_extend_the_pinned_history(lab,tmp_path):
    result = restore(lab,tmp_path/'restored')
    ledger = lab.backup.open_restored(tmp_path/'restored',result['receipt_sha256'],lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
    row = lab.c.build(index=1)
    model = DurableWebRisk(lab.model.verified,ledger)
    value = model.decide(row['challenge'].request,**arguments(row))
    assert value.verified_adverse and value.alert
    assert ledger.summary(row['challenge'].request,OPERATOR,now=NOW)['events'] == 4


def test_inflight_attempt_remains_pending_and_can_be_recovered_after_restore(lab,tmp_path):
    row = lab.c.build(index=2)
    base = lab.model.verified.baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
    lab.ledger.begin(row['challenge'].request,OPERATOR,digest_raw(row['nonce']),base,deadline=row['challenge'].expires_at,now=NOW)
    cp = tmp_path/'external/pending.json'
    receipt = lab.backup.checkpoint(cp,MAINTAINER,previous_path=lab.checkpoint,expected_previous_sha256=lab.checkpoint_sha,now=NOW)
    archive = lab.backup.backup(tmp_path/'pending-backup',cp,receipt['sha256'],MAINTAINER,now=NOW)
    restored = lab.backup.restore(tmp_path/'pending-backup',archive['manifest_sha256'],cp,receipt['sha256'],tmp_path/'pending-restored',MAINTAINER,now=NOW)
    ledger = lab.backup.open_restored(tmp_path/'pending-restored',restored['receipt_sha256'],cp,receipt['sha256'],MAINTAINER,now=NOW)
    state = ledger.recover_pending(row['challenge'].request,OPERATOR,now=NOW+timedelta(seconds=31))
    assert state['interrupted'] and state['review'] and not state['verified_adverse']


@pytest.mark.parametrize('fault', ['checkpoint_in_control','checkpoint_in_package','existing_backup','existing_restore','clock'])
def test_unsafe_paths_overwrite_and_clock_rollback_are_rejected(lab,tmp_path,fault):
    with pytest.raises(LedgerUnavailable):
        if fault == 'checkpoint_in_control': lab.backup.checkpoint(lab.ledger.control/'anchor.json',MAINTAINER,now=NOW)
        elif fault == 'checkpoint_in_package': lab.backup.backup(tmp_path/'external',lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
        elif fault == 'existing_backup': lab.backup.backup(lab.directory,lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
        elif fault == 'existing_restore': restore(lab,lab.directory)
        else: lab.backup.restore(lab.directory,lab.manifest_sha,lab.checkpoint,lab.checkpoint_sha,tmp_path/'old-clock',MAINTAINER,now=NOW-timedelta(seconds=1))
    assert (lab.directory/'manifest.json').is_file()


def test_checkpoint_is_immutable_and_wrong_previous_pin_cannot_advance(lab,tmp_path):
    with pytest.raises(LedgerUnavailable,match='fresh_file'):
        lab.backup.checkpoint(lab.checkpoint,MAINTAINER,now=NOW)
    with pytest.raises(LedgerUnavailable,match='file_pin'):
        lab.backup.checkpoint(tmp_path/'external/bad.json',MAINTAINER,previous_path=lab.checkpoint,expected_previous_sha256='a'*64,now=NOW)


def test_recovery_template_does_not_require_source_files_to_still_exist(lab,tmp_path):
    template = WebEvidenceLedger(tmp_path/'lost/events.sqlite',tmp_path/'lost/witness')
    manager = WebLedgerBackup(template,lab.key,'recovery-1',maintainers=MAINTAINERS)
    result = manager.restore(lab.directory,lab.manifest_sha,lab.checkpoint,lab.checkpoint_sha,tmp_path/'recovered',MAINTAINER,now=NOW)
    ledger = manager.open_restored(tmp_path/'recovered',result['receipt_sha256'],lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
    assert ledger.summary(lab.row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']


CHILD = r'''
import json,os,sys
from pathlib import Path
from datetime import datetime
from app.security import Principal,Role
from scripts.f1_lab.web_evidence_ledger import WebEvidenceLedger
from scripts.f1_lab.web_ledger_backup import WebLedgerBackup
s=json.loads(Path(sys.argv[1]).read_text())
p=Principal('backup-maintainer','web-lab',frozenset({Role.ADMIN}),'api_key')
b=WebLedgerBackup(WebEvidenceLedger(s['database'],s['control']),Path(s['key_file']).read_bytes(),'recovery-1',maintainers=frozenset({('web-lab','backup-maintainer')}))
b._phase=lambda point: os._exit(79) if point==sys.argv[2] else None
now=datetime.fromisoformat(s['now'])
if s['operation']=='backup': b.backup(s['output'],s['checkpoint'],s['checkpoint_sha'],p,now=now)
else: b.restore(s['backup'],s['manifest_sha'],s['checkpoint'],s['checkpoint_sha'],s['output'],p,now=now)
raise SystemExit(3)
'''


@pytest.mark.parametrize('operation,point,published', [('backup','after_backup_payload',False),('backup','after_backup_publish',True),
    ('restore','before_restore_state',False),('restore','before_restore_publish',False),('restore','after_restore_publish',True)])
def test_actual_process_exit_never_publishes_partial_backup_or_restoration(lab,tmp_path,operation,point,published):
    key_file = tmp_path/'temporary-recovery.key'
    key_file.write_bytes(lab.key); key_file.chmod(0o600)
    output = tmp_path/'interrupted'
    spec = {'database':str(lab.ledger.database),'control':str(lab.ledger.control),'key_file':str(key_file),
        'checkpoint':str(lab.checkpoint),'checkpoint_sha':lab.checkpoint_sha,'backup':str(lab.directory),
        'manifest_sha':lab.manifest_sha,'output':str(output),'now':NOW.isoformat(),'operation':operation}
    path = tmp_path/'child-spec.json'
    path.write_text(json.dumps(spec))
    p = subprocess.run([sys.executable,'-c',CHILD,str(path),point],cwd=Path(__file__).resolve().parents[1],
        capture_output=True,text=True,timeout=30,check=False,env={**os.environ,'AWS_EC2_METADATA_DISABLED':'true'})
    assert p.returncode == 79,p.stderr
    if operation == 'backup':
        assert (output/'manifest.json').exists() == published
        if published:
            result = lab.backup.restore(output,sha((output/'manifest.json').read_bytes()),lab.checkpoint,lab.checkpoint_sha,tmp_path/'from-crashed-backup',MAINTAINER,now=NOW)
            assert result['head']['seq'] == 2
        else:
            with pytest.raises(LedgerUnavailable):
                lab.backup.restore(output,'a'*64,lab.checkpoint,lab.checkpoint_sha,tmp_path/'not-published',MAINTAINER,now=NOW)
    else:
        assert (output/'restore.json').exists() == published
        if published:
            ledger = lab.backup.open_restored(output,sha((output/'restore.json').read_bytes()),lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
            assert ledger.summary(lab.row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']
        else:
            with pytest.raises(LedgerUnavailable):
                lab.backup.open_restored(output,'a'*64,lab.checkpoint,lab.checkpoint_sha,MAINTAINER,now=NOW)
