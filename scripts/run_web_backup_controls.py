"""Authored encrypted backup/restore controls; no deployment or detection eval."""

import argparse
import json
import secrets
from pathlib import Path
from types import SimpleNamespace

from app.security import Principal, Role
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, arguments
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import LedgerUnavailable, WebEvidenceLedger
from scripts.f1_lab.web_ledger_backup import CheckpointedWebLedger, WebLedgerBackup
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import VerifiedWebRisk
from scripts.run_operation_refinement import ROOT, fingerprint, pinned

SCOPE = 'authored local encrypted-backup and checkpoint controls only'
MAINTAINER = Principal('backup-maintainer','web-lab',frozenset({Role.ADMIN}),'api_key')
MAINTAINERS = frozenset({('web-lab','backup-maintainer')})


def run(plan_path, expected_sha256, output):
    plan_path,output = Path(plan_path),Path(output)
    plan = pinned(plan_path,expected_sha256)
    require(plan['schema'] == 'f1-web-backup-controls-1' and plan['scope'] == SCOPE
            and plan['automatic_activation_allowed'] is False,'web_backup_controls_plan')
    require(pinned(ROOT/plan['v46_receipt']['path'],plan['v46_receipt']['sha256'])['completed'],'web_backup_prior_incomplete')
    require(not output.exists() and not output.is_symlink(),'web_backup_controls_fresh_output')
    paths = ('scripts/f1_lab/web_ledger_backup.py','scripts/run_web_backup_controls.py',
             'scripts/f1_lab/web_evidence_ledger.py','scripts/f1_lab/web_durable_risk.py',
             'scripts/f1_lab/web_verified_context.py')
    sources = {name:fingerprint(ROOT/name) for name in paths}
    output.mkdir(parents=True)
    report = {'schema':'extra-web-backup-controls-1','completed':False,'scope':SCOPE,
        'plan':fingerprint(plan_path),'sources':sources,'cases':[], 'checkpoints':[],
        'recovery_key_persisted':False,'recovery_key_published':False,'witness_secret_in_plain_backup':False,
        'automatic_activation_allowed':False,'host_ha_or_remote_worm_demonstrated':False,
        'actual_server_observations_collected':0,'detection_f1_measured':False,'paid_api_calls':0,
        'aws_sdk_calls':0,'github_pushes':0,'goal_qualified':False}
    def save():
        (output/'run.json.part').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
        (output/'run.json.part').replace(output/'run.json')
    def record(name,passed):
        require(passed,'web_backup_expected_outcome')
        report['cases'].append({'case':name,'expected_outcome_passed':True})
    def rejects(call):
        try:
            call()
        except LedgerUnavailable:
            return True
        return False
    save()
    try:
        c = WebControls(output/'public-controls')
        base = WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _:.02),
            SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))
        verified = VerifiedWebRisk(base,c.bridge)
        source = WebEvidenceLedger(output/'source/events.sqlite',output/'source/witness')
        source.initialize()
        row = c.build(permission='deny')
        require(DurableWebRisk(verified,source).decide(row['challenge'].request,**arguments(row)).verified_adverse,
                'web_backup_adverse_setup')
        recovery_key = secrets.token_bytes(32)  # Demonstration only. Never persisted or printed.
        manager = WebLedgerBackup(source,recovery_key,'demo-recovery-1',maintainers=MAINTAINERS)
        cp1_path = output/'external-checkpoints/checkpoint-1.json'
        cp1 = manager.checkpoint(cp1_path,MAINTAINER,now=NOW)
        report['checkpoints'].append({'receipt':fingerprint(cp1_path),'checkpoint':cp1['checkpoint']})
        b1_path = output/'archives/snapshot-1'
        b1 = manager.backup(b1_path,cp1_path,cp1['sha256'],MAINTAINER,now=NOW)
        record('encrypted_consistent_snapshot_created',b1['snapshot']['head']['seq'] == 2
            and {p.name for p in b1_path.iterdir()} == {'payload.aesgcm','manifest.json'})
        r1_path = output/'restored/snapshot-1'
        r1 = manager.restore(b1_path,b1['manifest_sha256'],cp1_path,cp1['sha256'],r1_path,MAINTAINER,now=NOW)
        restored = manager.open_restored(r1_path,r1['receipt_sha256'],cp1_path,cp1['sha256'],MAINTAINER,now=NOW)
        record('restored_checkpointed_ledger_retains_adverse',restored.summary(row['challenge'].request,OPERATOR,now=NOW)['verified_adverse'])
        later = c.build(index=1)
        result = DurableWebRisk(verified,restored).decide(later['challenge'].request,**arguments(later))
        record('legitimate_append_extends_history_without_clearing_risk',result.verified_adverse and result.alert)
        current = WebLedgerBackup(restored,recovery_key,'demo-recovery-1',maintainers=MAINTAINERS)
        cp2_path = output/'external-checkpoints/checkpoint-2.json'
        cp2 = current.checkpoint(cp2_path,MAINTAINER,previous_path=cp1_path,expected_previous_sha256=cp1['sha256'],now=NOW)
        report['checkpoints'].append({'receipt':fingerprint(cp2_path),'checkpoint':cp2['checkpoint']})
        b2_path = output/'archives/snapshot-2'
        b2 = current.backup(b2_path,cp2_path,cp2['sha256'],MAINTAINER,now=NOW)
        r2_path = output/'restored/snapshot-2'
        r2 = current.restore(b2_path,b2['manifest_sha256'],cp2_path,cp2['sha256'],r2_path,MAINTAINER,now=NOW)
        newest = current.open_restored(r2_path,r2['receipt_sha256'],cp2_path,cp2['sha256'],MAINTAINER,now=NOW)
        record('new_checkpoint_and_snapshot_restore_four_events',newest.summary(row['challenge'].request,OPERATOR,now=NOW)['events'] == 4)
        record('older_backup_rejected_by_latest_checkpoint',rejects(lambda:current.restore(
            b1_path,b1['manifest_sha256'],cp2_path,cp2['sha256'],output/'rejected/stale',MAINTAINER,now=NOW)))
        rollback_path = output/'restored/old-store-copy'
        old = manager.restore(b1_path,b1['manifest_sha256'],cp1_path,cp1['sha256'],rollback_path,MAINTAINER,now=NOW)
        require(old['head']['seq'] == 2,'web_backup_old_copy_setup')
        guarded = CheckpointedWebLedger(rollback_path/'state/events.sqlite',rollback_path/'state/witness',cp2_path,cp2['sha256'])
        record('full_old_store_rejected_after_latest_pin_is_applied',rejects(lambda:guarded.summary(row['challenge'].request,OPERATOR,now=NOW)))
        wrong = WebLedgerBackup(source,secrets.token_bytes(32),'demo-recovery-1',maintainers=MAINTAINERS)
        record('wrong_recovery_key_rejected',rejects(lambda:wrong.restore(
            b2_path,b2['manifest_sha256'],cp2_path,cp2['sha256'],output/'rejected/wrong-key',MAINTAINER,now=NOW)))
        damaged = output/'tampered-copy'
        damaged.mkdir(mode=0o700)
        for name in ('manifest.json','payload.aesgcm'):
            (damaged/name).write_bytes((b2_path/name).read_bytes())
        payload = bytearray((damaged/'payload.aesgcm').read_bytes())
        payload[-1] ^= 1
        (damaged/'payload.aesgcm').write_bytes(payload)
        record('tampered_ciphertext_rejected',rejects(lambda:current.restore(
            damaged,b2['manifest_sha256'],cp2_path,cp2['sha256'],output/'rejected/tampered',MAINTAINER,now=NOW)))
        record('unconfigured_maintenance_identity_rejected',rejects(lambda:manager.checkpoint(
            output/'external-checkpoints/not-authorized.json',OPERATOR,now=NOW)))
        record('existing_restore_destination_not_overwritten',rejects(lambda:current.restore(
            b2_path,b2['manifest_sha256'],cp2_path,cp2['sha256'],r2_path,MAINTAINER,now=NOW)))
        report['summary'] = {'cases':len(report['cases']),'expected_outcomes_passed':len(report['cases']),
            'initial_checkpoint_seq':cp1['checkpoint']['head']['seq'],'latest_checkpoint_seq':cp2['checkpoint']['head']['seq'],
            'adverse_retained':newest.summary(row['challenge'].request,OPERATOR,now=NOW)['verified_adverse']}
        report['backups'] = [{'directory':p.relative_to(ROOT).as_posix(),**b} for p,b in [(b1_path,b1),(b2_path,b2)]]
        report['restores'] = [{'directory':p.relative_to(ROOT).as_posix(),**r} for p,r in [(r1_path,r1),(r2_path,r2)]]
        require(all(fingerprint(ROOT/name) == value for name,value in sources.items()),'web_backup_control_sources_changed')
        require(pinned(plan_path,expected_sha256) == plan,'web_backup_control_plan_changed')
        report['completed'] = True
    except (ValueError,TypeError,OSError,KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--expected-plan-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = run(args.plan,args.expected_plan_sha256,args.output)
    print(json.dumps({'completed':result['completed'],'controls':result['summary'],'goal_qualified':False}))


if __name__ == '__main__':
    main()
