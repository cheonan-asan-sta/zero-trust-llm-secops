"""Local loopback requests -> real byte capture -> verified ledger -> restore."""

import argparse
import base64
import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

import httpx

from app.security import Principal, Role
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import load_operation_refinement
from scripts.f1_lab.web_capture_lab import ALLOW_PATH, DENY_PATH, LocalWebCaptureLab
from scripts.f1_lab.web_capture_transport import loopback_http
from scripts.f1_lab.web_ledger_backup import WebLedgerBackup
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.run_operation_refinement import ROOT, fingerprint, pinned

SCOPE = 'local TCP HTTP capture integration only; no independent attack labels'


def target(path):
    value = base64.b64encode(b'["cat","/tmp/local-fixture"]')
    return path+'?parameters='+quote(value.decode(),safe='')


def run(plan_path, expected_sha256, output):
    plan_path,output = Path(plan_path),Path(output)
    plan = pinned(plan_path,expected_sha256)
    require(plan['schema'] == 'f1-web-capture-controls-1' and plan['scope'] == SCOPE
            and plan['production_enabled'] is False,'web_capture_controls_plan')
    require(pinned(ROOT/plan['v47_receipt']['path'],plan['v47_receipt']['sha256'])['completed'], 'web_capture_prior_incomplete')
    operation = pinned(ROOT/plan['operation_plan']['path'],plan['operation_plan']['sha256'])
    stateless = pinned(ROOT/plan['stateless_run']['path'],plan['stateless_run']['sha256'])
    specs = operation['models']
    base = load_operation_refinement(ROOT/stateless['policy']['path'],stateless['policy']['sha256'],
        ROOT/specs['web']['path'],specs['web']['sha256'],ROOT/specs['heads']['path'],specs['heads']['sha256'],
        ROOT/specs['vpn']['path'],specs['vpn']['sha256'])
    baseline = WebResidualRefinement(base)
    require(not output.exists() and not output.is_symlink(),'web_capture_controls_fresh_output')
    paths = ('scripts/f1_lab/web_request_capture.py','scripts/f1_lab/web_capture_lab.py',
        'scripts/f1_lab/web_capture_transport.py','scripts/run_web_capture_controls.py',
        'scripts/f1_lab/web_verified_context.py','scripts/f1_lab/web_durable_risk.py',
        'scripts/f1_lab/web_evidence_ledger.py','scripts/f1_lab/web_ledger_backup.py',
        'app/security.py','app/config.py')
    sources = {name:fingerprint(ROOT/name) for name in paths}
    output.mkdir(parents=True)
    report = {'schema':'extra-web-capture-controls-1','completed':False,'scope':SCOPE,
        'plan':fingerprint(plan_path),'sources':sources,'cases':[],
        'transport':'TCP 127.0.0.1 only; proxy headers disabled; client environment proxies disabled',
        'authentication':'existing API-key digest verifier; local server-owned service session; no MFA performed',
        'execution':'fixed server-owned Python fixture only; never client query commands',
        'real_idp_or_edr_connected':False,'production_enabled':False,'independent_detection_performance_measured':False,
        'native_public_rows_replayed':0,'paid_api_calls':0,'aws_sdk_calls':0,'github_pushes':0,'goal_qualified':False,
        'api_and_signing_private_keys_persisted':False,'demo_backup_recovery_key_persisted':False}
    def save():
        (output/'run.json.part').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
        (output/'run.json.part').replace(output/'run.json')
    def record(name,passed,**facts):
        require(passed,'web_capture_expected_outcome')
        report['cases'].append({'case':name,'expected_outcome_passed':True,**facts})
    save()
    try:
        normal = LocalWebCaptureLab(output/'normal',baseline,max_body_bytes=1024)
        rows = []
        with loopback_http(normal.app) as url, httpx.Client(base_url=url,timeout=5,trust_env=False) as client:
            def call(name,body,*,path=ALLOW_PATH,headers=None,expected=200):
                response = client.post(target(path),content=body,headers=headers if headers is not None else {'X-API-Key':normal.api_key})
                receipt = json.loads((normal.directory/'captures'/(response.headers['x-capture-id']+'.json')).read_bytes())
                record(name,response.status_code == expected and receipt['status'] == expected,
                    capture_id=receipt['request_id'],http_status=response.status_code,body_complete=receipt['body_complete'])
                rows.append(receipt)
                return receipt,response
            body = b'local-http-body\x00\xff'
            row,response = call('complete_actual_binary_body',body)
            require(row['body_sha256'] == hashlib.sha256(body).hexdigest()
                    and response.json()['body_sha256'] == row['body_sha256'],'web_capture_body_digest')
            call('missing_credential_is_unbound',b'no-key',headers={},expected=401)
            call('invalid_credential_is_unbound',b'bad-key',headers={'X-API-Key':'incorrect'},expected=401)
            denied,_ = call('policy_denial_blocks_fixture',b'denied',path=DENY_PATH,expected=403)
            require(denied['decision'] is not None and not denied['decision']['verified_adverse'],'web_capture_contained_denial')
            spoofed,_ = call('client_identity_and_request_headers_ignored',b'spoof',headers={
                'X-API-Key':normal.api_key,'X-Request-ID':'attacker-selected-id','X-User':'admin',
                'X-Session':'forged','X-Tenant':'other','X-Forwarded-For':'203.0.113.9'})
            require(spoofed['request_id'] != 'attacker-selected-id','web_capture_server_request_id')
            empty,_ = call('actually_empty_body_has_digest',b'')
            require(empty['body_sha256'] == hashlib.sha256(b'').hexdigest(),'web_capture_actual_empty_digest')
            large,_ = call('overlimit_body_not_fabricated_complete',b'x'*1025,expected=413)
            require(not large['body_complete'] and large['body_sha256'] is None,'web_capture_overlimit')
            normal.revoke_session()
            call('revoked_local_service_session_rejected',b'revoked',expected=401)
        faulty = LocalWebCaptureLab(output/'controlled-fault',baseline,fault_denied_execution=True)
        with loopback_http(faulty.app) as url, httpx.Client(base_url=url,timeout=5,trust_env=False) as client:
            response = client.post(target(DENY_PATH),content=b'fixed-fixture-only',headers={'X-API-Key':faulty.api_key})
        fault_id = response.headers['x-capture-id']
        fault_receipt = json.loads((faulty.directory/'captures'/(fault_id+'.json')).read_bytes())
        rows.append(fault_receipt)
        record('controlled_denial_execution_contradiction_recorded',response.status_code == 200
            and fault_receipt['decision']['verified_adverse'] and fault_receipt['decision']['alert'])
        request = faulty.pipeline.request_for(fault_id,faulty.operator)
        admin = Principal('capture-maintainer','capture-lab',frozenset({Role.ADMIN}),'api_key')
        manager = WebLedgerBackup(faulty.ledger,secrets.token_bytes(32),'capture-demo-recovery',
            maintainers=frozenset({('capture-lab','capture-maintainer')}))
        cp_path = output/'external-checkpoints/collected.json'
        now = datetime.now(UTC)
        checkpoint = manager.checkpoint(cp_path,admin,previous_path=faulty.checkpoint['path'],
            expected_previous_sha256=faulty.checkpoint['sha256'],now=now)
        archive_path = output/'archive'
        archive = manager.backup(archive_path,cp_path,checkpoint['sha256'],admin,now=now)
        restored_path = output/'restored'
        restored = manager.restore(archive_path,archive['manifest_sha256'],cp_path,checkpoint['sha256'],restored_path,admin,now=now)
        ledger = manager.open_restored(restored_path,restored['receipt_sha256'],cp_path,checkpoint['sha256'],admin,now=now)
        summary = ledger.summary(request,faulty.operator,now=now)
        record('collected_adverse_survives_encrypted_restore',summary['verified_adverse'] and summary['alert'])
        report['summary'] = {'expected_outcomes_passed':len(report['cases']),'cases':len(report['cases']),
            'local_http_requests_captured':len(rows),'requests_with_durable_decisions':sum(r['decision'] is not None for r in rows),
            'fixed_child_processes':normal.executions+faulty.executions,'restored_adverse':summary['verified_adverse'],
            'server_and_child_processes_stopped':True,'production_observations_collected':0,'new_independent_final_cases':0}
        report['capture_receipts'] = rows
        report['checkpoint'] = {'sha256':checkpoint['sha256'],'checkpoint':checkpoint['checkpoint']}
        report['backup'] = archive
        report['restore'] = restored
        report['models'] = specs
        require(all(fingerprint(ROOT/name) == value for name,value in sources.items()),'web_capture_sources_changed')
        require(all(hashlib.sha256((ROOT/p['path']).read_bytes()).hexdigest() == p['sha256'] for p in specs.values()),
                'web_capture_models_changed')
        require(pinned(plan_path,expected_sha256) == plan,'web_capture_plan_changed')
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
    print(json.dumps({'completed':result['completed'],'summary':result['summary'],'goal_qualified':False}))


if __name__ == '__main__':
    main()
