"""Local web ledger integration controls; no production or F1 measurement."""

import argparse
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, arguments
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import LedgerUnavailable, WebEvidenceLedger
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import VerifiedWebRisk, WebTrustBridge, digest_raw
from scripts.run_operation_refinement import ROOT, fingerprint, pinned

SCOPE = 'authored local durability controls only; not malicious ground truth'


def run(plan_path, expected_sha256, output):
    plan_path,output = Path(plan_path),Path(output)
    plan = pinned(plan_path,expected_sha256)
    require(plan['schema'] == 'f1-web-durable-controls-1' and plan['scope'] == SCOPE
            and plan['automatic_resolution_allowed'] is False, 'web_durable_controls_plan')
    prior = pinned(ROOT/plan['v45_receipt']['path'],plan['v45_receipt']['sha256'])
    require(prior['completed'], 'web_durable_prior_complete')
    require(not output.exists() and not output.is_symlink(),'web_durable_fresh_output')
    paths = ('scripts/f1_lab/web_evidence_ledger.py','scripts/f1_lab/web_durable_risk.py',
             'scripts/run_web_durable_controls.py','scripts/f1_lab/web_verified_context.py',
             'scripts/f1_lab/web_residual.py')
    sources = {name:fingerprint(ROOT/name) for name in paths}
    output.mkdir(parents=True)
    report = {'schema':'extra-web-durable-controls-1','completed':False,'scope':SCOPE,
        'plan':fingerprint(plan_path),'sources':sources,'cases':[],
        'actual_server_observations_collected':0,'new_independent_final_cases':0,'detection_f1_measured':False,
        'raw_native_data_replayed':False,'automatic_enforcement_allowed':False,'automatic_resolution_allowed':False,
        'ed25519_private_keys_persisted':False,'local_witness_hmac_key_persisted':True,
        'witness_key_published':False,'paid_api_calls':0,'aws_sdk_calls':0,'github_pushes':0,'goal_qualified':False}
    def save():
        (output/'run.json.part').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8',newline='\n')
        (output/'run.json.part').replace(output/'run.json')
    def record(name,passed,**facts):
        require(passed,'web_durable_expected_outcome')
        report['cases'].append({'case':name,'expected_outcome_passed':True,**facts})
    save()
    try:
        c = WebControls(output/'public-controls')
        base = WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _:.02),
            SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))
        verified = VerifiedWebRisk(base,c.bridge)
        ledger = WebEvidenceLedger(output/'events.sqlite',output/'witness')
        ledger.initialize()
        model = DurableWebRisk(verified,ledger)
        def call(row):
            return model.decide(row['challenge'].request,**arguments(row))
        original = c.build(permission='deny')
        result = call(original)
        record('verified_adverse_committed',result.alert and result.verified_adverse and result.storage_state == 'recorded')
        result = call(original)
        record('exact_retry_deduplicated',result.alert and result.storage_state == 'duplicate'
            and ledger.summary(original['challenge'].request,OPERATOR,now=NOW)['events'] == 2)
        healthy = c.build(index=1)
        result = call(healthy)
        record('later_consistent_proof_keeps_adverse',result.alert and result.evidence_state == 'retained_adverse')
        missing = c.build(index=1)
        missing['bundle'] = None
        result = call(missing)
        record('later_missing_proof_keeps_adverse',result.alert and result.verified_adverse)
        verified.bridge = WebTrustBridge(c.pinned)
        c.bridge = verified.bridge
        ledger = WebEvidenceLedger(output/'events.sqlite',output/'witness')
        model = DurableWebRisk(verified,ledger)
        result = call(original)
        record('reopened_ledger_and_empty_bridge_retain_risk',result.alert and result.evidence_state == 'retained_adverse')
        baseline = c.build(index=2)
        baseline['nonce'] = None
        result = call(baseline)
        record('baseline_review_is_not_verified_adverse',result.review and not result.alert and not result.verified_adverse)
        pending = c.build(index=3)
        before = base.decide(pending['features'],pending['case_id'],evidence=pending['evidence'])
        ledger.begin(pending['challenge'].request,OPERATOR,digest_raw(pending['nonce']),before,
                     deadline=pending['challenge'].expires_at,now=NOW)
        later = NOW+timedelta(seconds=31)
        recovered = ledger.recover_pending(pending['challenge'].request,OPERATOR,now=later)
        record('expired_unfinished_attempt_is_uncertain_review',recovered['review'] and recovered['interrupted']
               and not recovered['verified_adverse'] and recovered['pending_attempts'] == 0)
        from app.security import Principal
        other = Principal('other-owner',OPERATOR.tenant_id,OPERATOR.roles,OPERATOR.auth_method)
        rejected = False
        try:
            ledger.summary(original['challenge'].request,other,now=later)
        except LedgerUnavailable:
            rejected = True
        record('other_owner_cannot_read_case',rejected)
        rejected = False
        changed = original['challenge'].request.model_copy(update={'body_sha256':'b'*64})
        try:
            ledger.begin(changed,OPERATOR,'b'*64,before,deadline=later+timedelta(seconds=30),now=later)
        except LedgerUnavailable:
            rejected = True
        record('same_request_id_body_conflict_rejected',rejected)
        final = ledger.summary(original['challenge'].request,OPERATOR,now=later)
        record('unrelated_interruption_cannot_clear_completed_adverse',final['alert'] and final['verified_adverse'])
        report['summary'] = {'cases':len(report['cases']),'expected_outcomes_passed':len(report['cases']),
            'original_request_attempts':final['attempts'],'original_request_events':final['events'],
            'verified_adverse_retained':final['verified_adverse'],'uncertain_request':recovered}
        witness = json.loads((output/'witness/witness.json').read_bytes())
        report['public_checkpoint'] = witness['state']['current']
        report['database'] = fingerprint(output/'events.sqlite')
        require(all(fingerprint(ROOT/name) == value for name,value in sources.items()),'web_durable_sources_changed')
        require(pinned(plan_path,expected_sha256) == plan,'web_durable_plan_changed')
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
    print(json.dumps({'completed':result['completed'],'controls':result['summary']['cases'],'goal_qualified':False}))


if __name__ == '__main__':
    main()
