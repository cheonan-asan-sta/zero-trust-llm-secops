"""Free local prospective controls; does not measure historical detection F1."""

import argparse
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_context_controls import WebControls, arguments
from scripts.f1_lab.web_residual import WebResidualRefinement
from scripts.f1_lab.web_verified_context import VerifiedWebRisk
from scripts.run_operation_refinement import ROOT, fingerprint, pinned

SCOPE = 'authored functional controls only; not independent malicious truth'
CASES = [
    ('consistent_execution', {}, 'consistent', False),
    ('permission_denied_but_executed', {'permission':'deny'}, 'adverse', True),
    ('authentication_failed_but_executed', {'authentication':'failure'}, 'adverse', True),
    ('mfa_failed_but_executed', {'mfa':'failure'}, 'adverse', True),
    ('permission_denied_and_blocked', {'permission':'deny','executed':False}, 'review', False),
    ('authentication_unknown', {'authentication':'unknown'}, 'incomplete', False),
    ('permission_unknown', {'permission':'unknown'}, 'incomplete', False),
    ('execution_unknown', {'executed':None}, 'incomplete', False),
    ('mfa_unknown', {'mfa':'unknown'}, 'review', False),
    ('missing_bundle', {}, 'unavailable', False),
    ('forged_runtime', {'permission':'deny'}, 'unavailable', False),
    ('replay_after_valid_verification', {'permission':'deny'}, 'unavailable', False),
    ('consistent_context_keeps_existing_alert', {}, 'consistent', True),
]


def run(plan_path, expected_sha256, output):
    plan_path, output = Path(plan_path), Path(output)
    plan = pinned(plan_path, expected_sha256)
    require(plan['schema'] == 'f1-web-context-controls-1' and plan['scope'] == SCOPE
            and plan['score_lowering_allowed'] is False and plan['automatic_enforcement_allowed'] is False,
            'web_controls_plan')
    prior = pinned(ROOT/plan['v44_receipt']['path'], plan['v44_receipt']['sha256'])
    require(prior['completed'], 'web_controls_prior_complete')
    require(not output.exists() and not output.is_symlink(), 'web_controls_fresh_output')
    paths = ('scripts/f1_lab/web_verified_context.py', 'scripts/f1_lab/web_context_controls.py',
             'scripts/run_web_context_controls.py', 'scripts/f1_lab/web_residual.py',
             'scripts/f1_lab/operation_refinement.py')
    sources = {name:fingerprint(ROOT/name) for name in paths}
    output.mkdir(parents=True)
    report = {'schema':'extra-web-context-controls-1','completed':False,'scope':SCOPE,
        'created_at':datetime.now(UTC).isoformat(),'plan':fingerprint(plan_path),'sources':sources,'cases':[],
        'actual_server_observations_collected':0,'historical_sidecars_supplied':0,'new_independent_final_cases':0,
        'historical_native_data_replayed':False,'detection_f1_measured':False,'labels_changed':False,
        'paid_api_calls':0,'aws_sdk_calls':0,'github_pushes':0,'private_keys_persisted':False,
        'production_adopted':False,'goal_qualified':False,'automatic_enforcement_allowed':False}
    def save():
        (output/'run.json.part').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n',encoding='utf8',newline='\n')
        (output/'run.json.part').replace(output/'run.json')
    save()
    try:
        controls = WebControls(output/'public-controls')
        web = SimpleNamespace(probability=lambda _:.02)
        baseline = WebResidualRefinement(OperationRefinement(web,SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))
        model = VerifiedWebRisk(baseline,controls.bridge)
        for index, (name, changes, expected_state, expected_alert) in enumerate(CASES,1):
            web.probability = (lambda _:.99) if name == 'consistent_context_keeps_existing_alert' else (lambda _:.02)
            row = controls.build(index=index,**changes)
            before = baseline.decide(row['features'],row['case_id'],evidence=row['evidence'])
            if name == 'missing_bundle':
                row['bundle'] = None
            if name == 'forged_runtime':
                proof = row['bundle'].proofs[2].model_copy(update={'signature':'A'*86})
                row['bundle'] = row['bundle'].model_copy(update={'proofs':[*row['bundle'].proofs[:2],proof]})
            if name == 'replay_after_valid_verification':
                first = model.decide(**arguments(row))
                require(first.evidence_state == 'adverse' and first.alert, 'web_controls_replay_setup')
            result = model.decide(**arguments(row))
            require(result.evidence_state == expected_state and result.alert == expected_alert
                    and result.score >= before.score and result.review and not result.automatic_enforcement_allowed,
                    'web_controls_expected_result')
            report['cases'].append({'case':name,'before_score':before.score,'before_alert':before.alert,
                'after_score':result.score,'after_alert':result.alert,'after_review':result.review,
                'evidence_state':result.evidence_state,'reason':result.reason,'expected_outcome_passed':True,
                'evidence_sha256':result.evidence_sha256,'label_purpose':'functional_policy_expectation_only'})
        report['summary'] = {'cases':len(report['cases']),'expected_outcomes_passed':len(report['cases']),
            'states':dict(Counter(row['evidence_state'] for row in report['cases']))}
        require(all(fingerprint(ROOT/name) == value for name,value in sources.items()), 'web_controls_source_changed')
        require(pinned(plan_path,expected_sha256) == plan, 'web_controls_plan_changed')
        report['public_registry'] = fingerprint(output/'public-controls/web-registry.json')
        report['completed'] = True
    except (ValueError, TypeError, OSError, KeyError) as error:
        report['failure_type'] = type(error).__name__
        raise
    finally:
        report['ended_at'] = datetime.now(UTC).isoformat()
        save()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',required=True,type=Path)
    parser.add_argument('--expected-plan-sha256',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args = parser.parse_args()
    result = run(args.plan,args.expected_plan_sha256,args.output)
    print(json.dumps({'completed':result['completed'],'controls':result['summary'],'goal_qualified':False}))


if __name__ == '__main__':
    main()
