"""Pinned prediction-only replay of same-source audit serial ordering."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.ordered_audit_login import OrderedAuditReview
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_audit_auth_review import SCENARIOS, predict


def run(plan_path, expected_sha256, output, *, auth_review_factory=None):
    require(sha(plan_path) == expected_sha256, 'ordered_plan_pin')
    plan = decode(Path(plan_path).read_bytes())
    require(type(plan) is dict and set(plan) == {'schema', 'scope', 'goal_qualified',
        'baseline', 'baseline_sha256', 'scenarios'}
        and plan['schema'] == 'ordered-audit-replay-1' and plan['scope'] == 'observed_development_only'
        and plan['goal_qualified'] is False
        and [s['name'] for s in plan['scenarios']] == SCENARIOS, 'ordered_plan_schema')
    require(sha(plan['baseline']) == plan['baseline_sha256'], 'ordered_baseline_pin')
    baseline = decode(Path(plan['baseline']).read_bytes())
    require(baseline['completed'] is True and baseline['goal_qualified'] is False
        and set(baseline['scenarios']) == set(SCENARIOS), 'ordered_baseline_scope')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output/'prediction').mkdir()
    report = {'schema': 'ordered-audit-prediction-1', 'completed': False,
        'scope': 'already observed development; no new independent evaluation',
        'goal_qualified': False, 'labels_opened_by_predictor': False,
        'plan_sha256': expected_sha256, 'baseline_sha256': plan['baseline_sha256'],
        'aws_calls': 0, 'paid_api_calls': 0, 'scenarios': {}}
    for spec in plan['scenarios']:
        require(sha(spec['preparation']) == spec['preparation_sha256'], 'ordered_preparation_pin')
        preparation = decode(Path(spec['preparation']).read_bytes())
        require(preparation['completed'] is True and not preparation['inputs_contain_truth'],
                'ordered_preparation_scope')
        expected = baseline['scenarios'][spec['name']]['prediction']['predictions_sha256']
        result = predict(None, preparation, spec['raw'], spec['prediction'], expected,
            output/'prediction'/(spec['name']+'-predictions.jsonl'), review_factory=OrderedAuditReview,
            auth_review_factory=auth_review_factory)
        require(result['population'] == baseline['scenarios'][spec['name']]['population']
                and result['inference_errors'] == 0 and not result['labels_opened_by_predictor'],
                'ordered_prediction_population')
        report['scenarios'][spec['name']] = result
        (output/'prediction-seal.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    report['completed'] = True
    (output/'prediction-seal.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    result = run(args.plan, args.sha256, args.output)
    print(json.dumps({'completed': result['completed'], 'scenarios': len(result['scenarios']),
                      'labels_opened_by_predictor': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
