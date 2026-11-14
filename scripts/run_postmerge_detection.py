"""Development replay first; frozen predictions and separately unsealed truth afterward."""

import argparse
import json
from pathlib import Path

from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import ROOT, load_detector, predict, score, sha, source_pins


def development(output, prior):
    output, prior = Path(output), Path(prior)
    require(not output.exists() and not output.is_symlink(), 'postmerge_fresh_output')
    reference = decode(prior.read_bytes())
    require(reference['completed'] is True and len(reference['scenarios']) == 3, 'postmerge_prior_complete')
    plan = decode((ROOT/'infra/f1-lab/operation-refinement-protocol.json').read_bytes())
    policy_path = ROOT/'runtime/f1/operation-refinement-v40-20261113/policy.json'
    model = load_detector(ROOT, plan['models'], {'path': str(policy_path.relative_to(ROOT)), 'sha256': sha(policy_path)})
    pins = source_pins(ROOT)
    output.mkdir(parents=True)
    result = {'schema': 'f1-postmerge-development-1', 'completed': False,
        'scope': 'previously observed development/calibration only', 'prior_sha256': sha(prior), 'source_pins': pins,
        'scenarios': {}, 'labels_changed': False, 'models_refitted': False,
        'goal_qualified': False, 'paid_api_calls': 0, 'aws_calls': 0, 'production_adopted': False}
    try:
        for scenario in plan['scenarios']:
            name = scenario['name']
            prepared = ROOT/scenario['directory']
            preparation_path = prepared/'preparation.json'
            require(sha(preparation_path) == scenario['preparation_sha256'], 'postmerge_preparation_hash')
            preparation = decode(preparation_path.read_bytes())
            target = output/(name+'-predictions.jsonl')
            prediction = predict(prepared, preparation, ROOT/scenario['pairs_directory'], model, target)
            evaluated = score(target, prepared/'truth.jsonl', prediction['predictions_sha256'],
                              preparation['files']['truth.jsonl']['sha256'])
            require(evaluated['metrics']['before'] == reference['scenarios'][name]['metrics']['after'],
                    'postmerge_baseline_drift')
            evaluated['prediction_seal'] = prediction
            result['scenarios'][name] = evaluated
            print(json.dumps({'scenario': name, 'changes': evaluated['changes']}), flush=True)
        changes = [row['changes'] for row in result['scenarios'].values()]
        result['candidate_development_gate_passed'] = (
            sum(c['new_tp'] for c in changes) > 0 and all(c['lost_tp'] == c['introduced_fp'] == 0 for c in changes)
            and all(row['metrics']['after']['inference_errors'] == 0 for row in result['scenarios'].values()))
        require(source_pins(ROOT) == pins, 'postmerge_sources_changed_during_replay')
        result.update(completed=True, source_pins_unchanged=True)
    finally:
        (output/'run.json').write_bytes(canonical(result)+b'\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--prior', type=Path, required=True)
    args = parser.parse_args()
    result = development(args.output, args.prior)
    print(json.dumps({'completed': result['completed'],
                      'candidate_development_gate_passed': result['candidate_development_gate_passed']}))


if __name__ == '__main__':
    main()
