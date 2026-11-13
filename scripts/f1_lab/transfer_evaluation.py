"""Frozen, label-free predictions and later scoring. No fitting or access effects."""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW, MAX_ROWS, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision, load_operation_refinement
from scripts.f1_lab.raw_observations import raw_time
from scripts.f1_lab.vpn_risk_retention import RiskRetention
from scripts.f1_lab.web_residual import WebResidualRefinement, build_evidence
from scripts.f1_lab.web_sensitive_read import evidence, refine
from scripts.run_operation_refinement import prepare_contexts
from scripts.run_vpn_risk_retention import prepare_retention

ROOT = Path(__file__).resolve().parents[2]
MAX_ARTIFACT = 8*1024**3


def sha(path, maximum=MAX_ARTIFACT):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, 'transfer_artifact_file')
    result, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        while body := stream.read(1024**2):
            size += len(body)
            require(size <= maximum, 'transfer_artifact_bound')
            result.update(body)
    return result.hexdigest()


def source_pins(root):
    root = Path(root)
    paths = [p for name in ('app', 'scripts') for p in (root/name).rglob('*.py') if '__pycache__' not in p.parts]
    paths += list((root/'infra/f1-lab').glob('*.json'))
    result = {}
    for path in sorted(paths):
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2*1024**2,
                'transfer_code_file')
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    return result


def freeze(root, acquisition, output, *, archive):
    root, output = Path(root), Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_freeze')
    require(acquisition['completed'] is True and acquisition['asset']['asset_id'] == 'ait-lds21-harrison-sealed'
            and acquisition['publisher_md5_verified'] is True, 'transfer_sealed_acquisition')
    require(sha(archive) == acquisition['local_sha256']
            and not (Path(archive).parent/'evaluation-access.json').exists(), 'transfer_source_not_sealed')
    plan = decode((root/'infra/f1-lab/operation-refinement-protocol.json').read_bytes())
    for spec in plan['models'].values():
        require(sha(root/spec['path']) == spec['sha256'], 'transfer_model_pin')
    value = {'schema': 'f1-source-transfer-freeze-1', 'candidate': 'v44-plus-sensitive-read-intent-v49',
        'source_pins': source_pins(root), 'models': plan['models'],
        'operation_policy': {'path': 'runtime/f1/operation-refinement-v40-20261113/policy.json',
                             'sha256': sha(root/'runtime/f1/operation-refinement-v40-20261113/policy.json')},
        'archive_sha256': acquisition['local_sha256'], 'source_id': 'ait-harrison',
        'simulation_start': int(datetime(2022, 2, 4, tzinfo=UTC).timestamp()),
        'simulation_end': int(datetime(2022, 2, 9, tzinfo=UTC).timestamp()),
        'metadata_source': 'https://zenodo.org/records/19483937',
        'member_selection': 'all exact label-mirrored Apache *-access.log, *-error.log and openvpn.log files; metadata-only selection',
        'source_limits': {'access_rows': 2000000, 'access_bytes': 512*1024**2,
                          'error_vpn_rows': 100000, 'error_vpn_bytes': 64*1024**2},
        'maximum_total_rows': 2000000,
        'raw_and_label_member_bodies_opened_before_freeze': 0,
        'publisher_metadata_reviewed': True, 'models_refitted': False,
        'thresholds': {'alert': .95, 'vpn_review': .9},
        'scope': 'one-shot source-held-out transfer, not certified six-domain final evaluation',
        'goal_qualified': False, 'independent_human_review': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical(value)+b'\n')
    return sha(output)


def check_freeze(root, path, expected_sha256):
    require(sha(path, 2*1024**2) == expected_sha256, 'transfer_freeze_hash')
    value = decode(Path(path).read_bytes())
    require(value['schema'] == 'f1-source-transfer-freeze-1' and value['goal_qualified'] is False,
            'transfer_freeze_schema')
    require(source_pins(root) == value['source_pins'], 'transfer_code_changed')
    for spec in [*value['models'].values(), value['operation_policy']]:
        require(sha(Path(root)/spec['path']) == spec['sha256'], 'transfer_model_changed')
    return value


def load_detector(root, specs, policy):
    root = Path(root)
    base = load_operation_refinement(root/policy['path'], policy['sha256'],
        root/specs['web']['path'], specs['web']['sha256'], root/specs['heads']['path'], specs['heads']['sha256'],
        root/specs['vpn']['path'], specs['vpn']['sha256'])
    return RiskRetention(base)


def web_sources(raw_directory, preparation):
    result, prior = {}, {}
    audit_path = Path(raw_directory)/'audit.json'
    require(sha(audit_path) == preparation['source_manifest_sha256'], 'transfer_raw_manifest')
    audit = decode(audit_path.read_bytes())
    for index, pair in enumerate(preparation['pairs']):
        kind = 'access' if '-access.' in pair['raw_member'] else 'error' if '-error.' in pair['raw_member'] else None
        if kind is None:
            continue
        path = Path(raw_directory)/f'pair-{index}-raw.source'
        require(path.stat().st_size <= (512*1024**2 if kind == 'access' else 64*1024**2), 'transfer_source_bytes')
        provenance = audit['pairs'][index]['provenance']
        require(provenance['raw_sha256'] == pair['raw_sha256'] and provenance['raw_member'] == pair['raw_member'],
                'transfer_raw_alignment')
        digest, count = hashlib.sha256(), 0
        batch = []
        with path.open('rb') as stream:
            while raw := stream.readline(MAX_ROW+1):
                count += 1
                require(len(raw) <= MAX_ROW and count <= (2000000 if kind == 'access' else 100000),
                        'transfer_source_rows')
                digest.update(raw)
                line, moment = raw.decode('utf-8', errors='replace'), None
                if kind == 'access':
                    item = evidence(line, pair['raw_sha256'], count)
                    if item is not None:
                        result[item.case_id] = item
                else:
                    try:
                        moment = raw_time(line, provenance['simulation_start'], provenance['simulation_end'], source_timezone='UTC')
                    except (ValueError, RecursionError):
                        pass
                batch.append((count, moment, line))
                # Access evidence is row-local. Error history must retain the whole bounded source.
                if kind == 'access' and len(batch) == 1000:
                    prior.update(build_evidence(batch, kind, pair['raw_sha256']))
                    batch = []
        require(count == pair['rows'] and digest.hexdigest() == pair['raw_sha256'], 'transfer_source_hash')
        if batch:
            prior.update(build_evidence(batch, kind, pair['raw_sha256']))
    return prior, result


def observations(directory, preparation):
    """No label path is accepted or opened by this iterator."""
    path = Path(directory)/'inputs.jsonl'
    require(sha(path) == preparation['files']['inputs.jsonl']['sha256'], 'transfer_inputs_hash')
    pair_index, ordinal = 0, 0
    with path.open('rb') as stream:
        while raw := stream.readline(MAX_ROW+1):
            require(len(raw) <= MAX_ROW and pair_index < len(preparation['pairs']), 'transfer_input_rows')
            row = decode(raw)
            require(set(row) == {'case_id', 'features', 'observation_error'}, 'transfer_label_free_input')
            pair = preparation['pairs'][pair_index]
            ordinal += 1
            case = hashlib.sha256((pair['raw_sha256']+':'+str(ordinal)).encode()).hexdigest()
            require(row['case_id'] == case, 'transfer_case_order')
            yield pair_index, row
            if ordinal == pair['rows']:
                pair_index, ordinal = pair_index+1, 0
    require(pair_index == len(preparation['pairs']) and ordinal == 0, 'transfer_input_population')
    require(sha(path) == preparation['files']['inputs.jsonl']['sha256'], 'transfer_inputs_changed')


def predict(directory, preparation, raw_directory, model, output):
    """All before/after decisions are written before scoring can receive truth."""
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'transfer_fresh_predictions')
    contexts, _ = prepare_contexts(Path(raw_directory), preparation)
    contexts = prepare_retention(Path(raw_directory), preparation, contexts, model.vpn_model)
    web, sensitive = web_sources(raw_directory, preparation)
    prior = WebResidualRefinement(model.operation_model)
    cache, total, failures = {}, 0, 0
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_suffix(output.suffix+'.part')
    require(not partial.exists() and not partial.is_symlink(), 'transfer_partial_predictions_exist')
    with partial.open('xb') as target:
        for index, row in observations(directory, preparation):
            case, features = row['case_id'], row['features']
            before = after = None
            error = None
            try:
                require(features is not None and row['observation_error'] is None, 'transfer_observation_error')
                key = canonical(features)
                if key not in cache:
                    require(len(cache) < 100000, 'transfer_feature_cache_bound')
                    cache[key] = model.web_model.probability(features)
                score = cache[key]
                base = (model.decide(features, case, contexts[case]) if case in contexts
                        else OperationDecision(score, score, score >= .95, score >= .95, 'unchanged'))
                before = prior.refine(base, features, case, web.get(case))
                after = refine(before, features, case, sensitive.get(case))
                require(after.score >= before.score and (not before.alert or after.alert)
                        and not after.automatic_enforcement_allowed, 'transfer_monotonicity')
            except (ValueError, KeyError, TypeError, RecursionError):
                error = 'inference_or_binding_error'
                failures += 1
            target.write(canonical({'case_id': case, 'source_index': index,
                'before': before.alert if before is not None else None,
                'after': after.alert if after is not None and error is None else None,
                'before_score': before.score if before is not None else None,
                'after_score': after.score if after is not None and error is None else None,
                'reason': after.reason if after is not None and error is None else error,
                'error': error})+b'\n')
            total += 1
    partial.rename(output)
    return {'predictions_sha256': sha(output), 'population': total, 'inference_errors': failures,
            'labels_opened_by_predictor': False, 'automatic_enforcement_allowed': False}


def score(predictions, truth, expected_prediction_sha256, expected_truth_sha256):
    """Exact ordered join; inference errors remain in the denominator for both classes."""
    require(sha(predictions) == expected_prediction_sha256 and sha(truth) == expected_truth_sha256,
            'transfer_score_hash')
    groups, changes = {}, {'new_tp': 0, 'introduced_fp': 0, 'lost_tp': 0, 'removed_fp': 0}
    total = 0
    seen = set()
    with Path(predictions).open('rb') as outputs, Path(truth).open('rb') as labels:
        while raw := outputs.readline(MAX_ROW+1):
            gold = labels.readline(MAX_ROW+1)
            require(len(raw) <= MAX_ROW and 0 < len(gold) <= MAX_ROW, 'transfer_truth_population')
            row, label = decode(raw), decode(gold)
            require(row['case_id'] == label['case_id'] and type(label['malicious']) is bool,
                    'transfer_truth_alignment')
            require(isinstance(row['case_id'], str) and re.fullmatch('[a-f0-9]{64}', row['case_id'])
                    and row['case_id'] not in seen and total < MAX_ROWS, 'transfer_duplicate_or_invalid_case')
            seen.add(row['case_id'])
            require(type(row['source_index']) is int and row['source_index'] >= 0, 'transfer_source_index')
            group = groups.setdefault(row['source_index'], {'before': counts(), 'after': counts()})
            for name in group:
                record(group[name], label['malicious'], row[name])
            if row['before'] is not None and row['after'] is not None and row['before'] != row['after']:
                changes['new_tp' if row['after'] and label['malicious'] else 'introduced_fp'
                        if row['after'] else 'lost_tp' if label['malicious'] else 'removed_fp'] += 1
            total += 1
        require(not labels.read(1), 'transfer_extra_truth')
    require(total > 0, 'transfer_empty_population')
    sums = {name: {key: sum(g[name][key] for g in groups.values()) for key in counts()} for name in ('before', 'after')}
    require(sha(predictions) == expected_prediction_sha256 and sha(truth) == expected_truth_sha256,
            'transfer_scoring_inputs_changed')
    return {'population': total, 'metrics': {k: metrics(v) for k, v in sums.items()},
            'per_source': [{'source_index': index, 'metrics': {k: metrics(v) for k, v in group.items()}}
                           for index, group in sorted(groups.items())], 'changes': changes,
            'goal_qualified': False, 'independent_human_review': False}
