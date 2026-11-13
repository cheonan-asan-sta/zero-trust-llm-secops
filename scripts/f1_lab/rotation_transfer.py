"""Prospective Wilson source transfer contract; no original six-domain goal claim."""

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from scripts.f1_lab.line_truth import pair_members
from scripts.f1_lab.native_jsonl import MAX_ROW, MAX_ROWS, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.rotation_selection import select as web_rotations
from scripts.f1_lab.transfer_evaluation import sha, source_pins

POLICY = {
    'schema': 'f1-rotated-source-transfer-2',
    'candidate_chain': ['v49-sensitive-read', 'v51-credential-command-history', 'v52-successful-post'],
    'source_id': 'ait-wilson', 'asset_id': 'ait-lds21-wilson-sealed',
    'publisher_record': 19483937, 'publisher_version': 'v2_1', 'filename': 'wilson_no-pcaps.zip',
    'publisher_md5': '98285593473dc05d0a6899f7cdefcd2d', 'license_id': 'cc-by-nc-sa-4.0',
    'metadata_source': 'https://zenodo.org/records/19483937',
    'simulation_start': int(datetime(2022, 2, 3, tzinfo=UTC).timestamp()),
    'simulation_end': int(datetime(2022, 2, 9, tzinfo=UTC).timestamp()),
    'required_kinds': ['access', 'error', 'vpn'], 'maximum_total_rows': MAX_ROWS,
    'source_limits': {'access_rows': 2000000, 'access_bytes': 512*1024**2,
                      'error_vpn_rows': 100000, 'error_vpn_bytes': 64*1024**2},
    'member_selection': 'exact mirrored Apache *-access.log / *-error.log with optional .1 through .9999; OpenVPN openvpn.log only',
    'context_scope': 'one physical source; no cross-rotation history, deduplication or label borrowing',
    'evaluation_unit': 'physical_log_line', 'goal_qualified': False,
    'original_six_domain_goal_replaced': False, 'independent_human_review': False,
    'forward_time_split': False, 'publisher_schedule_metadata_visible': True,
    'scope': 'one-shot source-held-out Apache/OpenVPN transfer; shared simulated generation family',
    'body_access_before_freeze': 0, 'score_lowering_threshold': .05,
    'alert_threshold': .95, 'command_history_seconds': 60,
}


def freeze(root, acquisition, archive, output):
    root, archive, output = Path(root), Path(archive), Path(output)
    require(not output.exists() and not output.is_symlink(), 'rotated_transfer_fresh_freeze')
    asset = acquisition['asset']
    require(acquisition['completed'] is True and acquisition['publisher_md5_verified'] is True,
            'rotated_transfer_acquisition_incomplete')
    for asset_key, policy_key in (('asset_id', 'asset_id'), ('record_id', 'publisher_record'),
            ('record_version', 'publisher_version'), ('filename', 'filename'),
            ('publisher_md5', 'publisher_md5'), ('license_id', 'license_id')):
        require(canonical(asset[asset_key]) == canonical(POLICY[policy_key]), 'rotated_transfer_publisher_contract')
    require(sha(archive) == acquisition['local_sha256'] and archive.stat().st_size == asset['bytes']
            and not (archive.parent/'evaluation-access.json').exists(), 'rotated_transfer_unsealed_source')
    plan = decode((root/'infra/f1-lab/operation-refinement-protocol.json').read_bytes())
    for spec in plan['models'].values():
        require(sha(root/spec['path']) == spec['sha256'], 'rotated_transfer_model_pin')
    policy_path = 'runtime/f1/operation-refinement-v40-20261113/policy.json'
    value = {'policy': POLICY, **{key: POLICY[key] for key in
        ('source_id', 'metadata_source', 'simulation_start', 'simulation_end', 'maximum_total_rows')},
        'source_pins': source_pins(root), 'archive_sha256': acquisition['local_sha256'],
        'models': plan['models'], 'operation_policy': {'path': policy_path, 'sha256': sha(root/policy_path)},
        'acquisition_sha256': hashlib.sha256(canonical(acquisition)).hexdigest(),
        'frozen_at': datetime.now(UTC).isoformat()}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(canonical(value)+b'\n')
    return sha(output)


def check_freeze(root, path, expected_sha256):
    root = Path(root)
    require(sha(path, 2*1024**2) == expected_sha256, 'rotated_transfer_freeze_hash')
    value = decode(Path(path).read_bytes())
    require(canonical(value['policy']) == canonical(POLICY), 'rotated_transfer_policy_changed')
    require(all(canonical(value[key]) == canonical(POLICY[key]) for key in
        ('source_id', 'metadata_source', 'simulation_start', 'simulation_end', 'maximum_total_rows')),
        'rotated_transfer_duplicate_policy_drift')
    require(source_pins(root) == value['source_pins'], 'rotated_transfer_code_changed')
    plan = decode((root/'infra/f1-lab/operation-refinement-protocol.json').read_bytes())
    require(canonical(plan['models']) == canonical(value['models']), 'rotated_transfer_models_changed')
    require(value['operation_policy']['path'] == 'runtime/f1/operation-refinement-v40-20261113/policy.json',
            'rotated_transfer_operation_path')
    for spec in [*value['models'].values(), value['operation_policy']]:
        require(sha(root/spec['path']) == spec['sha256'], 'rotated_transfer_model_hash')
    return value


def select_pairs(entries):
    """Metadata only. Require all declared telemetry kinds before raw access."""
    selected, excluded = web_rotations(entries)
    indexed = {entry['archive_name']: entry for entry in entries}
    for name in sorted(indexed):
        parts = PurePosixPath(name).parts
        if parts.count('gather') != 1:
            continue
        index = parts.index('gather')
        if len(parts) < index+4 or parts[index+2] != 'logs' or parts[-1] != 'openvpn.log':
            continue
        label = PurePosixPath(*parts[:index], 'labels', *parts[index+1:]).as_posix()
        if label not in indexed:
            excluded.append({'member': name, 'reason': 'no_exact_mirrored_labels; truth unknown'})
            continue
        pair_members(name, label)
        facts = PurePosixPath(*parts[:index+2], 'facts.json').as_posix()
        require(indexed[name]['bounded_read_eligible'] and indexed[label]['bounded_read_eligible']
                and facts in indexed and indexed[facts]['bounded_read_eligible'], 'rotated_transfer_vpn_metadata')
        selected.append({'raw_member': name, 'label_member': label, 'facts_member': facts, 'kind': 'vpn',
            'rotation': 0, 'context_scope': POLICY['context_scope']})
    require({pair['kind'] for pair in selected} == set(POLICY['required_kinds']) and len(selected) <= 64,
            'rotated_transfer_declared_coverage_missing')
    return sorted(selected, key=lambda pair: pair['raw_member']), sorted(excluded, key=lambda row: row['member'])


def pair_predictions(baseline, final_stage, expected_baseline_sha256, expected_stage_sha256, output):
    """Pair v49 and v52 before labels; keep every row and failed inference."""
    require(sha(baseline) == expected_baseline_sha256 and sha(final_stage) == expected_stage_sha256,
            'rotated_transfer_stage_hash')
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'rotated_transfer_fresh_pairing')
    partial = output.with_suffix(output.suffix+'.part')
    total, failures, seen = 0, 0, set()
    with Path(baseline).open('rb') as older, Path(final_stage).open('rb') as newer, partial.open('xb') as target:
        while body := older.readline(MAX_ROW+1):
            next_body = newer.readline(MAX_ROW+1)
            require(0 < len(body) <= MAX_ROW and 0 < len(next_body) <= MAX_ROW, 'rotated_transfer_stage_row')
            old, new = decode(body), decode(next_body)
            require(old['case_id'] == new['case_id'] and old['source_index'] == new['source_index'],
                    'rotated_transfer_stage_alignment')
            require(isinstance(old['case_id'], str) and re.fullmatch('[a-f0-9]{64}', old['case_id'])
                    and old['case_id'] not in seen, 'rotated_transfer_duplicate_or_invalid_case')
            seen.add(old['case_id'])
            require(all(type(v) is bool or v is None for v in (old['after'], new['after'])),
                    'rotated_transfer_stage_prediction')
            require(type(old['source_index']) is int and old['source_index'] >= 0,
                    'rotated_transfer_stage_index')
            total += 1
            require(total <= MAX_ROWS, 'rotated_transfer_stage_bound')
            failures += new['after'] is None
            target.write(canonical({'case_id': old['case_id'], 'source_index': old['source_index'],
                'before': old['after'], 'after': new['after'], 'before_score': old['after_score'],
                'after_score': new['after_score'], 'reason': new['reason'], 'error': new['error']})+b'\n')
        require(total > 0 and not newer.read(1), 'rotated_transfer_stage_population')
    require(sha(baseline) == expected_baseline_sha256 and sha(final_stage) == expected_stage_sha256,
            'rotated_transfer_stage_changed')
    partial.rename(output)
    return {'population': total, 'inference_errors': failures, 'predictions_sha256': sha(output),
            'labels_opened_by_predictor': False}
