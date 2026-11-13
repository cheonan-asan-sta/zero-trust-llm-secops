"""Exercise controlled signed sessions, with explicitly optional simulated operator approvals."""

import argparse
import hashlib
import json
import math
import statistics
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security import Principal, Role
from scripts.evaluate_f1_shadow import score
from scripts.f1_lab.confidence import independent_trial_reference
from scripts.f1_lab.detector import RULE_IDS, ShadowDetector
from scripts.f1_lab.provenance import git_context
from scripts.f1_lab.registry import PinnedApprovalVerifier
from scripts.f1_lab.session_controls import verify
from scripts.f1_lab.session_inference import infer_session
from scripts.f1_lab.source_registry import FrozenSignalVerifier
from scripts.f1_lab.temporal import TemporalStore

ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def public_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def trust_fixture(inputs, operator_plans):
    earliest = min(datetime.fromisoformat(case['events'][0]['timestamp']) for case in inputs)
    latest = max(datetime.fromisoformat(case['events'][-1]['timestamp']) for case in inputs)
    before, after = earliest-timedelta(hours=1), latest+timedelta(hours=1)
    producer_keys, sources, bindings, assignments = {}, [], [], {}
    for start in range(0, len(inputs), 80):
        group, key = 'events-'+str(start//80), Ed25519PrivateKey.generate()
        producer_keys[group] = key
        selected = inputs[start:start+80]
        sources.append({'source_id': group, 'tenant_id': 'controlled-lab',
            'user_ids': [case['events'][0]['user']['user_id'] for case in selected],
            'device_ids': [case['events'][0]['device']['device_id'] for case in selected],
            'roles': sorted({event['user']['role'] for case in selected for event in case['events']}),
            'keys': [{'key_id': 'event-key', 'public_key_pem': public_pem(key),
                      'not_before': before.isoformat(), 'not_after': after.isoformat()}]})
        bindings.append(('controlled-lab', group, 'event-key'))
        for case in selected:
            assignments[case['case_id']] = group
    approval_keys, authorities = {}, []
    by_case = {case['case_id']: case for case in inputs}
    for group in sorted({plan['issuer_group'] for plan in operator_plans}):
        key = Ed25519PrivateKey.generate()
        approval_keys[group] = key
        plans = [plan for plan in operator_plans if plan['issuer_group'] == group]
        selected = [by_case[plan['case_id']] for plan in plans]
        authorities.append({'tenant_id': 'controlled-lab', 'issuer_id': 'owner-'+hashlib.sha256(group.encode()).hexdigest()[:16],
            'key_id': 'business-key', 'public_key_pem': public_pem(key),
            'allowed_deviations': sorted({d for plan in plans for d in plan['permitted_deviations']}),
            'user_ids': [case['events'][0]['user']['user_id'] for case in selected],
            'device_ids': [case['events'][0]['device']['device_id'] for case in selected],
            'resource_ids': sorted({event['resource']['resource_id'] for case in selected for event in case['events']}),
            'actions': sorted({event['action'] for case in selected for event in case['events']}),
            'key_not_before': before.isoformat(), 'key_not_after': after.isoformat()})
    registry = {'schema_version': 'zt-business-authorities-1', 'version': 1,
                'authorities': authorities, 'revoked_approval_ids': []}
    return {'sources': sources}, registry, producer_keys, approval_keys, bindings, assignments


def run(dataset, anchor, destination, *, fixture_approvals=False, fixture_window_approvals=False):
    if fixture_window_approvals and not fixture_approvals:
        raise ValueError('controlled_window_mode_requires_explicit_fixture_approval_mode')
    if destination.exists() or destination.is_symlink():
        raise ValueError('controlled_fresh_result_directory_required')
    manifest = verify(dataset, anchor)
    inputs = rows(dataset / 'inputs.jsonl')
    labels = {r['case_id']: r for r in rows(dataset / 'labels.jsonl')}
    plans = {r['case_id']: r for r in rows(dataset / 'operator-plans.jsonl')}
    if len(inputs) != manifest['sessions'] or len(labels) != len(inputs) or {c['case_id'] for c in inputs} != set(labels):
        raise ValueError('controlled_population_mismatch')
    source_registry, approval_registry, producer_keys, approval_keys, bindings, assignments = trust_fixture(inputs, list(plans.values()))
    destination.parent.mkdir(parents=True, exist_ok=True)
    result_rows, latencies, event_count = [], [], 0
    source_paths = [Path(__file__), ROOT / 'scripts/evaluate_f1_shadow.py',
        ROOT / 'scripts/ca_recovery_state.py', *sorted((ROOT / 'scripts/f1_lab').glob('*.py')),
        ROOT / 'app/models.py', ROOT / 'app/security.py', ROOT / 'app/config.py',
        ROOT / 'app/zero_trust_models.py', ROOT / 'app/continuous_signal_models.py',
        ROOT / 'app/services/trusted_signals.py', ROOT / 'app/services/detection_benchmark.py']
    captured = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                for p in source_paths}
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.controlled-run-') as temporary:
        lab = Path(temporary)
        if not lab.resolve().is_relative_to(destination.parent.resolve()):
            raise ValueError('controlled_runtime_scope')
        source_path, approval_path = lab / 'sources.json', lab / 'approvals.json'
        source_raw = canonical(source_registry)
        source_path.write_bytes(source_raw)
        approval_raw = canonical(approval_registry)
        approval_path.write_bytes(approval_raw)
        approval_anchor = hashlib.sha256(approval_raw).hexdigest()
        verifier = FrozenSignalVerifier(source_path, hashlib.sha256(source_raw).hexdigest())
        approval_verifier = PinnedApprovalVerifier(approval_path, approval_anchor, minimum_version=1)
        principal = Principal('controlled-evaluator', 'controlled-lab', frozenset({Role.ANALYST}), 'api_key')
        for ordinal, case in enumerate(inputs):
            case_root = lab / ('run-'+str(ordinal))
            store = TemporalStore(case_root / 'events.db', case_root / 'control', verifier, bindings, capacity=50)
            store.initialize()
            detector = ShadowDetector(temporal_store=store, approval_verifier=approval_verifier if fixture_approvals else None)
            single = ShadowDetector(approval_verifier=approval_verifier if fixture_approvals else None)
            group = assignments[case['case_id']]
            plan = plans.get(case['case_id']) if fixture_approvals else None
            result = infer_session(case, source_id=group, producer_key=producer_keys[group],
                principal=principal, store=store, detector=detector, single_detector=single,
                operator_plan=plan, approval_key=approval_keys[plan['issuer_group']] if plan is not None else None,
                fixture_window_approvals=fixture_window_approvals)
            latencies.extend(result.pop('latencies_ms'))
            event_count += result['signed_events_attempted']
            truth = labels[case['case_id']]
            detected = result['detected']
            result_rows.append({**result, 'family_id': truth['family_id'],
                'threat': truth['threat'], 'detected': detected, 'expected_rule_ids': truth['expected_rule_ids'],
                'error': result['temporal_error'],
                'outcome': 'TP' if truth['threat'] and detected else 'FN' if truth['threat'] else 'FP' if detected else 'TN'})
        if captured != {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes().replace(b'\r\n', b'\n')).hexdigest()
                        for p in source_paths}:
            raise ValueError('controlled_source_changed_during_run')
    temporal_score = score(result_rows, RULE_IDS.values())
    raw_rows = [{**r, 'detected': r['single_event_any_alert'], 'predicted_rule_ids': r['single_event_any_matches'],
                 'error': r['single_event_error'],
                 'assessment_status': r['single_event_assessment_status'],
                 'outcome': 'TP' if r['threat'] and r['single_event_any_alert'] else 'FN' if r['threat']
                 else 'FP' if r['single_event_any_alert'] else 'TN'} for r in result_rows]
    raw_score = score(raw_rows, RULE_IDS.values())
    for result in (temporal_score, raw_score):
        result['within_authored_family_bootstrap_target_supported'] = result['statistical_target_supported']
        result['statistical_target_supported'] = False
        result['statistical_support_scope'] = 'Controlled, author-labeled variants do not establish independent population support.'
        result['complete_inference_run'] = result['evaluation_errors'] == 0
        result['hypothetical_independent_trial_reference'] = independent_trial_reference(result['confusion'])
    ordered = sorted(latencies)
    summary = {'schema': 'f1-controlled-session-result-2', **git_context(ROOT, captured),
        'source_files_lf_sha256': captured, 'dataset_manifest_sha256': anchor,
        'metric_unit': 'session_any_alert', 'scenario_families': manifest['family_count'],
        'sessions': len(result_rows), 'signed_events': event_count,
        'failed_event_attempts': {key: sum(r[key] for r in result_rows) for key in
            ('single_event_failed_events', 'temporal_failed_events', 'context_issuance_failed_events')},
        'time_mode': manifest['time_mode'], 'fixture_approvals_enabled': fixture_approvals,
        'producer_failure_policy': 'Input or producer signing failure aborts publication; no passing summary is written.',
        'inference_failure_policy': 'Each comparator continues independently; every session stays in its denominator and any error fails its gate.',
        'fixture_window_approvals_enabled': fixture_window_approvals,
        'simulated_service_principal': True,
        'public_source_registry_sha256': hashlib.sha256(canonical(source_registry)).hexdigest(),
        'source_registry_mode': 'frozen_external_pin; changed or unavailable bytes abort trust, not live authority rotation',
        'public_approval_registry_sha256': approval_anchor,
        'real_business_approvals': 0, 'independent_review': 'pending', 'new_independent_evaluation': False,
        'single_event_any_alert': raw_score, 'signed_temporal_any_alert': temporal_score,
        'per_event_end_to_end_latency_ms': {'p50': statistics.median(ordered),
            'p95': ordered[math.ceil(len(ordered)*.95)-1], 'p95_method': 'nearest-rank',
            'samples': len(ordered),
            'scope': 'local producer encoding/signing, optional fixture issuance, both comparator evaluations',
            'key_generation_and_setup_excluded': True, 'network_latency_included': False},
        'goals': {'original_event_benchmark_replaced': False, 'goal_qualified': False},
        'effects': {'cloud_calls': 0, 'paid_api_calls': 0, 'access_grants': 0, 'session_changes': 0},
        'ephemeral_stores_remaining': 0,
        'limits': ['Controlled regression fixtures, not actual enterprise sessions or blind evaluation.',
                   'Optional approvals are explicitly simulated operator plans, not real business authorization.',
                   'Session metrics and existing 720-event metrics have separate denominators.',
                   'Source timestamps use a controlled virtual clock; latency uses measured wall time.']}
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.controlled-result-') as temporary:
        stage = Path(temporary) / 'result'
        stage.mkdir()
        for name, body in [('summary.json', summary), ('cases.json', result_rows),
                           ('public-source-registry.json', source_registry), ('public-approval-registry.json', approval_registry)]:
            (stage / name).write_bytes(canonical(body)+b'\n')
        stage.rename(destination)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', required=True, type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--fixture-approvals', action='store_true', help='Explicitly simulate operator plans; never real approval evidence')
    parser.add_argument('--fixture-window-approvals', action='store_true',
                        help='Also bind simulated approvals to live authenticated window facts')
    args = parser.parse_args()
    result = run(args.dataset, args.expected_sha256, args.directory, fixture_approvals=args.fixture_approvals,
                 fixture_window_approvals=args.fixture_window_approvals)
    print(json.dumps({key: result[key] for key in ('sessions', 'signed_events', 'fixture_approvals_enabled',
        'single_event_any_alert', 'signed_temporal_any_alert', 'goals')}))


if __name__ == '__main__':
    main()
