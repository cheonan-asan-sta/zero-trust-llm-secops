"""Prepare leakage checks and residual-error review; no final inference or labels."""

import argparse
import hashlib
import json
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from app.models import SecurityEvent
from scripts.audit_f1_features import security_projection
from scripts.f1_lab.evaluation_preparation import (
    DOMAINS,
    CaseMetadata,
    ExposureLedger,
    PreparationProtocol,
    analyze,
)
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.prepare_f1_intake import MATERIAL_FIELDS
from scripts.prepare_f1_review import verify as verify_baseline

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {'benchmark_manifest', 'benchmark_cases', 'baseline_freeze', 'native_plan',
          'native_comparison', 'vpn_evidence'}
OUTPUT_FILES = {'protocol.json', 'catalog.jsonl', 'exposure-ledger.json', 'split-components.json',
                'preparation-report.json', 'source-inventory.json', 'error-review-queue.jsonl'}


def read_pinned(path, expected, maximum=16*1024**2):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, 'preparation_bounded_file')
    with path.open('rb') as stream:
        body = stream.read(maximum+1)
    require(len(body) <= maximum and hashlib.sha256(body).hexdigest() == expected, 'preparation_file_pin')
    return body


def local_path(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and '..' not in path.parts and '\\' not in name and ':' not in name,
            'preparation_relative_path')
    resolved = ROOT.joinpath(*path.parts)
    require(resolved.resolve().is_relative_to(ROOT.resolve()), 'preparation_path_scope')
    return resolved


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def build_catalog(raw, expected_count):
    records = []
    source_sha256 = hashlib.sha256(raw).hexdigest()
    for body in raw.splitlines():
        require(0 < len(body) <= 65536 and len(records) < 20000, 'preparation_case_row_bound')
        row = decode(body)
        require(type(row.get('threat')) is bool and row.get('domain') in DOMAINS
                and row.get('split') in {'development', 'holdout'}, 'preparation_legacy_case_contract')
        require(isinstance(row.get('event'), dict) and all(isinstance(row['event'].get(k), dict)
                and fields <= row['event'][k].keys() for k, fields in MATERIAL_FIELDS.items()),
                'preparation_explicit_security_fields')
        event = SecurityEvent.model_validate(row['event'])
        require(event.ground_truth is None, 'preparation_no_truth_in_observation')
        pattern = digest([security_projection(event)])
        namespace = 'authored-benchmark-720'
        groups = {'session': [digest([namespace, 'session', row['session_id']])],
            'subject': [digest([namespace, 'subject', event.user.user_id])],
            'device': [digest([namespace, 'device', event.device.device_id])],
            'family': [digest([namespace, 'family', row['family_id']])], 'pattern': [pattern]}
        records.append(CaseMetadata(case_id=row['case_id'], source_id=namespace,
            source_sha256=source_sha256, payload_sha256=digest(event.analysis_payload()),
            source_kind='authored_regression', metric_unit='event_detection', label_purpose='malicious_activity',
            label='threat' if row['threat'] else 'normal', exposure='observed', requested_split='development',
            original_split=row['split'], identity_namespace_status='documented', start=event.timestamp,
            end=event.timestamp, domains=[row['domain']], groups=groups))
    require(len(records) == expected_count, 'preparation_exact_benchmark_population')
    return records


def residual_queue(freeze_directory, freeze_sha, native):
    manifest = verify_baseline(freeze_directory, freeze_sha)
    require(manifest['detector_changed'] is False, 'preparation_original_baseline')
    grouped = defaultdict(list)
    for body in (freeze_directory/'evidence.jsonl').read_bytes().splitlines():
        row = decode(body)
        grouped[row['family_id']].append(row)
    queue = []
    for family, rows in sorted(grouped.items()):
        outcomes = Counter(r['outcome'] for r in rows)
        queue.append({'review_id': 'legacy-'+family, 'track': 'authored_event_baseline',
            'metric_unit': 'event_detection', 'family_id': family,
            'domains': sorted({r['domain'] for r in rows}), 'case_ids': [r['case_id'] for r in rows],
            'source_split': sorted({r['split'] for r in rows}), 'outcomes': dict(outcomes),
            'case_count': len(rows), 'missed_expected_rule_cases': sum(bool(r['missed_expected_rule_ids']) for r in rows),
            'unexpected_rule_cases': sum(bool(r['unexpected_rule_ids']) for r in rows),
            'observed_review_flags': {
                'resource_role_missing': sum(r['observed_input']['resource'].get('required_role') is None for r in rows),
                'posture_unknown': sum(r['observed_input']['device']['security_posture'] == 'unknown' for r in rows),
                'mfa_unknown': sum(r['observed_input']['auth_context']['mfa'] == 'unknown' for r in rows),
                'unsigned_exception_claim': sum(r['observed_input']['behavior']['policy_exception_approved'] for r in rows)},
            'source_evidence_sha256': hashlib.sha256((freeze_directory/'evidence.jsonl').read_bytes()).hexdigest(),
            'priority': 'P1', 'review_status': 'pending', 'reviewer_subject': None,
            'cause_confirmed': False, 'label_changed': False,
            'next_action': 'Compare existing rule trace and evidence; record missing observations, label disputes and counterexamples.'})
    require(sum(q['case_count'] for q in queue) == manifest['evidence_cases']
            and len(queue) == manifest['review_families'], 'preparation_error_population')
    for name, scenario in native['scenarios'].items():
        for pair in scenario['per_pair']:
            m = pair['metrics']['alert']
            if not (m['fp'] or m['fn']):
                continue
            member = pair['raw_member']
            if member.endswith('/openvpn.log'):
                category = 'vpn'
                action = 'Acquire real verified device/permission sidecars; v41 tested reductions lost TP. Keep existing alerts.'
            elif '-error.' in member:
                category = 'web_error'
                action = 'Review missed malicious error rows; keep narrow ENOENT scope and existing threat detection.'
            elif '-access.' in member:
                category = 'web_access'
                action = 'Review POST/redirect/error response and missing body/authorization context before new exceptions.'
            elif member.endswith('auth.log'):
                category = 'authentication'
                action = 'Inspect raw authentication semantics and strictly earlier context without invented identity/device facts.'
            else:
                category = 'other_raw_observation'
                action = 'Inspect source-specific FN/FP and label/observation ambiguity; establish domain mapping before improvement.'
            queue.append({'review_id': 'native-'+digest([name, member])[:24], 'track': 'observed_native_development',
                'metric_unit': 'physical_log_row', 'scenario': name, 'raw_member': member,
                'category': category, 'domains': [], 'domain_mapping_status': 'unverified',
                'case_ids': [], 'case_inventory_available': False, 'confusion': m,
                'priority': 'P1' if category != 'other_raw_observation' else 'P2',
                'review_status': 'pending', 'reviewer_subject': None, 'cause_confirmed': False,
                'label_changed': False, 'next_action': action})
    return queue


def prepare(protocol_path, expected_sha256, output):
    protocol_path, output = Path(protocol_path), Path(output)
    body = read_pinned(protocol_path, expected_sha256, 65536)
    protocol = PreparationProtocol.model_validate(decode(body))
    require(set(protocol.inputs) == INPUTS, 'preparation_input_inventory')
    require(not output.exists() and not output.is_symlink(), 'preparation_fresh_output')
    data = {name: read_pinned(local_path(pin.path), pin.sha256) for name, pin in protocol.inputs.items()}
    benchmark, native_plan, native = (decode(data[n]) for n in ('benchmark_manifest', 'native_plan', 'native_comparison'))
    require(benchmark['case_count'] == 720 and benchmark['cases_sha256'] == protocol.inputs['benchmark_cases'].sha256
            and native['completed'], 'preparation_frozen_inputs')
    records = build_catalog(data['benchmark_cases'], benchmark['case_count'])
    observed_sources = {protocol.inputs['benchmark_cases'].sha256}
    references, source_inventory = [], []
    # Preparation receipts contain hashes/group inventory only. Raw bodies/labels are not opened.
    for scenario in native_plan['scenarios']:
        path = local_path(scenario['directory']+'/preparation.json')
        prep = decode(read_pinned(path, scenario['preparation_sha256']))
        for pair in prep['pairs']:
            observed_sources.add(pair['raw_sha256'])
        for spec in prep['files'].values():
            observed_sources.add(spec['sha256'])
        references.append({'path': str(path.relative_to(ROOT).as_posix()), 'sha256': scenario['preparation_sha256']})
        source_inventory.append({'source_id': 'ait-'+scenario['name'], 'role': 'observed_development',
            'metric_unit': 'physical_log_row', 'population': native['scenarios'][scenario['name']]['population'],
            'new_independent_cases': 0, 'source_reference': scenario['directory'], 'group_audit': 'pending_for_new_final'})
    vpn = decode(data['vpn_evidence'])['final_run']['report']['controls']
    require(vpn['scope'].startswith('authored prospective functional controls'), 'preparation_control_label_purpose')
    ledger = ExposureLedger(schema_version='f1-exposure-ledger-1',
        observed_source_ids=['authored-benchmark-720','m7-authentication','rba-authentication','vpn-policy-controls']+
                            ['ait-'+s['name'] for s in native_plan['scenarios']],
        observed_source_sha256=sorted(observed_sources |
            {'445f69377a2e12b4203a68f15cd9a4013fbc7e0ef21c19843969f671b1334a30'}),
        observed_payload_sha256=sorted({r.payload_sha256 for r in records} |
                                      {r['raw_line_sha256'] for r in vpn['controls']}),
        observed_pattern_sha256=sorted({key for r in records for key in r.groups['pattern']}),
        evidence_references=[pin.path for pin in protocol.inputs.values()])
    report, components = analyze(records, ledger, protocol)
    report.update(protocol_sha256=expected_sha256, preparation_receipt_pins=references,
        created_at=datetime.now(UTC).isoformat(), original_source_splits_preserved=dict(Counter(r.original_split for r in records)),
        label_visibility='Only previously observed benchmark labels read; reserved source bodies and labels remain unopened.')
    source_inventory += [
        {'source_id': 'authored-benchmark-720', 'role': 'observed_regression', 'metric_unit': 'event_detection',
         'population': 720, 'case_metadata_prepared': 720, 'new_independent_cases': 0},
        {'source_id': 'm7-authentication', 'role': 'observed_development', 'metric_unit': 'authentication_flow',
         'population': 22750, 'new_independent_cases': 0, 'scope_note': 'Prior whole-source audit, not reread or re-evaluated here.'},
        {'source_id': 'vpn-policy-controls', 'role': 'functional_controls_only', 'metric_unit': 'policy_control',
         'population': vpn['after']['population'], 'new_independent_cases': 0,
         'label_purpose': 'expected_alert_policy_not_independent_malicious_truth'},
    ]
    source_inventory += [{'source_id': s['source_id'], 'role': 'reserved_metadata_only',
        'new_independent_cases': 0, 'raw_bodies_opened': 0, 'labels_opened': 0,
        'group_and_label_adjudication': 'pending', 'reference': s['reference']} for s in protocol.reserved_sources]
    queue = residual_queue(local_path(protocol.inputs['baseline_freeze'].path).parent,
                           protocol.inputs['baseline_freeze'].sha256, native)
    report['review_queue'] = {'groups': len(queue), 'by_track': dict(Counter(r['track'] for r in queue)),
        'independent_reviews_completed': 0, 'legacy_evidence_cases_preserved': True,
        'legacy_evidence_cases': sum(r.get('case_count', 0) for r in queue), 'native_rows_replayed': 0}
    files = {'protocol.json': body, 'catalog.jsonl': b''.join(canonical(r.model_dump(mode='json'))+b'\n' for r in records),
        'exposure-ledger.json': canonical(ledger.model_dump(mode='json'))+b'\n',
        'split-components.json': canonical(components)+b'\n', 'preparation-report.json': canonical(report)+b'\n',
        'source-inventory.json': canonical(source_inventory)+b'\n',
        'error-review-queue.jsonl': b''.join(canonical(r)+b'\n' for r in queue)}
    sources = {}
    for name in ('scripts/f1_lab/evaluation_preparation.py','scripts/prepare_independent_evaluation.py',
                 'scripts/prepare_f1_intake.py','scripts/prepare_f1_review.py','scripts/audit_f1_features.py'):
        sources[name] = hashlib.sha256(local_path(name).read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent, prefix='.independent-') as temporary:
        stage = Path(temporary)/'packet'
        stage.mkdir()
        for name, payload in files.items():
            (stage/name).write_bytes(payload)
        manifest = {'schema': 'f1-independent-preparation-freeze-1', 'protocol_sha256': expected_sha256,
            'sources': sources, 'files': {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()},
            'final_evaluation_ready': False, 'goal_qualified': False, 'inference_runs': 0,
            'paid_api_calls': 0, 'aws_sdk_calls': 0, 'github_pushes': 0}
        require(all(hashlib.sha256(local_path(n).read_bytes()).hexdigest() == sha for n, sha in sources.items())
                and all(read_pinned(local_path(p.path), p.sha256) == data[n] for n, p in protocol.inputs.items()),
                'preparation_sources_changed')
        freeze = canonical(manifest)+b'\n'
        (stage/'freeze.json').write_bytes(freeze)
        stage.rename(output)
    return {'freeze_sha256': hashlib.sha256(freeze).hexdigest(), **report}


def verify(output, expected_sha256):
    output = Path(output)
    manifest = decode(read_pinned(output/'freeze.json', expected_sha256, 65536))
    require(manifest['schema'] == 'f1-independent-preparation-freeze-1'
            and set(manifest['files']) == OUTPUT_FILES
            and {p.name for p in output.iterdir()} == OUTPUT_FILES | {'freeze.json'},
            'preparation_exact_output_inventory')
    for name, sha in manifest['files'].items():
        require(PurePosixPath(name).name == name, 'preparation_output_name')
        read_pinned(output/name, sha, 32*1024**2)
    report = decode((output/'preparation-report.json').read_bytes())
    require(report['final_evaluation_ready'] is False and manifest['inference_runs'] == 0,
            'preparation_not_an_evaluator')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare','check'))
    parser.add_argument('--protocol', type=Path)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if args.mode == 'prepare':
        require(args.protocol is not None, 'preparation_protocol_required')
        result = prepare(args.protocol, args.expected_sha256, args.directory)
        print(json.dumps({'freeze_sha256': result['freeze_sha256'], 'cases': result['cases_preserved'],
                          'evaluation_blockers': result['evaluation_blockers'], 'final_evaluation_ready': False}))
        return 0
    result = verify(args.directory, args.expected_sha256)
    print(json.dumps({'verified': True,'final_evaluation_ready':False,'evaluation_blockers':result['evaluation_blockers']}))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
