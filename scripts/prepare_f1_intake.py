"""Freeze raw-event intake checks and human review tasks without running a detector."""

import argparse
import hashlib
import json
import math
import re
import tempfile
from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import combinations, pairwise
from pathlib import Path
from typing import Literal

from pydantic import Field

from app.models import SecurityEvent, StrictModel
from scripts.audit_f1_features import security_projection
from scripts.f1_lab.detector import RULE_IDS
from scripts.f1_lab.resource_policy import unique_object

FILES = {'observations.jsonl': 64*1024**2, 'labels.jsonl': 4*1024**2, 'origin.json': 16384}
SPLITS = ('development', 'calibration', 'final_candidate')
MATERIAL_FIELDS = {'user': {'user_id', 'role', 'active'}, 'device': {'device_id', 'managed', 'security_posture'},
    'network': {'ip', 'location', 'access_method', 'location_anomaly'},
    'resource': {'resource_id', 'resource_type', 'required_role', 'sensitivity'},
    'auth_context': {'mfa', 'authentication_result', 'failed_attempts', 'session_age_minutes'},
    'behavior': {'request_rate', 'new_device', 'unusual_time', 'download_volume_mb', 'distinct_resources_10m'}}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def forbid_constant(_value):
    raise ValueError('intake_nonfinite_json')


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=forbid_constant)


def read(path, maximum):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError('intake_regular_bounded_file')
    with path.open('rb') as stream:
        raw = stream.read(maximum+1)
    if len(raw) > maximum:
        raise ValueError('intake_file_bound')
    return raw


class Manifest(StrictModel):
    schema_version: Literal['f1-raw-intake-1']
    metric_unit: Literal['session_any_alert']
    data_role: Literal['candidate_before_independent_review']
    files: dict[str, str]


class Origin(StrictModel):
    kind: Literal['controlled_regression', 'publisher_synthetic', 'organization_archive', 'other_public_archive']
    creator_subject: str = Field(min_length=2, max_length=64)
    reference: str = Field(min_length=5, max_length=1000)
    license_or_permission: str = Field(min_length=5, max_length=1000)
    collection_method: str = Field(min_length=10, max_length=1000)
    event_semantics_asserted: Literal['event_deltas', 'snapshots', 'unverified']
    transformations: list[str] = Field(max_length=50)


class Observation(StrictModel):
    case_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    tenant_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')
    session_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    events: list[SecurityEvent] = Field(min_length=1, max_length=1000)


class Label(StrictModel):
    case_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    split: Literal['development', 'calibration', 'final_candidate']
    family_id: str = Field(min_length=3, max_length=100)
    label: Literal['normal', 'threat', 'unknown']
    label_origin: Literal['author_assigned', 'publisher', 'reviewer_asserted', 'undetermined']
    expected_rule_ids: list[str] = Field(max_length=6)
    evidence_event_ids: list[str] = Field(min_length=1, max_length=1000)
    rationale: str = Field(min_length=10, max_length=2000)


class Review(StrictModel):
    case_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    reviewer_subject: str | None = Field(default=None, min_length=2, max_length=64)
    review_label: Literal['normal', 'threat', 'unknown'] | None = None
    evidence_event_ids: list[str] = Field(default_factory=list, max_length=1000)
    rationale: str = Field(default='', max_length=2000)
    reviewed_at: datetime | None = None


def load_bundle(directory, expected):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('intake_bundle_directory')
    raw = read(directory/'manifest.json', 16384)
    if digest(raw) != expected:
        raise ValueError('intake_external_manifest_anchor')
    manifest = Manifest.model_validate(decode(raw))
    if set(manifest.files) != set(FILES) or {p.name for p in directory.iterdir()} != {*FILES, 'manifest.json'}:
        raise ValueError('intake_exact_file_inventory')
    data = {}
    for name, maximum in FILES.items():
        payload = read(directory/name, maximum)
        if digest(payload) != manifest.files[name]:
            raise ValueError('intake_file_hash')
        data[name] = payload
    return data, manifest


def observations(raw):
    rows, events_total = [], 0
    for line in raw.splitlines():
        if len(line) > 2*1024**2 or len(rows) >= 5000:
            raise ValueError('intake_row_bound')
        body = decode(line)
        if not isinstance(body, dict) or not isinstance(body.get('events'), list):
            raise TypeError('intake_observation_shape')
        validated = []
        for event in body['events']:
            if isinstance(event, dict) and 'ground_truth' in event:
                raise ValueError('intake_truth_must_be_separate')
            if (not isinstance(event, dict) or not {'event_id', 'timestamp', 'action'} <= event.keys()
                    or any(not isinstance(event.get(context), dict) or not fields <= event[context].keys()
                           for context, fields in MATERIAL_FIELDS.items())):
                raise ValueError('intake_material_security_fields_must_be_explicit')
            model = SecurityEvent.model_validate_json(canonical(event), strict=True)
            if model.timestamp.tzinfo is None or model.timestamp.utcoffset() is None or not math.isfinite(model.behavior.download_volume_mb):
                raise ValueError('intake_observation_clock_or_finite_value')
            validated.append(model)
            events_total += 1
            if events_total > 50000:
                raise ValueError('intake_event_population_bound')
        row = Observation.model_validate({**body, 'events': validated})
        if [event.timestamp for event in row.events] != sorted(event.timestamp for event in row.events):
            raise ValueError('intake_declared_order_requires_normalization_review')
        rows.append(row)
    if not rows or len({row.case_id for row in rows}) != len(rows):
        raise ValueError('intake_unique_nonempty_case_population')
    return rows


def analyze(data, manifest_anchor):
    origin = Origin.model_validate(decode(data['origin.json']))
    inputs = observations(data['observations.jsonl'])
    labels = [Label.model_validate(decode(line)) for line in data['labels.jsonl'].splitlines()]
    by_id = {row.case_id: row for row in labels}
    if len(by_id) != len(labels) or set(by_id) != {row.case_id for row in inputs}:
        raise ValueError('intake_exact_label_population')
    groups = {split: defaultdict(set) for split in SPLITS}
    times, families, projections = defaultdict(list), defaultdict(set), defaultdict(list)
    sessions, event_ids, duplicate_ids, conflicts, subject_drift = set(), {}, 0, 0, 0
    unknown_values = Counter()
    inventory = []
    for case in inputs:
        label = by_id[case.case_id]
        known = set(RULE_IDS.values())
        if (len(set(label.expected_rule_ids)) != len(label.expected_rule_ids)
                or not set(label.expected_rule_ids) <= known
                or (label.label == 'threat') != bool(label.expected_rule_ids)
                or not set(label.evidence_event_ids) <= {e.event_id for e in case.events}
                or len(set(label.evidence_event_ids)) != len(label.evidence_event_ids)):
            raise ValueError('intake_label_scope_or_evidence')
        split = groups[label.split]
        identity = case.tenant_id, case.session_id
        duplicate_ids += identity in sessions
        sessions.add(identity)
        split['sessions'].add(identity)
        split['families'].add(label.family_id)
        subject_drift += len({(e.user.user_id, e.device.device_id) for e in case.events}) != 1
        sequence = digest(canonical([security_projection(e) for e in case.events]))
        split['declared_sequence_projections'].add(sequence)
        projections[sequence].append(label.label)
        for event in case.events:
            for key, is_unknown in [('device_posture_unknown', event.device.security_posture == 'unknown'),
                ('authentication_result_unknown', event.auth_context.authentication_result == 'unknown'),
                ('mfa_unknown', event.auth_context.mfa == 'unknown'),
                ('nullable_resource_role', event.resource.required_role is None),
                ('admin_without_resource_role', event.action == 'ADMIN' and event.resource.required_role is None),
                ('unsigned_exception_claim_true', event.behavior.policy_exception_approved)]:
                unknown_values[key] += bool(is_unknown)
            split['subjects'].add((case.tenant_id, event.user.user_id))
            split['devices'].add((case.tenant_id, event.device.device_id))
            times[label.split].append(event.timestamp)
            ident, value = (case.tenant_id, event.event_id), digest(canonical(event.model_dump(mode='json')))
            if ident in event_ids:
                duplicate_ids += 1
                conflicts += event_ids[ident] != value
            event_ids[ident] = value
        families[label.family_id].add(label.label)
        inventory.append({'case_id': case.case_id, 'tenant_id': case.tenant_id, 'session_id': case.session_id,
            'event_ids': sorted({e.event_id for e in case.events}), 'expected_label_asserted': label.label,
            'family_id': label.family_id, 'split': label.split})
    overlaps = {}
    for first, second in combinations(SPLITS, 2):
        overlaps[first+'__'+second] = {key: len(groups[first][key] & groups[second][key]) for key in
            ('sessions', 'subjects', 'devices', 'families', 'declared_sequence_projections')}
    populated = [split for split in SPLITS if times[split]]
    forward = all(max(times[first]) < min(times[second]) for first, second in pairwise(populated))
    conflicting_projections = sum('normal' in labels and 'threat' in labels for labels in projections.values())
    support = {}
    for split in SPLITS:
        selected = [row for row in labels if row.split == split]
        negative_families = len({row.family_id for row in selected if row.label == 'normal'})
        rules = {ident: {'positive_cases': sum(ident in row.expected_rule_ids for row in selected),
            'positive_families': len({row.family_id for row in selected if ident in row.expected_rule_ids})}
            for ident in RULE_IDS.values()}
        support[split] = {'normal_families': negative_families, 'rules': rules,
            'planned_family_support_met': negative_families >= 12 and all(row['positive_families'] >= 2 for row in rules.values()),
            'independent_sample_sufficiency_proven': False}
    blockers = []
    for failed, code in [
        (any(value for pair in overlaps.values() for value in pair.values()), 'cross_split_overlap'),
        (not forward, 'forward_time_contract_failed'), (len(populated) != 3, 'three_declared_splits_not_yet_available'),
        (duplicate_ids > 0, 'duplicate_session_or_event_identity'), (conflicts > 0, 'conflicting_event_identity'),
        (subject_drift > 0, 'session_identity_binding_drift'), (conflicting_projections > 0, 'opposite_labels_same_declared_sequence'),
        (any('normal' in values and 'threat' in values for values in families.values()), 'mixed_label_family_requires_scoring_review'),
        (any(label.label == 'unknown' for label in labels), 'unknown_labels_require_adjudication')]:
        if failed:
            blockers.append(code)
    return {'schema': 'f1-intake-analysis-1', 'manifest_sha256': manifest_anchor,
        'cases': len(inputs), 'events': sum(len(row.events) for row in inputs),
        'labels_asserted': dict(Counter(row.label for row in labels)),
        'split_counts': {split: dict(Counter(row.label for row in labels if row.split == split)) for split in SPLITS},
        'cross_split_overlap': overlaps, 'forward_time_contract_passed': forward,
        'opposite_label_sequence_groups': conflicting_projections, 'duplicate_identities': duplicate_ids,
        'conflicting_event_identities': conflicts, 'session_identity_drifts': subject_drift,
        'source_kind_asserted': origin.kind, 'event_semantics_asserted': origin.event_semantics_asserted,
        'explicit_unknown_or_untrusted_value_counts': dict(unknown_values),
        'planned_target_support': support,
        'structural_blockers': blockers, 'structural_checks_passed': not blockers,
        'material_security_fields_defaulted': 0, 'raw_source_files_copied': 0,
        'source_provenance_verified': False, 'issuer_attestation_verified': False,
        'independent_review_verified': False, 'final_evaluation_ready': False, 'goal_qualified': False,
        'metric_values': None, 'inference_runs': 0, 'network_calls': 0,
        'manual_prerequisites': ['independent labels and reviewer identity', 'source identity and signed observation provenance',
            'snapshot versus event-delta semantics', 'authoritative policy/business context', 'candidate freeze and final-data exposure review']}, inventory, origin


def prepare(bundle, anchor, destination):
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise ValueError('intake_fresh_output_required')
    data, manifest = load_bundle(bundle, anchor)
    report, inventory, origin = analyze(data, anchor)
    report_raw = canonical(report)+b'\n'
    contract = {'schema': 'f1-intake-review-contract-1', 'source_manifest_sha256': anchor,
        'source_files': manifest.files, 'creator_subject_asserted': origin.creator_subject,
        'inventory': inventory, 'immutable_files': {'intake-report.json': digest(report_raw)},
        'independent_review_verified': False, 'labels_automatically_changed': False}
    contract_raw = canonical(contract)+b'\n'
    tasks = [Review(case_id=row['case_id']).model_dump(mode='json') for row in inventory]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent, prefix='.intake-') as temporary:
        stage = Path(temporary)/'packet'
        stage.mkdir()
        for name, raw in [('contract.json', contract_raw), ('intake-report.json', report_raw),
                          ('reviews.jsonl', b''.join(canonical(row)+b'\n' for row in tasks))]:
            (stage/name).write_bytes(raw)
        # A changed source cannot quietly acquire this review contract.
        load_bundle(bundle, anchor)
        stage.rename(destination)
    return {'review_contract_sha256': digest(contract_raw), 'cases': len(tasks),
        'structural_blockers': report['structural_blockers'], 'independent_review_verified': False, 'goal_qualified': False}


def assess(directory, expected, *, bundle):
    directory = Path(directory)
    raw = read(directory/'contract.json', 16*1024**2)
    if digest(raw) != expected:
        raise ValueError('intake_review_external_contract_anchor')
    contract = decode(raw)
    if contract.get('schema') != 'f1-intake-review-contract-1' or contract.get('independent_review_verified') is not False:
        raise ValueError('intake_review_contract')
    _data, manifest = load_bundle(bundle, contract['source_manifest_sha256'])
    if manifest.files != contract['source_files'] or set(contract['immutable_files']) != {'intake-report.json'}:
        raise ValueError('intake_review_source_contract')
    report_raw = read(directory/'intake-report.json', 1024**2)
    if digest(report_raw) != contract['immutable_files']['intake-report.json']:
        raise ValueError('intake_review_analysis_changed')
    population = {row['case_id']: row for row in contract['inventory']}
    reviews = [Review.model_validate(decode(line)) for line in read(directory/'reviews.jsonl', 16*1024**2).splitlines()]
    if len(reviews) != len(population) or {row.case_id for row in reviews} != set(population):
        raise ValueError('intake_review_exact_population')
    complete = disagreements = proposals = 0
    for review in reviews:
        case = population[review.case_id]
        if review.reviewer_subject is not None and review.reviewer_subject.strip().casefold() == contract['creator_subject_asserted'].strip().casefold():
            raise ValueError('intake_review_creator_cannot_self_review')
        if not set(review.evidence_event_ids) <= set(case['event_ids']) or len(set(review.evidence_event_ids)) != len(review.evidence_event_ids):
            raise ValueError('intake_review_evidence_scope')
        if review.reviewed_at is not None and (review.reviewed_at.tzinfo is None or review.reviewed_at.utcoffset() is None
                or review.reviewed_at > datetime.now(UTC)):
            raise ValueError('intake_review_timestamp')
        done = bool(review.reviewer_subject and review.reviewer_subject.strip() and review.review_label
                    and review.evidence_event_ids and len(review.rationale.strip()) >= 10 and review.reviewed_at)
        complete += done
        if done:
            if case['expected_label_asserted'] == 'unknown':
                proposals += review.review_label != 'unknown'
            else:
                disagreements += review.review_label != case['expected_label_asserted']
    return {'cases': len(reviews), 'review_records_complete': complete, 'pending': len(reviews)-complete,
        'disagreements': disagreements, 'new_label_proposals': proposals,
        'record_completion_ready_for_team_adjudication': complete == len(reviews),
        'structural_checks_passed': decode(report_raw)['structural_checks_passed'],
        'independent_review_verified': False, 'labels_automatically_changed': False,
        'final_evaluation_ready': False, 'goal_qualified': False, 'inference_runs': 0, 'network_calls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('prepare', 'assess'))
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--expected-sha256', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.bundle, args.expected_sha256, args.directory) if args.mode == 'prepare' else assess(
            args.directory, args.expected_sha256, bundle=args.bundle)
    except (ValueError, TypeError, OSError, KeyError, RecursionError) as error:
        code = str(error) if type(error) is ValueError else ''
        if not re.fullmatch(r'intake_[a-z0-9_]{1,100}', code):
            code = 'intake_validation_or_integrity_rejected'
        print(json.dumps({'error': 'intake_rejected', 'failure_type': type(error).__name__,
                          'reason_code': code, 'inference_runs': 0, 'network_calls': 0}))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 2 if args.mode == 'assess' and result['pending'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
