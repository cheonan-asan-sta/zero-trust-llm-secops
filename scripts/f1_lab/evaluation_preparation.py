"""Metadata-only split and exposure checks; never opens final observations/labels."""

import hashlib
from collections import Counter, defaultdict
from datetime import datetime
from itertools import pairwise
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from app.models import StrictModel
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.operation_context import canonical

DOMAINS = ('credential', 'device', 'privilege', 'lateral', 'exfiltration', 'remote')
AXES = ('session', 'subject', 'device', 'family', 'pattern')
SPLITS = ('development', 'calibration', 'final_reserved')
SHA = Annotated[str, Field(pattern=r'^[a-f0-9]{64}$')]
MAX_CASES = 20000


class CaseMetadata(StrictModel):
    case_id: str = Field(pattern=r'^[A-Za-z0-9._-]{1,128}$')
    source_id: str = Field(min_length=1, max_length=128)
    source_sha256: SHA
    payload_sha256: SHA
    source_kind: Literal['authored_regression', 'publisher_testbed', 'organization_observation']
    metric_unit: Literal['event_detection', 'session_any_alert', 'policy_control']
    label_purpose: Literal['malicious_activity', 'expected_alert_policy', 'unadjudicated']
    label: Literal['normal', 'threat', 'unknown'] | None
    exposure: Literal['observed', 'sealed_unseen', 'unestablished']
    requested_split: Literal['development', 'calibration', 'final_reserved', 'unassigned']
    original_split: str = Field(min_length=1, max_length=128)
    identity_namespace_status: Literal['documented', 'unverified']
    start: datetime
    end: datetime
    domains: list[str] = Field(max_length=6)
    groups: dict[str, list[SHA]]

    @field_validator('start', 'end')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('independent_metadata_timezone')
        return value

    @model_validator(mode='after')
    def contract(self):
        require(self.start <= self.end, 'independent_metadata_time_order')
        require(set(self.groups) == set(AXES) and all(len(v) <= 16 and len(set(v)) == len(v)
                for v in self.groups.values()), 'independent_group_axes')
        require(len(set(self.domains)) == len(self.domains) and set(self.domains) <= set(DOMAINS),
                'independent_domain_scope')
        require(self.exposure != 'sealed_unseen' or self.label is None, 'independent_sealed_label_must_stay_unread')
        require(self.label_purpose != 'expected_alert_policy' or self.metric_unit == 'policy_control',
                'independent_policy_labels_not_attack_truth')
        return self


class ExposureLedger(StrictModel):
    schema_version: Literal['f1-exposure-ledger-1']
    observed_source_ids: list[str] = Field(default_factory=list, max_length=10000)
    observed_source_sha256: list[SHA] = Field(max_length=10000)
    observed_payload_sha256: list[SHA] = Field(max_length=100000)
    observed_pattern_sha256: list[SHA] = Field(max_length=100000)
    evidence_references: list[str] = Field(max_length=1000)

    @model_validator(mode='after')
    def distinct(self):
        for values in (self.observed_source_ids, self.observed_source_sha256,
                       self.observed_payload_sha256, self.observed_pattern_sha256):
            require(len(set(values)) == len(values), 'independent_exposure_duplicate')
        return self


class FilePin(StrictModel):
    path: str = Field(min_length=1, max_length=512)
    sha256: SHA


class PreparationProtocol(StrictModel):
    schema_version: Literal['f1-independent-preparation-1']
    stage: Literal['preparation_only']
    candidate_freeze_sha256: None
    metric_tracks: list[str]
    domains: list[str]
    disjoint_axes: list[str]
    targets: dict[str, float]
    planned_final_sessions: dict[str, int]
    inputs: dict[str, FilePin]
    reserved_sources: list[dict[str, str]] = Field(max_length=100)
    notes: list[str] = Field(max_length=50)

    @model_validator(mode='after')
    def fixed_contract(self):
        require(self.domains == list(DOMAINS) and self.disjoint_axes == list(AXES), 'independent_original_scope')
        require(self.metric_tracks == ['event_detection', 'session_any_alert', 'policy_control'],
                'independent_metric_units')
        require(self.targets == {'precision': .95, 'recall': .95, 'f1': .95, 'false_positive_rate': .05},
                'independent_original_targets')
        require(self.planned_final_sessions == {'normal': 300, 'threat': 300}, 'independent_sample_plan')
        return self


def analyze(records, ledger, protocol):
    require(isinstance(records, list) and 0 < len(records) <= MAX_CASES
            and all(isinstance(r, CaseMetadata) for r in records), 'independent_case_bound')
    require(len({r.case_id for r in records}) == len(records), 'independent_duplicate_case_id')
    require(isinstance(ledger, ExposureLedger) and isinstance(protocol, PreparationProtocol), 'independent_contract_types')
    parent = list(range(len(records)))
    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    def union(a, b):
        a, b = root(a), root(b)
        if a != b:
            parent[max(a, b)] = min(a, b)
    seen = {}
    for i, record in enumerate(records):
        links = [('payload', record.payload_sha256)]
        links += [(axis, key) for axis in AXES for key in record.groups[axis]]
        for key in links:
            require(key in seen or len(seen) < 200000, 'independent_link_bound')
            if key in seen:
                union(i, seen[key])
            else:
                seen[key] = i
    groups = defaultdict(list)
    for i, record in enumerate(records):
        groups[root(i)].append(record)
    components = []
    for values in groups.values():
        members = sorted(r.case_id for r in values)
        roles = sorted({r.requested_split for r in values if r.requested_split != 'unassigned'})
        components.append({'component_sha256': hashlib.sha256(canonical(members)).hexdigest(),
            'case_ids': members, 'requested_splits': roles, 'cross_split_conflict': len(roles) > 1,
            'earliest': min(r.start for r in values).isoformat(), 'latest': max(r.end for r in values).isoformat()})
    components.sort(key=lambda c: c['component_sha256'])
    sources, payloads, patterns = (set(getattr(ledger, name)) for name in
        ('observed_source_sha256', 'observed_payload_sha256', 'observed_pattern_sha256'))
    exposure_reasons, final_issues = {}, {}
    for r in records:
        reasons = []
        if r.exposure == 'observed':
            reasons.append('declared_observed')
        if r.source_id in ledger.observed_source_ids:
            reasons.append('source_identity_previously_observed')
        if r.source_sha256 in sources:
            reasons.append('source_previously_observed')
        if r.payload_sha256 in payloads:
            reasons.append('payload_previously_observed')
        if patterns.intersection(r.groups['pattern']):
            reasons.append('pattern_previously_observed')
        exposure_reasons[r.case_id] = reasons
        if r.requested_split == 'final_reserved':
            issues = list(reasons)
            if r.exposure != 'sealed_unseen':
                issues.append('unseen_status_not_established')
            if r.source_kind == 'authored_regression':
                issues.append('authored_controls_not_independent_observations')
            if r.metric_unit == 'policy_control' or r.label_purpose != 'malicious_activity':
                issues.append('policy_or_unadjudicated_labels_not_malicious_truth')
            if r.identity_namespace_status != 'documented':
                issues.append('identity_namespace_unverified')
            if any(not r.groups[axis] for axis in AXES):
                issues.append('required_group_metadata_missing')
            if not r.domains:
                issues.append('domain_mapping_pending')
            if issues:
                final_issues[r.case_id] = issues
    selected = {split: [r for r in records if r.requested_split == split] for split in SPLITS}
    available = [s for s in SPLITS if selected[s]]
    forward = all(max(r.end for r in selected[a]) < min(r.start for r in selected[b]) for a, b in pairwise(available))
    blockers = []
    for failed, code in [
        (len(available) != 3, 'three_populated_splits_required'),
        (any(r.requested_split == 'unassigned' for r in records), 'unassigned_cases'),
        (any(c['cross_split_conflict'] for c in components), 'connected_component_crosses_splits'),
        (not forward, 'strict_forward_time_split_failed'),
        (bool(final_issues), 'final_exposure_or_source_contract_failed'),
        (not selected['final_reserved'], 'no_final_cases_acquired'),
    ]:
        if failed:
            blockers.append(code)
    support = {}
    for split, values in selected.items():
        support[split] = {}
        for unit in protocol.metric_tracks:
            rows = [r for r in values if r.metric_unit == unit]
            support[split][unit] = {'cases': len(rows),
                'known_labels': dict(Counter(r.label for r in rows if r.label is not None)),
                'sealed_labels_unread': sum(r.label is None for r in rows),
                'domain_case_support': {d: sum(d in r.domains for r in rows) for d in DOMAINS}}
    # This tool is a preparation stage, not an evaluator or reviewer identity verifier.
    return {'schema': 'f1-independent-preparation-report-1', 'cases_preserved': len(records),
        'metric_units_separated': True, 'components': len(components),
        'components_crossing_splits': sum(c['cross_split_conflict'] for c in components),
        'largest_component_cases': max(len(c['case_ids']) for c in components),
        'missing_group_metadata': {axis: sum(not r.groups[axis] for r in records) for axis in AXES},
        'support': support, 'forward_time_contract_passed': forward,
        'observed_cases': sum(bool(v) for v in exposure_reasons.values()),
        'final_case_blockers': final_issues, 'structural_blockers': blockers,
        'metadata_structure_ready': not blockers,
        'evaluation_blockers': blockers+['candidate_not_frozen', 'source_and_label_adjudication_pending',
                                        'final_class_support_unverified'],
        'candidate_frozen': False, 'independent_review_verified': False,
        'final_evaluation_ready': False, 'goal_qualified': False,
        'model_inference_runs': 0, 'labels_changed': False, 'cases_dropped': 0,
        'final_observation_bodies_opened': 0, 'final_label_bodies_opened': 0}, components
