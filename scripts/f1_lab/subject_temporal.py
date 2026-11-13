"""Opt-in subject activity window for local shadow experiments.

Sessions remain separately authenticated and bound. Only received events of the
same tenant, analyst and user are aggregated. A session-only approval verifier
must never authorize this wider window, so the public summary is incomplete for
legacy callers and only SubjectShadowDetector consumes its explicit contract.
"""

from datetime import timedelta

from app.services.trusted_signals import SignalRegistryUnavailable
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.approvals import ApprovalVerifier
from scripts.f1_lab.approvals import require as approval_require
from scripts.f1_lab.detector import ShadowDetector
from scripts.f1_lab.registry import PinnedApprovalVerifier
from scripts.f1_lab.resource_policy import ResourcePolicyUnavailable
from scripts.f1_lab.temporal import TemporalStore, TemporalUnavailable, canonical, digest, require

PROFILE = 'f1-tenant-analyst-user-activity-1'


class SubjectTemporalStore(TemporalStore):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config_sha256 = digest(canonical({'base_configuration': self.config_sha256,
            'profile': PROFILE, 'approval_contract': 'all_observed_subject_devices_and_exact_fact_set',
            'legacy_summary_complete': False}))

    def _summary(self, entries, head, session_id, principal, now, *, duplicate=False):
        owned = [r for r in entries if r['tenant'] == principal.tenant_id and r['session'] == session_id]
        require(owned and all(r['operator'] == principal.subject for r in owned), 'temporal_session_unavailable')
        anchor = SignedSessionSignal.model_validate(owned[0]['signal']).event
        try:
            current_sources = self.verifier.current_source_digests(now)
        except SignalRegistryUnavailable:
            raise TemporalUnavailable('temporal_current_authority_unavailable') from None
        start = now-timedelta(seconds=self.window_seconds)
        scoped, related = [], []
        for record in entries:
            if record['tenant'] != principal.tenant_id:
                continue
            signal = SignedSessionSignal.model_validate(record['signal'])
            event = signal.event
            if not start < event.timestamp <= now:
                continue
            identity = signal.tenant_id, signal.source_id, signal.key_id
            trusted = current_sources.get(identity) == record['source_digest']
            related.append((record, event, trusted))
            if record['operator'] == principal.subject and event.user.user_id == anchor.user.user_id:
                scoped.append((record, event, trusted))
        # Include received-but-now-untrusted devices in adverse scope. Their loss
        # of authority also prevents the wider window from becoming complete.
        devices = {anchor.device.device_id, *(event.device.device_id for _, event, _ in scoped)}
        selected = [(record, event) for record, event, trusted in scoped if trusted]
        events = [event for _, event in selected]
        excluded = sum(not trusted for _, _, trusted in scoped)
        snapshot = None
        if self.resource_policies is not None:
            try:
                snapshot = self.resource_policies.snapshot(now=now)
            except ResourcePolicyUnavailable:
                pass
        sensitivities, policy_unavailable, policy_denied = [], 0, 0
        for event in events:
            if self.resource_policies is None:
                sensitivities.append(event.resource.sensitivity)
                continue
            try:
                if snapshot is None:
                    raise ResourcePolicyUnavailable('resource_policy_unavailable')
                decision = snapshot.resolve(event, principal.tenant_id)
                sensitivities.append(decision.effective_sensitivity)
                policy_denied += not decision.role_and_action_allowed
            except ResourcePolicyUnavailable:
                sensitivities.append('critical')
                policy_unavailable += 1
        adverse, adverse_facts, adverse_excluded = set(), [], 0
        for record, event, trusted in related:
            markers = set()
            if event.device.device_id in devices and event.device.security_posture in {'at_risk', 'compromised'}:
                markers.add(event.device.security_posture)
            if event.user.user_id == anchor.user.user_id and not event.user.active:
                markers.add('inactive')
            if not markers:
                continue
            adverse_facts.append((record['input_sha256'], record['source_digest'], sorted(markers), trusted))
            if trusted:
                adverse.update(markers)
            else:
                adverse_excluded += 1
        facts = sorted((record['input_sha256'], record['source_digest'], trusted) for record, _, trusted in scoped)
        complete = bool(events) and excluded == adverse_excluded == policy_unavailable == 0
        return {'schema': 'f1-subject-temporal-summary-1', 'aggregation_profile': PROFILE,
            'store_id': head['store_id'], 'tenant_id': principal.tenant_id, 'operator': principal.subject,
            'session_id': session_id, 'user_id': anchor.user.user_id, 'device_id': anchor.device.device_id,
            'device_ids': sorted(devices), 'as_of': now.isoformat(), 'window_seconds': self.window_seconds,
            'duplicate': duplicate, 'event_count': len(events), 'authority_excluded_events': excluded,
            'complete': False, 'subject_evidence_complete': complete,
            'legacy_complete_false_reason': 'subject_profile_requires_subject_verifier_and_detector',
            'related_adverse_authority_excluded_events': adverse_excluded,
            'adverse_evidence_scope': 'tenant_shared_subject_devices_posture_and_user_inactive; received_window_only',
            'activity_evidence_scope': 'same_tenant_analyst_user_across_sessions_and_devices',
            'resource_policy_unavailable_events': policy_unavailable, 'resource_policy_denied_events': policy_denied,
            'resource_policy_binding': self.resource_policies.configuration_binding if self.resource_policies is not None else None,
            'collection_completeness_proven': False, 'coverage_scope': 'authenticated_received_events_only',
            'failed_login_events': sum(e.action == 'LOGIN' and e.auth_context.authentication_result == 'failure' for e in events),
            'sensitive_download_mb': sum(e.behavior.download_volume_mb for e, sensitivity in zip(events, sensitivities)
                if e.action == 'DOWNLOAD' and sensitivity in {'high', 'critical'}),
            'distinct_resources': len({e.resource.resource_id for e in events}),
            'resource_ids': sorted({e.resource.resource_id for e in events}), 'actions': sorted({e.action.value for e in events}),
            'event_ids': sorted({e.event_id for e in events}),
            'saw_compromised': 'compromised' in adverse, 'saw_at_risk': 'at_risk' in adverse,
            'saw_inactive': 'inactive' in adverse,
            'saw_rejected_mfa': any(e.auth_context.mfa == 'failed' for e in events),
            'journal_head_sha256': head['hash'],
            'evidence_sha256': digest(canonical({'schema': PROFILE, 'configuration': self.config_sha256,
                'subject': [principal.tenant_id, principal.subject, anchor.user.user_id],
                'anchor_session': [session_id, anchor.device.device_id], 'devices': sorted(devices),
                'events': facts, 'related_adverse_facts': sorted(adverse_facts),
                'resource_policy_unavailable': policy_unavailable}))}


class SubjectApprovalVerifier(ApprovalVerifier):
    def verify_window(self, signed, event, tenant_id, window, *, now=None):
        approval_require(window.get('aggregation_profile') == PROFILE
            and window.get('subject_evidence_complete') is True, 'approval_subject_profile_required')
        devices = window.get('device_ids')
        authority = self.authorities.get((tenant_id, signed.context.issuer_id, signed.context.key_id))
        approval_require(isinstance(devices, list) and devices and all(isinstance(d, str) and d for d in devices)
            and len(devices) == len(set(devices)) and signed.context.device_id in devices
            and authority is not None and set(devices) <= authority.device_ids, 'approval_subject_device_scope')
        return super().verify_window(signed, event, tenant_id, window, now=now)


class PinnedSubjectApprovalVerifier(PinnedApprovalVerifier):
    def current(self):
        verifier, metadata = super().current()
        strict = SubjectApprovalVerifier(tuple(verifier.authorities.values()), revoked_approval_ids=verifier.revoked)
        return strict, metadata


class SubjectShadowDetector(ShadowDetector):
    def __init__(self, *, temporal_store, approval_verifier=None, **kwargs):
        if type(temporal_store) is not SubjectTemporalStore:
            raise TypeError('subject_temporal_store_required')
        if approval_verifier is not None and type(approval_verifier) not in {SubjectApprovalVerifier, PinnedSubjectApprovalVerifier}:
            raise TypeError('subject_approval_verifier_required')
        super().__init__(temporal_store=temporal_store, approval_verifier=approval_verifier, **kwargs)

    @property
    def config_sha256(self):
        return digest(canonical({'base_detector_configuration': super().config_sha256,
            'engine': 'f1-subject-shadow-1', 'aggregation_profile': PROFILE}))

    def evaluate(self, *args, **kwargs):
        raise ValueError('subject_shadow_requires_authenticated_received_events')

    def evaluate_signed(self, signal, principal, *, approval=None, now=None):
        self._separate_authorities()
        public = self.temporal.observe(signal, principal, now=now)
        require(public.get('aggregation_profile') == PROFILE and public.get('complete') is False
                and type(public.get('subject_evidence_complete')) is bool, 'subject_summary_contract')
        # Internal copy only: never accept a summary supplied by an API client.
        window = {**public, 'complete': public['subject_evidence_complete']}
        result = self._evaluate(signal.event, principal.tenant_id, approval=approval, now=now, window=window)
        result.update(engine='f1-subject-shadow-1', aggregation_profile=PROFILE, temporal_evidence=public)
        return result
