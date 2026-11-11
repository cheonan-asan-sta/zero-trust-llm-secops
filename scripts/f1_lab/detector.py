"""Draft shadow detector using observed inputs, never labels, case names or access APIs."""

import hashlib
import json
import math

from cryptography.hazmat.primitives import serialization
from pydantic import Field

from app.config import get_settings
from app.models import SecurityEvent, StrictModel
from scripts.f1_lab.approvals import ApprovalRejected, ApprovalVerifier, SignedApproval
from scripts.f1_lab.registry import PinnedApprovalVerifier
from scripts.f1_lab.resource_policy import PinnedResourcePolicies, ResourcePolicyUnavailable
from scripts.f1_lab.temporal import TemporalStore

RULE_IDS = {
    'credential': '8a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d',
    'device': '9b2c3d4e-5f60-4b7c-9d8e-9f0a1b2c3d4e',
    'privilege': 'ac3d4e5f-6071-4c8d-ae9f-0a1b2c3d4e5f',
    'lateral': 'bd4e5f60-7182-4d9e-bf0a-1b2c3d4e5f60',
    'exfiltration': 'ce5f6071-8293-4eaf-801b-2c3d4e5f6071',
    'remote': 'd1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6',
}


class DraftThresholds(StrictModel):
    credential_failures: int = Field(default=3, strict=True, ge=2, le=30)
    resource_fanout: int = Field(default=8, strict=True, ge=2, le=100)
    bulk_download_mb: float = Field(default=500, gt=0, le=10000, allow_inf_nan=False)


class ShadowDetector:
    def __init__(self, *, thresholds=None, approval_verifier=None, temporal_store=None, resource_policies=None):
        self.thresholds = thresholds if thresholds is not None else DraftThresholds()
        if not isinstance(self.thresholds, DraftThresholds):
            raise TypeError('draft_threshold_contract_required')
        self.approvals = approval_verifier
        self.temporal = temporal_store
        if self.approvals is not None and not isinstance(self.approvals, (ApprovalVerifier, PinnedApprovalVerifier)):
            raise TypeError('shadow_approval_verifier_contract_required')
        if self.temporal is not None and not isinstance(self.temporal, TemporalStore):
            raise TypeError('shadow_temporal_store_contract_required')
        if resource_policies is not None and not isinstance(resource_policies, PinnedResourcePolicies):
            raise TypeError('shadow_resource_policy_contract_required')
        if self.temporal is not None:
            inherited = self.temporal.resource_policies
            if resource_policies is not None and (inherited is None or
                    inherited.configuration_binding != resource_policies.configuration_binding):
                raise ValueError('shadow_resource_policy_and_window_must_agree')
            resource_policies = inherited
        self.resource_policies = resource_policies

    @property
    def config_sha256(self):
        contract = {'engine': 'f1-shadow-5', 'thresholds': self.thresholds.model_dump(),
                    'context_policy': 'pinned_exact_event_scoped_ed25519',
                    'status': 'draft_no_production_integration',
                    'missing_evidence_policy': 'report_inconclusive_without_inventing_labels',
                    'resource_policy_binding': self.resource_policies.configuration_binding if self.resource_policies is not None else None,
                    'temporal_configuration': self.temporal.config_sha256 if self.temporal is not None else None}
        return hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()

    def evaluate(self, event: SecurityEvent, tenant_id: str, *, approval: SignedApproval | None = None, now=None):
        return self._evaluate(event, tenant_id, approval=approval, now=now)

    def _separate_authorities(self):
        if self.approvals is None:
            return
        approvals = self.approvals.current()[0] if isinstance(self.approvals, PinnedApprovalVerifier) else self.approvals
        source_keys = set()
        for source in self.temporal.verifier._sources().values():
            for key in source.keys:
                if (source.tenant_id, source.source_id, key.key_id) in self.temporal.event_sources:
                    public = serialization.load_pem_public_key(key.public_key_pem.encode())
                    source_keys.add((source.tenant_id, public.public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw)))
        for authority in approvals.authorities.values():
            identity = (authority.tenant_id, authority.public_key.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
            if identity in source_keys:
                raise ValueError('shadow_observation_and_approval_keys_must_be_distinct')

    def evaluate_signed(self, signal, principal, *, approval=None, now=None):
        if self.temporal is None:
            raise ValueError('shadow_signed_event_store_required')
        self._separate_authorities()
        window = self.temporal.observe(signal, principal, now=now)
        result = self._evaluate(signal.event, principal.tenant_id, approval=approval, now=now, window=window)
        result['temporal_evidence'] = window
        return result

    def _evaluate(self, event, tenant_id, *, approval=None, now=None, window=None):
        if get_settings().app_environment not in {'local', 'test'}:
            raise ValueError('shadow_detector_local_test_only')
        if not isinstance(event, SecurityEvent) or not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError('shadow_input_contract_required')
        if not math.isfinite(event.behavior.download_volume_mb):
            raise ValueError('shadow_nonfinite_observation')
        scopes, window_scopes, status, context_error = frozenset(), frozenset(), 'absent', None
        window_context_status = 'absent'
        if approval is not None:
            status = 'rejected'
            if self.approvals is None:
                context_error = 'approval_verifier_unconfigured'
            else:
                try:
                    scopes = self.approvals.verify(approval, event, tenant_id, now=now)
                    status = 'verified'
                except ApprovalRejected as error:
                    context_error = str(error)
        if status == 'verified' and window is not None and approval.context.window_evidence_sha256 is not None:
            try:
                window_scopes = self.approvals.verify_window(approval, event, tenant_id, window, now=now)
                window_context_status = 'verified'
            except ApprovalRejected as error:
                window_context_status = 'rejected'
                context_error = str(error)
        matches, reasons, suppressed = set(), [], []

        def signal(domain, code, *, deviation=None, temporal=False):
            allowed = window_scopes if temporal else scopes
            if deviation is not None and deviation in allowed:
                suppressed.append(code)
            else:
                matches.add(RULE_IDS[domain])
                reasons.append(code)

        action = event.action
        auth, behavior = event.auth_context, event.behavior
        device, network = event.device, event.network
        resource = event.resource
        sensitivity = resource.sensitivity
        resource_policy, resource_policy_status = None, 'not_configured'
        if self.resource_policies is not None:
            try:
                resource_policy = self.resource_policies.resolve(event, tenant_id, now=now)
                resource_policy_status = 'verified'
                sensitivity = resource_policy.effective_sensitivity
            except ResourcePolicyUnavailable:
                resource_policy_status = 'unavailable'
                signal('privilege', 'AUTHORITATIVE_RESOURCE_POLICY_UNAVAILABLE')
        if resource_policy is not None and not resource_policy.role_and_action_allowed:
            # Context signed by a business operator cannot override an explicit
            # resource-owner deny. There is no access-grant endpoint here.
            signal('privilege', 'AUTHORITATIVE_RESOURCE_POLICY_DENIED')
        # Signed business exceptions never suppress inactive identities, rejected
        # MFA or explicit compromised/at-risk posture evidence.
        if not event.user.active:
            signal('credential', 'INACTIVE_IDENTITY')
        if auth.mfa == 'failed':
            signal('credential', 'MFA_REJECTED')
        if auth.authentication_result == 'failure' and auth.failed_attempts >= self.thresholds.credential_failures:
            signal('credential', 'REPEATED_AUTHENTICATION_FAILURE', deviation='authentication_failure')
        if action == 'LOGIN' and auth.authentication_result == 'failure' and auth.failed_attempts > 0 and behavior.unusual_time:
            signal('credential', 'OFF_HOURS_FAILED_AUTHENTICATION', deviation='authentication_failure')
        if action == 'LOGIN' and network.location_anomaly and auth.mfa in {'unknown', 'not_required'}:
            signal('credential', 'ANOMALOUS_LOGIN_WITHOUT_MFA')
        if device.security_posture in {'compromised', 'at_risk'}:
            signal('device', 'ADVERSE_DEVICE_POSTURE')
        elif not device.managed and device.security_posture == 'unknown' and behavior.new_device:
            signal('device', 'NEW_UNMANAGED_UNKNOWN_DEVICE', deviation='new_unmanaged_device')
        if self.resource_policies is None and resource.required_role is not None and event.user.role != resource.required_role:
            signal('privilege', 'RESOURCE_ROLE_MISMATCH', deviation='role_mismatch')
        if action == 'REMOTE_ACCESS':
            signal('remote', 'REMOTE_ACCESS_REQUIRES_BUSINESS_CONTEXT', deviation='remote_access')
        elif network.access_method == 'remote' and auth.mfa in {'unknown', 'not_required'}:
            signal('remote', 'REMOTE_CONTEXT_WITHOUT_VERIFIED_MFA')
        if (action != 'LOGIN' and behavior.distinct_resources_10m >= self.thresholds.resource_fanout
                and (behavior.request_rate == 'high' or action == 'REMOTE_ACCESS')):
            signal('lateral', 'MULTI_RESOURCE_ACTIVITY', deviation='resource_fanout')
        if (action == 'DOWNLOAD' and sensitivity in {'high', 'critical'}
                and behavior.download_volume_mb >= self.thresholds.bulk_download_mb):
            signal('exfiltration', 'SENSITIVE_BULK_DOWNLOAD', deviation='bulk_export')
        if window is not None:
            # Only an exact authenticated fact-set approval can cover preceding
            # events. Current-event approvals never suppress these findings.
            if not window['complete']:
                signal('credential', 'TEMPORAL_AUTHORITY_OR_EVIDENCE_INCOMPLETE')
            if window['resource_policy_denied_events']:
                signal('privilege', 'RECENT_RESOURCE_POLICY_DENIED')
            if window['failed_login_events'] >= self.thresholds.credential_failures:
                signal('credential', 'REPEATED_SIGNED_FAILED_LOGIN_EVENTS', deviation='authentication_failure', temporal=True)
            if window['sensitive_download_mb'] >= self.thresholds.bulk_download_mb:
                signal('exfiltration', 'CUMULATIVE_SIGNED_SENSITIVE_DOWNLOAD', deviation='bulk_export', temporal=True)
            if window['distinct_resources'] >= self.thresholds.resource_fanout:
                signal('lateral', 'CUMULATIVE_SIGNED_RESOURCE_FANOUT', deviation='resource_fanout', temporal=True)
            if window['saw_compromised']:
                signal('device', 'RECENT_COMPROMISED_DEVICE')
            if window['saw_at_risk']:
                signal('device', 'RECENT_AT_RISK_DEVICE')
            if window['saw_inactive']:
                signal('credential', 'RECENT_INACTIVE_IDENTITY')
            if window['saw_rejected_mfa']:
                signal('credential', 'RECENT_REJECTED_MFA')
        gaps = []
        if self.resource_policies is None and action == 'ADMIN' and resource.required_role is None:
            gaps.append('RESOURCE_REQUIRED_ROLE_NOT_SUPPLIED')
        if (window is None and action == 'DOWNLOAD' and sensitivity in {'high', 'critical'}
                and behavior.download_volume_mb < self.thresholds.bulk_download_mb):
            gaps.append('AUTHENTICATED_CUMULATIVE_VOLUME_NOT_ASSESSED')
        if window is not None and not window['complete']:
            gaps.append('RECEIVED_WINDOW_AUTHORITY_INCOMPLETE')
        if resource_policy_status == 'unavailable':
            gaps.append('AUTHORITATIVE_RESOURCE_POLICY_UNAVAILABLE')
        return {'engine': 'f1-shadow-5', 'status': 'draft_shadow_only',
                'config_sha256': self.config_sha256, 'detected': bool(matches),
                'assessment_status': 'alert' if matches else 'inconclusive' if gaps else 'no_alert',
                'evidence_gaps': gaps, 'no_alert_is_access_authorization': False,
                'resource_policy_status': resource_policy_status,
                'effective_resource_sensitivity': sensitivity,
                'predicted_rule_ids': sorted(matches), 'reason_codes': reasons,
                'signed_context_status': status, 'context_error': context_error,
                'signed_window_context_status': window_context_status,
                'context_only_suppressed_signals': suppressed,
                'unsigned_exception_claim_used': False, 'external_calls': 0,
                'access_grants': 0, 'session_changes': 0}
