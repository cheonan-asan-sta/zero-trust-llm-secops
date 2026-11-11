"""Draft shadow detector using observed inputs, never labels, case names or access APIs."""

import hashlib
import json
import math

from pydantic import Field

from app.config import get_settings
from app.models import SecurityEvent, StrictModel
from scripts.f1_lab.approvals import ApprovalRejected, ApprovalVerifier, SignedApproval

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
    def __init__(self, *, thresholds=None, approval_verifier: ApprovalVerifier | None = None):
        self.thresholds = thresholds if thresholds is not None else DraftThresholds()
        if not isinstance(self.thresholds, DraftThresholds):
            raise TypeError('draft_threshold_contract_required')
        self.approvals = approval_verifier

    @property
    def config_sha256(self):
        contract = {'engine': 'f1-shadow-1', 'thresholds': self.thresholds.model_dump(),
                    'context_policy': 'pinned_exact_event_scoped_ed25519',
                    'status': 'draft_no_production_integration'}
        return hashlib.sha256(json.dumps(contract, sort_keys=True).encode()).hexdigest()

    def evaluate(self, event: SecurityEvent, tenant_id: str, *, approval: SignedApproval | None = None, now=None):
        if get_settings().app_environment not in {'local', 'test'}:
            raise ValueError('shadow_detector_local_test_only')
        if not isinstance(event, SecurityEvent) or not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError('shadow_input_contract_required')
        if not math.isfinite(event.behavior.download_volume_mb):
            raise ValueError('shadow_nonfinite_observation')
        scopes, status, context_error = frozenset(), 'absent', None
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
        matches, reasons, suppressed = set(), [], []

        def signal(domain, code, *, deviation=None):
            if deviation is not None and deviation in scopes:
                suppressed.append(code)
            else:
                matches.add(RULE_IDS[domain])
                reasons.append(code)

        action = event.action
        auth, behavior = event.auth_context, event.behavior
        device, network = event.device, event.network
        resource = event.resource
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
        if resource.required_role is not None and event.user.role != resource.required_role:
            signal('privilege', 'RESOURCE_ROLE_MISMATCH', deviation='role_mismatch')
        if action == 'REMOTE_ACCESS':
            signal('remote', 'REMOTE_ACCESS_REQUIRES_BUSINESS_CONTEXT', deviation='remote_access')
        elif network.access_method == 'remote' and auth.mfa in {'unknown', 'not_required'}:
            signal('remote', 'REMOTE_CONTEXT_WITHOUT_VERIFIED_MFA')
        if (action != 'LOGIN' and behavior.distinct_resources_10m >= self.thresholds.resource_fanout
                and (behavior.request_rate == 'high' or action == 'REMOTE_ACCESS')):
            signal('lateral', 'MULTI_RESOURCE_ACTIVITY', deviation='resource_fanout')
        if (action == 'DOWNLOAD' and resource.sensitivity in {'high', 'critical'}
                and behavior.download_volume_mb >= self.thresholds.bulk_download_mb):
            signal('exfiltration', 'SENSITIVE_BULK_DOWNLOAD', deviation='bulk_export')
        return {'engine': 'f1-shadow-1', 'status': 'draft_shadow_only',
                'config_sha256': self.config_sha256, 'detected': bool(matches),
                'predicted_rule_ids': sorted(matches), 'reason_codes': reasons,
                'signed_context_status': status, 'context_error': context_error,
                'context_only_suppressed_signals': suppressed,
                'unsigned_exception_claim_used': False, 'external_calls': 0,
                'access_grants': 0, 'session_changes': 0}
