"""Label-free controlled inference; each comparator owns its failures and denominator."""

import base64
import hashlib
import time
from datetime import timedelta

from app.services.trusted_signals import canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.approvals import ApprovalContext, event_digest, sign
from scripts.f1_lab.session_controls import ControlledSession, OperatorPlan


def infer_session(case, *, source_id, producer_key, principal, store, detector, single_detector,
                  operator_plan=None, approval_key=None, fixture_window_approvals=False):
    """No label, family or expected-rule input. A failed comparator cannot skip its peer."""
    case = ControlledSession.model_validate(case)
    if operator_plan is not None:
        operator_plan = OperatorPlan.model_validate(operator_plan)
        if operator_plan.case_id != case.case_id or approval_key is None:
            raise ValueError('controlled_plan_identity_or_key')
    raw_matches, temporal_matches, latencies = set(), set(), []
    raw_errors = temporal_errors = issuance_errors = 0
    last_prediction = None
    for event in case.events:
        started, now = time.perf_counter(), event.timestamp
        signal = SignedSessionSignal(tenant_id=case.tenant_id, source_id=source_id, key_id='event-key',
            session_id=case.session_id, expected_version=0, event=event,
            issued_at=now, expires_at=now+timedelta(seconds=90), signature='A'*86)
        signature = base64.urlsafe_b64encode(producer_key.sign(canonical_signal(signal))).decode().rstrip('=')
        signal = signal.model_copy(update={'signature': signature})
        approval = None
        if operator_plan is not None:
            try:
                window = store.observe(signal, principal, now=now) if fixture_window_approvals else None
                context = ApprovalContext(
                    approval_id='approval-'+hashlib.sha256((case.case_id+event.event_id).encode()).hexdigest()[:32],
                    tenant_id=case.tenant_id,
                    issuer_id='owner-'+hashlib.sha256(operator_plan.issuer_group.encode()).hexdigest()[:16],
                    key_id='business-key', event_sha256=event_digest(event), user_id=event.user.user_id,
                    device_id=event.device.device_id, resource_id=event.resource.resource_id, action=event.action,
                    permitted_deviations=operator_plan.permitted_deviations,
                    maximum_download_mb=operator_plan.maximum_window_download_mb,
                    issued_at=now, expires_at=now+timedelta(seconds=60),
                    window_evidence_sha256=window['evidence_sha256'] if window is not None else None)
                approval = sign(context, approval_key)
            except (ValueError, TypeError, RuntimeError):
                # A missing proof never authorizes a deviation. Both comparators
                # still run without it; the cohort cannot pass a clean-run gate.
                issuance_errors += 1
        try:
            raw_prediction = single_detector.evaluate(event, case.tenant_id, approval=approval, now=now)
            raw_matches.update(raw_prediction['predicted_rule_ids'])
        except (ValueError, TypeError, RuntimeError):
            raw_errors += 1
        try:
            prediction = detector.evaluate_signed(signal, principal, approval=approval, now=now)
            temporal_matches.update(prediction['predicted_rule_ids'])
            last_prediction = prediction
        except (ValueError, TypeError, RuntimeError):
            temporal_errors += 1
        latencies.append((time.perf_counter()-started)*1000)
    return {'case_id': case.case_id, 'signed_events_attempted': len(case.events),
        'single_event_any_alert': bool(raw_matches), 'single_event_any_matches': sorted(raw_matches),
        'detected': bool(temporal_matches), 'predicted_rule_ids': sorted(temporal_matches),
        'last_successful_prediction': last_prediction,
        'single_event_error': 'controlled_inference_failed' if raw_errors or issuance_errors else None,
        'temporal_error': 'controlled_inference_failed' if temporal_errors or issuance_errors else None,
        'single_event_failed_events': raw_errors, 'temporal_failed_events': temporal_errors,
        'context_issuance_failed_events': issuance_errors, 'latencies_ms': latencies,
        'fallback_policy': 'any_successful_alert_else_no_alert; errors retained and gate fails'}
