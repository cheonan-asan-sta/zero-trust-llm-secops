"""Exact crypto/liveness attribution guards; native controls cover real PAM."""

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from scripts.f1_lab import execution_risk_evidence as risk
from scripts.f1_lab.live_execution_context import PamExecutionContext
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.run_systemd_caller_controls import token_for
from tests.test_service_caller_identity import callbacks, fixture


def policy(tmp_path, registry, *, revoked=(), version=1):
    now = datetime.now(UTC)
    value = risk.CallerRiskPolicy(version=version, issued_at=now,
        expires_at=now+timedelta(minutes=5), authentication_registry_sha256=registry.sha256,
        revoked_caller_refs=list(revoked))
    path = tmp_path/'risk-policy.json'
    path.write_bytes(canonical(value.model_dump(mode='json')))
    return risk.PinnedCallerRiskPolicy(path, hashlib.sha256(path.read_bytes()).hexdigest()), value


@pytest.fixture
def live(tmp_path, monkeypatch):
    keys, service, identity_key, broker, issue = fixture(tmp_path)
    request = issue()
    configured, _ = callbacks(keys, service)
    receipt, event, proofs = broker.dispatch(request.request_id, token_for(request, identity_key), **configured)
    runtime = proofs[0].observation
    monkeypatch.setattr(risk, 'snapshot_process', lambda _: (event.boot_id, runtime))
    selected, _ = policy(tmp_path, broker.registry)
    return broker, request, receipt, event, proofs, selected


def observe(live, **changes):
    broker, request, receipt, event, proofs, selected = live
    args = {'caller_registry': broker.registry, 'request': request, 'receipt': receipt, 'risk_policy': selected}
    args.update(changes)
    return risk.service_evidence(broker.joiner, event, proofs, **args)


def decision(event, *, kind='audit-share', base=None, uncertainty=.98):
    return risk.add_identity_uncertainty(base or OperationDecision(.1, .1, False, False, 'independent'),
        event, kind=kind, uncertainty_score=uncertainty)


def test_current_crypto_bound_identity_resolves_only_supplemental_alert_and_keeps_review(live):
    *_, event, _, _ = live
    before = decision(event)
    evidence = observe(live)
    after = risk.refine_execution(before, evidence)
    assert evidence.state == 'approved' and before.alert and not after.alert
    assert after.score == .1 and after.review and not after.automatic_enforcement_allowed


@pytest.mark.parametrize('base', [OperationDecision(.99, .99, True, True, 'payload'),
    OperationDecision(.1, .96, True, True, 'independent_retained_risk'),
    OperationDecision(.1, .9, False, True, 'independent_review'),
    OperationDecision(.95, .1, False, True, 'high_original_baseline'),
    OperationDecision(.1, .1, True, False, 'independent_alarm')])
def test_verified_caller_never_overrides_independent_threat_or_boundary_review(live, base):
    *_, event, _, _ = live
    before = decision(event, base=base)
    assert risk.refine_execution(before, observe(live)) is before


@pytest.mark.parametrize('field', ['caller_registry','request','receipt','risk_policy'])
def test_missing_part_cannot_clear_existing_alert(live, field):
    *_, event, _, _ = live
    before = decision(event)
    facts = observe(live, **{field: None})
    assert facts.state == 'unavailable' and risk.refine_execution(before, facts) is before


@pytest.mark.parametrize('field,value', [('signature','A'*86),('service_evidence_sha256','f'*64),
    ('caller_ref_sha256','f'*64),('request_sha256','f'*64),('event_sha256','f'*64)])
def test_forged_or_cross_request_receipt_never_resolves_risk(live, field, value):
    _, _, receipt, event, _, _ = live
    before = decision(event)
    facts = observe(live, receipt=receipt.model_copy(update={field: value}))
    assert facts.state == 'unavailable' and risk.refine_execution(before, facts) is before


@pytest.mark.parametrize('changes', [{'pid':43},{'start_ticks':2},{'command_sha256':'f'*64},
    {'effective_uid':0},{'login_uid':1}])
def test_reused_or_changed_live_process_never_inherits_caller_approval(live, monkeypatch, changes):
    _, _, _, event, proofs, _ = live
    monkeypatch.setattr(risk, 'snapshot_process', lambda _: (event.boot_id, proofs[0].observation.model_copy(update=changes)))
    assert observe(live).state == 'unavailable'


def test_explicit_current_revocation_detects_missed_caller_risk(live, tmp_path):
    broker, _, receipt, event, _, _ = live
    selected, _ = policy(tmp_path, broker.registry, revoked=[receipt.caller_ref_sha256], version=2)
    before = decision(event, uncertainty=.1)
    evidence = observe(live, risk_policy=selected)
    after = risk.refine_execution(before, evidence)
    assert not before.alert and evidence.state == 'adverse' and after.alert and after.review
    assert not after.automatic_enforcement_allowed


@pytest.mark.parametrize('mutation', ['hash','expired','version','wrong_registry','duplicate'])
def test_revocation_policy_cannot_be_used_if_untrusted_or_ambiguous(live, tmp_path, mutation):
    broker, _, receipt, _, _, _ = live
    selected, value = policy(tmp_path, broker.registry, revoked=[receipt.caller_ref_sha256])
    if mutation == 'version':
        selected.minimum_version = 2
    else:
        if mutation == 'hash':
            selected.path.write_bytes(b'{}')
        else:
            updates = {'expired': {'expires_at': value.issued_at},
                'wrong_registry': {'authentication_registry_sha256': 'f'*64},
                'duplicate': {'revoked_caller_refs': [receipt.caller_ref_sha256]*2}}[mutation]
            selected.path.write_bytes(canonical(value.model_copy(update=updates).model_dump(mode='json')))
            selected.sha256 = hashlib.sha256(selected.path.read_bytes()).hexdigest()
    assert observe(live, risk_policy=selected).state == 'unavailable'


@pytest.mark.parametrize('kind,event_sha', [('auth',None),('audit-share','f'*64)])
def test_evidence_cannot_move_between_kind_or_event(live, kind, event_sha):
    *_, event, _, _ = live
    before = decision(event)
    facts = risk.ExecutionRiskEvidence(kind, event_sha or event.sha256, 'approved','a'*64)
    assert risk.refine_execution(before, facts) is before


def test_generic_historical_alert_cannot_be_relabelled_as_context(live):
    *_, event, _, _ = live
    with pytest.raises(ValueError, match='bound_decision'):
        risk.refine_execution(OperationDecision(.98,.98,True,True,'historical'), observe(live))
    with pytest.raises(ValueError, match='attribution'):
        risk.add_identity_uncertainty(decision(event), event, kind='auth', uncertainty_score=.98)


@pytest.mark.parametrize('revoked', [False, True])
def test_pam_uses_same_verified_caller_and_current_revocation_policy(live, tmp_path, monkeypatch, revoked):
    broker, request, receipt, event, proofs, selected = live
    if revoked:
        selected, _ = policy(tmp_path, broker.registry, revoked=[receipt.caller_ref_sha256])
    context = PamExecutionContext('consistent','b'*64,'local_oidc',receipt.caller_ref_sha256)
    monkeypatch.setattr(risk,'collect_pam_context',lambda *args,**kwargs:context)
    facts = risk.pam_evidence(object(),object(),broker.joiner,event,proofs,cursor_sha256='c'*64,
        caller_registry=broker.registry,request=request,receipt=receipt,risk_policy=selected)
    assert facts.state == ('adverse' if revoked else 'approved')


def test_pam_missing_or_moved_receipt_still_fails_after_trusted_journal_boundary(live, monkeypatch):
    broker, request, receipt, event, proofs, selected = live
    context = PamExecutionContext('consistent','b'*64,'local_oidc',receipt.caller_ref_sha256)
    monkeypatch.setattr(risk,'collect_pam_context',lambda *args,**kwargs:context)
    facts = risk.pam_evidence(object(),object(),broker.joiner,event,proofs,cursor_sha256='c'*64,
        caller_registry=broker.registry,request=request,receipt=receipt.model_copy(update={'event_sha256':'f'*64}),
        risk_policy=selected)
    assert facts.state == 'unavailable'


@pytest.mark.parametrize('state', ['approved', 'adverse'])
def test_missing_evidence_digest_never_changes_original_decision(live, state):
    *_, event, _, _ = live
    before=decision(event)
    assert risk.refine_execution(before,risk.ExecutionRiskEvidence('audit-share',event.sha256,state)) is before
