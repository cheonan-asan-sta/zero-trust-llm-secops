import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.security import Principal, Role
from app.services.trusted_signals import SignalVerifier
from scripts import evaluate_f1_sessions as evaluation
from scripts.f1_lab.detector import RULE_IDS, ShadowDetector
from scripts.f1_lab.session_controls import build, prepare
from scripts.f1_lab.session_inference import infer_session
from scripts.f1_lab.temporal import TemporalStore


@pytest.fixture
def inference_lab(tmp_path):
    inputs, labels, _plans = build(variants=1)
    case_id = next(r['case_id'] for r in labels if r['family_id'] == 'slow-failed-login')
    case = next(c for c in inputs if c['case_id'] == case_id)
    case['events'] = case['events'][:3]
    sources, _registry, keys, _approvals, bindings, assignments = evaluation.trust_fixture([case], [])
    path = tmp_path / 'sources.json'
    path.write_bytes(evaluation.canonical(sources))
    store = TemporalStore(tmp_path / 'events.db', tmp_path / 'control', SignalVerifier(path), bindings)
    store.initialize()
    return {'case': case, 'source_id': assignments[case_id], 'producer_key': keys[assignments[case_id]],
        'principal': Principal('operator', 'controlled-lab', frozenset({Role.ANALYST}), 'api_key'),
        'store': store, 'detector': ShadowDetector(temporal_store=store), 'single_detector': ShadowDetector()}


def run(lab, **overrides):
    args = {**lab, **overrides}
    return infer_session(args.pop('case'), **args)


def broken(*_args, **_kwargs):
    raise RuntimeError('private diagnostic must not appear in exported evidence')


def test_real_signed_inference_keeps_time_window_gain_separate_from_raw_event_control(inference_lab):
    result = run(inference_lab)
    assert result['signed_events_attempted'] == len(result['latencies_ms']) == 3
    assert result['predicted_rule_ids'] == [RULE_IDS['credential']]
    assert not result['single_event_any_alert']
    assert result['temporal_failed_events'] == result['single_event_failed_events'] == 0


def test_failed_raw_comparator_cannot_skip_the_real_temporal_detector(inference_lab):
    result = run(inference_lab, single_detector=SimpleNamespace(evaluate=broken))
    assert result['detected'] and result['temporal_error'] is None
    assert result['single_event_failed_events'] == 3 and result['single_event_error']
    assert 'private diagnostic' not in json.dumps(result)


def test_failed_temporal_comparator_cannot_mark_successful_raw_events_failed(inference_lab):
    calls = []

    def evaluate(*args, **kwargs):
        calls.append(1)
        return inference_lab['single_detector'].evaluate(*args, **kwargs)

    result = run(inference_lab, detector=SimpleNamespace(evaluate_signed=broken),
                 single_detector=SimpleNamespace(evaluate=evaluate))
    assert len(calls) == result['temporal_failed_events'] == 3
    assert result['single_event_error'] is None and result['temporal_error']
    assert not result['detected'] and result['last_successful_prediction'] is None


def test_partial_temporal_failure_stays_an_error_even_after_a_later_alert(inference_lab):
    calls = []

    def evaluate(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            broken()
        return inference_lab['detector'].evaluate_signed(*args, **kwargs)

    result = run(inference_lab, detector=SimpleNamespace(evaluate_signed=evaluate))
    assert len(calls) == result['signed_events_attempted'] == 3
    assert result['temporal_failed_events'] == 1 and result['temporal_error']
    # The missing event was never silently counted as received.
    assert result['last_successful_prediction']['temporal_evidence']['event_count'] == 2
    assert not result['detected']


@pytest.mark.parametrize('field', ['threat', 'family_id', 'expected_rule_ids'])
def test_truth_fields_cannot_enter_the_inference_contract(inference_lab, field):
    with pytest.raises(ValidationError):
        run(inference_lab, case={**inference_lab['case'], field: 'smuggled'})


def test_issuance_failure_still_runs_both_detectors_without_fabricating_approval(inference_lab):
    plan = {'case_id': inference_lab['case']['case_id'], 'issuer_group': 'fixture-owner',
        'permitted_deviations': ['authentication_failure'], 'maximum_window_download_mb': 0,
        'approval_source': 'simulated_operator_plan_not_real_organizational_approval'}
    result = run(inference_lab, operator_plan=plan, approval_key=SimpleNamespace(sign=broken),
                 fixture_window_approvals=True)
    assert result['context_issuance_failed_events'] == 3
    assert result['single_event_failed_events'] == result['temporal_failed_events'] == 0
    assert result['single_event_error'] and result['temporal_error'] and result['detected']
    assert result['last_successful_prediction']['signed_context_status'] == 'absent'


def test_exported_run_separates_comparator_errors_and_retains_every_case(tmp_path, monkeypatch):
    dataset = tmp_path / 'dataset'
    prepared = prepare(dataset, variants=1)

    class RawFault(ShadowDetector):
        def evaluate(self, *_args, **_kwargs):
            broken()

    monkeypatch.setattr(evaluation, 'ShadowDetector', RawFault)
    result = evaluation.run(dataset, prepared['manifest_sha256'], tmp_path / 'result')
    raw, temporal = result['single_event_any_alert'], result['signed_temporal_any_alert']
    assert raw['evaluation_errors'] == result['sessions'] == 32
    assert raw['confusion']['fn'] == 18 and raw['confusion']['tn'] == 14
    assert not raw['gate_passed'] and not raw['complete_inference_run']
    assert temporal['evaluation_errors'] == 0 and temporal['complete_inference_run']
    assert sum(temporal['confusion'].values()) == 32
    assert result['failed_event_attempts']['single_event_failed_events'] == result['signed_events']
    assert result['failed_event_attempts']['temporal_failed_events'] == 0
    assert result['ephemeral_stores_remaining'] == 0
    assert not list(tmp_path.glob('.controlled-run-*'))
