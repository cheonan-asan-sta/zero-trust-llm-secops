import pytest

from scripts.f1_lab import vpn_observation_segments as module
from scripts.f1_lab.vpn_observation_segments import VPNObservationSegments


def line(peer='192.0.2.8:12345', name=''):
    return f'2022-02-03 10:00:00 {name}{peer} TLS: Initial packet from peer\n'


def add(audit, *, moment=1, malicious=False, before=False, after=False, raw=None):
    audit.observe(audit.ordinal+1, line() if raw is None else raw, moment, malicious, before, after)


def test_many_detected_lines_are_one_observation_segment_not_many_independent_attacks():
    audit = VPNObservationSegments()
    for i in range(28):
        add(audit, moment=i, malicious=True, before=True, after=True)
    result = audit.finish()
    assert result['line_metrics']['after']['tp'] == 28
    assert result['summary']['threat_labeled_segments'] == 1
    assert result['summary']['stages']['after']['threat_segments_detected'] == 1
    assert result['summary']['max_threat_rows_in_one_segment'] == 28
    assert not result['goal_qualified'] and not result['authenticated_sessions_measured']
    assert not result['independent_trials_established'] and not result['line_metrics_replaced']


def test_normal_alarm_in_mixed_segment_does_not_hide_missed_threat():
    audit = VPNObservationSegments()
    add(audit, moment=1, before=True, after=True)
    add(audit, moment=2, malicious=True, before=False, after=False)
    result = audit.finish()
    assert result['summary']['mixed_label_segments'] == 1
    assert result['summary']['stages']['after']['threat_segments_detected'] == 0
    assert result['summary']['stages']['after']['threat_segments_missed'] == 1
    assert result['summary']['stages']['after']['threat_segments_with_only_normal_row_alerts'] == 1
    assert result['line_metrics']['after']['fn'] == result['line_metrics']['after']['fp'] == 1


def test_normal_only_alarm_counts_one_segment_while_preserving_all_false_positive_rows():
    audit = VPNObservationSegments()
    for i in range(4):
        add(audit, moment=i, before=True, after=True)
    result = audit.finish()
    assert result['summary']['normal_only_segments'] == 1
    assert result['summary']['stages']['after']['normal_segments_alerting'] == 1
    assert result['line_metrics']['after']['fp'] == 4


@pytest.mark.parametrize('times,expected', [([1, 61], 1), ([1, 61.01], 2), ([1, 1], 1), ([3, 2], 2)])
def test_fixed_gap_boundary_and_original_order(times, expected):
    audit = VPNObservationSegments()
    for stamp in times:
        add(audit, moment=stamp)
    assert audit.finish()['summary']['segments'] == expected


def test_other_endpoint_and_changed_name_do_not_infer_an_authenticated_identity():
    audit = VPNObservationSegments()
    add(audit, raw=line(name='alice/'))
    add(audit, raw=line(name='bob/'))
    add(audit, raw=line(peer='192.0.2.8:12346'))
    add(audit, raw=line(peer='192.0.2.9:12345'))
    assert audit.finish()['summary']['segments'] == 3


def test_missing_time_closes_history_and_unparsed_rows_remain_in_line_counts():
    audit = VPNObservationSegments()
    add(audit)
    add(audit, moment=None, malicious=True, after=None)
    add(audit, moment=2)
    add(audit, moment=3, raw='unparsed server log', before=True, after=True)
    result = audit.finish()
    assert result['summary']['segments'] == 2
    assert result['summary']['unassigned_rows'] == 2
    assert result['population'] == 4 and result['line_metrics']['after']['inference_errors'] == 1
    assert result['line_metrics']['after']['fn'] == result['line_metrics']['after']['fp'] == 1


def test_clock_regression_closes_other_connections_too():
    audit = VPNObservationSegments()
    add(audit, moment=100)
    add(audit, moment=90, raw=line(peer='192.0.2.9:12345'))
    add(audit, moment=101)
    result = audit.finish()
    assert result['summary']['segments'] == 3 and result['summary']['time_regressions'] == 1


def test_prediction_errors_cannot_be_counted_as_successful_detection():
    audit = VPNObservationSegments()
    add(audit, malicious=True, after=None)
    result = audit.finish()
    assert result['summary']['stages']['after']['segments_with_inference_errors'] == 1
    assert result['summary']['stages']['after']['threat_segments_missed'] == 1
    assert result['line_metrics']['after']['fn'] == 1


@pytest.mark.parametrize('moment', [True, float('nan'), float('inf'), '1'])
def test_invalid_time_rejected(moment):
    with pytest.raises(ValueError, match='vpn_segment_time'):
        add(VPNObservationSegments(), moment=moment)


@pytest.mark.parametrize('value', [1, 'true', [], {}])
def test_non_boolean_decision_rejected(value):
    with pytest.raises(ValueError, match='vpn_segment_label_or_prediction'):
        add(VPNObservationSegments(), after=value)


def test_population_order_and_capacity_guards(monkeypatch):
    audit = VPNObservationSegments()
    with pytest.raises(ValueError, match='ordinal'):
        audit.observe(2, line(), 1, False, False, False)
    monkeypatch.setattr(module, 'MAX_CONNECTIONS', 1)
    add(audit)
    with pytest.raises(ValueError, match='connection_bound'):
        add(audit, raw=line(peer='192.0.2.9:12345'))
    assert audit.finish()['population'] == 1


def test_empty_finished_and_oversized_input_rejected(monkeypatch):
    audit = VPNObservationSegments()
    with pytest.raises(ValueError, match='empty'):
        audit.finish()
    monkeypatch.setattr(module, 'MAX_ROW', 10)
    with pytest.raises(ValueError, match='line_bound'):
        add(audit)
    monkeypatch.setattr(module, 'MAX_ROW', 1000)
    add(audit)
    audit.finish()
    with pytest.raises(ValueError, match='finished'):
        audit.finish()
    with pytest.raises(ValueError, match='ordinal'):
        add(audit)


def test_physical_files_never_share_an_endpoint_segment():
    first, second = VPNObservationSegments(), VPNObservationSegments()
    add(first, malicious=True, after=True)
    add(second, after=True)
    assert first.finish()['summary']['threat_labeled_segments'] == 1
    assert second.finish()['summary']['normal_only_segments'] == 1
