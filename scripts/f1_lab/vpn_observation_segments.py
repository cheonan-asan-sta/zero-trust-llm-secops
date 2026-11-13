"""Post-seal VPN support audit; endpoint segments are not authenticated sessions."""

import math

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.native_jsonl import MAX_ROW, require
from scripts.f1_lab.vpn_context import endpoint

GAP_SECONDS = 60
MAX_EVENTS = 100000
MAX_CONNECTIONS = 10000


def stage_counts():
    return {'threat_segments_detected': 0, 'threat_segments_missed': 0,
            'normal_segments_alerting': 0, 'normal_segments_quiet': 0,
            'threat_segments_with_only_normal_row_alerts': 0,
            'segments_with_inference_errors': 0}


class VPNObservationSegments:
    """One physical file, exact IPv4 endpoint and <=60s gaps, original order.

    Names/IP values are transient linking observations, never identity or trust.
    Missing time closes open segments; time regression starts a new epoch.
    A normal-row alert in a mixed segment cannot count as detected threat.
    """

    def __init__(self):
        self.active, self.last_time, self.ordinal, self.finished = {}, None, 0, False
        self.total = {stage: counts() for stage in ('before', 'after')}
        self.summary = {'segments': 0, 'threat_labeled_segments': 0, 'normal_only_segments': 0,
            'mixed_label_segments': 0, 'assigned_rows': 0, 'unassigned_rows': 0,
            'missing_endpoint_rows': 0, 'missing_time_rows': 0, 'time_regressions': 0,
            'max_threat_rows_in_one_segment': 0, 'max_rows_in_one_segment': 0,
            'stages': {stage: stage_counts() for stage in ('before', 'after')}}

    def close(self, key):
        group = self.active.pop(key)
        summary = self.summary
        positive, negative = group['positive'], group['negative']
        summary['segments'] += 1
        summary['threat_labeled_segments'] += positive > 0
        summary['normal_only_segments'] += positive == 0
        summary['mixed_label_segments'] += positive > 0 and negative > 0
        summary['max_threat_rows_in_one_segment'] = max(summary['max_threat_rows_in_one_segment'], positive)
        summary['max_rows_in_one_segment'] = max(summary['max_rows_in_one_segment'], positive+negative)
        for stage, flags in group['stages'].items():
            target = summary['stages'][stage]
            if positive:
                target['threat_segments_detected' if flags['positive_alert'] else 'threat_segments_missed'] += 1
                target['threat_segments_with_only_normal_row_alerts'] += flags['negative_alert'] and not flags['positive_alert']
            else:
                target['normal_segments_alerting' if flags['negative_alert'] else 'normal_segments_quiet'] += 1
            target['segments_with_inference_errors'] += flags['error']

    def close_all(self):
        for key in list(self.active):
            self.close(key)

    def observe(self, ordinal, line, moment, malicious, before, after):
        require(not self.finished and type(ordinal) is int and ordinal == self.ordinal+1
                and ordinal <= MAX_EVENTS, 'vpn_segment_ordinal_or_bound')
        require(isinstance(line, str) and len(line.encode('utf8')) <= MAX_ROW, 'vpn_segment_line_bound')
        require(moment is None or type(moment) in {int, float} and math.isfinite(moment), 'vpn_segment_time')
        require(type(malicious) is bool and all(value is None or type(value) is bool for value in (before, after)),
                'vpn_segment_label_or_prediction')
        parsed = endpoint(line)
        resetting = moment is None or self.last_time is not None and moment < self.last_time
        require(parsed is None or moment is None or resetting or parsed[1] in self.active
                or len(self.active) < MAX_CONNECTIONS, 'vpn_segment_connection_bound')
        self.ordinal = ordinal
        for stage, value in (('before', before), ('after', after)):
            record(self.total[stage], malicious, value)
        self.summary['missing_endpoint_rows'] += parsed is None
        self.summary['missing_time_rows'] += moment is None
        if moment is None:
            self.close_all()
            self.last_time = None
        else:
            if self.last_time is not None and moment < self.last_time:
                self.close_all()
                self.summary['time_regressions'] += 1
            self.last_time = moment
        if parsed is None or moment is None:
            self.summary['unassigned_rows'] += 1
            return
        self.summary['assigned_rows'] += 1
        key = parsed[1]
        if key in self.active and moment-self.active[key]['last_time'] > GAP_SECONDS:
            self.close(key)
        require(key in self.active or len(self.active) < MAX_CONNECTIONS, 'vpn_segment_connection_bound')
        group = self.active.setdefault(key, {'last_time': moment, 'positive': 0, 'negative': 0,
            'stages': {stage: {'positive_alert': False, 'negative_alert': False, 'error': False}
                       for stage in ('before', 'after')}})
        group['last_time'] = moment
        group['positive' if malicious else 'negative'] += 1
        for stage, value in (('before', before), ('after', after)):
            group['stages'][stage]['positive_alert' if malicious else 'negative_alert'] |= value is True
            group['stages'][stage]['error'] |= value is None

    def finish(self):
        require(not self.finished and self.ordinal > 0, 'vpn_segment_finished_or_empty')
        self.close_all()
        self.finished = True
        require(self.summary['assigned_rows']+self.summary['unassigned_rows'] == self.ordinal,
                'vpn_segment_population')
        return {'schema': 'f1-vpn-observation-segments-1', 'completed': True,
            'population': self.ordinal, 'line_metrics': {stage: metrics(value) for stage, value in self.total.items()},
            'summary': self.summary, 'gap_seconds': GAP_SECONDS, 'goal_qualified': False,
            'authenticated_sessions_measured': False, 'independent_trials_established': False,
            'line_metrics_replaced': False, 'model_selection_feedback_allowed': False,
            'limitations': ['same physical file and logged IPv4 endpoint; endpoint reuse/NAT may join distinct sessions',
                'missing time/endpoints are unassigned, retained in original line metrics',
                'physical file boundaries, >60s gaps and clock regression split observations',
                'publisher malicious-line labels; mixed segments reported, no relabeling',
                'normal-row-only alarms do not count as detected malicious rows',
                'no independence confidence interval or final target certification']}
