"""Descriptive, telemetry-stratified transfer results; never final goal certification."""

from scripts.f1_lab.native_bayes import counts, metrics
from scripts.f1_lab.native_jsonl import MAX_ROWS, require

KINDS = ('access', 'error', 'vpn')
TARGETS = {'precision': .95, 'recall': .95, 'f1': .95,
           'false_positive_rate': .05, 'false_negative_rate': .05}


def checked_counts(value):
    require(isinstance(value, dict), 'transfer_summary_counts')
    result = {key: value.get(key) for key in counts()}
    require(all(type(n) is int and 0 <= n <= MAX_ROWS for n in result.values()), 'transfer_summary_integer_counts')
    population = sum(result[key] for key in ('tp', 'fp', 'fn', 'tn'))
    require(0 < population <= MAX_ROWS and result['inference_errors'] <= result['fp']+result['fn'],
            'transfer_summary_population')
    require(metrics(result) == value, 'transfer_summary_metrics_disagree')
    return result


def described(value):
    result = metrics(value)
    positives, negatives = value['tp']+value['fn'], value['fp']+value['tn']
    result.update(positive_support=positives, negative_support=negatives,
        false_negative_rate=value['fn']/positives if positives else None,
        positive_fraction=positives/result['population'])
    conditions = {key: result[key] is not None and (result[key] >= target if key in
        {'precision', 'recall', 'f1'} else result[key] <= target) for key, target in TARGETS.items()}
    result.update(target_conditions=conditions, both_classes_present=positives > 0 and negatives > 0,
        observed_metric_targets_met=all(conditions.values()) and positives > 0 and negatives > 0
                                    and value['inference_errors'] == 0)
    return result


def summarize(scored, raw_audit):
    require(isinstance(scored, dict) and isinstance(raw_audit, dict)
            and raw_audit.get('completed') is True and scored.get('goal_qualified') is False,
            'transfer_summary_scope')
    pairs, rows = raw_audit.get('pairs'), scored.get('per_source')
    require(isinstance(pairs, list) and isinstance(rows, list) and 0 < len(pairs) == len(rows) <= 64,
            'transfer_summary_sources')
    kinds = {kind: {name: counts() for name in ('before', 'after')} for kind in KINDS}
    total = {name: counts() for name in ('before', 'after')}
    sources, seen = [], set()
    for row in rows:
        index = row.get('source_index')
        require(type(index) is int and 0 <= index < len(pairs) and index not in seen,
                'transfer_summary_source_index')
        seen.add(index)
        pair = pairs[index]
        kind = pair['provenance']['kind']
        require(kind in KINDS and type(pair['raw_rows']) is int and pair['raw_rows'] > 0,
                'transfer_summary_kind_rows')
        item = {'source_index': index, 'kind': kind, 'metrics': {}}
        for stage in ('before', 'after'):
            value = checked_counts(row['metrics'][stage])
            require(sum(value[key] for key in ('tp', 'fp', 'fn', 'tn')) == pair['raw_rows'],
                    'transfer_summary_source_population')
            for key, number in value.items():
                kinds[kind][stage][key] += number
                total[stage][key] += number
            item['metrics'][stage] = described(value)
        sources.append(item)
    require(len(seen) == len(pairs), 'transfer_summary_source_coverage')
    for stage, value in total.items():
        require(checked_counts(scored['metrics'][stage]) == value, 'transfer_summary_total_disagrees')
    population = sum(total['after'][key] for key in ('tp', 'fp', 'fn', 'tn'))
    require(type(scored.get('population')) is int and scored['population'] == population
            and type(raw_audit.get('population')) is int and raw_audit['population'] == population,
            'transfer_summary_total_population')
    grouped = []
    for kind, stages in kinds.items():
        present = any(stages['after'][key] for key in ('tp', 'fp', 'fn', 'tn'))
        grouped.append({'kind': kind, 'present': present,
            'metrics': {name: described(value) for name, value in stages.items()} if present else None})
    return {'schema': 'f1-stratified-source-transfer-summary-1', 'completed': True,
        'evaluation_unit': 'physical_log_line', 'targets': TARGETS,
        'overall': {name: described(value) for name, value in total.items()},
        'by_telemetry_kind': grouped, 'per_source': sorted(sources, key=lambda row: row['source_index']),
        'all_declared_kinds_have_two_classes': all(row['present'] and row['metrics']['after']['both_classes_present']
                                                  for row in grouped),
        'all_declared_kind_point_targets_met': all(row['present'] and row['metrics']['after']['observed_metric_targets_met']
                                                  for row in grouped),
        'goal_qualified': False, 'original_six_domain_goal_replaced': False,
        'independent_human_review': False, 'session_metrics_measured': False,
        'original_domain_coverage': {name: 'unverified' for name in
            ('credential', 'device', 'privilege', 'lateral', 'exfiltration', 'remote')},
        'confidence_intervals': None,
        'limitations': ['descriptive line counts; repeated/correlated events are not independent sessions',
            'access/error/VPN telemetry kinds are not the original six security domains',
            'undefined rates remain null; no absent class is counted as successful evaluation',
            'observed point targets do not certify independence, production performance or goal completion']}


def markdown(result):
    def rate(number):
        return '산출 불가' if number is None else f'{number*100:.4f}%'
    lines = ['# 출처 분리 평가: 수집 종류별 결과', '',
        '단위는 물리 로그 행이다. 원래 여섯 영역의 독립 최종 목표 달성 판정은 아니다.', '',
        '| 범위 | TP | FP | FN | TN | 정밀도 | 재현율 | F1 | 오탐률 | 미탐률 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, value in [('전체', result['overall']['after']), *[(row['kind'], row['metrics']['after']
            if row['present'] else None) for row in result['by_telemetry_kind']]]:
        if value is None:
            lines.append(f'| {name} | 자료 없음 | — | — | — | — | — | — | — | — |')
        else:
            cells = [name, *(str(value[k]) for k in ('tp', 'fp', 'fn', 'tn')),
                     *(rate(value[k]) for k in ('precision', 'recall', 'f1', 'false_positive_rate', 'false_negative_rate'))]
            lines.append('| '+' | '.join(cells)+' |')
    lines += ['', ('정상 또는 위협 표본이 없으면 해당 비율은 산출 불가로 표시한다. '
        '전체 수치는 큰 로그 집단의 영향을 받으므로 종류별 실패를 대체하지 않는다.'), '',
        ('세션·주체·기기·공격 계열 독립성, 원래 여섯 영역 대응 및 운영 성능은 별도로 검증해야 한다. '
        '행을 독립 표본으로 가정한 신뢰구간은 제공하지 않는다.'), '']
    return '\n'.join(lines)
