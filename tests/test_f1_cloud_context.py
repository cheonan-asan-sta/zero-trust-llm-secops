import hashlib
import json
from copy import deepcopy

import pytest

from scripts.f1_lab.cloud_context import enrich
from scripts.f1_lab.cloud_observations import partition_with_request_facts
from scripts.prepare_cloud_context import prepare


def view(time, *, principal='principal', event='event', readonly=True, error=False):
    ref = lambda value: hashlib.sha256(value.encode()).hexdigest() if value else None
    return {'features': {'event_source': 's3.amazonaws.com', 'api_name': 'GetObject', 'read_only': readonly,
                         'api_error_present': error},
            'provenance': {'event_time': time, 'principal_reference': ref(principal), 'event_reference': ref(event),
                           'resource_references': []}}


def test_strict_past_and_time_ties_do_not_depend_on_original_row_order():
    rows = [('first', view(10, event='first')), ('tie-a', view(11, event='a')),
            ('tie-b', view(11, event='b')), ('last', view(12, event='last'))]
    result, _ = enrich(rows)
    reversed_result, _ = enrich(list(reversed(rows)))
    assert result == reversed_result
    assert result['first']['features']['history_observed_calls_10s'] == 0
    assert result['tie-a']['features']['history_observed_calls_10s'] == 1
    assert result['tie-a']['features'] == result['tie-b']['features']
    assert result['last']['features']['history_observed_calls_10s'] == 2


def test_appending_arbitrary_future_events_cannot_change_past_features():
    past = [('a', view(0, event='a')), ('b', view(1, event='b'))]
    first, _ = enrich(past)
    second, _ = enrich(past+[('future', view(60, event='different', readonly=False, error=True))])
    assert all(first[key] == second[key] for key, _ in past)


def test_principal_isolation_and_missing_link_not_global_fallback():
    rows = [('a', view(0, principal='one', event='a')), ('b', view(1, principal='two', event='b')),
            ('c', view(2, principal=None, event='c')), ('d', view(None, event='d'))]
    result, stats = enrich(rows)
    assert result['b']['features']['history_observed_calls_60s'] == 0
    assert result['c']['features']['history_observed_calls_60s'] is None
    assert result['d']['features']['history_link_available'] is False
    assert stats['missing_time_or_principal'] == 2


def test_known_write_denominator_and_exact_window_boundaries():
    rows = [('a', view(0, event='a', readonly=None)), ('b', view(50, event='b', readonly=False, error=True)),
            ('c', view(60, event='c')), ('d', view(60.1, event='d'))]
    result, _ = enrich(rows)
    at = result['c']['features']
    assert at['history_observed_calls_60s'] == 2
    assert at['history_observed_calls_10s'] == 1
    assert at['history_observed_write_ratio_60s'] == 6  # Only one known readOnly, and it is a write.
    assert at['history_observed_error_ratio_60s'] == 4  # One error / two observed calls.


def test_duplicate_source_rows_remain_but_history_counts_unique_event_once():
    same = view(0, event='same')
    result, stats = enrich([('a', same), ('duplicate', deepcopy(same)), ('next', view(1, event='next'))])
    assert len(result) == 3 and result['a'] == result['duplicate']
    assert result['next']['features']['history_observed_calls_60s'] == 1
    assert stats['duplicate_reference_rows_retained'] == 1


def test_conflicting_equal_time_references_are_unavailable_not_arbitrarily_selected():
    rows = [('a', view(0, event='same')), ('b', view(0, event='same', readonly=False)), ('c', view(1, event='c'))]
    result, stats = enrich(rows)
    reverse, _ = enrich(list(reversed(rows)))
    assert result == reverse and stats['event_reference_content_conflicts'] == 2
    assert result['a']['features'] is result['b']['features'] is None
    assert result['c']['features']['history_observed_calls_60s'] == 0


def test_later_conflict_does_not_change_already_observed_past():
    original = [('a', view(0, event='same'))]
    first, _ = enrich(original)
    later, stats = enrich(original+[('future', view(1, event='same', readonly=False))])
    assert first['a'] == later['a'] and later['future']['features'] is None
    assert stats['event_reference_content_conflicts'] == 1


def fixture(tmp_path, reverse_labels=False):
    source = tmp_path/'input'
    source.mkdir(parents=True)
    for index in (0, 1):
        observations, labels = [], []
        for ordinal in range(3):
            raw = {'eventID': f'event-{index}-{ordinal}', 'eventTime': f'2026-02-18T10:58:{index*3+ordinal:02d}Z',
                   'eventName': 'GetObject', 'eventSource': 's3.amazonaws.com',
                   'userIdentity': {'type': 'IAMUser', 'principalId': 'same-principal'},
                   'should_sample': bool(ordinal % 2) != reverse_labels}
            if raw['should_sample']:
                raw['attack_name'] = 'scenario'
            observation, gold = partition_with_request_facts(raw)
            identifier = f'{index}-{ordinal}'
            observations.append({'case_id': identifier, 'observation': observation, 'error': None})
            labels.append({'case_id': identifier, **gold})
        for name, values in [('observations', observations), ('truth', labels)]:
            (source/f'asset-{index}-{name}.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in values))
    return source, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.iterdir()}


def test_workflow_retains_order_and_opaque_truth_and_is_label_independent(tmp_path):
    source, anchors = fixture(tmp_path/'a')
    result = prepare(source, anchors, tmp_path/'out-a')
    second, other = fixture(tmp_path/'b', reverse_labels=True)
    opposite = prepare(second, other, tmp_path/'out-b')
    assert result['completed'] and result['truth_copied_unchanged'] and opposite['completed']
    for index in (0, 1):
        assert (tmp_path/f'out-a/asset-{index}-truth.jsonl').read_bytes() == (source/f'asset-{index}-truth.jsonl').read_bytes()
        assert (tmp_path/f'out-a/asset-{index}-observations.jsonl').read_bytes() == (tmp_path/f'out-b/asset-{index}-observations.jsonl').read_bytes()


@pytest.mark.parametrize('fault', ['hash', 'alignment', 'rows'])
def test_workflow_rejects_changed_or_misaligned_source_without_publishing_success(tmp_path, fault):
    source, anchors = fixture(tmp_path)
    path = source/'asset-0-truth.jsonl'
    lines = path.read_text().splitlines()
    if fault == 'hash':
        path.write_text('\n'.join(lines)+'\n ')
    elif fault == 'rows':
        path.write_text('\n'.join(lines[:-1])+'\n')
        anchors[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    else:
        item = json.loads(lines[0])
        item['case_id'] = 'wrong'
        lines[0] = json.dumps(item)
        path.write_text('\n'.join(lines)+'\n')
        anchors[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        prepare(source, anchors, tmp_path/'out')
    assert not (tmp_path/'out/preparation.json').exists()
