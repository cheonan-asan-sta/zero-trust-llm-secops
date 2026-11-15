"""Strictly past public-log observations; never a claim of complete/live history."""

import hashlib
import math
from collections import Counter, deque
from itertools import groupby

from scripts.f1_lab.cloud_diagnostics import canonical
from scripts.f1_lab.native_jsonl import require

CONTEXT_FIELDS = ('history_observed_calls_10s', 'history_observed_calls_60s', 'history_observed_writes_60s',
                  'history_observed_errors_60s', 'history_observed_api_kinds_60s', 'history_observed_resources_60s',
                  'history_unknown_resources_60s', 'history_observed_write_ratio_60s', 'history_observed_error_ratio_60s',
                  'history_observed_prefix_age')
COUNT_THRESHOLDS = (1, 2, 4, 8, 16, 32, 64, 128, 256)


def bucket(value):
    return sum(value >= threshold for threshold in COUNT_THRESHOLDS)


def ratio(numerator, denominator):
    return None if not denominator else sum(numerator/denominator >= threshold for threshold in (0.01, 0.1, 0.25, 0.5, 0.75, 1.0))


def reference(value):
    return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def enrich(rows):
    require(isinstance(rows, list) and len(rows) <= 50000, 'cloud_context_population')
    output, ordered, diagnostics = {}, [], Counter()
    identifiers = set()
    for identifier, view in rows:
        require(isinstance(identifier, str) and identifier not in identifiers, 'cloud_context_unique_case')
        identifiers.add(identifier)
        if view is None:
            output[identifier] = {'features': None, 'error': 'base_observation_unavailable'}
            diagnostics['base_observation_unavailable'] += 1
            continue
        require(isinstance(view, dict) and isinstance(view.get('features'), dict)
                and isinstance(view.get('provenance'), dict) and not set(CONTEXT_FIELDS) & view['features'].keys(),
                'cloud_context_base_view')
        provenance = view['provenance']
        instant, principal = provenance.get('event_time'), provenance.get('principal_reference')
        missing = not reference(principal) or type(instant) not in (int, float) or not math.isfinite(instant)
        output[identifier] = {'features': {**dict.fromkeys(CONTEXT_FIELDS), 'history_link_available': not missing}, 'error': None}
        if missing:
            diagnostics['missing_time_or_principal'] += 1
        else:
            ordered.append((instant, identifier, view))
    histories, first_seen, seen_events = {}, {}, {}
    for instant, ties in groupby(sorted(ordered, key=lambda row: (row[0], row[1])), key=lambda row: row[0]):
        # Snapshot before this whole time group. No event at the same timestamp
        # can become another tied event's past based on its row/label ordering.
        pending, signatures, events = [], {}, {}
        ties = list(ties)
        for _, identifier, view in ties:
            event = view['provenance'].get('event_reference')
            signatures[identifier] = hashlib.sha256(canonical(view)).hexdigest()
            if reference(event):
                events.setdefault(event, set()).add(signatures[identifier])
        conflicts = {event for event, values in events.items() if len(values) > 1
                     or event in seen_events and seen_events[event] not in values}
        for event in conflicts:
            seen_events[event] = None
        for _, identifier, view in ties:
            provenance, features = view['provenance'], view['features']
            principal = provenance['principal_reference']
            event = provenance.get('event_reference')
            signature = signatures[identifier]
            duplicate = False
            if event in conflicts:
                output[identifier] = {'features': None, 'error': 'event_reference_content_conflict'}
                diagnostics['event_reference_content_conflicts'] += 1
                continue
            if reference(event) and event in seen_events:
                if seen_events[event] != signature:
                    output[identifier] = {'features': None, 'error': 'event_reference_content_conflict'}
                    diagnostics['event_reference_content_conflicts'] += 1
                    continue
                duplicate = True
                diagnostics['duplicate_reference_rows_retained'] += 1
            elif reference(event):
                seen_events[event] = signature
            history = histories.setdefault(principal, deque())
            while history and history[0]['time'] < instant-60:
                history.popleft()
            before_10 = sum(row['time'] >= instant-10 for row in history)
            writes = sum(row['read_only'] is False for row in history)
            known_readonly = sum(type(row['read_only']) is bool for row in history)
            errors = sum(row['error'] for row in history)
            resources = set().union(*(row['resources'] for row in history)) if history else set()
            prefix_age = instant-first_seen.get(principal, instant)
            values = {'history_observed_calls_10s': bucket(before_10), 'history_observed_calls_60s': bucket(len(history)),
                      'history_observed_writes_60s': bucket(writes), 'history_observed_errors_60s': bucket(errors),
                      'history_observed_api_kinds_60s': bucket(len({row['api'] for row in history})),
                      'history_observed_resources_60s': bucket(len(resources)),
                      'history_unknown_resources_60s': bucket(sum(not row['resources'] for row in history)),
                      'history_observed_write_ratio_60s': ratio(writes, known_readonly),
                      'history_observed_error_ratio_60s': ratio(errors, len(history)),
                      'history_observed_prefix_age': sum(prefix_age >= t for t in (1, 10, 60, 300, 3600, 86400)),
                      'history_link_available': True}
            output[identifier] = {'features': values, 'error': None}
            if not duplicate:
                refs = provenance.get('resource_references', [])
                require(isinstance(refs, list) and all(reference(value) for value in refs), 'cloud_context_resource_references')
                pending.append((principal, {'time': instant, 'api': features['event_source']+':'+features['api_name'],
                                'read_only': features.get('read_only'), 'error': features.get('api_error_present') is True,
                                'resources': set(refs)}))
        for principal, item in pending:
            first_seen.setdefault(principal, instant)
            histories[principal].append(item)
    require(len(output) == len(rows), 'cloud_context_row_preservation')
    return output, {'rows': len(rows), **dict(diagnostics), 'time_policy': 'strictly earlier; ties withheld; inclusive lower window edge',
                    'complete_history_verified': False, 'classifier_fitted': False, 'goal_qualified': False}
