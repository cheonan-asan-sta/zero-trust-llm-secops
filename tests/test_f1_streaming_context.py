import hashlib
import random

import pytest

from scripts.f1_lab.raw_context import HTTPWindow
from scripts.f1_lab.streaming_context import IncrementalHTTPWindow, http_fields


def request(client='192.0.2.1', target='/index', status=200):
    return f'{client} - - [21/Jan/2022:00:00:00 +0000] "GET {target} HTTP/1.1" {status} 10'


def test_incremental_window_matches_old_oracle_with_ties_edges_clients_and_repeated_targets():
    rng = random.Random(20261112)
    slow, fast = HTTPWindow(), IncrementalHTTPWindow()
    moment = 0
    for index in range(3000):
        moment += rng.choice([0, 0, .125, 1, 10, 60, 61])
        line = request(client=rng.choice(['192.0.2.1', '192.0.2.2', '2001:db8::1', 'unknown']),
                       target='/'+str(rng.randrange(20)), status=rng.choice([200, 301, 404, 500]))
        instant = None if index % 53 == 0 else moment
        assert fast.observe(line, instant) == slow.observe(line, instant)
    assert fast.peak_events < 100 and fast.events > 2000


def test_no_future_information_and_inclusive_window_boundaries():
    slow, fast = HTTPWindow(), IncrementalHTTPWindow()
    for instant in (0, 0, 1, 10, 60, 60.0001, 70, 71, 130, 190):
        assert fast.observe(request(), instant) == slow.observe(request(), instant)
    with pytest.raises(ValueError, match='time_regression'):
        fast.observe(request(), 189)


def test_expired_last_client_does_not_leak_counter_or_target_state():
    slow, fast = HTTPWindow(), IncrementalHTTPWindow()
    for index in range(1000):
        client = f'192.0.{index//250}.{index%250+1}'
        assert fast.observe(request(client=client), index*61) == slow.observe(request(client=client), index*61)
    assert len(fast.groups) == 1 and len(fast.queues[60]) == 1
    assert fast.peak_events == fast.peak_groups == 1


def test_total_source_can_exceed_old_request_list_limit_while_active_state_stays_bounded():
    fast = IncrementalHTTPWindow(max_active=100)
    target = hashlib.sha256(b'/index').digest()
    for index in range(100_005):
        result = fast.observe_fields('192.0.2.1', target, False, index*2)
    assert result['http_window_available'] and fast.events == 100_005
    assert fast.peak_events == 31 and len(fast.queues[60]) == 31


@pytest.mark.parametrize('limits,lines,code', [
    ({'max_active': 2}, [request(), request(client='192.0.2.2'), request()], 'active_bound'),
    ({'max_groups': 1}, [request(), request(client='192.0.2.2')], 'group_bound'),
    ({'max_per_client': 1}, [request(), request()], 'event_bound'),
])
def test_resource_caps_fail_explicitly_instead_of_truncating_or_scoring_a_prefix(limits, lines, code):
    fast = IncrementalHTTPWindow(**limits)
    with pytest.raises(ValueError, match=code):
        for line in lines:
            fast.observe(line, 0)


def test_invalid_or_missing_observations_do_not_create_context():
    fast = IncrementalHTTPWindow()
    assert http_fields('no request') is None
    for line, moment in [('no request', 1), (request(), None), (request(client='unknown'), 2)]:
        assert fast.observe(line, moment) == HTTPWindow().observe(line, moment)
    assert not fast.groups and not fast.events
