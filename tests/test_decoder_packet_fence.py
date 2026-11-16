"""Conditional time math cannot certify an arbitrary producer or a human."""

from dataclasses import FrozenInstanceError

import pytest

from scripts.f1_lab.decoder_packet_fence import DecoderPacketFence


def row(ordinal=1, timestamp_us=10000000, decoder_packets=1, kernel_packets=1, **overrides):
    return {'ordinal': ordinal, 'timestamp_us': timestamp_us, 'decoder_packets': decoder_packets,
            'kernel_packets': kernel_packets, 'kernel_drops': 0, 'uptime': ordinal,
            'row_sha256': 'a' * 64, **overrides}


def test_first_sufficient_counter_is_a_bound_not_application_receipt_or_identity():
    fence = DecoderPacketFence([row(), row(2, 11000000, 2, 2)], 2)
    bound = fence.strict_past(1, 9999999000, 10000001)
    assert bound.seen_no_later_than_us == 10000000
    assert bound.counter_ordinal == 1 and bound.counter_row_sha256 == 'a' * 64
    assert bound.application_receipt_time_proven is False and bound.actor_or_authority_proven is False


def test_later_repeated_counter_cannot_refresh_old_observation():
    fence = DecoderPacketFence([row(), row(2, 20000000)], 1)
    assert fence.strict_past(1, 9999999000, 20000001) is None


def test_a_later_capture_cannot_be_laundered_by_an_earlier_counter():
    fence = DecoderPacketFence([row()], 1)
    assert fence.bound(1, 10000000001) is None


@pytest.mark.parametrize('capture,current,eligible', [
    (10000000000, 10000000, False), (10000000000, 10000001, True),
    (10000000000, 15000000, True), (10000000000, 15000001, False),
    (9999999999, 15000000, False),
])
def test_strict_time_and_both_age_boundaries(capture, current, eligible):
    assert (DecoderPacketFence([row()], 1).strict_past(1, capture, current) is not None) is eligible


@pytest.mark.parametrize('counter', ['kernel_drops', 'kernel_packets', 'decoder_packets', 'timestamp_us',
                                     'uptime', 'ordinal', 'row_sha256'])
def test_missing_fields_do_not_become_safe_defaults(counter):
    value = row()
    del value[counter]
    with pytest.raises(ValueError, match='stats_fields'):
        DecoderPacketFence([value], 1)


@pytest.mark.parametrize('field', ['kernel_drops', 'kernel_packets', 'decoder_packets', 'timestamp_us',
                                  'uptime', 'ordinal'])
@pytest.mark.parametrize('value', [True, 1.0, '1', None])
def test_boolean_string_float_and_null_counters_rejected(field, value):
    with pytest.raises(ValueError, match='integer_counters'):
        DecoderPacketFence([row(**{field: value})], 1)


@pytest.mark.parametrize('field,value', [('kernel_drops', 1), ('decoder_packets', 2),
                                        ('kernel_packets', 2), ('uptime', -1), ('ordinal', 0),
                                        ('timestamp_us', -1)])
def test_loss_and_invalid_ranges_rejected(field, value):
    with pytest.raises(ValueError, match='counter_bounds_or_loss'):
        DecoderPacketFence([row(**{field: value})], 1)


@pytest.mark.parametrize('field,value', [('ordinal', 1), ('timestamp_us', 9999999),
                                       ('kernel_packets', 0), ('decoder_packets', 0), ('uptime', 0)])
def test_reset_or_clock_or_physical_order_regression_rejected(field, value):
    with pytest.raises(ValueError, match='regression'):
        DecoderPacketFence([row(), row(2, 11000000, **{field: value})] if field not in {'ordinal', 'timestamp_us'}
                           else [row(), {**row(2, 11000000), field: value}], 1)


def test_asynchronous_kernel_and_decoder_samples_are_not_falsely_ordered():
    fence = DecoderPacketFence([row(kernel_packets=0), row(2, 11000000)], 1)
    assert fence.bound(1, 9000000000).counter_ordinal == 1


def test_terminal_counters_must_cover_the_complete_capture():
    with pytest.raises(ValueError, match='terminal_population'):
        DecoderPacketFence([row()], 2)


def test_caller_mutation_and_returned_bound_cannot_change_history():
    data = [row()]
    fence = DecoderPacketFence(data, 1)
    data[0]['timestamp_us'] = 1
    assert fence.bound(1, 9000000000).seen_no_later_than_us == 10000000
    with pytest.raises(FrozenInstanceError):
        fence.bound(1, 9000000000).seen_no_later_than_us = 1


@pytest.mark.parametrize('ordinal,stamp,current,window', [(True, 0, 0, 1), (0, 0, 0, 1),
    (2, 0, 0, 1), (1, True, 0, 1), (1, -1, 0, 1), (1, 0, True, 1),
    (1, 0, -1, 1), (1, 0, 0, True), (1, 0, 0, 5000001), (1, 0, 0, 0)])
def test_invalid_query_references_rejected(ordinal, stamp, current, window):
    with pytest.raises(ValueError):
        DecoderPacketFence([row()], 1).strict_past(ordinal, stamp, current, window_us=window)
