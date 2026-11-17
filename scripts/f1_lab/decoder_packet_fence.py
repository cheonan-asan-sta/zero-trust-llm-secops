"""Conditional native-decoder time bounds; never an application receipt time.

The caller must separately verify the pinned producer's single worker, complete
ordered capture and counter semantics. A coherent count sequence alone does not
establish those properties, source identity, a command or user authorization.
"""

import bisect
import re
from dataclasses import dataclass

from scripts.f1_lab.native_jsonl import require

FIELDS = frozenset({'ordinal', 'timestamp_us', 'kernel_packets', 'kernel_drops',
                    'decoder_packets', 'uptime', 'row_sha256'})
MAX_PACKETS = 10000000
MAX_TIME_US = 4102444800_000000


@dataclass(frozen=True)
class CounterPoint:
    ordinal: int
    timestamp_us: int
    decoder_packets: int
    row_sha256: str


@dataclass(frozen=True)
class ConditionalDecoderBound:
    packet_ordinal: int
    capture_time_ns: int
    seen_no_later_than_us: int
    counter_ordinal: int
    counter_row_sha256: str
    application_receipt_time_proven: bool = False
    actor_or_authority_proven: bool = False


class DecoderPacketFence:
    def __init__(self, records, full_packet_count):
        require(type(full_packet_count) is int and 0 < full_packet_count <= MAX_PACKETS,
                'decoder_fence_packet_population')
        require(type(records) is list and 0 < len(records) <= 200000, 'decoder_fence_stats_population')
        points = []
        previous = None
        for row in records:
            require(type(row) is dict and set(row) == FIELDS, 'decoder_fence_stats_fields')
            require(all(type(row[k]) is int for k in FIELDS - {'row_sha256'}), 'decoder_fence_integer_counters')
            require(0 < row['ordinal'] <= 10000000 and 0 <= row['timestamp_us'] < MAX_TIME_US
                    and 0 <= row['uptime'] < 10**9
                    and 0 <= row['kernel_packets'] <= full_packet_count
                    and 0 <= row['decoder_packets'] <= full_packet_count
                    and row['kernel_drops'] == 0, 'decoder_fence_counter_bounds_or_loss')
            require(type(row['row_sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['row_sha256']),
                    'decoder_fence_counter_reference')
            if previous is not None:
                require(row['ordinal'] > previous['ordinal']
                        and all(row[k] >= previous[k] for k in
                                ('timestamp_us', 'kernel_packets', 'decoder_packets', 'uptime')),
                        'decoder_fence_clock_counter_or_order_regression')
            # Kernel and decoder counters can be sampled at different times.
            # Neither an intermediate equality nor a kernel>=decoder relation
            # is assumed. Missing drop counters are never replaced with zero.
            points.append(CounterPoint(row['ordinal'], row['timestamp_us'],
                                       row['decoder_packets'], row['row_sha256']))
            previous = row.copy()
        require(previous['kernel_packets'] == previous['decoder_packets'] == full_packet_count,
                'decoder_fence_terminal_population')
        self.full_packet_count = full_packet_count
        self.points = tuple(points)
        self.counts = tuple(p.decoder_packets for p in points)

    def bound(self, packet_ordinal, capture_time_ns):
        require(type(packet_ordinal) is int and 0 < packet_ordinal <= self.full_packet_count
                and type(capture_time_ns) is int and 0 <= capture_time_ns < MAX_TIME_US * 1000,
                'decoder_fence_packet_reference')
        # First sufficient counter only: a later repeated counter must not move
        # an old observation forward and make it appear newly available.
        point = self.points[bisect.bisect_left(self.counts, packet_ordinal)]
        if capture_time_ns > point.timestamp_us * 1000:
            return None
        return ConditionalDecoderBound(packet_ordinal, capture_time_ns, point.timestamp_us,
                                       point.ordinal, point.row_sha256)

    def strict_past(self, packet_ordinal, capture_time_ns, current_us, *, window_us=5000000):
        require(type(current_us) is int and 0 <= current_us < MAX_TIME_US
                and type(window_us) is int and 0 < window_us <= 5000000, 'decoder_fence_query_window')
        bound = self.bound(packet_ordinal, capture_time_ns)
        if (bound is None or not current_us - window_us <= bound.seen_no_later_than_us < current_us
                or not (current_us - window_us) * 1000 <= capture_time_ns < current_us * 1000):
            return None
        return bound
