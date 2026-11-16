"""Conditional DNS-UDP parser bounds, with request AND response accounting.

This is a different source contract from a PCAP decoder prefix. The caller
must verify the single-worker producer and complete one-event-per-transaction
EVE projection. Neither contract proves historical application delivery.
"""

import bisect
import re
from dataclasses import dataclass

from scripts.f1_lab.native_jsonl import require

PROFILE = 'suricata-6.0.4-single-worker-complete-eve-dns-udp-tx-1'
MAX_TIME_US = 4102444800_000000
FIELDS = {'ordinal', 'timestamp_us', 'dns_udp_transactions', 'kernel_packets',
          'kernel_drops', 'decoder_packets', 'uptime', 'row_sha256'}


@dataclass(frozen=True)
class ConditionalTransactionBound:
    transaction_ordinal: int
    event_time_us: int
    seen_no_later_than_us: int
    counter_ordinal: int
    counter_row_sha256: str
    application_receipt_time_proven: bool = False
    actor_or_authority_proven: bool = False


class DnsTransactionFence:
    def __init__(self, records, transaction_count, reported_packet_count):
        require(type(transaction_count) is int and 0 < transaction_count <= 200000
                and type(reported_packet_count) is int and 0 < reported_packet_count <= 10000000,
                'dns_transaction_fence_population')
        require(type(records) is list and 0 < len(records) <= 200000, 'dns_transaction_stats_population')
        prior, points = None, []
        for row in records:
            require(type(row) is dict and set(row) == FIELDS, 'dns_transaction_stats_fields')
            require(all(type(row[k]) is int for k in FIELDS - {'row_sha256'}), 'dns_transaction_integer_counters')
            require(0 < row['ordinal'] <= 1000000 and 0 <= row['timestamp_us'] < MAX_TIME_US
                    and 0 <= row['uptime'] < 10**9 and row['kernel_drops'] == 0
                    and 0 <= row['dns_udp_transactions'] <= transaction_count
                    and 0 <= row['kernel_packets'] <= reported_packet_count
                    and 0 <= row['decoder_packets'] <= reported_packet_count,
                    'dns_transaction_counter_bounds_or_loss')
            require(type(row['row_sha256']) is str and re.fullmatch('[a-f0-9]{64}', row['row_sha256']),
                    'dns_transaction_counter_reference')
            if prior is not None:
                require(row['ordinal'] > prior['ordinal'] and all(row[k] >= prior[k] for k in
                    ('timestamp_us', 'dns_udp_transactions', 'kernel_packets', 'decoder_packets', 'uptime')),
                    'dns_transaction_clock_counter_or_order_regression')
            points.append((row['dns_udp_transactions'], row['timestamp_us'], row['ordinal'], row['row_sha256']))
            prior = row.copy()
        require(prior['dns_udp_transactions'] == transaction_count
                and prior['kernel_packets'] == prior['decoder_packets'] == reported_packet_count,
                'dns_transaction_terminal_population')
        self.total, self.points = transaction_count, tuple(points)
        self.counts = tuple(p[0] for p in points)

    def bound(self, transaction_ordinal, event_time_us):
        require(type(transaction_ordinal) is int and 0 < transaction_ordinal <= self.total
                and type(event_time_us) is int and 0 <= event_time_us < MAX_TIME_US,
                'dns_transaction_event_reference')
        # Never use a later repeated count to refresh an old observation.
        _count, stamp, ordinal, pin = self.points[bisect.bisect_left(self.counts, transaction_ordinal)]
        if event_time_us > stamp:
            return None
        return ConditionalTransactionBound(transaction_ordinal, event_time_us, stamp, ordinal, pin)
