"""The frozen service review using typed native DNS transactions, not packets."""

import bisect
import hashlib
from pathlib import Path

from scripts.f1_lab.dns_transaction_fence import PROFILE
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.shared_dns_native_review import HEX, WINDOW_US, SharedDnsNativeReview
from scripts.f1_lab.transfer_evaluation import sha

ROLES = {'russellmitchell': 'training', 'fox': 'observed_nontraining_calibration'}
MANIFEST_FIELDS = {'schema', 'intake_sha256', 'source_transaction_contract_verified', 'producer_profile',
    'eve_sha256', 'transaction_count', 'audit_source_sha256', 'observations_file', 'observations_sha256',
    'observation_count', 'historical_application_receipt_proven', 'actor_or_authority_proven',
    'goal_qualified', 'new_independent_evaluation', 'scenario', 'role'}
OBSERVATION_FIELDS = {'transaction_ordinal', 'eve_ordinal', 'event_time_us', 'row_sha256', 'qname_sha256',
    'query_shape_supported', 'payload_labels', 'non_hostname_base64_characters', 'encoded_shape', 'source_transaction_bound'}
BOUND_FIELDS = {'transaction_ordinal', 'event_time_us', 'seen_no_later_than_us', 'counter_ordinal',
                'counter_row_sha256', 'application_receipt_time_proven', 'actor_or_authority_proven'}


def validate_observation(row, total):
    require(type(row) is dict and set(row) == OBSERVATION_FIELDS, 'dns_tx_review_observation_fields')
    require(all(type(row[k]) is int for k in ('transaction_ordinal', 'eve_ordinal', 'event_time_us', 'payload_labels'))
            and 0 < row['transaction_ordinal'] <= total and 0 < row['eve_ordinal'] <= 1000000
            and 0 <= row['event_time_us'] < 4102444800_000000 and 0 <= row['payload_labels'] <= 7,
            'dns_tx_review_observation_numbers')
    require(all(type(row[k]) is str and HEX.fullmatch(row[k]) for k in ('row_sha256', 'qname_sha256')),
            'dns_tx_review_observation_hashes')
    require(all(type(row[k]) is bool for k in ('query_shape_supported', 'non_hostname_base64_characters', 'encoded_shape'))
            and row['encoded_shape'] == (row['query_shape_supported'] and row['payload_labels'] >= 3
                                       and row['non_hostname_base64_characters'])
            and (row['query_shape_supported'] or row['payload_labels'] == 0 and not row['non_hostname_base64_characters']),
            'dns_tx_review_shape')
    bound = row['source_transaction_bound']
    require(type(bound) is dict and set(bound) == BOUND_FIELDS, 'dns_tx_review_bound_fields')
    require(all(type(bound[k]) is int for k in
                ('transaction_ordinal', 'event_time_us', 'seen_no_later_than_us', 'counter_ordinal'))
            and bound['transaction_ordinal'] == row['transaction_ordinal'] and bound['event_time_us'] == row['event_time_us']
            and row['event_time_us'] <= bound['seen_no_later_than_us'] < 4102444800_000000
            and 0 < bound['counter_ordinal'] <= 1000000, 'dns_tx_review_bound_reference')
    require(type(bound['counter_row_sha256']) is str and HEX.fullmatch(bound['counter_row_sha256'])
            and bound['application_receipt_time_proven'] is False and bound['actor_or_authority_proven'] is False,
            'dns_tx_review_no_authority_or_receipt')


class SharedDnsTransactionReview(SharedDnsNativeReview):
    def __init__(self, source_pin, raw_lines, manifest_path, manifest_pin):
        require(type(source_pin) is str and HEX.fullmatch(source_pin), 'dns_tx_review_raw_pin_type')
        require(type(raw_lines) is list and 0 < len(raw_lines) <= 100000
                and all(type(s) is str and len(s.encode()) <= MAX_ROW for s in raw_lines), 'dns_tx_review_raw_bound')
        raw = ''.join(raw_lines).encode()
        require(len(raw) <= 64 * 1024**2 and hashlib.sha256(raw).hexdigest() == source_pin, 'dns_tx_review_raw_pin')
        path = Path(manifest_path)
        require(sha(path, 65536) == manifest_pin, 'dns_tx_review_manifest_pin')
        manifest = decode(path.read_bytes())
        require(type(manifest) is dict and set(manifest) == MANIFEST_FIELDS
                and manifest['schema'] == 'staged-shared-dns-transactions-1'
                and manifest['source_transaction_contract_verified'] is True and manifest['producer_profile'] == PROFILE
                and manifest['audit_source_sha256'] == source_pin and manifest['scenario'] in ROLES
                and manifest['role'] == ROLES[manifest['scenario']]
                and manifest['observations_file'] == 'shared-dns-transactions.jsonl'
                and all(type(manifest[k]) is str and HEX.fullmatch(manifest[k]) for k in
                        ('intake_sha256', 'eve_sha256', 'observations_sha256'))
                and type(manifest['transaction_count']) is int and 0 < manifest['transaction_count'] <= 200000
                and type(manifest['observation_count']) is int
                and 0 <= manifest['observation_count'] <= manifest['transaction_count']
                and all(manifest[k] is False for k in ('historical_application_receipt_proven',
                    'actor_or_authority_proven', 'goal_qualified', 'new_independent_evaluation')),
                'dns_tx_review_manifest_scope')
        observations = path.parent / manifest['observations_file']
        require(sha(observations, 128 * 1024**2) == manifest['observations_sha256'], 'dns_tx_review_projection_pin')
        self.rows = []
        prior_tx = prior_eve = prior_bound = prior_counter = count = 0
        prior_time = -1
        with observations.open('rb') as stream:
            for body in iter(lambda: stream.readline(MAX_ROW + 1), b''):
                count += 1
                require(len(body) <= MAX_ROW and count <= 200000, 'dns_tx_review_projection_bound')
                row = decode(body)
                validate_observation(row, manifest['transaction_count'])
                bound = row['source_transaction_bound']
                require(row['transaction_ordinal'] > prior_tx and row['eve_ordinal'] > prior_eve
                        and row['event_time_us'] >= prior_time and bound['seen_no_later_than_us'] >= prior_bound
                        and bound['counter_ordinal'] >= prior_counter, 'dns_tx_review_projection_order')
                prior_tx, prior_eve, prior_time = row['transaction_ordinal'], row['eve_ordinal'], row['event_time_us']
                prior_bound, prior_counter = bound['seen_no_later_than_us'], bound['counter_ordinal']
                if row['encoded_shape']:
                    self.rows.append(row)
        require(count == manifest['observation_count'], 'dns_tx_review_projection_population')
        self.times = tuple(row['source_transaction_bound']['seen_no_later_than_us'] for row in self.rows)
        self.source, self.intake = source_pin, manifest['intake_sha256']
        self.pins = ((path, manifest_pin, 65536), (observations, manifest['observations_sha256'], 128 * 1024**2))
        self.line_pins = tuple(hashlib.sha256(s.encode()).hexdigest() for s in raw_lines)
        self.ordinal, self.last, self.disabled = 0, None, False
        self.seen, self.active = set(), {}

    def observe(self, ordinal, line, *, source_sha256):
        current = self._service_time(ordinal, line, source_sha256=source_sha256)
        if current is None:
            return None
        left = bisect.bisect_left(self.times, max(0, current - WINDOW_US))
        right = bisect.bisect_left(self.times, current)
        for row in self.rows[left:right]:
            if current - WINDOW_US <= row['event_time_us'] < current:
                bound = row['source_transaction_bound']
                return {'intake_sha256': self.intake, 'transaction_ordinal': row['transaction_ordinal'],
                        'eve_ordinal': row['eve_ordinal'], 'row_sha256': row['row_sha256'],
                        'counter_ordinal': bound['counter_ordinal'], 'counter_row_sha256': bound['counter_row_sha256'],
                        'native_parser_seen_no_later_than_us': bound['seen_no_later_than_us'],
                        'first_observed_source_unit_episode': True, 'historical_application_receipt_proven': False,
                        'actor_or_authority_proven': False, 'automatic_enforcement_allowed': False}
        return None


def open_review(source_pin, raw_lines, manifest_path, manifest_pin):
    require(sha(manifest_path, 65536) == manifest_pin, 'dns_review_dispatch_pin')
    schema = decode(Path(manifest_path).read_bytes()).get('schema')
    require(schema in {'staged-shared-dns-native-context-1', 'staged-shared-dns-transactions-1'}, 'dns_review_dispatch_schema')
    reader = SharedDnsTransactionReview if schema == 'staged-shared-dns-transactions-1' else SharedDnsNativeReview
    return reader(source_pin, raw_lines, manifest_path, manifest_pin)
