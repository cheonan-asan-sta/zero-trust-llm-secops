"""Bounded EVE DNS-UDP transaction projection; never interpret counts as packets.

Suricata 6.0.4 allocates separate transactions for requests and responses. V2
answers emit one event; requests can emit one per question. The latter must be
one question here: repeated/gapped native query tx IDs reject the source.
"""

import hashlib
from dataclasses import asdict
from pathlib import Path

from scripts.f1_lab.dns_transaction_fence import DnsTransactionFence
from scripts.f1_lab.native_jsonl import MAX_ROW, decode, require
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.raw_observations import entropy
from scripts.f1_lab.suricata_single_worker import timestamp_us
from scripts.f1_lab.transfer_evaluation import sha

TRUTH = {'label', 'malicious', 'expected_alert', 'ground_truth', 'attack_labels'}


def name_shape(name):
    require(type(name) is str and len(name.encode()) <= 1024, 'dns_transaction_name_bound')
    labels = name.split('.')
    supported = (0 < len(name) <= 253 and all(1 <= len(label) <= 63 for label in labels)
        and all(33 <= ord(c) <= 126 and c != '\\' for c in name)
        and 1 + sum(1 + len(label) for label in labels) <= 255)
    payloads = sum(32 <= len(label) <= 63 and entropy(label) >= 4.5 for label in labels) if supported else 0
    non_hostname = supported and any(c in name for c in '+/*=')
    return {'qname_sha256': hashlib.sha256(name.encode()).hexdigest(), 'query_shape_supported': supported,
            'payload_labels': payloads, 'non_hostname_base64_characters': non_hostname,
            'encoded_shape': supported and payloads >= 3 and non_hostname}


def project(source, expected_bytes, output, producer):
    output = Path(output)
    require(not output.exists() and not output.is_symlink(), 'dns_transaction_projection_fresh')
    output.mkdir(parents=True)
    rows = total = transactions = queries = answers = unsupported = 0
    digest, stats_digest, query_digest = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
    stats, per_flow = [], {}
    prior_time = -1
    with (output / 'queries.jsonl').open('xb') as sink, (output / 'stats.jsonl').open('xb') as counter_sink:
        for body in iter(lambda: source.readline(MAX_ROW + 1), b''):
            rows += 1
            total += len(body)
            require(len(body) <= MAX_ROW and rows <= 1000000 and total <= expected_bytes,
                    'dns_transaction_eve_bound')
            digest.update(body)
            event = decode(body)
            require(type(event) is dict and type(event.get('event_type')) is str and not TRUTH & event.keys(),
                    'dns_transaction_eve_shape_or_truth')
            if event['event_type'] == 'stats':
                value = event['stats']
                # All fields mandatory: missing counters are not zero.
                item = {'ordinal': rows, 'timestamp_us': timestamp_us(event['timestamp']),
                    'dns_udp_transactions': value['app_layer']['tx']['dns_udp'],
                    'kernel_packets': value['capture']['kernel_packets'],
                    'kernel_drops': value['capture']['kernel_drops'], 'decoder_packets': value['decoder']['pkts'],
                    'uptime': value['uptime'], 'row_sha256': hashlib.sha256(body).hexdigest()}
                stats.append(item)
                require(len(stats) <= 200000, 'dns_transaction_stats_bound')
                encoded = canonical(item) + b'\n'
                counter_sink.write(encoded)
                stats_digest.update(encoded)
                continue
            if event['event_type'] != 'dns':
                continue
            # Count every UDP DNS request AND answer, even unsupported names.
            # TCP, v1 answers and ambiguous/dropped questions reject this profile.
            require(event['proto'] == 'UDP' and type(event['flow_id']) is int
                    and 0 <= event['flow_id'] < 2**64 and type(event['dns']) is dict
                    and not TRUTH & event['dns'].keys(), 'dns_transaction_transport_or_identity')
            dns = event['dns']
            kind, stamp = dns['type'], timestamp_us(event['timestamp'])
            require(kind in {'query', 'answer'} and stamp >= prior_time, 'dns_transaction_event_order')
            require(all(type(event[k]) is int and 0 < event[k] <= 65535 for k in ('src_port', 'dest_port'))
                    and all(type(event[k]) is str and 0 < len(event[k]) <= 64 for k in ('src_ip', 'dest_ip')),
                    'dns_transaction_endpoints')
            require(type(dns['id']) is int and 0 <= dns['id'] <= 65535, 'dns_transaction_wire_id')
            # JsonDnsLogger uses LOG_DIR_FLOW for both query and answer. These
            # endpoints describe the flow orientation, not the answer packet.
            require(event['dest_port'] == 53, 'dns_transaction_flow_direction')
            endpoints = (event['src_ip'], event['src_port'], event['dest_ip'], event['dest_port'])
            if kind == 'query':
                require(type(dns['tx_id']) is int and dns['tx_id'] >= 0,
                        'dns_transaction_query_id')
            else:
                require(type(dns.get('version')) is int and dns['version'] == 2,
                        'dns_transaction_v2_answer')
            endpoint_pin = hashlib.sha256(canonical(endpoints)).hexdigest()
            prior = per_flow.get(event['flow_id'])
            native_index = 0 if prior is None else prior[1]
            require(prior is None or prior[0] == endpoint_pin, 'dns_transaction_flow_collision')
            if kind == 'query':
                require(dns['tx_id'] == native_index, 'dns_transaction_query_gap_or_multiple_questions')
            per_flow[event['flow_id']] = endpoint_pin, native_index + 1
            require(len(per_flow) <= 200000, 'dns_transaction_flow_bound')
            prior_time = stamp
            transactions += 1
            require(transactions <= 200000, 'dns_transaction_event_bound')
            if kind == 'answer':
                answers += 1
                continue
            queries += 1
            require(type(dns['rrtype']) is str and 0 < len(dns['rrtype']) <= 32, 'dns_transaction_rrtype')
            shape = name_shape(dns['rrname'])
            unsupported += not shape['query_shape_supported']
            encoded = canonical({'transaction_ordinal': transactions, 'eve_ordinal': rows, 'event_time_us': stamp,
                'row_sha256': hashlib.sha256(body).hexdigest(), **shape}) + b'\n'
            sink.write(encoded)
            query_digest.update(encoded)
    require(total == expected_bytes, 'dns_transaction_complete_member')
    fence = DnsTransactionFence(stats, transactions, producer['reported_packet_count'])
    require(producer['runtime_started_us'] <= stats[0]['timestamp_us'] <= stats[-1]['timestamp_us']
            < producer['runtime_stopped_second_us'] + 1000000, 'dns_transaction_runtime_clock')
    observations_digest = hashlib.sha256()
    with (output / 'queries.jsonl').open('rb') as queries_in, (output / 'observations.jsonl').open('xb') as sink:
        for body in queries_in:
            query = decode(body)
            bound = fence.bound(query['transaction_ordinal'], query['event_time_us'])
            require(bound is not None, 'dns_transaction_counter_clock_contradiction')
            require(producer['runtime_started_us'] <= query['event_time_us']
                    < producer['runtime_stopped_second_us'] + 1000000, 'dns_transaction_query_runtime_clock')
            encoded = canonical({**query, 'source_transaction_bound': asdict(bound)}) + b'\n'
            sink.write(encoded)
            observations_digest.update(encoded)
    expected = {'queries.jsonl': query_digest.hexdigest(), 'stats.jsonl': stats_digest.hexdigest(),
                'observations.jsonl': observations_digest.hexdigest()}
    require(all(sha(output / name) == pin for name, pin in expected.items()), 'dns_transaction_projection_drift')
    return {'completed': True, 'eve_rows': rows, 'bytes': total, 'eve_sha256': digest.hexdigest(),
            'dns_udp_transactions': transactions, 'queries': queries, 'answers': answers,
            'unsupported_query_shapes': unsupported, 'stats_rows': len(stats), 'files': expected,
            'historical_application_receipt_proven': False, 'actor_or_authority_proven': False}
