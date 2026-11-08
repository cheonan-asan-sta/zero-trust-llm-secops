"""Bounded synthetic requests inside the existing operator; credentials stay in RAM."""

import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from scripts.continuous_mtls_assets import _request, mint
from scripts.measure_signal_infrastructure import distribution
from scripts.pep_lab import DOCUMENT_HASH


def validate_rows(rows, expected, delivered):
    if (not isinstance(rows, list) or len(rows) != 16 or type(expected) is not int
            or not 0 <= expected <= 16 or type(delivered) is not int or delivered != expected):
        raise ValueError('selection_delivery_count')
    allowed = 0
    for row in rows:
        if (type(row.get('status')) is not int or row['status'] not in {200, 403}
                or row.get('tls_version') not in {'TLSv1.2', 'TLSv1.3'}
                or type(row.get('http_ms')) not in {int, float}
                or (row.get('body_sha256') == DOCUMENT_HASH) != (row['status'] == 200)):
            raise ValueError('selection_response_contract')
        allowed += row['status'] == 200
    if allowed != expected:
        raise ValueError('selection_allowed_count')
    return distribution([row['http_ms'] for row in rows])


def run(kind, concurrency):
    if kind not in {'valid', 'shared', 'missing'} or type(concurrency) is not int or concurrency not in {1, 4, 8}:
        raise ValueError('selection_workload_scope')
    pairs = []
    for _ in range(16 if kind == 'valid' else int(kind == 'shared')):
        session = 'selection-' + uuid.uuid4().hex
        value = mint({'session_id': session})
        if value['status'] != 200 or value['body']['session']['status'] != 'ACTIVE' or not value['body']['grant_token']:
            raise ValueError('selection_mint_failed')
        pairs.append((session, value['body']['grant_token']))
    headers = [{'X-Session-ID': pair[0], 'X-Grant-Token': pair[1]} for pair in pairs]
    if kind == 'shared':
        headers *= 16
    if kind == 'missing':
        headers = [{} for _ in range(16)]

    def request(header):
        started = time.perf_counter()
        result = _request({'profile': 'frontend', 'path': '/documents', 'headers': header})
        return {name: result[name] for name in ('status', 'body_sha256', 'tls_version')} | {
            'http_ms': (time.perf_counter() - started) * 1000}

    def wave():
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            rows = list(pool.map(request, headers))
        return {'rows': rows, 'wave_seconds': time.perf_counter() - started}

    result = {'kind': kind, 'concurrency': concurrency, **wave()}
    if kind == 'shared':
        result['replay'] = wave()
    return result


if __name__ == '__main__':
    value = json.load(sys.stdin)
    print(json.dumps(run(value['kind'], value['concurrency'])))
