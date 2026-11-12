import hashlib
import json

import pytest

from scripts.f1_lab.raw_context import PROFILE
from scripts.prepare_native_context import prepare as enrich
from scripts.prepare_native_raw import prepare


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path):
    source = tmp_path/'source'
    source.mkdir()
    raw = source/'pair-0-raw.source'
    raw.write_text('192.0.2.1 - - [21/Jan/2022:00:00:02 +0000] "GET /two HTTP/1.1" 404 10\n'
                   '192.0.2.1 - - [21/Jan/2022:00:00:01 +0000] "GET /one HTTP/1.1" 200 10\n')
    labels = source/'pair-0-labels.source'
    labels.write_text('{"line":1,"labels":["attack"]}\n')
    manifest = {'completed': True, 'scope': 'authored functional fixture only',
                'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
                'pairs': [{'pair_id': 'f'*64, 'raw_rows': 2,
                           'provenance': {'raw_member': 'gather/host/logs/access.log',
                                          'label_member': 'labels/host/logs/access.log',
                                          'raw_sha256': digest(raw), 'label_sha256': digest(labels),
                                          'simulation_start': 1642723200, 'simulation_end': 1643068800}}]}
    meta = source/'audit.json'
    meta.write_text(json.dumps(manifest))
    base = tmp_path/'base'
    prepare(source, digest(meta), base)
    return source, base


def test_enrichment_preserves_original_order_truth_and_row_ids_but_uses_chronological_history(tmp_path):
    source, base = fixture(tmp_path)
    before = (base/'inputs.jsonl').read_bytes()
    result = enrich(base, digest(base/'preparation.json'), source, tmp_path/'rich')
    rows = [json.loads(body) for body in (tmp_path/'rich/inputs.jsonl').read_bytes().splitlines()]
    prior = [json.loads(body) for body in before.splitlines()]
    assert result['completed'] and result['feature_profile'] == PROFILE
    assert result['truth_copied_unchanged'] and not result['goal_qualified']
    assert (tmp_path/'rich/truth.jsonl').read_bytes() == (base/'truth.jsonl').read_bytes()
    assert [r['case_id'] for r in rows] == [r['case_id'] for r in prior]
    assert rows[0]['features']['http_requests_1s'] == 1  # second in chronological order
    assert rows[1]['features']['http_requests_1s'] == 0  # first; no future information
    assert (base/'inputs.jsonl').read_bytes() == before
    assert all('labels' not in row['features'] for row in rows)


def test_forged_case_alignment_cannot_be_hidden_by_rehashing_preparation(tmp_path):
    source, base = fixture(tmp_path)
    inputs = base/'inputs.jsonl'
    rows = [json.loads(body) for body in inputs.read_bytes().splitlines()]
    rows[0]['case_id'] = '0'*64
    inputs.write_text(''.join(json.dumps(row)+'\n' for row in rows))
    receipt = base/'preparation.json'
    data = json.loads(receipt.read_bytes())
    data['files']['inputs.jsonl'] = {'sha256': digest(inputs), 'bytes': inputs.stat().st_size}
    receipt.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='original_row_alignment'):
        enrich(base, digest(receipt), source, tmp_path/'rich')
    assert not json.loads((tmp_path/'rich/preparation.json').read_bytes())['completed']


def test_changed_raw_bytes_are_not_used_even_with_unchanged_base_input(tmp_path):
    source, base = fixture(tmp_path)
    raw = source/'pair-0-raw.source'
    raw.write_bytes(raw.read_bytes().replace(b'/one', b'/bad'))
    with pytest.raises(ValueError, match='raw_hash_or_rows'):
        enrich(base, digest(base/'preparation.json'), source, tmp_path/'rich')
    assert not (tmp_path/'rich/inputs.jsonl').exists()
