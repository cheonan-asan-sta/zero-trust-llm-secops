import hashlib
import json

import pytest

from scripts.f1_lab.raw_context import PROFILE
from scripts.f1_lab.raw_semantics import PROFILE as SEMANTIC_PROFILE
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.prepare_native_context import prepare as enrich
from scripts.prepare_native_raw import prepare


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(tmp_path, *, vpn=False, auth=False, labels_text='{"line":1,"labels":["attack"]}\n'):
    source = tmp_path/'source'
    source.mkdir()
    raw = source/'pair-0-raw.source'
    raw.write_text('Jan 21 00:00:02 host systemd-logind[12]: New session c1 of user alice.\n'
                   'Jan 21 00:00:01 host su[11]: Successful su for alice by daemon\n' if auth else
                   '2022-01-21 00:00:02 alice/192.0.2.1:1194 VERIFY OK\n'
                   '2022-01-21 00:00:01 192.0.2.1:1194 TLS: Initial packet\n' if vpn else
                   '192.0.2.1 - - [21/Jan/2022:00:00:02 +0000] "GET /two HTTP/1.1" 404 10\n'
                   '192.0.2.1 - - [21/Jan/2022:00:00:01 +0000] "GET /one HTTP/1.1" 200 10\n')
    labels = source/'pair-0-labels.source'
    labels.write_text(labels_text)
    name = 'auth.log' if auth else 'openvpn.log' if vpn else 'access.log'
    manifest = {'completed': True, 'scope': 'authored functional fixture only',
                'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
                'pairs': [{'pair_id': 'f'*64, 'raw_rows': 2,
                           'provenance': {'raw_member': 'gather/host/logs/'+name,
                                          'label_member': 'labels/host/logs/'+name,
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


def test_vpn_history_keeps_original_order_and_is_independent_of_truth(tmp_path):
    preparations, features = [], []
    for index in (1, 2):
        directory = tmp_path/str(index)
        directory.mkdir()
        source, base = fixture(directory, vpn=True, labels_text=json.dumps({'line': index, 'labels': ['attack']})+'\n')
        output = directory/'rich'
        result = enrich(base, digest(base/'preparation.json'), source, output, profile=VPN_PROFILE)
        preparations.append(result)
        features.append((output/'inputs.jsonl').read_bytes())
        assert result['completed'] and result['truth_copied_unchanged']
        assert result['files']['truth.jsonl'] == json.loads((base/'preparation.json').read_bytes())['files']['truth.jsonl']
        rows = [json.loads(body) for body in features[-1].splitlines()]
        assert rows[0]['features']['vpn_peer_seen_before']
        assert rows[0]['features']['vpn_connection_initial_before']
        assert not rows[1]['features']['vpn_peer_seen_before']
    assert features[0] == features[1]
    assert preparations[0]['files']['truth.jsonl'] != preparations[1]['files']['truth.jsonl']


def test_vpn_profile_does_not_create_endpoint_context_in_http_rows(tmp_path):
    source, base = fixture(tmp_path)
    output = tmp_path/'rich'
    enrich(base, digest(base/'preparation.json'), source, output, profile=VPN_PROFILE)
    assert all(not json.loads(body)['features']['vpn_endpoint_available'] for body in (output/'inputs.jsonl').read_bytes().splitlines())


def test_semantic_auth_history_is_causal_and_unchanged_when_only_truth_changes(tmp_path):
    inputs = []
    for index in (1, 2):
        directory = tmp_path/str(index)
        directory.mkdir()
        source, base = fixture(directory, auth=True, labels_text=json.dumps({'line': index, 'labels': ['attack']})+'\n')
        output = directory/'rich'
        result = enrich(base, digest(base/'preparation.json'), source, output, profile=SEMANTIC_PROFILE)
        assert result['completed'] and result['truth_copied_unchanged']
        inputs.append((output/'inputs.jsonl').read_bytes())
        rows = [json.loads(body) for body in inputs[-1].splitlines()]
        assert rows[0]['features']['auth_subject_prior_privilege_tool']
        assert not rows[1]['features']['auth_subject_prior_privilege_tool']
    assert inputs[0] == inputs[1]


def test_semantic_http_profile_keeps_existing_http_history(tmp_path):
    source, base = fixture(tmp_path)
    output = tmp_path/'rich'
    result = enrich(base, digest(base/'preparation.json'), source, output, profile=SEMANTIC_PROFILE)
    rows = [json.loads(body) for body in (output/'inputs.jsonl').read_bytes().splitlines()]
    assert result['completed'] and rows[0]['features']['http_semantic_available']
    assert rows[0]['features']['http_requests_1s'] == 1 and rows[1]['features']['http_requests_1s'] == 0
    assert not any(row['features']['auth_subject_context_available'] for row in rows)
