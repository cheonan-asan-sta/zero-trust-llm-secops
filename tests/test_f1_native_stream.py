import hashlib
import json
from dataclasses import replace

import pytest

from scripts.f1_lab.native_binary_tree import NativeBinaryTree
from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.raw_context import PROFILE
from scripts.f1_lab.raw_semantics import PROFILE as SEMANTIC_PROFILE
from scripts.prepare_native_context import prepare as legacy_enrich
from scripts.prepare_native_raw import prepare as legacy_base
from scripts.prepare_native_stream import StreamLimits, connect, prepare

# The ten-row fixture fits in a 2 GiB Docker tmpfs. Production admission still
# reserves the default 5 GiB headroom plus its 8 GiB output and 8 GiB DB/journal.
FIXTURE_LIMITS = StreamLimits(database_bytes=1024**2, output_bytes=1024**2, min_free_bytes=1024**2)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(root, *, truth_line=1):
    root.mkdir()
    pairs = []
    sources = [
        ('apache2/access.log', (b'192.0.2.1 - - [21/Jan/2022:00:01:01 +0000] "GET /same HTTP/1.1" 500 10\n'
         b'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET /same HTTP/1.1" 404 10\n'
         b'192.0.2.1 - - [21/Jan/2022:00:00:00 +0000] "GET /other?q=one+two HTTP/1.1" 200 10\n'
         b'192.0.2.1 - - [21/Jan/2022:00:00:01 +0000] "GET /bad\xff HTTP/1.1" 404 10\n'
         b'unknown - - [21/Jan/2022:00:00:10 +0000] "GET /two HTTP/1.1" 200 10\n'
         b'192.0.2.1 - - [unparseable time] "GET /badtime HTTP/1.1" 200 10\n')),
        ('auth.log', (b'Jan 21 00:00:02 host systemd-logind[12]: New session c1 of user alice.\n'
         b'Jan 21 00:00:01 host su[11]: Successful su for alice by daemon\n'
         b'Jan 21 00:00:01 host su[11]: Successful su for alice by daemon\n'
         b'Jan 21 00:00:01 host systemd-logind[12]: New session c1 of user bob.\n')),
    ]
    for index, (name, raw) in enumerate(sources):
        raw_path, labels = root/f'pair-{index}-raw.source', root/f'pair-{index}-labels.source'
        raw_path.write_bytes(raw)
        labels.write_text(json.dumps({'line': truth_line, 'labels': ['attack']})+'\n')
        pairs.append({'pair_id': str(index)*64, 'raw_rows': len(raw.splitlines()), 'provenance': {
            'raw_member': 'gather/host/logs/'+name, 'label_member': 'labels/host/logs/'+name,
            'raw_sha256': digest(raw_path), 'label_sha256': digest(labels),
            'simulation_start': 1642723200, 'simulation_end': 1643068800}})
    manifest = {'completed': True, 'scope': 'authored equivalence and failure fixture only', 'pairs': pairs,
                'timestamp_basis': 'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check'}
    (root/'audit.json').write_text(json.dumps(manifest))
    return root, digest(root/'audit.json')


@pytest.mark.parametrize('profile', [PROFILE, SEMANTIC_PROFILE])
def test_stream_matches_legacy_bytes_case_order_truth_references_and_frozen_predictions(tmp_path, profile):
    source, sha = fixture(tmp_path/'source')
    base, old, new = tmp_path/'base', tmp_path/'old', tmp_path/'new'
    original = legacy_base(source, sha, base)
    legacy_enrich(base, digest(base/'preparation.json'), source, old, profile=profile)
    result = prepare(source, sha, new, profile=profile, limits=FIXTURE_LIMITS)
    assert result['completed'] and result['pairs'] == original['pairs']
    assert result['streaming']['base_inputs'] == original['files']['inputs.jsonl']
    for name in ('inputs.jsonl', 'truth.jsonl', 'references.jsonl'):
        assert (old/name).read_bytes() == (new/name).read_bytes()
    assert not list(new.glob('spool-*.sqlite3'))
    old_rows = [decode(body) for body in (old/'inputs.jsonl').read_bytes().splitlines()]
    new_rows = [decode(body) for body in (new/'inputs.jsonl').read_bytes().splitlines()]
    tree = NativeBinaryTree(profile=profile, min_leaf=1, class_balanced=False)
    for index, item in enumerate(old_rows):
        if item['features'] is not None:
            tree.observe_training(item['features'], bool(index % 2))
    frozen = NativeBinaryTree.restore(tree.fit().export())
    for a, b in zip(old_rows, new_rows, strict=True):
        if a['features'] is not None:
            assert frozen.probability(a['features']) == frozen.probability(b['features'])
    assert not result['goal_qualified'] and not result['inputs_contain_truth']


def test_changed_truth_only_changes_truth_sidecar_not_model_input(tmp_path):
    results = []
    for line in (1, 2):
        source, sha = fixture(tmp_path/f'source-{line}', truth_line=line)
        output = tmp_path/f'out-{line}'
        prepare(source, sha, output, limits=FIXTURE_LIMITS)
        results.append({name: (output/name).read_bytes() for name in ('inputs.jsonl', 'truth.jsonl')})
    assert results[0]['inputs.jsonl'] == results[1]['inputs.jsonl']
    assert results[0]['truth.jsonl'] != results[1]['truth.jsonl']


def test_raw_tampering_and_failed_attempt_are_not_accepted_or_overwritten(tmp_path):
    source, sha = fixture(tmp_path/'source')
    path = source/'pair-0-raw.source'
    original = path.read_bytes()
    path.write_bytes(original.replace(b'/same', b'/evil'))
    output = tmp_path/'failed'
    with pytest.raises(ValueError, match='raw_pair_hash_or_rows'):
        prepare(source, sha, output, limits=FIXTURE_LIMITS)
    failed = (output/'preparation.json').read_bytes()
    assert not json.loads(failed)['completed'] and not (output/'inputs.jsonl').exists()
    assert (output/'inputs.jsonl.part').exists()
    with pytest.raises(ValueError, match='fresh_stream_output'):
        prepare(source, sha, output, limits=FIXTURE_LIMITS)
    assert (output/'preparation.json').read_bytes() == failed
    path.write_bytes(original)
    recovered = prepare(source, sha, tmp_path/'recovered', limits=FIXTURE_LIMITS)
    clean = prepare(source, sha, tmp_path/'clean', limits=FIXTURE_LIMITS)
    assert recovered['files'] == clean['files'] and recovered['completed']


def test_resource_exhaustion_preserves_failed_receipt_and_never_produces_partial_scores(tmp_path):
    source, sha = fixture(tmp_path/'source')
    output = tmp_path/'bounded'
    with pytest.raises(ValueError, match='stream_output_bound'):
        prepare(source, sha, output, limits=replace(FIXTURE_LIMITS, output_bytes=1))
    report = json.loads((output/'preparation.json').read_bytes())
    assert not report['completed'] and not report['goal_qualified']
    assert report['failure_type'] == 'ValueError' and not (output/'truth.jsonl').exists()


def test_disk_admission_and_invalid_limits_are_explicit(tmp_path, monkeypatch):
    source, sha = fixture(tmp_path/'source')
    monkeypatch.setattr('scripts.prepare_native_stream.shutil.disk_usage', lambda _: type('Disk', (), {'free': 1})())
    output = tmp_path/'no-room'
    with pytest.raises(ValueError, match='stream_admission_headroom'):
        prepare(source, sha, output)
    assert not json.loads((output/'preparation.json').read_bytes())['completed']
    with pytest.raises(ValueError, match='stream_limits'):
        prepare(source, sha, tmp_path/'bad-limit', limits=replace(StreamLimits(), active_http_events=0))
    assert not (tmp_path/'bad-limit').exists()


def test_sqlite_resource_cap_and_time_index_are_effective(tmp_path):
    connection = connect(tmp_path/'bounded.sqlite3', 65536)
    try:
        assert connection.execute('PRAGMA max_page_count').fetchone()[0] == 16
        assert connection.execute('PRAGMA cache_size').fetchone()[0] == -16384
        steps = [row[-1] for row in connection.execute('EXPLAIN QUERY PLAN SELECT * FROM http ORDER BY (moment IS NULL), moment, ordinal')]
        assert any('http_time' in step for step in steps) and not any('TEMP B-TREE' in step for step in steps)
        import sqlite3
        with pytest.raises(sqlite3.OperationalError, match='full'):
            connection.execute('INSERT INTO observations VALUES (1,?,NULL)', (b'x'*100000,))
    finally:
        connection.close()
