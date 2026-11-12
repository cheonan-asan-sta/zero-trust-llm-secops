import hashlib
import json

import pytest

from scripts.f1_lab.line_truth import LineTruthIndex, annotations
from scripts.f1_lab.native_jsonl import RawReference


def file(tmp_path, name, body):
    path = tmp_path/name
    path.write_bytes(body)
    return path, hashlib.sha256(body).hexdigest()


def arguments(tmp_path, raw=b'normal\nattack\n', gold=None):
    if gold is None:
        gold = b'{"line":2,"labels":["attack"]}\n'
    raw_path, raw_sha = file(tmp_path, 'raw', raw)
    labels, label_sha = file(tmp_path, 'labels', gold)
    return {'raw_path': raw_path, 'raw_sha256': raw_sha, 'label_path': labels, 'label_sha256': label_sha,
            'entity': 'host-a', 'location': '/var/log/auth.log',
            'raw_member': 'scenario/gather/host-a/logs/auth.log',
            'label_member': 'scenario/labels/host-a/logs/auth.log', 'archive_sha256': 'a'*64,
            'simulation_start': 1642723200, 'simulation_end': 1643068800, 'publisher_trimmed_pair': True}


@pytest.fixture
def index(tmp_path):
    instance = LineTruthIndex(tmp_path/'index.db')
    yield instance
    instance.close()


def lookup(index, line, host='host-a', location='/var/log/auth.log'):
    return index.lookup(host, location, RawReference(line, location).content_sha256)


def test_exact_line_numbers_and_unknown_separate(index, tmp_path):
    report = index.add_pair(**arguments(tmp_path))
    assert report['raw_rows'] == 2 and report['malicious_rows'] == 1 and report['normal_rows'] == 1
    assert lookup(index, 'attack')['truth'] is True
    assert lookup(index, 'normal')['truth'] is False
    assert lookup(index, 'missing')['truth'] is None
    assert lookup(index, 'attack', host='host-b')['truth'] is None
    assert lookup(index, 'attack', location='/var/log/other')['truth'] is None
    assert not report['goal_qualified'] and not report['provenance']['timestamp_audit_performed']


def test_duplicate_raw_content_conflicting_truth_is_unknown(index, tmp_path):
    index.add_pair(**arguments(tmp_path, raw=b'same\nsame\n'))
    result = lookup(index, 'same')
    assert result['truth'] is None and result['reason'] == 'conflicting_exact_lines'
    assert result['matching_positive_rows'] == result['matching_normal_rows'] == 1


def test_spaces_not_collapsed(index, tmp_path):
    index.add_pair(**arguments(tmp_path, raw=b'same \nsame\n'))
    assert lookup(index, 'same ')['truth'] is False and lookup(index, 'same')['truth'] is True


def test_missing_label_file_never_becomes_normal(index, tmp_path):
    args = arguments(tmp_path)
    args['label_path'].unlink()
    with pytest.raises(ValueError, match='regular_file'):
        index.add_pair(**args)
    assert lookup(index, 'normal')['truth'] is None


def test_no_default_coverage(index, tmp_path):
    args = arguments(tmp_path)
    args['publisher_trimmed_pair'] = False
    with pytest.raises(ValueError, match='paired_coverage_required'):
        index.add_pair(**args)


def test_other_host_label_file_cannot_match_by_basename(index, tmp_path):
    args = arguments(tmp_path)
    args['label_member'] = 'scenario/labels/host-b/logs/auth.log'
    with pytest.raises(ValueError, match='exact_pair_member'):
        index.add_pair(**args)


@pytest.mark.parametrize('number', [0, -1, True, '2', 3])
def test_bad_or_out_of_range_label_never_commits_partial_truth(index, tmp_path, number):
    args = arguments(tmp_path, gold=(json.dumps({'line': number, 'labels': ['attack']})+'\n').encode())
    with pytest.raises(ValueError, match='annotation_'):
        index.add_pair(**args)
    assert lookup(index, 'normal')['truth'] is None
    assert index.connection.execute('SELECT COUNT(*) FROM pairs').fetchone()[0] == 0


def test_wrong_raw_hash_rolls_back_all_rows(index, tmp_path):
    args = arguments(tmp_path)
    args['raw_sha256'] = '0'*64
    with pytest.raises(ValueError, match='raw_pair_hash'):
        index.add_pair(**args)
    assert lookup(index, 'attack')['truth'] is None


def test_empty_present_label_file_with_explicit_paired_coverage(index, tmp_path):
    report = index.add_pair(**arguments(tmp_path, gold=b''))
    assert report['malicious_rows'] == 0 and report['normal_rows'] == 2
    assert lookup(index, 'attack')['truth'] is False


def test_duplicate_annotation_line_rejected(tmp_path):
    labels, sha = file(tmp_path, 'labels', b'{"line":1,"labels":["one"]}\n{"line":1,"labels":["two"]}\n')
    with pytest.raises(ValueError, match='annotation_line'):
        annotations(labels, sha)
