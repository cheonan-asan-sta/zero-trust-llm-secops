import json

import pytest

from scripts import prepare_native_stream as module
from tests.test_f1_native_stream import FIXTURE_LIMITS, digest, fixture


def test_label_free_features_are_identical_and_no_truth_file_is_created(tmp_path, monkeypatch):
    source, sha = fixture(tmp_path/'source')
    labeled = tmp_path/'labeled'
    module.prepare(source, sha, labeled, limits=FIXTURE_LIMITS)
    def forbidden(*args):
        raise AssertionError('sealed labels must not be opened')
    monkeypatch.setattr(module, 'annotations', forbidden)
    for path in source.glob('*-labels.source'):
        path.unlink()
    output = tmp_path/'observations'
    report = module.prepare(source, sha, output, limits=FIXTURE_LIMITS, include_truth=False)
    assert report['completed'] and report['schema'] == 'f1-native-raw-observations-1'
    assert report['labels_loaded'] is False and report['label_population_known'] is False
    assert set(report['files']) == {'inputs.jsonl', 'references.jsonl'}
    assert not (output/'truth.jsonl').exists() and not (output/'truth.jsonl.part').exists()
    assert all(pair['malicious'] is None and pair['normal'] is None for pair in report['pairs'])
    for name in report['files']:
        assert (output/name).read_bytes() == (labeled/name).read_bytes()


def test_observations_mode_does_not_require_a_label_body_digest(tmp_path):
    source, _ = fixture(tmp_path/'source')
    path = source/'audit.json'
    data = json.loads(path.read_bytes())
    for pair in data['pairs']:
        pair['provenance'].pop('label_sha256')
    path.write_text(json.dumps(data))
    assert module.prepare(source, digest(path), tmp_path/'out', limits=FIXTURE_LIMITS,
                          include_truth=False)['completed']


@pytest.mark.parametrize('bad', [None, 0, 1, 'false'])
def test_truth_mode_is_explicit_before_output_creation(tmp_path, bad):
    source, sha = fixture(tmp_path/'source')
    with pytest.raises(ValueError, match='stream_truth_mode'):
        module.prepare(source, sha, tmp_path/'out', limits=FIXTURE_LIMITS, include_truth=bad)
    assert not (tmp_path/'out').exists()
