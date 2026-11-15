import json

import pytest

from scripts.freeze_m7 import SOURCE, freeze_candidate, verify_frozen


def test_freeze_roundtrip_and_no_rebaseline(tmp_path):
    destination = tmp_path / 'frozen'
    anchor = freeze_candidate(SOURCE.parent / 'pilot', destination)
    assert verify_frozen(destination, anchor)['independent_review'] == 'pending'
    with pytest.raises(ValueError):
        freeze_candidate(SOURCE.parent / 'pilot', destination)
    with pytest.raises(ValueError):
        verify_frozen(destination, '0' * 64)


@pytest.mark.parametrize('name', ['labels.jsonl', 'evaluation.jsonl', 'source.json', 'NOTICE.md'])
def test_changed_frozen_bytes_rejected(tmp_path, name):
    destination = tmp_path / 'frozen'
    anchor = freeze_candidate(SOURCE.parent / 'pilot', destination)
    with (destination / name).open('ab') as f:
        f.write(b'\n')
    with pytest.raises(ValueError):
        verify_frozen(destination, anchor)


def test_independent_review_cannot_be_claimed_by_editing_freeze(tmp_path):
    destination = tmp_path / 'frozen'
    anchor = freeze_candidate(SOURCE.parent / 'pilot', destination)
    manifest = json.loads((destination / 'freeze.json').read_bytes())
    manifest['independent_review'] = 'complete'
    (destination / 'freeze.json').write_text(json.dumps(manifest), encoding='utf8')
    with pytest.raises(ValueError):
        verify_frozen(destination, anchor)
