from types import SimpleNamespace

import pytest

from scripts.f1_lab import provenance


@pytest.mark.parametrize('mode', ['missing_git', 'not_a_checkout', 'bad_hash'])
def test_missing_or_invalid_git_never_claims_clean_source(tmp_path, monkeypatch, mode):
    def run(*args, **kwargs):
        if mode == 'missing_git':
            raise FileNotFoundError('git')
        return SimpleNamespace(stdout='bad-hash' if mode == 'bad_hash' else '', returncode=0 if mode == 'bad_hash' else 1)

    monkeypatch.setattr(provenance.subprocess, 'run', run)
    result = provenance.git_context(tmp_path)
    assert result['source_commit'] is None and result['source_dirty'] is None
    assert 'unavailable' in result['git_metadata']


def test_git_metadata_never_replaces_source_snapshot_requirement(tmp_path, monkeypatch):
    outcomes = iter([SimpleNamespace(stdout='a'*40+'\n', returncode=0),
                     SimpleNamespace(stdout='?? scripts/new.py\n', returncode=0)])
    monkeypatch.setattr(provenance.subprocess, 'run', lambda *a, **kw: next(outcomes))
    result = provenance.git_context(tmp_path)
    assert result['source_commit'] == 'a'*40 and result['source_dirty'] is True
    assert 'hashes_still_required' in result['git_metadata']
