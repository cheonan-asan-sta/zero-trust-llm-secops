"""Artifact freeze never turns old metrics into current or independent evaluation."""

import json
import subprocess

import pytest

from scripts import freeze_evaluation_evidence as module
from tests import test_runtime_release


@pytest.fixture
def archive(tmp_path):
    root = test_runtime_release.tree.__wrapped__(tmp_path)
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Test', '-c', 'user.email=test@example.test',
                    'commit', '--allow-empty', '-qm', 'Fixture'], check=True)
    directory = root / 'runtime/m6/old'
    directory.mkdir(parents=True)
    report = {'mode': 'live', 'models': {'model': {'summary': {
        'abstained_count': 7, 'response_error_count': 1, 'conservative_recall': .4,
        'metrics': {'recall': 1.0}}}}, 'wire_verification': {'same_input_bytes_per_model': True}}
    (directory / 'report.json').write_text(json.dumps(report))
    (directory / 'requests.jsonl').write_text('{"input":"observed evidence"}\n')
    return root, directory


def test_freeze_preserves_bytes_and_distinguishes_conditional_metrics(archive):
    root, directory = archive
    output = root / 'runtime/frozen'
    before = {p.name: p.read_bytes() for p in directory.iterdir()}
    result = module.freeze(output, [directory], root=root)
    assert module.verify(output, root=root, expected_manifest=result['manifest_sha256'])['verified']
    document = json.loads((output / 'manifest.json').read_text())
    summary = document['historical_reports']['runtime/m6/old/report.json']['models']['model']
    assert summary['metrics']['recall'] == 1 and summary['conservative_recall'] == .4
    assert summary['abstained_count'] == 7 and summary['response_error_count'] == 1
    assert document['new_independent_evaluation'] is False
    assert document['current_source_equivalence_claimed'] is False and document['new_model_calls'] == 0
    assert {p.name: p.read_bytes() for p in directory.iterdir()} == before


@pytest.mark.parametrize('target', ['artifact', 'source', 'manifest'])
def test_verify_rejects_changed_artifacts_source_or_external_manifest_pin(archive, target):
    root, directory = archive
    output = root / 'runtime/frozen'
    result = module.freeze(output, [directory], root=root)
    path = {'artifact': directory / 'requests.jsonl', 'source': root / 'Dockerfile',
            'manifest': output / 'manifest.json'}[target]
    path.write_text(path.read_text() + '\n')
    with pytest.raises(ValueError, match={'artifact': 'artifact_changed', 'source': 'source_changed',
                                         'manifest': 'manifest_changed'}[target]):
        module.verify(output, root=root, expected_manifest=result['manifest_sha256'])


def test_symlink_and_non_evaluation_roots_are_rejected(archive):
    root, directory = archive
    (directory / 'shortcut.json').symlink_to(root / 'Dockerfile')
    with pytest.raises(ValueError, match='symlink'):
        module.freeze(root / 'runtime/frozen', [directory], root=root)
    with pytest.raises(ValueError, match='artifact_scope'):
        module.freeze(root / 'runtime/frozen', [root / 'app'], root=root)
