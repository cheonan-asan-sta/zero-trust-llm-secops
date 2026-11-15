import pytest

from scripts.f1_lab.rotation_selection import select
from scripts.f1_lab.transfer_evaluation import sha
from scripts.prepare_rotation_development import prepare
from tests.test_f1_transfer_evaluation import frozen_fixture


def entries(*suffixes):
    names = ['gather/host/facts.json']
    for suffix in suffixes:
        names += ['gather/host/logs/apache2/site-access.log'+suffix,
                  'labels/host/logs/apache2/site-access.log'+suffix]
    return [{'archive_name': name, 'bounded_read_eligible': True} for name in names]


def test_each_rotation_keeps_exact_mirror_and_physical_file_context():
    pairs, skipped = select(entries('', '.1', '.2', '.10'))
    assert len(pairs) == 4 and not skipped
    assert {p['rotation'] for p in pairs} == {0, 1, 2, 10}
    for pair in pairs:
        assert pair['raw_member'].replace('gather/', 'labels/', 1) == pair['label_member']
        assert 'one physical file only' in pair['context_scope']


@pytest.mark.parametrize('suffix', ['.0', '.01', '.-1', '.10000', '.1.gz', '.gz', '.bak', '.1/other'])
def test_ambiguous_compressed_or_noncanonical_suffix_is_not_admitted(suffix):
    pairs, _ = select(entries('', suffix))
    assert len(pairs) == 1 and pairs[0]['rotation'] == 0


def test_rotated_log_cannot_borrow_labels_from_unrotated_sibling():
    values = entries('', '.1')
    values = [v for v in values if v['archive_name'] != 'labels/host/logs/apache2/site-access.log.1']
    pairs, skipped = select(values)
    assert len(pairs) == len(skipped) == 1
    assert 'truth unknown' in skipped[0]['reason']


def test_duplicate_names_and_unbounded_members_are_rejected():
    values = entries('.1')
    with pytest.raises(ValueError, match='duplicate_member'):
        select(values+values[:1])
    values[-1]['bounded_read_eligible'] = False
    with pytest.raises(ValueError, match='ineligible_pair'):
        select(values)


def test_intake_is_observed_only_and_keeps_labels_and_physical_population(tmp_path):
    root, archive, _, _ = frozen_fixture(tmp_path)
    exposure = {'source_id': 'ait-harrison', 'role': 'observed_development', 'goal_qualified': False,
                'archive_sha256': sha(archive), 'simulation_start': 1643932800, 'simulation_end': 1644364800}
    before = sha(archive)
    result = prepare(root, archive, before, tmp_path/'out', exposure)
    assert result['completed'] and result['population'] == 2
    assert not result['goal_qualified'] and not result['labels_changed']
    assert sha(archive) == before and len(result['excluded_unpaired']) == 1
    assert result['pairs'][0]['provenance']['label_sha256'] == sha(tmp_path/'out/pair-0-labels.source')
    with pytest.raises(ValueError, match='observed_role_required'):
        prepare(root, archive, before, tmp_path/'forbidden', {**exposure, 'role': 'final_reserved'})
    assert not (tmp_path/'forbidden').exists()
