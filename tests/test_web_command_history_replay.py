"""The replay freezes label-free outputs and preserves the entire population."""

import hashlib
from dataclasses import replace

import pytest

from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.transfer_evaluation import sha
from scripts.f1_lab.web_command_history import build_evidence
from scripts.run_web_command_history import predict

SOURCE = 'a' * 64


def case(n):
    return hashlib.sha256((SOURCE + ':' + str(n)).encode()).hexdigest()


def setup(tmp_path, lines, old_decisions):
    preparation = {'pairs': [{'raw_sha256': SOURCE, 'rows': len(lines)}], 'files': {}}
    inputs = tmp_path/'inputs.jsonl'
    inputs.write_bytes(b''.join(canonical({'case_id': case(n), 'features': core_features(line),
        'observation_error': None})+b'\n' for n, line in enumerate(lines, 1)))
    preparation['files']['inputs.jsonl'] = {'sha256': sha(inputs)}
    old = tmp_path/'old.jsonl'
    old.write_bytes(b''.join(canonical({'case_id': case(n), 'source_index': 0, 'after': decision,
        'after_score': .99 if decision else .1 if decision is False else None,
        'before_score': .1, 'reason': 'unchanged', 'error': None if decision is not None else 'old_error'})+b'\n'
        for n, decision in enumerate(old_decisions, 1)))
    return preparation, old


def request(encoded):
    return ('192.0.2.1 - - [08/Feb/2022:07:56:00 +0000] "GET /uploads/tool.php?a='
            + encoded + ' HTTP/1.1" 200 100 "-" "test-agent"')


def test_no_truth_file_needed_and_errors_preserved(tmp_path):
    prep, old = setup(tmp_path, ['unparsed']*3, [True, False, None])
    output = tmp_path/'new.jsonl'
    result = predict(tmp_path, prep, old, sha(old), {}, output)
    assert not (tmp_path/'truth.jsonl').exists()
    assert result['population'] == 3 and result['inference_errors'] == 1
    assert result['labels_opened_by_predictor'] is False
    rows = [decode(row) for row in output.read_bytes().splitlines()]
    assert [row['after'] for row in rows] == [True, False, None]
    assert result['predictions_sha256'] == sha(output)


def test_bound_additive_replay_and_binding_failure_remains_in_population(tmp_path):
    # ["cat", "/etc/shadow"] and ["id", "-u"], encoded data only.
    seed = request('WyJjYXQiLCAiL2V0Yy9zaGFkb3ciXQ==')
    followup = request('WyJpZCIsICItdSJd')
    prep, old = setup(tmp_path, [seed, followup], [True, False])
    evidence = build_evidence([(1, 100, seed), (2, 110, followup)], SOURCE)
    output = tmp_path/'new.jsonl'
    result = predict(tmp_path, prep, old, sha(old), evidence, output)
    assert result['inference_errors'] == 0
    rows = [decode(row) for row in output.read_bytes().splitlines()]
    assert rows[0]['after'] is True and rows[1]['after'] is True
    evidence[case(2)] = replace(evidence[case(2)], intrinsic_sha256='b'*64)
    bad_output = tmp_path/'binding-failure.jsonl'
    result = predict(tmp_path, prep, old, sha(old), evidence, bad_output)
    rows = [decode(row) for row in bad_output.read_bytes().splitlines()]
    assert result['population'] == 2 and result['inference_errors'] == 1
    assert rows[1]['before'] is False and rows[1]['after'] is None


def test_unused_evidence_and_changed_baseline_fail(tmp_path):
    prep, old = setup(tmp_path, ['unparsed'], [False])
    with pytest.raises(ValueError, match='extra_baseline_or_evidence'):
        predict(tmp_path, prep, old, sha(old), {'nonexistent-case': None}, tmp_path/'new.jsonl')
    with pytest.raises(ValueError, match='baseline_hash'):
        predict(tmp_path, prep, old, 'b'*64, {}, tmp_path/'wrong-hash.jsonl')


def test_old_population_mismatch_and_reordered_cases_fail(tmp_path):
    prep, old = setup(tmp_path, ['unparsed']*2, [True])
    with pytest.raises(ValueError, match='baseline_row'):
        predict(tmp_path, prep, old, sha(old), {}, tmp_path/'missing.jsonl')
    prep, old = setup(tmp_path, ['unparsed']*2, [True, False])
    rows = old.read_bytes().splitlines(keepends=True)
    old.write_bytes(b''.join(reversed(rows)))
    with pytest.raises(ValueError, match='baseline_alignment'):
        predict(tmp_path, prep, old, sha(old), {}, tmp_path/'reordered.jsonl')


def test_existing_output_is_not_overwritten(tmp_path):
    prep, old = setup(tmp_path, ['unparsed'], [False])
    output = tmp_path/'new.jsonl'
    output.write_bytes(b'previous evidence')
    with pytest.raises(FileExistsError):
        predict(tmp_path, prep, old, sha(old), {}, output)
    assert output.read_bytes() == b'previous evidence'
