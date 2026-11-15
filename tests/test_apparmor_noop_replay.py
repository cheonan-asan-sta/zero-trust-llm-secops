import hashlib
from pathlib import Path

import pytest

from scripts.f1_lab.native_jsonl import decode
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_apparmor_noop_review import observations, predict


def setup(tmp_path):
    raw = tmp_path/'raw'
    raw.mkdir()
    first = b'type=SERVICE_START msg=audit(1700000000.123:11): pid=1 uid=0 unit=example comm="systemd"\n'
    source_sha = hashlib.sha256(first).hexdigest()
    pair = {'raw_member':'one-host/logs/audit/audit.log', 'raw_sha256':source_sha, 'rows':1}
    (raw/'pair-0-raw.source').write_bytes(first)
    manifest = {'completed':True, 'pairs':[{'provenance':pair}]}
    (raw/'audit.json').write_bytes(canonical(manifest))
    preparation = {'source_manifest_sha256':sha(raw/'audit.json'), 'pairs':[pair]}
    baseline = tmp_path/'baseline.jsonl'
    row = {'case_id':hashlib.sha256((source_sha+':1').encode()).hexdigest(),
           'source_index':0, 'before_score':.99, 'after_score':.99,
           'after':True, 'reason':'unchanged', 'error':None}
    baseline.write_bytes(canonical(row)+b'\n')
    return preparation, raw, baseline, row


def test_replay_preserves_non_noop_source_population_and_decision_without_labels(tmp_path):
    preparation, raw, baseline, old = setup(tmp_path)
    out = tmp_path/'predictions.jsonl'
    report = predict(preparation, raw, baseline, sha(baseline), out)
    assert report['population'] == 1 and report['changed_decisions'] == 0
    assert report['inference_errors'] == report['selected_noop_rows'] == 0
    assert not report['labels_opened_by_predictor']
    row = decode(out.read_bytes())
    assert row['case_id'] == old['case_id'] and row['before'] is row['after'] is True
    assert row['before_score'] == row['after_score'] == .99
    assert not (tmp_path/'truth.jsonl').exists()


@pytest.mark.parametrize('change', ['raw', 'manifest', 'row_count', 'baseline_hash', 'case_order', 'extra_row'])
def test_replay_rejects_modified_source_manifest_population_and_case_order(tmp_path, change):
    prep, raw, baseline, row = setup(tmp_path)
    pin = sha(baseline)
    if change == 'raw':
        (raw/'pair-0-raw.source').write_bytes(b'changed')
    elif change == 'manifest':
        (raw/'audit.json').write_bytes(b'{}')
    elif change == 'row_count':
        prep['pairs'][0]['rows'] = 2
    elif change == 'baseline_hash':
        pin = 'f'*64
    elif change == 'case_order':
        row['source_index'] = 1
        baseline.write_bytes(canonical(row)+b'\n')
        pin = sha(baseline)
    else:
        baseline.write_bytes((canonical(row)+b'\n')*2)
        pin = sha(baseline)
    with pytest.raises(ValueError, match='apparmor_'):
        predict(prep, raw, baseline, pin, tmp_path/'predictions.jsonl')
    assert not (tmp_path/'predictions.jsonl').exists()


def test_replay_does_not_overwrite_prior_prediction_artifact(tmp_path):
    prep, raw, baseline, _ = setup(tmp_path)
    out = tmp_path/'predictions.jsonl'
    out.write_bytes(b'previous-result')
    with pytest.raises(ValueError, match='apparmor_fresh_prediction'):
        predict(prep, raw, baseline, sha(baseline), out)
    assert out.read_bytes() == b'previous-result'


def test_no_source_can_borrow_raw_bytes_from_a_different_manifest(tmp_path):
    prep, raw, _, _ = setup(tmp_path)
    v = decode((raw/'audit.json').read_bytes())
    v['pairs'][0]['provenance']['raw_member'] = 'other-host/logs/audit/audit.log'
    (raw/'audit.json').write_bytes(canonical(v))
    prep['source_manifest_sha256'] = sha(raw/'audit.json')
    with pytest.raises(ValueError, match='apparmor_raw_binding'):
        observations(prep, raw)


def test_error_rows_remain_errors_and_are_not_removed_from_population(tmp_path):
    prep, raw, baseline, row = setup(tmp_path)
    row.update(after=None, after_score=None, error='original_inference_error')
    baseline.write_bytes(canonical(row)+b'\n')
    out = tmp_path/'predictions.jsonl'
    result = predict(prep, raw, baseline, sha(baseline), out)
    assert result['population'] == result['inference_errors'] == 1
    assert decode(out.read_bytes())['after'] is None
    assert decode(out.read_bytes())['error'] == 'original_inference_error'


def test_unrelated_source_kind_is_copied_without_opening_nonmounted_raw(tmp_path):
    prep, raw, baseline, _ = setup(tmp_path)
    prep['pairs'][0]['raw_member'] = 'one-host/logs/access.log'
    Path(raw/'pair-0-raw.source').unlink()
    result = predict(prep, raw, baseline, sha(baseline), tmp_path/'predictions.jsonl')
    assert result['population'] == 1 and result['changed_decisions'] == 0
