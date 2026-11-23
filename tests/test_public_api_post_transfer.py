import pytest

from scripts import evaluate_public_api_post_transfer as transfer
from scripts.evaluate_local_remote_holdout import fingerprint, read, write
from scripts.evaluate_public_api_post_transfer import (
    OBSERVATIONS,
    decode_observation,
    is_successful_post,
    verify_reproduced_candidate,
)


def test_testbed_projection_excludes_campaign_fields_and_authorization_value():
    assert not {"label", "label_source", "attack_family", "attack_tool", "campaign_id"} & set(
        OBSERVATIONS
    )
    row = {
        "http_method": "POST",
        "url_path_raw": "/records",
        "url_query": "page=1",
        "http_version": "HTTP/1.1",
        "headers": '{"content-type":"application/json","Authorization":"test-credential"}',
        "response_status": 201,
        "request_body": '{"status":"ready"}',
        "response_size": 20,
        "src_ip": "192.0.2.1",
        "timestamp": "2026-08-02T18:16:08.832Z",
    }
    assert is_successful_post(row)
    stamp, line, event = decode_observation(row)
    assert stamp % 1 == pytest.approx(0.832)
    assert '"POST /records?page=1 HTTP/1.1" 201 20' in line
    assert event["headers"] == {"Content-Type": "application/json", "Content-Length": "18"}


def test_reproduced_prediction_must_keep_decision_near_threshold(tmp_path):
    original, replay, changed = (tmp_path / item for item in ("original", "replay", "changed"))
    for output, score in ((original, 0.58), (replay, 0.5800000000001), (changed, 0.5799999999999)):
        output.mkdir()
        write(output / "plan.json", {"threshold": 0.58})
        write(output / "predictions.json", [{"ordinal": 5, "score": score}])
    seal = original / "seal.json"
    write(
        seal,
        {
            "plan_sha256": fingerprint(original / "plan.json"),
            "predictions_sha256": fingerprint(original / "predictions.json"),
        },
    )
    verify_reproduced_candidate(original, replay, fingerprint(seal))
    with pytest.raises(ValueError, match="predictions did not reproduce"):
        verify_reproduced_candidate(original, changed, fingerprint(seal))


def test_external_scoring_requires_a_seal_and_counts_existing_detection_loss(tmp_path, monkeypatch):
    rows = [
        {
            "app": "sample",
            "http_method": "POST",
            "response_status": 200,
            "label": "attack",
            "attack_family": "test",
        },
        {
            "app": "sample",
            "http_method": "POST",
            "response_status": 200,
            "label": "benign",
            "attack_family": None,
        },
    ]

    class LabelTable:
        def read(self, columns):
            assert "request_body" not in columns
            return self

        def to_pylist(self):
            return rows

    monkeypatch.setattr(transfer, "source", lambda _: LabelTable())
    plan, predictions, seal = (
        tmp_path / name for name in ("plan.json", "predictions.json", "seal.json")
    )
    write(plan, {"archive_sha256": transfer.ARCHIVE_SHA, "selected_rows": 2})
    write(
        predictions,
        [
            {"ordinal": 1, "native": True, "crs": False, "candidate": False},
            {"ordinal": 2, "native": False, "crs": False, "candidate": True},
        ],
    )
    write(seal, {"plan_sha256": fingerprint(plan), "predictions_sha256": fingerprint(predictions)})
    with pytest.raises(ValueError, match="seal mismatch"):
        transfer.score(tmp_path / "archive", tmp_path, "wrong-seal")
    transfer.score(tmp_path / "archive", tmp_path, fingerprint(seal))
    report = read(tmp_path / "report.json")
    assert report["retention_gate_passed"] is False
    assert report["numerical_gate_passed"] is False
    assert report["groups"]["all"]["candidate"]["new_false_positives"] == 1
    assert report["attack_families"]["test"]["lost_true_positives"] == 1
