import json

import pytest

from scripts.evaluate_local_remote_holdout import fingerprint, write
from scripts.evaluate_public_post_body_scope import project
from scripts.evaluate_public_post_body_shape import split_by_date
from scripts.evaluate_public_post_crs_rules import compare_reference, load_crs


def capture(tmp_path, rows):
    path = tmp_path / "crs-predictions.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    write(
        tmp_path / "seal.json",
        {
            "source_sha256": "source",
            "reference_sha256": "native",
            "attack_rule_ids": True,
            "predictions_sha256": fingerprint(path),
        },
    )
    return path


def test_rule_evidence_keeps_ordinal_and_requires_same_sealed_predictions(tmp_path):
    rows = [{"ordinal": 1, "alert": True, "rule_ids": [941100]}, {"ordinal": 2, "alert": False}]
    path = capture(tmp_path, rows)
    observed, _ = load_crs(tmp_path, "source", "native", with_rules=True)
    assert observed == {1: (True, {941100}), 2: (False, set())}
    compare_reference({1: {}, 2: {}}, {1: (True, set()), 2: (False, set())}, observed)
    with pytest.raises(ValueError, match="changed an existing CRS decision"):
        compare_reference({1: {}, 2: {}}, {1: (False, set()), 2: (False, set())}, observed)
    with pytest.raises(ValueError, match="populations differ"):
        compare_reference({1: {}}, {1: (True, set())}, observed)

    path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="seal verification"):
        load_crs(tmp_path, "source", "native", with_rules=True)


@pytest.mark.parametrize(
    "rows",
    [
        [{"ordinal": 1, "alert": None}],
        [{"ordinal": 1, "alert": True, "rule_ids": [941100, 941100]}],
        [{"ordinal": 1, "alert": False}, {"ordinal": 1, "alert": False}],
    ],
)
def test_invalid_rule_observations_fail_before_fitting(tmp_path, rows):
    capture(tmp_path, rows)
    with pytest.raises(ValueError, match="invalid or unavailable CRS decision"):
        load_crs(tmp_path, "source", "native", with_rules=True)


def test_split_excludes_matching_request_pairs_from_earlier_dates():
    initial = [(1, "unique", []), (2, "same-as-calibration", []), (3, "same-as-temporal", [])]
    calibration = [(4, "same-as-calibration", []), (5, "same-as-temporal", [])]
    temporal = [(6, "same-as-temporal", [])]
    assert split_by_date(
        {"development": initial, "calibration": calibration, "temporal": temporal}
    ) == ([initial[0]], [calibration[0]], temporal)


def test_passive_body_scope_projects_only_observed_format_metadata():
    target = {"ordinal": 1, "method": "POST", "target": "/record", "protocol": "HTTP/1.1"}
    formats = {"Content-Type": "application/json", "Content-Encoding": "identity"}
    event = {**target, "headers": {**formats, "Cookie": "unused"}, "body": "{}", "label": "unused"}
    assert project(event, include_body=False) == target
    assert project(event, include_body=True) == {**target, "headers": formats, "body": "{}"}
    assert project({**event, "headers": {}}, include_body=True) == target
