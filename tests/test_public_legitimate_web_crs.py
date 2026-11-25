import json

from scripts.evaluate_public_legitimate_web_crs import observation
from scripts.evaluate_public_post_body_scope import project
from scripts.evaluate_public_web_shape_transfer import MODES, score


def test_only_unambiguous_recorded_body_metadata_is_projected():
    row = {"method": "POST", "url": "/record", "data": "{}",
           "headers": {"Content-Type": "application/json", "Cookie": "unused"}}
    observed = observation(row, 1)
    assert project(observed, include_body=True)["headers"] == {"Content-Type": "application/json"}

    row["headers"]["content-type"] = "text/plain"
    ambiguous = observation(row, 1)
    assert project(ambiguous, include_body=True) == project(ambiguous, include_body=False)


def test_shape_comparison_excludes_exact_overlap_and_keeps_fixed_crs_alert(tmp_path):
    path = tmp_path / "predictions.jsonl"
    rows = [
        {"ordinal": 1, "training_overlap": False, MODES[0]: True, MODES[1]: False},
        {"ordinal": 2, "training_overlap": False, MODES[0]: False, MODES[1]: True},
        {"ordinal": 3, "training_overlap": True, MODES[0]: True, MODES[1]: True},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    report = score(path, [True, False, False], "fpad", [True, False, False])
    assert report["scope"] == {"total_rows": 3, "exact_training_overlap": 1}
    assert report["results"]["all"]["crs_or_legitimate_model"]["tp"] == 1
    assert report["changes"]["lost_true_positives"] == 1
    assert report["crs_fusion"] == {"new_false_positives": 1}
