from scripts.evaluate_public_legitimate_web_crs import observation
from scripts.evaluate_public_post_body_scope import project


def test_only_unambiguous_recorded_body_metadata_is_projected():
    row = {"method": "POST", "url": "/record", "data": "{}",
           "headers": {"Content-Type": "application/json", "Cookie": "unused"}}
    observed = observation(row, 1)
    assert project(observed, include_body=True)["headers"] == {"Content-Type": "application/json"}

    row["headers"]["content-type"] = "text/plain"
    ambiguous = observation(row, 1)
    assert project(ambiguous, include_body=True) == project(ambiguous, include_body=False)
