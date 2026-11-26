import csv

from scripts.evaluate_public_successful_post import (
    FIELDS,
    apache_observation,
    published_truth,
    selected,
    source_rows,
)


def test_successful_post_capture_does_not_project_publisher_labels(tmp_path):
    source = tmp_path / "publisher.csv"
    header = [*FIELDS, *(f"unused_{index}" for index in range(24 - len(FIELDS)))]
    labels = ["000 - Normal", *(f"{index:03d} - Category" for index in range(1, 14))]
    row = {
        "timestamp": "17/Jul/2020:12:00:00 +0000",
        "src_ip": "192.0.2.10",
        "request_http_method": "POST",
        "request_http_request": "/search",
        "request_http_protocol": "HTTP/1.1",
        "response_http_status_code": "201",
        "request_body": "private_body=example",
    }
    with source.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header + labels)
        writer.writerow([row.get(key, "") for key in header] + ["0", "1", *(["0"] * 12)])
        writer.writerow(["unclassifiable"])

    captured, malformed = list(source_rows(source))
    assert captured[0] == 1 and captured[2] is None
    assert malformed == (2, None, None)
    assert selected(captured[1])
    _, log_projection = apache_observation(captured[1])
    assert log_projection is not None and "private_body" not in log_projection

    labeled, _ = list(source_rows(source, include_truth=True))
    truth = labeled[2]
    assert published_truth(truth) is True
    assert published_truth(["1", *truth[1:]]) is None
    assert published_truth(["0"] * len(truth)) is None
