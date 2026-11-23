import hashlib
from zipfile import ZipFile

import pytest

from scripts import evaluate_public_apache_transfer as evaluator
from scripts.evaluate_local_remote_holdout import fingerprint, read, write


def test_publisher_alternatives_keep_repeated_rule_ids(tmp_path):
    member = "organization-x/log/apache2/web-access.log"
    rows = [b"signal alpha", b"signal beta", b"noise"]
    source = tmp_path / "source.zip"
    output = tmp_path / "output"
    output.mkdir()
    rule_yaml = """\
- id: repeated
  sensitivity: moderate
  filter: [signal, alpha]
- id: repeated
  sensitivity: moderate
  filter: [signal, beta]
- id: strict-only
  sensitivity: strict
  filter: [not present]
"""
    with ZipFile(source, "w") as archive:
        archive.writestr(member, b"\n".join(rows))
        archive.writestr(evaluator.LABEL_MEMBER, rule_yaml)
    with ZipFile(source) as archive:
        _, digest = evaluator.records(archive, member)

    plan = output / "plan.json"
    write(plan, {"archive_sha256": evaluator.SOURCE_SHA, "candidate_commit": "test",
                 "evaluator_sha256": evaluator.evaluator_sha256(), "members": [member]})
    predictions = output / "predictions.jsonl"
    with predictions.open("wb") as stream:
        for ordinal, hit in enumerate((True, True, False), 1):
            case = hashlib.sha256(f"{digest}:{ordinal}".encode()).hexdigest()
            stream.write(evaluator.canonical({"case_id": case, "before": hit, "after": hit}) + b"\n")
    seal = output / "seal.json"
    write(seal, {"plan_sha256": fingerprint(plan), "prediction_sha256": fingerprint(predictions),
                 "media": [{"member": member, "rows": len(rows), "sha256": digest}]})

    with pytest.raises(ValueError, match="sealed evaluation changed"):
        evaluator.score(source, output, "0" * 64, "publisher")

    evaluator.score(source, output, fingerprint(seal), "publisher")
    result = read(output / "report-publisher.json")
    assert result["publisher_rules_used"] == 3
    assert result["publisher_distinct_rule_ids"] == 2
    assert result["rule_match_counts"] == {"repeated": 2}
    assert (result["after"]["tp"], result["after"]["tn"], result["after"]["fp"]) == (2, 1, 0)
