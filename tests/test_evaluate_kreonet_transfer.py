from scripts import evaluate_kreonet_model as model
from scripts import evaluate_kreonet_transfer as transfer
from scripts.evaluate_local_remote_holdout import fingerprint, read


def test_transfer_fixture_labels_are_separate_and_policy_can_be_invisible(tmp_path):
    observations = transfer.generate_fixtures(tmp_path)
    truth = read(tmp_path / "fixture_truth.json")
    assert len(truth) == 96
    assert sum(row["truth"] for row in truth.values()) == 48
    assert '"label"' not in observations.read_text(encoding="utf-8")
    projected, labels = model.read_observations(
        observations,
        dict.fromkeys(truth, ("holdout", False)),
        local_source_sha256=fingerprint(observations),
    )
    assert labels == {}

    def signatures(scenario):
        return sorted(
            sorted(model.project(projected[key], "timing").items())
            for key, row in truth.items()
            if row["scenario"] == scenario
        )

    assert signatures("approved_login") == signatures("required_factor_missing")
    assert signatures("approved_login") == signatures("revoked_entitlement_used")
    assert signatures("approved_after_typo") == signatures("device_not_approved")


def test_shadow_alert_cannot_change_decision_and_disabling_or_fault_preserves_rules():
    def timed_out():
        raise TimeoutError

    for existing in (False, True):
        alert = transfer.shadow_decision(existing, lambda: (0.8, 0.5))
        assert alert == {"enforced": existing, "alert": True, "state": "scored"}
        assert transfer.shadow_decision(existing, timed_out) == {
            "enforced": existing,
            "alert": False,
            "state": "model_unavailable",
        }
        assert transfer.shadow_decision(existing, None) == {
            "enforced": existing,
            "alert": False,
            "state": "disabled",
        }
