"""Reject materialized operational inputs that differ from the frozen experiment."""

from copy import deepcopy
from datetime import datetime, timedelta

import pytest

from scripts.m7_context_dataset import build_dataset
from scripts.m7_context_provenance import _digest, validate_provenance
from scripts.m7_context_runtime import run_case


def _case(family, directory):
    inputs, labels = build_dataset(1)
    identifier = next(row["case_id"] for row in labels if row["family"] == family)
    spec = next(row for row in inputs if row["case_id"] == identifier)
    return spec, run_case(spec, directory)


def test_materialized_scenarios_keep_old_contract_and_do_not_invent_prior_use(tmp_path):
    inputs, _ = build_dataset(1)
    for index, spec in enumerate(inputs):
        row = run_case(spec, tmp_path / str(index))
        if spec["prior_use"] is None:
            assert validate_provenance(spec, row)["frozen_operational_context_matched"] is True
        else:
            # The old contract required an already consumed approval. Current
            # execution cannot create that history from missing observer evidence.
            earlier = [entry for entry in row["provenance"]["context_records"]
                       if entry["kind"] == "evaluation"]
            assert len(earlier) == 1
            assert earlier[0]["payload"]["verdict"] == "unknown"
            with pytest.raises(ValueError, match="context_provenance_prior_use_record"):
                validate_provenance(spec, row)


def test_expired_approval_cannot_be_substituted_with_internally_valid_window(tmp_path):
    spec, row = _case("benign_expired_approval", tmp_path / "case")
    approval = next(item for item in row["provenance"]["context_records"] if item["kind"] == "approval")
    approval["payload"]["request"]["valid_until"] = (
        datetime.fromisoformat(spec["base_time"]) + timedelta(seconds=60)
    ).isoformat()
    row["with_context"].update(verdict="normal", reason="APPROVED_BASELINE_MATCH",
                               baseline_id=spec["baseline"]["id"], approval_id=spec["approval"]["id"])
    with pytest.raises(ValueError, match="context_provenance_window_time"):
        validate_provenance(spec, row)


def test_other_device_report_cannot_be_changed_to_target_device_even_with_new_digest(tmp_path):
    spec, row = _case("other_device_report", tmp_path / "case")
    provenance = row["provenance"]
    intake, marker = provenance["observation_intake"], provenance["observations"][0]
    for observed in (intake["request"]["observation"], intake["observation"], marker["observation"]):
        observed["subject_id"] = spec["scope"]["device_id"]
    intake["input_sha256"] = _digest(intake["request"])
    marker["input_digest_sha256"] = intake["input_sha256"]
    with pytest.raises(ValueError, match="context_provenance_observation_request"):
        validate_provenance(spec, row)


def test_changed_baseline_sample_cannot_be_hidden_by_matching_context_record(tmp_path):
    spec, row = _case("approved_upload", tmp_path / "case")
    provenance = row["provenance"]
    sample = provenance["baseline_sample_captures"][0]
    sample["activity"]["events"][0]["api_action"] = "DeleteObject"
    entry = next(item for item in provenance["context_records"]
                 if item["kind"] == "capture" and item["record_id"] == sample["capture_id"])
    entry["payload"]["capture"] = deepcopy(sample)
    entry["payload"]["input_digest"] = _digest(sample)
    with pytest.raises(ValueError, match="context_provenance_sample_activity"):
        validate_provenance(spec, row)


def test_revocation_cannot_be_omitted_from_materialized_context(tmp_path):
    spec, row = _case("benign_revoked_approval", tmp_path / "case")
    row["provenance"]["context_records"] = [
        item for item in row["provenance"]["context_records"] if item["kind"] != "revocation"
    ]
    with pytest.raises(ValueError, match="context_provenance_revocation"):
        validate_provenance(spec, row)


def test_prior_evaluation_history_cannot_be_omitted(tmp_path):
    spec, row = _case("exhausted_approval", tmp_path / "case")
    row["provenance"]["context_records"] = [
        item for item in row["provenance"]["context_records"] if item["kind"] != "evaluation"
    ]
    with pytest.raises(ValueError, match="context_provenance_prior_use_count"):
        validate_provenance(spec, row)


def test_manual_revoke_cannot_be_injected_into_a_nonrevoked_experiment(tmp_path):
    spec, row = _case("approved_upload", tmp_path / "case")
    row["provenance"]["session_history"][0]["reason_codes"].append("OPERATOR_REVOKED")
    with pytest.raises(ValueError, match="context_provenance_manual_revoke_count"):
        validate_provenance(spec, row)


def test_observation_rejection_is_not_replaceable_by_a_completed_receipt(tmp_path):
    spec, row = _case("unregistered_report", tmp_path / "case")
    row["provenance"]["observation_intake"].update(accepted=True, state="completed")
    with pytest.raises(ValueError, match="context_provenance_observation_acceptance"):
        validate_provenance(spec, row)
