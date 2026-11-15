"""Replay the exposed 240 sessions and evaluate fresh execution-evidence controls.

The old observations and labels are immutable. Fresh records are authored local lab
telemetry, not new external/public incident data or an EDR deployment.
"""

import argparse
import copy
import json
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.behavior_context_api import behavior_context_router
from app.behavior_context_models import ApprovalCreate, BaselineCreate, ContextRevocation
from app.behavior_execution_models import ExecutionActor, ExecutionDestination, ExecutionPolicy
from app.security import get_principal
from app.services.public_detection import PublicDetectionService
from app.zero_trust_models import SessionRevocationRequest
from scripts.behavior_execution_collector import ExecutionCollector, initialize
from scripts.evaluate_m6 import canonical, digest, unique_fields
from scripts.evaluate_m7_context import exclusive_write, implementation_hashes, jsonl, read_rows
from scripts.m7_context_dataset import OPAQUE, _activity, audit_inputs, audit_prior_overlap, opaque
from scripts.m7_context_provenance import validate_provenance
from scripts.m7_context_runtime import ContextLab, _public
from scripts.m7_context_scoring import (
    _approval_supported,
    _prediction,
    evidence_alignment,
    summarize,
)

ROOT = Path(__file__).resolve().parents[1]
PREVIOUS = ROOT / "runtime/m7/behavior-context-evaluation"
DEFAULT_DIRECTORY = ROOT / "runtime/m7/behavior-execution-evaluation"
ARMS = ("rule_only", "with_context")
STRATA = (
    ("approved_exact_execution", "normal", "match"),
    ("approved_multiple_destinations", "normal", "match"),
    ("approved_other_device_alert", "normal", "match"),
    ("benign_missing_actor", "normal", "none"),
    ("benign_missing_destination", "normal", "none"),
    ("benign_absent_execution_evidence", "normal", "none"),
    ("benign_binary_update_stale_approval", "normal", "mismatch"),
    ("unauthorized_workload", "threat", "mismatch"),
    ("unauthorized_principal", "threat", "mismatch"),
    ("unauthorized_destination", "threat", "mismatch"),
    ("additional_unauthorized_destination", "threat", "mismatch"),
    ("hidden_abuse_same_actor_destination", "threat", "none"),
    ("attack_with_corrupted_report", "threat", "none"),
    ("attack_with_unbound_capture_report", "threat", "none"),
    ("unresolved_execution_policy", "unknown", "none"),
    ("unresolved_stale_evidence", "unknown", "none"),
    ("unresolved_retired_source", "unknown", "none"),
)
FILES = ("legacy/inputs.jsonl", "legacy/private/scoring.jsonl",
         "fresh/inputs.jsonl", "fresh/private/scoring.jsonl")


def _hash(path):
    return digest(Path(path).read_bytes())


def prior_artifacts(previous=PREVIOUS, pinned=None):
    previous = Path(previous)
    names = ("manifest.json", "inputs.jsonl", "private/scoring.jsonl", "predictions.jsonl", "report.json")
    hashes = {name: _hash(previous / name) for name in names}
    if pinned is not None and hashes != pinned:
        raise ValueError("execution_evaluation_prior_changed")
    manifest = json.loads((previous / "manifest.json").read_bytes(), object_pairs_hook=unique_fields)
    report = json.loads((previous / "report.json").read_bytes(), object_pairs_hook=unique_fields)
    if (manifest["sessions"] != 240 or report["sessions"] != 240
            or manifest["files"] != {name: hashes[name] for name in ("inputs.jsonl", "private/scoring.jsonl")}
            or report["manifest_sha256"] != hashes["manifest.json"]
            or report["predictions_sha256"] != hashes["predictions.jsonl"]):
        raise ValueError("execution_evaluation_prior_integrity")
    return hashes


def _new_context(repetition):
    instant = datetime(2026, 11, 10, 4, tzinfo=UTC)
    scope = {"source": "cloudtrail", "user_id": opaque(), "device_id": opaque(),
             "resource_id": "zt-demo-documents", "action": "READ", "principal_hash": opaque()}
    resources = [opaque() for _ in range(25)]

    def sample(offset):
        return {"capture_id": opaque(), "session_id": opaque(), "activity": _activity(
            "cloudtrail", instant + timedelta(seconds=offset), scope["principal_hash"],
            resources, 100 + repetition % 10, "GetObject",
        )}

    return {"case_id": opaque(), "base_time": instant.isoformat(), "tenant_id": opaque(),
            "scope": scope, "baseline_samples": [sample(i) for i in range(3)], "target": sample(10),
            "baseline": {"id": opaque(), "enabled": True, "revoked": False},
            "approval": {"id": opaque(), "mode": "valid", "max_uses": 1},
            "observation": {"id": opaque(), "kind": "none", "scope": "same",
                            "signature": "valid", "posture": "compromised"},
            "session_revoke": False, "prior_use": None}


def build_fresh(repetitions=10):
    if type(repetitions) is not int or not 1 <= repetitions <= 20:
        raise ValueError("execution_evaluation_repetitions")
    inputs, labels = [], []
    for family, label, support in STRATA:
        for repetition in range(repetitions):
            context = _new_context(repetition)
            actor = {"principal_id": context["scope"]["user_id"], "workload_id": opaque(),
                     "executable_sha256": digest(opaque().encode())}
            endpoint = {"kind": "https", "host": "archive-" + opaque()[2:18] + ".example.invalid",
                        "port": 443, "path": "/exports/batch"}
            execution = {"evidence_id": opaque(), "policy": {"actor": actor, "destinations": [endpoint]},
                         "actor": copy.deepcopy(actor), "destinations": [copy.deepcopy(endpoint)],
                         "delivery": "send", "binding_capture_id": context["target"]["capture_id"]}
            if family == "approved_multiple_destinations":
                other = endpoint | {"path": "/exports/replica"}
                execution["policy"]["destinations"].append(other)
                execution["destinations"].append(copy.deepcopy(other))
            if family == "approved_other_device_alert":
                context["observation"].update(kind="device", scope="other")
            if family == "benign_missing_actor": execution["actor"] = None
            if family == "benign_missing_destination": execution["destinations"] = None
            if family == "benign_absent_execution_evidence": execution["delivery"] = "absent"
            if family == "unauthorized_workload": execution["actor"]["workload_id"] = opaque()
            if family == "unauthorized_principal": execution["actor"]["principal_id"] = opaque()
            if family == "benign_binary_update_stale_approval":
                execution["actor"]["executable_sha256"] = digest(opaque().encode())
            if family == "unauthorized_destination":
                execution["destinations"][0]["host"] = "receiver-" + opaque()[2:18] + ".example.invalid"
            if family == "additional_unauthorized_destination":
                execution["destinations"].append(endpoint | {"host": "receiver.example.invalid"})
            if family == "attack_with_corrupted_report": execution["delivery"] = "bad_signature"
            if family == "attack_with_unbound_capture_report":
                execution["binding_capture_id"] = opaque()
                execution["delivery"] = "wrong_capture"
            if family == "unresolved_execution_policy": execution["policy"] = None
            if family == "unresolved_stale_evidence": execution["delivery"] = "stale"
            if family == "unresolved_retired_source": execution["delivery"] = "revoked_source"
            inputs.append({"case_id": context["case_id"], "context": context, "execution": execution})
            labels.append({"case_id": context["case_id"], "label": label, "family": family,
                           "expected_support": support,
                           "reference_kind": "authored_local_execution_experiment"})
    inputs.sort(key=lambda row: row["case_id"])
    labels.sort(key=lambda row: row["case_id"])
    audit_fresh(inputs, labels)
    return inputs, labels


def audit_fresh(inputs, labels=None):
    if not inputs:
        raise ValueError("execution_evaluation_empty")
    for row in inputs:
        if set(row) != {"case_id", "context", "execution"} or row["case_id"] != row["context"]["case_id"]:
            raise ValueError("execution_evaluation_input_shape")
        execution = row["execution"]
        if set(execution) != {"evidence_id", "policy", "actor", "destinations", "delivery", "binding_capture_id"}:
            raise ValueError("execution_evaluation_label_or_field_leak")
        if any(not isinstance(execution[key], str) or not OPAQUE.fullmatch(execution[key])
               for key in ("evidence_id", "binding_capture_id")):
            raise ValueError("execution_evaluation_opaque_identifier")
        if execution["policy"] is not None: ExecutionPolicy.model_validate(execution["policy"])
        if execution["actor"] is not None: ExecutionActor.model_validate(execution["actor"])
        for actor in [execution["actor"], execution["policy"]["actor"] if execution["policy"] else None]:
            if actor and any(not OPAQUE.fullmatch(actor[key]) for key in ("principal_id", "workload_id")):
                raise ValueError("execution_evaluation_opaque_actor")
        if execution["destinations"] is not None:
            if not 1 <= len(execution["destinations"]) <= 16:
                raise ValueError("execution_evaluation_destinations")
            for item in execution["destinations"]: ExecutionDestination.model_validate(item)
        if execution["delivery"] not in {"send", "absent", "bad_signature", "wrong_capture", "stale", "revoked_source"}:
            raise ValueError("execution_evaluation_delivery")
    audit = audit_inputs([row["context"] for row in inputs])
    if labels is not None:
        if (len(inputs) != len(labels) or len({row["case_id"] for row in labels}) != len(labels)
                or {row["case_id"] for row in labels} != {row["case_id"] for row in inputs}
                or any(row["label"] not in {"normal", "threat", "unknown"} for row in labels)):
            raise ValueError("execution_evaluation_label_identity")
        audit["label_counts"] = dict(Counter(row["label"] for row in labels))
    return audit | {"execution_labels_in_inputs": 0}


class ReplayLab(ContextLab):
    def __init__(self, spec, directory, execution=None, historical_prior=None):
        super().__init__(spec, directory)
        self.execution = execution
        self.historical_prior = historical_prior

    def prepare_context(self):
        samples = [self.capture(item) for item in self.spec["baseline_samples"]]
        baseline, approval = self.spec["baseline"], self.spec["approval"]
        if baseline["enabled"]:
            self.service.create_baseline(BaselineCreate(
                baseline_id=baseline["id"], capture_ids=[sample.capture_id for sample in samples],
                valid_from=self.at(3), valid_until=self.at(300),
                note="Reviewed earlier local operation samples",
            ), self.operator, now=self.at(3))
        if approval["mode"] != "missing":
            self.service.create_approval(ApprovalCreate(
                approval_id=approval["id"], baseline_id=baseline["id"], max_uses=approval["max_uses"],
                valid_from=self.at(20 if approval["mode"] == "future" else 3),
                valid_until=self.at(9 if approval["mode"] == "expired" else 60),
                note="Bounded local operation window",
                execution_policy=self.execution["policy"] if self.execution else None,
            ), self.operator, now=self.at(3))
        prior = None
        if self.spec["prior_use"] is not None:
            prior = self.capture(self.spec["prior_use"])
            entry = self.historical_prior
            if (entry is None or entry["kind"] != "evaluation"
                    or entry["tenant_id"] != self.tenant
                    or entry["payload"]["capture_id"] != prior.capture_id
                    or entry["payload"]["approval_id"] != approval["id"]
                    or entry["payload"]["verdict"] != "normal"
                    or datetime.fromisoformat(entry["created_at"]) != self.at(6)):
                raise ValueError("execution_evaluation_missing_original_prior_use")
            # This is archived quota history, not a new verdict or invented execution proof.
            with self.store.transaction() as transaction:
                transaction.append(entry)
        if approval["mode"] == "revoked":
            self.service.revoke("approval", approval["id"], ContextRevocation(reason="Operation window cancelled"),
                                self.operator, now=self.at(8))
        if baseline["revoked"]:
            self.service.revoke("baseline", baseline["id"], ContextRevocation(reason="Reviewed operation profile withdrawn"),
                                self.operator, now=self.at(8))
        return samples, prior


def collect_execution(lab, target):
    config = lab.execution
    if config is None or config["delivery"] == "absent":
        return {"state": "not_supplied", "request": None, "http_status": None}
    key = Ed25519PrivateKey.generate()
    directory = lab.directory / "collector"
    initialize(directory, lab.tenant, "execution", "key", [lab.scope.model_dump(mode="json")],
               now=lab.at(0), key=key)
    registry = json.loads(lab.registry.read_text())
    registry["sources"].extend(json.loads((directory / "sources.json").read_text())["sources"])
    lab.registry.write_text(json.dumps(registry))
    application = FastAPI()
    application.include_router(behavior_context_router(lab.service))
    application.dependency_overrides[get_principal] = lambda: lab.operator
    client = TestClient(application)
    trace = {}

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            instant = lab.at(11)
            return instant.astimezone(tz) if tz else instant.replace(tzinfo=None)

    def transport(base_url, payload, *, tls_profile=None):
        payload = copy.deepcopy(payload)
        if config["delivery"] == "bad_signature": payload["signature"] = "A" * 86
        trace["request"] = _public(payload)
        with patch("app.services.behavior_context.datetime", Clock):
            response = client.post("/detections/context/execution-evidence", json=payload)
        trace["http_status"], trace["receipt"] = response.status_code, response.json()
        return response.status_code, response.json()

    record = {"evidence_id": config["evidence_id"], "observed_at": lab.at(10).isoformat(),
              "scope": lab.scope.model_dump(mode="json"), "session_id": target.session_id,
              "session_version": target.session_version, "session_input_sha256": target.session_input_sha256,
              "capture_id": config["binding_capture_id"], "capture_input_sha256": digest(canonical(_public(target.model_dump(mode="json")))),
              "event_ids": [event.id for event in target.activity.events],
              "connection_ids": target.connection_ids, "actor": config["actor"],
              "destinations": config["destinations"]}
    collector = ExecutionCollector(directory, "http://127.0.0.1:8080", transport=transport,
                                   clock=lambda: lab.at(11),
                                   lifetime_seconds=1 if config["delivery"] == "stale" else 90)
    queued = collector.enqueue(record)
    result = collector.send_once()
    if config["delivery"] == "revoked_source":
        registry["sources"][-1]["keys"][0]["enabled"] = False
        lab.registry.write_text(json.dumps(registry))
    trace.update(state=result["state"], queued=queued, transport_result=result,
                 registry=_public(json.loads(lab.registry.read_text())))
    return trace


def run_case(spec, directory, *, execution=None, historical_prior=None):
    lab = ReplayLab(spec, directory, execution, historical_prior)
    samples, prior = lab.prepare_context()
    target = lab.capture(spec["target"])
    observation = lab.observe()
    if spec["session_revoke"]:
        lab.operations.revoke(target.session_id, SessionRevocationRequest(
            expected_version=target.session_version, note="Scheduled local maintenance isolation",
        ), lab.operator, now=lab.at(11))
    trace = collect_execution(lab, target)
    before = lab.operations.journal_status()
    records = lab.store.read(lab.tenant)
    activity = target.activity.model_dump(mode="json")
    rule = PublicDetectionService().evaluate(target.activity)
    result = lab.service.evaluate(target.capture_id, lab.analyst, now=lab.at(12))
    if before != lab.operations.journal_status() or result["base_detection"] != rule:
        raise ValueError("execution_evaluation_changed_input_or_access_state")
    with lab.operations._transaction() as transaction:
        observations = [entry for entry in transaction[1] if entry["kind"] == "observation"]
    fingerprint = digest(canonical(activity))
    row = {"case_id": spec["case_id"], "session_id": target.session_id,
            "input_sha256": digest(canonical(spec)), "activity_sha256": fingerprint,
            "rule_input_sha256": fingerprint, "context_activity_sha256": fingerprint,
            "rule_only": rule, "with_context": result, "execution_trace": trace,
            "provenance": {"capture": _public(target.model_dump(mode="json")),
                           "baseline_sample_captures": [_public(item.model_dump(mode="json")) for item in samples],
                           "prior_use_capture": _public(prior.model_dump(mode="json")) if prior else None,
                           "context_records": _public(records), "observations": _public(observations),
                           "session_history": [item.model_dump(mode="json") for item in lab.operations.history(target.session_id, lab.operator)],
                           "observation_intake": observation, "evaluation_at": lab.at(12).isoformat()},
            "policy_journal_unchanged_by_evaluation": True,
            "historical_quota_replayed": historical_prior is not None}
    validate_run(spec, row, execution)
    return row


def validate_run(spec, row, execution=None):
    """Bind observed records to frozen setup without consulting a verdict or a label."""
    projected = copy.deepcopy(row)
    records = projected["provenance"]["context_records"]
    execution_records = [entry for entry in records if entry["kind"] == "execution"]
    projected["provenance"]["context_records"] = [entry for entry in records if entry["kind"] != "execution"]
    approvals = [entry for entry in projected["provenance"]["context_records"] if entry["kind"] == "approval"]
    for approval in approvals:
        policy = approval["payload"]["request"].pop("execution_policy", None)
        if policy != (execution["policy"] if execution else None):
            raise ValueError("execution_evaluation_materialized_policy_changed")
    validate_provenance(spec, projected)
    trace = row["execution_trace"]
    if execution is None or execution["delivery"] == "absent":
        if trace != {"state": "not_supplied", "request": None, "http_status": None} or execution_records:
            raise ValueError("execution_evaluation_invented_execution_evidence")
        return
    request = trace["request"]
    target = row["provenance"]["capture"]
    expected = {
        "schema_version": "zt-execution-1", "algorithm": "Ed25519",
        "tenant_id": spec["tenant_id"], "source_id": "execution", "key_id": "key",
        "evidence_id": execution["evidence_id"], "scope": spec["scope"],
        "session_id": target["session_id"], "session_version": target["session_version"],
        "session_input_sha256": target["session_input_sha256"],
        "capture_id": execution["binding_capture_id"], "capture_input_sha256": digest(canonical(target)),
        "event_ids": [event["id"] for event in target["activity"]["events"]],
        "connection_ids": target["connection_ids"], "actor": execution["actor"],
        "destinations": execution["destinations"],
    }
    base = datetime.fromisoformat(spec["base_time"])
    for key, offset in (("issued_at", 11), ("observed_at", 10),
                        ("expires_at", 12 if execution["delivery"] == "stale" else 101)):
        if datetime.fromisoformat(request[key]) != base + timedelta(seconds=offset):
            raise ValueError("execution_evaluation_materialized_evidence_clock")
        expected[key] = request[key]
    if request != expected:
        raise ValueError("execution_evaluation_materialized_evidence_changed")
    accepted = execution["delivery"] not in {"bad_signature", "wrong_capture"}
    status = 403 if execution["delivery"] == "bad_signature" else 404
    if ((accepted and trace["http_status"] != 201)
            or (not accepted and trace["http_status"] != status)
            or len(execution_records) != int(accepted)):
        raise ValueError("execution_evaluation_materialized_intake_changed")
    if accepted:
        entry = execution_records[0]
        if (entry["record_id"] != execution["evidence_id"]
                or entry["payload"]["evidence"] != request
                or entry["payload"]["input_digest"] != digest(canonical(request))
                or trace["receipt"]["evidence_id"] != execution["evidence_id"]
                or trace["receipt"]["input_digest"] != digest(canonical(request))):
            raise ValueError("execution_evaluation_materialized_receipt_changed")
    sources = [source for source in trace["registry"]["sources"] if source["source_id"] == "execution"]
    if (len(sources) != 1 or sources[0]["execution_scopes"] != [spec["scope"]]
            or sources[0]["tenant_id"] != spec["tenant_id"]
            or sources[0]["keys"][0]["enabled"] != (execution["delivery"] != "revoked_source")):
        raise ValueError("execution_evaluation_materialized_authority_changed")


def prepare(directory, *, previous=PREVIOUS, repetitions=10):
    directory, previous = Path(directory), Path(previous)
    if directory.exists(): raise ValueError("execution_evaluation_directory_exists")
    implementation = implementation_hashes()
    old_hashes = prior_artifacts(previous)
    inputs, labels = build_fresh(repetitions)
    audit = audit_fresh(inputs, labels)
    overlap = audit_prior_overlap([row["context"] for row in inputs])
    files = {"legacy/inputs.jsonl": (previous / "inputs.jsonl").read_bytes(),
             "legacy/private/scoring.jsonl": (previous / "private/scoring.jsonl").read_bytes(),
             "fresh/inputs.jsonl": jsonl(inputs), "fresh/private/scoring.jsonl": jsonl(labels)}
    if implementation_hashes() != implementation: raise ValueError("execution_evaluation_source_changed")
    manifest = {"schema": "m7-execution-evaluation-1", "created_at": datetime.now(UTC).isoformat(),
                "previous_directory": str(previous.resolve()), "previous_artifact_sha256": old_hashes,
                "implementation_sha256": implementation, "files": {name: digest(raw) for name, raw in files.items()},
                "fresh_sessions": len(inputs), "legacy_sessions": 240, "fresh_input_audit": audit,
                "fresh_prior_overlap": overlap, "external_model_requests": 0,
                "scope": "Authored local execution telemetry; exposed 240-session regression; no independent public generalization."}
    directory.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".execution-evaluation-", dir=directory.parent) as temporary:
        stage = Path(temporary) / "bundle"
        for name, raw in files.items(): exclusive_write(stage / name, raw)
        for name in ("legacy/private", "fresh/private"): (stage / name).chmod(0o700)
        exclusive_write(stage / "manifest.json", canonical(manifest) + b"\n")
        stage.rename(directory)
    return manifest


def checked(directory, expected_manifest=None):
    directory = Path(directory)
    raw = (directory / "manifest.json").read_bytes()
    manifest = json.loads(raw, object_pairs_hook=unique_fields)
    if expected_manifest and digest(raw) != expected_manifest:
        raise ValueError("execution_evaluation_manifest_changed")
    if manifest["schema"] != "m7-execution-evaluation-1" or set(manifest["files"]) != set(FILES):
        raise ValueError("execution_evaluation_manifest_shape")
    if manifest["implementation_sha256"] != implementation_hashes():
        raise ValueError("execution_evaluation_source_changed")
    for name, expected in manifest["files"].items():
        if _hash(directory / name) != expected: raise ValueError("execution_evaluation_dataset_changed")
    prior_artifacts(manifest["previous_directory"], manifest["previous_artifact_sha256"])
    fresh = read_rows((directory / "fresh/inputs.jsonl").read_bytes())
    audit_fresh(fresh)
    audit_prior_overlap([row["context"] for row in fresh], pinned=manifest["fresh_prior_overlap"])
    return manifest, digest(raw)


def _prediction_error(spec, error):
    return {"case_id": spec["case_id"], "session_id": spec["target"]["session_id"],
            "error_type": type(error).__name__, "rule_only": {"status": "error", "verdict": "unknown"},
            "with_context": {"status": "error", "verdict": "unknown"}}


def _execution_alignment(row, reference, spec=None):
    answer, provenance = row["with_context"], row.get("provenance", {})
    prediction = _prediction(row, "with_context")
    default = {"provenance_aligned": False, "reference_supported": False,
               "expected_abstention": prediction == "unknown" and reference["label"] == "unknown",
               "status": "error" if prediction == "error" else "unsupported"}
    if prediction == "error": return default
    reason = answer.get("reason", "")
    if not reason.startswith("EXECUTION_") and not (prediction == "normal" and spec is not None):
        old_reference = reference | {"expected_support": reference.get("expected_support", [])}
        return evidence_alignment(row, old_reference, "with_context")
    try:
        records = provenance["context_records"]
        approvals = [entry for entry in records if entry["kind"] == "approval"]
        eligible = [entry for entry in approvals if _approval_supported(
            provenance, entry["payload"]["request"]["baseline_id"], entry["record_id"],
        )]
        if spec is None:
            factual = (prediction == "unknown" and reason == "EXECUTION_POLICY_REQUIRED"
                       and bool(eligible) and all(entry["payload"]["request"].get("execution_policy") is None for entry in eligible))
        else:
            config = spec["execution"]
            trace = row["execution_trace"]
            request = trace.get("request")
            committed = [entry for entry in records if entry["kind"] == "execution"]
            exact = bool(request and len(committed) == 1
                         and committed[0]["payload"]["evidence"] == request
                         and committed[0]["payload"]["input_digest"] == digest(canonical(request)))
            if request:
                capture = provenance["capture"]
                exact &= (request["actor"] == config["actor"] and request["destinations"] == config["destinations"]
                          and request["capture_id"] == capture["capture_id"]
                          and request["session_id"] == capture["session_id"]
                          and request["session_version"] == capture["session_version"]
                          and request["session_input_sha256"] == capture["session_input_sha256"]
                          and request["capture_input_sha256"] == digest(canonical(capture))
                          and set(request["event_ids"]) == {event["id"] for event in capture["activity"]["events"]}
                          and request["scope"] == capture["scope"] and request["tenant_id"] == capture["tenant_id"])
            policy = config["policy"]
            complete = bool(config["actor"] is not None and config["destinations"] is not None)
            same = bool(policy and complete and config["actor"] == policy["actor"] and {
                canonical(item) for item in config["destinations"]
            } <= {canonical(item) for item in policy["destinations"]})
            current = bool(exact and config["delivery"] not in {"stale", "revoked_source"}
                           and datetime.fromisoformat(request["expires_at"]) > datetime.fromisoformat(provenance["evaluation_at"]))
            eligible_policy = bool(eligible and any(entry["payload"]["request"].get("execution_policy") == policy for entry in eligible))
            if prediction in {"normal", "threat"}:
                factual = bool(eligible_policy and current and complete
                               and set(answer.get("execution_evidence_ids", [])) == {config["evidence_id"]}
                               and ((prediction == "normal" and same and reason == "APPROVED_BASELINE_MATCH")
                                    or (prediction == "threat" and not same and reason == "EXECUTION_SCOPE_MISMATCH")))
            elif reason == "EXECUTION_POLICY_REQUIRED": factual = bool(eligible and policy is None)
            elif reason == "EXECUTION_EVIDENCE_REQUIRED": factual = bool(eligible_policy and not committed)
            elif reason == "EXECUTION_EVIDENCE_INCOMPLETE": factual = bool(eligible_policy and exact and not complete)
            elif reason == "EXECUTION_EVIDENCE_STALE": factual = bool(eligible_policy and exact and not current)
            else: factual = False
        return default | {"provenance_aligned": bool(factual),
                          "reference_supported": bool(factual and prediction == reference["label"]),
                          "status": "aligned" if factual else "unsupported"}
    except (KeyError, TypeError, ValueError):
        return default | {"status": "malformed_provenance"}


def score(predictions, labels, *, inputs=None, previous=None):
    references = {row["case_id"]: row for row in labels}
    rows_by_id = {row["case_id"]: row for row in predictions}
    if len(rows_by_id) != len(predictions) or len(references) != len(labels) or references.keys() != rows_by_id.keys():
        raise ValueError("execution_evaluation_score_identity")
    specifications = {row["case_id"]: row for row in inputs or []}
    rows = []
    for identifier in sorted(references):
        row, reference = rows_by_id[identifier], references[identifier]
        before = previous[identifier] if previous is not None else row
        before_arm = "with_context" if previous is not None else "rule_only"
        old_ref = reference if previous is not None else reference | {"expected_support": []}
        rows.append({"case_id": identifier, "session_id": row["session_id"], "label": reference["label"],
                     "family": reference["family"],
                     "rule_only": {"prediction": _prediction(before, before_arm),
                                   "evidence_alignment": evidence_alignment(before, old_ref, before_arm)},
                     "with_context": {"prediction": _prediction(row, "with_context"),
                                      "evidence_alignment": _execution_alignment(row, reference, specifications.get(identifier))}})
    return {"sessions": len(rows), "arm_names": {"rule_only": "previous_context" if previous else "current_rules", "with_context": "execution_context"},
            "arms": {arm: summarize(rows, arm) for arm in ARMS},
            "by_family": {family: {arm: summarize([row for row in rows if row["family"] == family], arm) for arm in ARMS}
                          for family in sorted({row["family"] for row in rows})},
            "paired_transitions": dict(Counter(row["rule_only"]["prediction"] + "->" + row["with_context"]["prediction"] for row in rows)),
            "rows": rows}


def evaluate(directory):
    directory = Path(directory)
    if (directory / "report.json").exists() or any((directory / cohort / "predictions.jsonl").exists() for cohort in ("legacy", "fresh")):
        raise ValueError("execution_evaluation_results_exist")
    manifest, manifest_hash = checked(directory)
    original = {row["case_id"]: row for row in read_rows((Path(manifest["previous_directory"]) / "predictions.jsonl").read_bytes())}
    cohorts = {name: read_rows((directory / name / "inputs.jsonl").read_bytes()) for name in ("legacy", "fresh")}
    results = {}
    for cohort, inputs in cohorts.items():
        predictions = []
        for item in inputs:
            spec = item if cohort == "legacy" else item["context"]
            archived = [entry for entry in original[spec["case_id"]]["provenance"]["context_records"] if entry["kind"] == "evaluation"] if cohort == "legacy" else []
            if len(archived) > 1: raise ValueError("execution_evaluation_historical_quota_count")
            with tempfile.TemporaryDirectory(prefix="execution-context-case-") as temporary:
                try:
                    result = run_case(spec, Path(temporary) / "case", execution=item["execution"] if cohort == "fresh" else None,
                                      historical_prior=archived[0] if archived else None)
                except (ValueError, RuntimeError, OSError, TypeError, LookupError) as error:
                    result = _prediction_error(spec, error)
                predictions.append(result)
            if len(predictions) % 20 == 0: print(json.dumps({"cohort": cohort, "predicted": len(predictions), "total": len(inputs)}), flush=True)
        exclusive_write(directory / cohort / "predictions.jsonl", jsonl(predictions))
        results[cohort] = predictions
    checked(directory, manifest_hash)
    # Decode reference labels only after every legacy and fresh prediction is durable.
    reports = {}
    for name, inputs in cohorts.items():
        labels = read_rows((directory / name / "private/scoring.jsonl").read_bytes())
        reports[name] = score(results[name], labels, inputs=inputs if name == "fresh" else None,
                              previous=original if name == "legacy" else None)
    checked(directory, manifest_hash)
    report = {"schema": "m7-execution-comparison-report-1", "manifest_sha256": manifest_hash,
              "finished_at": datetime.now(UTC).isoformat(), "cohorts": reports,
              "previous_artifacts_unchanged": True, "historical_quota_records_replayed": sum(row.get("historical_quota_replayed", False) for row in results["legacy"]),
              "labels_decoded_after_all_predictions_saved": True, "external_model_requests": 0,
              "independent_public_generalization_verified": False, "project_goals_met": False,
              "new_labels_independently_human_reviewed": False,
              "source_sha256": manifest["implementation_sha256"],
              "prediction_sha256": {name: _hash(directory / name / "predictions.jsonl") for name in cohorts}}
    exclusive_write(directory / "report.json", json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2).encode() + b"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "evaluate"))
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--previous", type=Path, default=PREVIOUS)
    parser.add_argument("--repetitions", type=int, default=10)
    args = parser.parse_args()
    if args.command == "prepare":
        manifest = prepare(args.directory, previous=args.previous, repetitions=args.repetitions)
        result = {"fresh_sessions": manifest["fresh_sessions"], "legacy_sessions": manifest["legacy_sessions"]}
    elif args.command == "verify":
        manifest, fingerprint = checked(args.directory)
        result = {"verified": True, "manifest_sha256": fingerprint}
    else:
        report = evaluate(args.directory)
        result = {name: {"sessions": item["sessions"], "arms": item["arms"]} for name, item in report["cohorts"].items()}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
