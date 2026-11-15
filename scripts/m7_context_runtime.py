"""Run paired behavior detectors against fresh, signed local operational records.

Only operational inputs enter this module. The caller stores scoring labels separately.
The lab has simulated upstream telemetry; signatures, intake, journal, approvals and
both detectors are the real application implementation. No external API is called.
"""

import base64
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    BehaviorScope,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.continuous_signal_models import SignedContinuousSignal
from app.models import SecurityEvent
from app.security import Principal, Role
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore
from app.services.continuous_signals import ContinuousSignalService
from app.services.public_detection import PublicDetectionService, PublicSession
from app.services.signal_inbox import SignalInbox
from app.services.trusted_signals import (
    SignalRejected,
    SignalVerifier,
    canonical_behavior_capture,
    canonical_observation,
    canonical_signal,
)
from app.services.zero_trust import ZeroTrustOperations
from app.zero_trust_models import SessionRevocationRequest, SignedSessionSignal


def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ).encode()).hexdigest()


def _sign(value, key, canonical):
    signed = base64.urlsafe_b64encode(key.sign(canonical(value))).decode().rstrip("=")
    return value.model_copy(update={"signature": signed})


def _public(value):
    """Provenance includes authentic record content but no signatures or bearer tokens."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items()
                if key not in {"signature", "grant_token", "lease_token", "private_key_pem"}}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


class ContextLab:
    def __init__(self, spec, directory):
        self.spec = spec
        self.base = datetime.fromisoformat(spec["base_time"])
        if self.base.utcoffset() is None:
            raise ValueError("context_lab_clock_requires_timezone")
        self.scope = BehaviorScope.model_validate(spec["scope"])
        self.tenant = spec["tenant_id"]
        self.operator = Principal("lab-operator", self.tenant, frozenset({Role.ADMIN}), "lab")
        self.analyst = Principal("lab-reader", self.tenant, frozenset({Role.ANALYST}), "lab")
        self.keys = {name: Ed25519PrivateKey.generate()
                     for name in ("session", "behavior", "device", "guardduty")}
        self.other_device = "d-" + digest([spec["case_id"], "other-device"])[:32]
        self.other_resource = ("zt-demo-vault" if self.scope.resource_id == "zt-demo-documents"
                               else "zt-demo-documents")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        sources = []
        for name, key in self.keys.items():
            source = {
                "source_id": name, "tenant_id": self.tenant, "enabled": True,
                "user_ids": [self.scope.user_id],
                "device_ids": [self.scope.device_id, self.other_device],
                "roles": ["employee", "administrator"],
                "keys": [{
                    "key_id": "key", "enabled": True,
                    "public_key_pem": key.public_key().public_bytes(
                        serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    ).decode(),
                    "not_before": self.at(-86400).isoformat(),
                    "not_after": self.at(86400).isoformat(),
                }],
            }
            if name == "behavior":
                source["behavior_scopes"] = [self.scope.model_dump(mode="json")]
            elif name == "device":
                source["observation_kinds"] = ["device"]
            elif name == "guardduty":
                source["observation_kinds"] = ["guardduty"]
                source["guardduty_resource_ids"] = [self.scope.resource_id, self.other_resource]
            sources.append(source)
        self.registry = self.directory / "registry.json"
        self.registry.write_text(json.dumps({"sources": sources}))
        self.registry.chmod(0o600)
        self.operations = ZeroTrustOperations(
            self.directory / "operations.sqlite3", signal_verifier=SignalVerifier(self.registry),
        )
        self.store = BehaviorContextStore(self.directory / "context.sqlite3")
        self.service = BehaviorContextService(self.store, self.operations)
        self.intake = ContinuousSignalService(
            self.operations, SignalInbox(self.operations.path),
        )

    def at(self, seconds):
        return self.base + timedelta(seconds=seconds)

    def capture(self, item):
        activity = PublicSession.model_validate(item["activity"])
        started = min(event.timestamp for event in activity.events)
        issued = max(event.timestamp for event in activity.events)
        role = "administrator" if self.scope.resource_id == "zt-demo-vault" else "employee"
        event = SecurityEvent.model_validate({
            "event_id": "e-" + digest([item["session_id"], "session-event"])[:32],
            "timestamp": started, "action": self.scope.action,
            "user": {"user_id": self.scope.user_id, "role": role, "active": True},
            "device": {"device_id": self.scope.device_id, "managed": True,
                       "security_posture": "healthy"},
            "network": {"ip": "192.0.2.10", "location": "lab", "access_method": "office"},
            "resource": {"resource_id": self.scope.resource_id, "resource_type": "document",
                         "sensitivity": "internal", "required_role": None},
            "auth_context": {"authentication_result": "success", "mfa": "success"},
            "behavior": {},
        })
        signal = SignedSessionSignal(
            session_id=item["session_id"], expected_version=0, event=event,
            tenant_id=self.tenant, source_id="session", key_id="key", issued_at=started,
            expires_at=started + timedelta(seconds=90), signature="A" * 86,
        )
        signal = _sign(signal, self.keys["session"], canonical_signal)
        evaluated = self.operations.evaluate_signed(signal, self.operator, now=started)
        if evaluated.session.status != "ACTIVE":
            raise ValueError("context_lab_initial_session_not_active")
        capture = SignedBehaviorCapture(
            tenant_id=self.tenant, capture_id=item["capture_id"], source_id="behavior",
            key_id="key", issued_at=issued, expires_at=issued + timedelta(seconds=90),
            scope=self.scope, session_id=item["session_id"],
            session_version=evaluated.session.version,
            session_input_sha256=evaluated.session.input_digest_sha256,
            connection_ids=sorted({event.connection_id for event in activity.events}),
            activity=activity, signature="A" * 86,
        )
        capture = _sign(capture, self.keys["behavior"], canonical_behavior_capture)
        self.service.accept_capture(capture, self.analyst, now=issued)
        return capture

    def prepare_context(self):
        samples = [self.capture(item) for item in self.spec["baseline_samples"]]
        baseline = self.spec["baseline"]
        approval = self.spec["approval"]
        if baseline["enabled"]:
            self.service.create_baseline(BaselineCreate(
                baseline_id=baseline["id"], capture_ids=[sample.capture_id for sample in samples],
                valid_from=self.at(3), valid_until=self.at(300),
                note="Reviewed earlier local operation samples",
            ), self.operator, now=self.at(3))
        if approval["mode"] != "missing":
            start = 20 if approval["mode"] == "future" else 3
            end = 9 if approval["mode"] == "expired" else 60
            self.service.create_approval(ApprovalCreate(
                approval_id=approval["id"], baseline_id=baseline["id"],
                valid_from=self.at(start), valid_until=self.at(end),
                note="Bounded local operation window", max_uses=approval["max_uses"],
            ), self.operator, now=self.at(3))
        prior = None
        if self.spec["prior_use"] is not None:
            prior = self.capture(self.spec["prior_use"])
            # Preserve what the current service actually observes. Legacy inputs
            # lack execution evidence, so an attempted prior use now remains held;
            # do not manufacture historical consumption or missing observations.
            self.service.evaluate(prior.capture_id, self.analyst, now=self.at(6))
        if approval["mode"] == "revoked":
            self.service.revoke("approval", approval["id"],
                                ContextRevocation(reason="Operation window cancelled"),
                                self.operator, now=self.at(8))
        if baseline["revoked"]:
            self.service.revoke("baseline", baseline["id"],
                                ContextRevocation(reason="Reviewed operation profile withdrawn"),
                                self.operator, now=self.at(8))
        return samples, prior

    def observe(self):
        config = self.spec["observation"]
        if config["kind"] == "none":
            return {"accepted": False, "state": "not_supplied", "event_id": config["id"]}
        if config["kind"] == "device":
            observed = {
                "kind": "device", "managed": True, "security_posture": config["posture"],
                "subject_id": self.scope.device_id if config["scope"] == "same" else self.other_device,
            }
        else:
            observed = {
                "kind": "guardduty", "subject_id": self.scope.user_id,
                "resource_id": self.scope.resource_id if config["scope"] == "same" else self.other_resource,
                "finding_sha256": digest([config["id"], "local-simulated-finding"]),
            }
        request = SignedContinuousSignal(
            tenant_id=self.tenant, source_id=config["kind"], key_id="key", event_id=config["id"],
            issued_at=self.at(11), observed_at=self.at(11), expires_at=self.at(101),
            observation=observed, signature="A" * 86,
        )
        key = (self.keys[config["kind"]] if config["signature"] == "valid"
               else Ed25519PrivateKey.generate())
        request = _sign(request, key, canonical_observation)
        provenance = {
            "event_id": config["id"], "observation": observed,
            "request": request.model_dump(mode="json", exclude={"signature"}),
            "input_sha256": hashlib.sha256(canonical_observation(request)).hexdigest(),
        }
        try:
            self.intake.accept(request, self.analyst, now=self.at(11))
        except SignalRejected:
            return provenance | {"accepted": False, "state": "rejected"}
        reopened = ZeroTrustOperations(
            self.operations.path, signal_verifier=SignalVerifier(self.registry),
        )
        processed = ContinuousSignalService(reopened, SignalInbox(reopened.path)).process_one(now=self.at(11))
        if processed is None or processed["state"] != "completed":
            raise ValueError("context_lab_observation_not_committed")
        return provenance | {"accepted": True, "state": "completed"}


def run_case(spec: dict, directory: Path) -> dict:
    """Execute one already-audited operational spec, with no scoring-file access."""
    # Import only the operational schema validator; it never reads scoring files.
    from scripts.m7_context_dataset import validate_input

    validate_input(spec)
    lab = ContextLab(spec, directory)
    samples, prior_use = lab.prepare_context()
    target = lab.capture(spec["target"])
    intake = lab.observe()
    if spec["session_revoke"]:
        lab.operations.revoke(target.session_id, SessionRevocationRequest(
            expected_version=target.session_version, note="Scheduled local maintenance isolation",
        ), lab.operator, now=lab.at(11))
    before = lab.operations.journal_status()
    context_records = lab.store.read(lab.tenant)
    activity = target.activity.model_dump(mode="json")
    rule_result = PublicDetectionService().evaluate(PublicSession.model_validate(activity))
    context_result = lab.service.evaluate(target.capture_id, lab.analyst, now=lab.at(12))
    if context_result["base_detection"] != rule_result:
        raise ValueError("context_lab_paired_detector_input_changed")
    if lab.operations.journal_status() != before:
        raise ValueError("context_lab_evaluation_changed_access_state")
    with lab.operations._transaction() as transaction:
        observations = [entry for entry in transaction[1] if entry["kind"] == "observation"]
    history = [session.model_dump(mode="json")
               for session in lab.operations.history(target.session_id, lab.operator)]
    activity_hash = digest(activity)
    return {
        "case_id": spec["case_id"], "session_id": target.session_id,
        "input_sha256": digest(spec), "activity_sha256": activity_hash,
        "rule_input_sha256": activity_hash, "context_activity_sha256": activity_hash,
        "rule_only": rule_result, "with_context": context_result,
        "paired_input_identical": True, "policy_journal_unchanged_by_evaluation": True,
        "provenance": {
            "capture": _public(target.model_dump(mode="json")),
            "baseline_sample_captures": [_public(item.model_dump(mode="json")) for item in samples],
            "prior_use_capture": _public(prior_use.model_dump(mode="json")) if prior_use else None,
            "context_records": _public(context_records),
            "observations": _public(observations), "evaluation_at": lab.at(12).isoformat(),
            "session_history": _public(history), "observation_intake": intake,
            "journal_status_before": before,
        },
    }
