"""Controlled current-time execution assertions, never actual AWS/OS compromise.

Uses fresh Ed25519 authorities, real stores/policy windows and actual file hashes.
Process identity/destinations are authored lab observations; no network destination
is contacted and no enterprise process/person attestation is claimed.
"""

import base64
import hashlib
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.behavior_execution_models import BehaviorScope, SignedExecutionEvidence
from app.services.behavior_context import BehaviorContextService
from app.services.behavior_context_store import BehaviorContextStore
from app.services.execution_analysis_evidence import collect_session_execution_evidence
from app.services.trusted_signals import canonical_behavior_capture, canonical_execution_evidence
from scripts.local_session_analysis_lab import SCENARIOS, LocalSessionAnalysisLab

EXECUTION_SCENARIOS = (
    ("primary_all", False),
    ("primary_subset_first", False),
    ("primary_subset_second", False),
    ("secondary", False),
    ("other_principal", True),
    ("other_workload", True),
    ("other_executable", True),
    ("host_suffix", True),
    ("other_port", True),
    ("path_prefix", True),
    ("extra_destination", True),
    ("mixed_policies", True),
)

GROUNDING_SCENARIOS = (
    ("missing_execution", None),
    ("missing_actor", None),
    ("missing_destinations", None),
    ("conflicting_reports", None),
    ("unresolved_legacy_scope", None),
    ("no_active_reviewed_policy", None),
)


def signed(model, key, canonical):
    signature = base64.urlsafe_b64encode(key.sign(canonical(model))).decode().rstrip("=")
    return model.model_copy(update={"signature": signature})


class LocalExecutionAnalysisLab(LocalSessionAnalysisLab):
    def __init__(self, directory):
        super().__init__(directory)
        self.scope = BehaviorScope(
            source="cloudtrail",
            user_id="local-user",
            device_id="local-device",
            resource_id="remote-read",
            action="READ",
            principal_hash="local-lab-actor",
        )
        self.keys = {kind: Ed25519PrivateKey.generate() for kind in ("behavior", "execution")}
        now = datetime.now(UTC)
        for kind, key in self.keys.items():
            self.registry["sources"].append(
                {
                    "source_id": "local-" + kind,
                    "tenant_id": "local-lab",
                    "user_ids": ["local-user"],
                    "device_ids": ["local-device"],
                    "roles": ["employee"],
                    kind + "_scopes": [self.scope.model_dump(mode="json")],
                    "keys": [
                        {
                            "key_id": "ephemeral-key",
                            "not_before": (now - timedelta(minutes=1)).isoformat(),
                            "not_after": (now + timedelta(hours=1)).isoformat(),
                            "public_key_pem": key.public_key()
                            .public_bytes(
                                serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo,
                            )
                            .decode(),
                        }
                    ],
                }
            )
        self.save_registry()
        self.behavior = BehaviorContextService(
            BehaviorContextStore(self.directory / "behavior.sqlite3"), self.service
        )
        with open(sys.executable, "rb") as executable:
            digest = hashlib.file_digest(executable, "sha256").hexdigest()
        self.primary_policy = {
            "actor": {
                "principal_id": "local-lab-actor",
                "workload_id": "reviewed-job-1",
                "executable_sha256": digest,
            },
            "destinations": [
                {"kind": "https", "host": "archive.example.test", "port": 443, "path": "/backup"},
                {"kind": "https", "host": "archive.example.test", "port": 443, "path": "/manifest"},
            ],
        }
        self.secondary_policy = {
            "actor": self.primary_policy["actor"] | {"workload_id": "reviewed-job-2"},
            "destinations": [
                {"kind": "https", "host": "secondary.example.test", "port": 443, "path": "/backup"}
            ],
        }

    def capture(self):
        signal, _ = super().create(next(s for s in SCENARIOS if s[0] == "read_over_vpn"))
        now = datetime.now(UTC)
        nonce = secrets.token_hex(12)
        connection = "connection-" + nonce
        capture = SignedBehaviorCapture(
            tenant_id="local-lab",
            capture_id="capture-" + nonce,
            source_id="local-behavior",
            key_id="ephemeral-key",
            issued_at=now,
            expires_at=min(signal.expires_at, now + timedelta(seconds=120)),
            scope=self.scope,
            session_id=signal.session_id,
            session_version=1,
            session_input_sha256=self.service.history(signal.session_id, self.principal)[
                -1
            ].input_digest_sha256,
            connection_ids=[connection],
            signature="A" * 86,
            activity={
                "source": "cloudtrail",
                "original_group_id": "group-" + nonce,
                "events": [
                    {
                        "id": f"event-{nonce}-{i}",
                        "timestamp": now,
                        "kind": "AwsApiCall",
                        "api_service": "s3.amazonaws.com",
                        "api_action": "PutObject",
                        "connection_id": connection,
                        "principal_hash": self.scope.principal_hash,
                        "resource_hashes": [f"object-{i % 25}"],
                        "outcome": "success",
                    }
                    for i in range(100)
                ],
            },
        )
        capture = signed(capture, self.keys["behavior"], canonical_behavior_capture)
        self.behavior.accept_capture(capture, self.principal)
        return signal, capture

    def prepare(self):
        samples = [self.capture()[1].capture_id for _ in range(3)]
        starts = datetime.now(UTC) + timedelta(seconds=2)
        ends = starts + timedelta(minutes=30)
        self.behavior.create_baseline(
            BaselineCreate(
                baseline_id="local-reviewed-baseline",
                capture_ids=samples,
                valid_from=starts,
                valid_until=ends,
                note="Controlled local lab reviewed captures; not deployment evidence",
            ),
            self.principal,
        )
        for i, policy in enumerate((self.primary_policy, self.secondary_policy)):
            self.behavior.create_approval(
                ApprovalCreate(
                    approval_id=f"local-reviewed-approval-{i}",
                    baseline_id="local-reviewed-baseline",
                    valid_from=starts,
                    valid_until=ends,
                    max_uses=100,
                    execution_policy=policy,
                    note="Controlled local lab execution scope",
                ),
                self.principal,
            )
        # Wait for an actually scheduled future window; never backdate training/approval.
        while (remaining := (starts - datetime.now(UTC)).total_seconds()) > 0:
            time.sleep(min(remaining, 0.05))

    def create_execution_case(self, name):
        if name not in dict(EXECUTION_SCENARIOS):
            raise ValueError("unknown_execution_scenario")
        signal, capture = self.capture()
        actor = dict(self.primary_policy["actor"])
        destinations = [dict(d) for d in self.primary_policy["destinations"]]
        if name == "secondary":
            actor, destinations = (
                dict(self.secondary_policy["actor"]),
                [dict(d) for d in self.secondary_policy["destinations"]],
            )
        elif name == "primary_subset_first":
            destinations = destinations[:1]
        elif name == "primary_subset_second":
            destinations = destinations[1:]
        elif name == "other_principal":
            actor["principal_id"] = "local-other-principal"
        elif name == "other_workload":
            actor["workload_id"] = "local-other-job"
        elif name == "other_executable":
            actor["executable_sha256"] = hashlib.sha256(b"different-local-artifact").hexdigest()
        elif name == "host_suffix":
            destinations[0]["host"] += ".other.test"
        elif name == "other_port":
            destinations[0]["port"] = 8443
        elif name == "path_prefix":
            destinations[0]["path"] += "/history"
        elif name == "extra_destination":
            destinations.append(dict(self.secondary_policy["destinations"][0]))
        elif name == "mixed_policies":
            destinations = [dict(d) for d in self.secondary_policy["destinations"]]
        self.record_execution(signal, capture, actor, destinations)
        context = collect_session_execution_evidence(
            self.service, self.behavior, signal, self.principal, capture.capture_id
        )
        return signal, capture, context

    def record_execution(self, signal, capture, actor, destinations):
        """Record observed facts, including explicit missing fields, without policy fill-in."""
        now = datetime.now(UTC)
        evidence = SignedExecutionEvidence(
            tenant_id="local-lab",
            evidence_id="report-" + secrets.token_hex(12),
            source_id="local-execution",
            key_id="ephemeral-key",
            issued_at=now,
            expires_at=min(capture.expires_at, now + timedelta(seconds=120)),
            observed_at=capture.issued_at,
            scope=self.scope,
            session_id=signal.session_id,
            session_version=1,
            session_input_sha256=capture.session_input_sha256,
            capture_id=capture.capture_id,
            capture_input_sha256=hashlib.sha256(canonical_behavior_capture(capture)).hexdigest(),
            event_ids=[e.id for e in capture.activity.events],
            connection_ids=capture.connection_ids,
            actor=actor,
            destinations=destinations,
            signature="A" * 86,
        )
        evidence = signed(evidence, self.keys["execution"], canonical_execution_evidence)
        self.behavior.accept_execution_evidence(evidence, self.principal)
        return evidence

    def create_grounding_case(self, name):
        if name not in dict(GROUNDING_SCENARIOS):
            raise ValueError("unknown_grounding_scenario")
        if name == "unresolved_legacy_scope":
            starts = datetime.now(UTC) + timedelta(seconds=2)
            self.behavior.create_approval(
                ApprovalCreate(
                    approval_id="local-legacy-approval",
                    baseline_id="local-reviewed-baseline",
                    valid_from=starts,
                    valid_until=starts + timedelta(minutes=5),
                    max_uses=100,
                    note="Authored development legacy scope with no execution policy",
                ),
                self.principal,
            )
            while (remaining := (starts - datetime.now(UTC)).total_seconds()) > 0:
                time.sleep(min(remaining, 0.05))
        elif name == "no_active_reviewed_policy":
            for identifier in (
                "local-reviewed-approval-0",
                "local-reviewed-approval-1",
                "local-legacy-approval",
            ):
                if identifier == "local-legacy-approval" and not self._has_legacy_approval():
                    continue
                self.behavior.revoke(
                    "approval",
                    identifier,
                    ContextRevocation(reason="Withdraw local scope before uncertainty review"),
                    self.principal,
                )
        signal, capture = self.capture()
        actor = dict(self.primary_policy["actor"])
        destinations = [dict(item) for item in self.primary_policy["destinations"]]
        if name == "missing_actor":
            actor = None
        elif name == "missing_destinations":
            destinations = None
        elif name == "unresolved_legacy_scope":
            actor["workload_id"] = "unreviewed-workload"
        if name != "missing_execution":
            self.record_execution(signal, capture, actor, destinations)
        if name == "conflicting_reports":
            self.record_execution(
                signal, capture, actor | {"workload_id": "conflicting-workload"}, destinations
            )
        context = collect_session_execution_evidence(
            self.service, self.behavior, signal, self.principal, capture.capture_id
        )
        return signal, capture, context

    def _has_legacy_approval(self):
        with self.behavior.store.transaction() as transaction:
            return (
                transaction.get("approval", self.principal.tenant_id, "local-legacy-approval")
                is not None
            )
