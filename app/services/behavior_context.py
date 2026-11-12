"""Resolve observed activity using reviewed baselines, bounded approvals and trusted history."""

import hashlib
import json
from collections import Counter, deque
from datetime import UTC, datetime

from app.behavior_context_models import (
    ApprovalCreate,
    BaselineCreate,
    ContextRevocation,
    SignedBehaviorCapture,
)
from app.behavior_execution_models import SignedExecutionEvidence
from app.security import Role
from app.services.behavior_context_store import ContextRecordConflict, ContextStoreUnavailable
from app.services.behavior_context_trust import behavior_snapshot
from app.services.behavior_execution import (
    execution_snapshot,
    policy_matches,
    require_capture_binding,
)
from app.services.public_detection import PublicDetectionService
from app.services.trusted_signals import SignalRejected


class ContextNotFound(ValueError):
    pass


class ContextInvalid(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode()).hexdigest()


def require(principal, role):
    if role not in principal.effective_roles:
        raise SignalRejected("context operation requires additional authority")


def activity_profile(activity):
    """Exact observed-operation bounds, without learning from the current candidate."""
    counts = Counter()
    ordered = sorted(activity.events, key=lambda event: event.timestamp)
    window = deque()
    peak = 0
    for event in ordered:
        fields = event.model_dump(mode="json", exclude={"id", "timestamp", "connection_id", "principal_hash"})
        fields["resource_hashes"] = sorted(fields["resource_hashes"])
        counts[digest(fields)] += 1
        window.append(event.timestamp)
        while window and (event.timestamp - window[0]).total_seconds() >= 1:
            window.popleft()
        peak = max(peak, len(window))
    return {"event_limits": dict(counts), "max_events": len(ordered),
            "max_span_seconds": (ordered[-1].timestamp - ordered[0].timestamp).total_seconds(),
            "max_events_per_second": peak}


def profile_fits(profile, limits):
    return (
        profile["max_events"] <= limits["max_events"]
        and profile["max_span_seconds"] <= limits["max_span_seconds"]
        and profile["max_events_per_second"] <= limits["max_events_per_second"]
        and all(count <= limits["event_limits"].get(key, 0)
                for key, count in profile["event_limits"].items())
    )


def active(entry, now, start, end):
    request = entry["payload"]["request"]
    left, right = datetime.fromisoformat(request["valid_from"]), datetime.fromisoformat(request["valid_until"])
    return (left <= start <= end < right and left <= now < right
            and datetime.fromisoformat(entry["created_at"]) <= start)


class BehaviorContextService:
    def __init__(self, store, operations):
        self.store = store
        self.operations = operations
        if store.path.resolve() == operations.path.resolve():
            raise ContextInvalid("context storage must be separate from the policy journal")
        self.detector = PublicDetectionService()

    def _capture(self, tx, capture_id, principal):
        entry = tx.get("capture", principal.tenant_id, capture_id)
        if entry is None:
            raise ContextNotFound("capture not found")
        return entry, SignedBehaviorCapture.model_validate(entry["payload"]["capture"])

    def accept_capture(self, capture, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.ANALYST)
        capture = SignedBehaviorCapture.model_validate(
            capture.model_dump(mode="json") if isinstance(capture, SignedBehaviorCapture) else capture,
        )
        with self.store.transaction() as tx:
            previous = tx.get("capture", principal.tenant_id, capture.capture_id)
            proof = self.operations.signal_verifier.verify_behavior_capture(
                capture, principal, now, enforce_freshness=previous is None,
            )
            if previous is not None:
                if previous["payload"]["input_digest"] != proof.input_digest:
                    raise ContextRecordConflict("capture identifier reused with different input")
                return {"capture_id": capture.capture_id, "duplicate": True,
                        "input_digest": proof.input_digest}
            snapshot = behavior_snapshot(self.operations, capture, principal, now)
            if not snapshot["binding_valid"]:
                raise SignalRejected("capture does not bind to a verified session")
            result = tx.put("capture", principal.tenant_id, capture.capture_id,
                            {"capture": capture.model_dump(mode="json"),
                             "input_digest": proof.input_digest, "source_digest": proof.source_digest,
                             "normal_session_at_acceptance": snapshot["normal_session_eligible"]},
                            actor=principal.subject, now=now)
        return {"capture_id": capture.capture_id, "duplicate": result["duplicate"],
                "input_digest": proof.input_digest}

    def create_baseline(self, request, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.ADMIN)
        request = BaselineCreate.model_validate(
            request.model_dump(mode="json") if isinstance(request, BaselineCreate) else request,
        )
        profiles, event_ids, groups, scope, features = [], set(), set(), None, set()
        with self.store.transaction() as tx:
            previous = tx.get("baseline", principal.tenant_id, request.baseline_id)
            if previous is not None:
                if previous["payload"]["request"] != request.model_dump(mode="json"):
                    raise ContextRecordConflict("baseline identifier reused with different request")
                return {"baseline_id": request.baseline_id, "duplicate": True,
                        "sample_count": len(request.capture_ids),
                        "profile": previous["payload"]["profile"],
                        "revoked": tx.revoked("baseline", principal.tenant_id, request.baseline_id)}
            if request.valid_from < now:
                raise ContextInvalid("a reviewed baseline cannot be backdated")
            for identifier in request.capture_ids:
                entry, capture = self._capture(tx, identifier, principal)
                snapshot = behavior_snapshot(self.operations, capture, principal, now)
                base = self.detector.evaluate(capture.activity)
                observed_scope = capture.scope.model_dump(mode="json")
                ids = {event.id for event in capture.activity.events}
                if (not snapshot["binding_valid"]
                        or not entry["payload"].get("normal_session_at_acceptance", False)
                        or snapshot["evidence"]
                        or base["verdict"] == "threat"
                        or max(event.timestamp for event in capture.activity.events) >= request.valid_from
                        or datetime.fromisoformat(entry["created_at"]) > request.valid_from
                        or ids & event_ids or capture.activity.original_group_id in groups
                        or (scope is not None and scope != observed_scope)):
                    raise ContextInvalid("baseline samples must be distinct, eligible, prior reviewed activity")
                scope = observed_scope
                event_ids.update(ids)
                groups.add(capture.activity.original_group_id)
                profiles.append(activity_profile(capture.activity))
                features.update(item["feature"] for item in base["findings"])
            if len(event_ids) > 5000:
                raise ContextInvalid("reviewed baseline exceeds evidence bound")
            limits = {"event_limits": {}, "max_events": 0, "max_span_seconds": 0,
                      "max_events_per_second": 0}
            for profile in profiles:
                for key in ("max_events", "max_span_seconds", "max_events_per_second"):
                    limits[key] = max(limits[key], profile[key])
                for key, count in profile["event_limits"].items():
                    limits["event_limits"][key] = max(limits["event_limits"].get(key, 0), count)
            payload = {"request": request.model_dump(mode="json"), "scope": scope,
                       "profile": limits, "features": sorted(features),
                       "training_event_ids": sorted(event_ids), "training_groups": sorted(groups)}
            result = tx.put("baseline", principal.tenant_id, request.baseline_id, payload,
                            actor=principal.subject, now=now)
        return {"baseline_id": request.baseline_id, "duplicate": result["duplicate"],
                "sample_count": len(profiles), "profile": limits}

    def accept_execution_evidence(self, request, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.ANALYST)
        request = SignedExecutionEvidence.model_validate(
            request.model_dump(mode="json") if isinstance(request, SignedExecutionEvidence) else request,
        )
        with self.store.transaction() as tx:
            previous = tx.get("execution", principal.tenant_id, request.evidence_id)
            proof = self.operations.signal_verifier.verify_execution_evidence(
                request, principal, now, enforce_freshness=previous is None,
            )
            entry, capture = self._capture(tx, request.capture_id, principal)
            require_capture_binding(request, capture, entry["payload"]["input_digest"])
            if previous is not None:
                if previous["payload"]["input_digest"] != proof.input_digest:
                    raise ContextRecordConflict("execution identifier reused with different input")
                return {"evidence_id": request.evidence_id, "input_digest": proof.input_digest,
                        "duplicate": True}
            if not behavior_snapshot(self.operations, capture, principal, now)["binding_valid"]:
                raise SignalRejected("execution evidence session binding rejected")
            result = tx.put("execution", principal.tenant_id, request.evidence_id, {
                "evidence": request.model_dump(mode="json"), "input_digest": proof.input_digest,
                "source_digest": proof.source_digest,
            }, actor=principal.subject, now=now)
        return {"evidence_id": request.evidence_id, "input_digest": proof.input_digest,
                "duplicate": result["duplicate"]}

    def create_approval(self, request, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.RESPONDER)
        request = ApprovalCreate.model_validate(
            request.model_dump(mode="json") if isinstance(request, ApprovalCreate) else request,
        )
        with self.store.transaction() as tx:
            previous = tx.get("approval", principal.tenant_id, request.approval_id)
            if previous is not None:
                if previous["payload"]["request"] != request.model_dump(mode="json"):
                    raise ContextRecordConflict("approval identifier reused with different request")
                return {"approval_id": request.approval_id, "duplicate": True,
                        "revoked": tx.revoked("approval", principal.tenant_id, request.approval_id)}
            if request.valid_from < now:
                raise ContextInvalid("work approval cannot be backdated")
            baseline = tx.get("baseline", principal.tenant_id, request.baseline_id)
            if baseline is None or tx.revoked("baseline", principal.tenant_id, request.baseline_id):
                raise ContextNotFound("active baseline not found")
            bounds = baseline["payload"]["request"]
            if not (datetime.fromisoformat(bounds["valid_from"]) <= request.valid_from
                    < request.valid_until <= datetime.fromisoformat(bounds["valid_until"])):
                raise ContextInvalid("approval must stay within baseline validity")
            result = tx.put("approval", principal.tenant_id, request.approval_id,
                            {"request": request.model_dump(mode="json"),
                             "scope": baseline["payload"]["scope"],
                             "baseline_digest": digest(baseline["payload"])},
                            actor=principal.subject, now=now)
        return {"approval_id": request.approval_id, "duplicate": result["duplicate"]}

    def revoke(self, kind, identifier, request, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.ADMIN if kind == "baseline" else Role.RESPONDER)
        request = ContextRevocation.model_validate(
            request.model_dump(mode="json") if isinstance(request, ContextRevocation) else request,
        )
        if kind not in {"baseline", "approval"}:
            raise ContextInvalid("context revocation kind invalid")
        with self.store.transaction() as tx:
            if tx.get(kind, principal.tenant_id, identifier) is None:
                raise ContextNotFound("context record not found")
            result = tx.put("revocation", principal.tenant_id, digest([kind, identifier]),
                            {"target_kind": kind, "target_id": identifier, "reason": request.reason},
                            actor=principal.subject, now=now)
        return {"record_id": identifier, "revoked": True, "duplicate": result["duplicate"]}

    def evaluate(self, capture_id, principal, *, now=None):
        now = now or datetime.now(UTC)
        require(principal, Role.ANALYST)
        with self.store.transaction() as tx:
            entry, capture = self._capture(tx, capture_id, principal)
            snapshot = behavior_snapshot(self.operations, capture, principal, now)
            base = self.detector.evaluate(capture.activity)
            result = {"capture_id": capture_id, "verdict": "unknown", "reason": "CONTEXT_REQUIRED",
                      "base_detection": base, "trusted_evidence": snapshot["evidence"],
                      "baseline_id": None, "approval_id": None,
                      "investigation_required": True, "enforcement_eligible": False,
                      "session_binding_valid": snapshot["binding_valid"],
                      "current_session_status": snapshot["current_status"],
                      "execution_status": "not_checked", "execution_evidence_ids": []}
            if not snapshot["binding_valid"]:
                result["reason"] = "SESSION_BINDING_INVALID"
            elif snapshot["evidence"]:
                result.update(verdict="threat", reason="TRUSTED_ADVERSE_EVIDENCE",
                              investigation_required=False)
            elif base["verdict"] == "threat":
                result.update(verdict="threat", reason="EXPLICIT_REMOTE_SHELL_ATTEMPT",
                              investigation_required=False)
            elif not snapshot["normal_session_eligible"]:
                result["reason"] = "SESSION_NOT_ELIGIBLE"
            else:
                profile = activity_profile(capture.activity)
                start = min(event.timestamp for event in capture.activity.events)
                end = max(event.timestamp for event in capture.activity.events)
                scope = capture.scope.model_dump(mode="json")
                observed_ids = {event.id for event in capture.activity.events}
                features = {item["feature"] for item in base["findings"]}
                execution = None
                mismatched_approvals = []
                unresolved_execution_policy = False
                for approval in tx.entries:
                    if (approval["kind"] != "approval" or approval["tenant_id"] != principal.tenant_id
                            or tx.revoked("approval", principal.tenant_id, approval["record_id"])
                            or approval["payload"]["scope"] != scope
                            or not active(approval, now, start, end)):
                        continue
                    baseline_id = approval["payload"]["request"]["baseline_id"]
                    admitted = {item["payload"]["capture_id"] for item in tx.entries
                                if item["kind"] == "evaluation"
                                and item["tenant_id"] == principal.tenant_id
                                and item["payload"].get("verdict") == "normal"
                                and item["payload"].get("approval_id") == approval["record_id"]}
                    if (capture_id not in admitted and len(admitted)
                            >= approval["payload"]["request"].get("max_uses", 1)):
                        continue
                    baseline = tx.get("baseline", principal.tenant_id, baseline_id)
                    if (baseline is None or tx.revoked("baseline", principal.tenant_id, baseline_id)
                            or not active(baseline, now, start, end)):
                        continue
                    payload = baseline["payload"]
                    if (payload["scope"] != scope
                            or approval["payload"]["baseline_digest"] != digest(payload)
                            or observed_ids & set(payload["training_event_ids"])
                            or capture.activity.original_group_id in payload["training_groups"]
                            or not features <= set(payload["features"])
                            or not profile_fits(profile, payload["profile"])):
                        continue
                    policy = approval["payload"]["request"].get("execution_policy")
                    if policy is None:
                        unresolved_execution_policy = True
                        result.update(reason="EXECUTION_POLICY_REQUIRED", execution_status="missing")
                        continue
                    if execution is None:
                        execution = execution_snapshot(
                            tx.entries, capture, entry["payload"]["input_digest"],
                            self.operations.signal_verifier, principal, now,
                        )
                    result.update(execution_status=execution["status"],
                                  execution_evidence_ids=execution["evidence_ids"])
                    if execution["status"] != "complete":
                        result["reason"] = {
                            "missing": "EXECUTION_EVIDENCE_REQUIRED",
                            "incomplete": "EXECUTION_EVIDENCE_INCOMPLETE",
                            "stale": "EXECUTION_EVIDENCE_STALE",
                            "conflict": "EXECUTION_EVIDENCE_CONFLICT",
                        }[execution["status"]]
                        continue
                    if not policy_matches(policy, execution):
                        mismatched_approvals.append((baseline_id, approval["record_id"]))
                        continue
                    result.update(verdict="normal", reason="APPROVED_BASELINE_MATCH",
                                  investigation_required=False, baseline_id=baseline_id,
                                  approval_id=approval["record_id"], execution_status="match")
                    break
                if result["verdict"] != "normal" and unresolved_execution_policy:
                    result.update(reason="EXECUTION_POLICY_REQUIRED", execution_status="missing")
                elif result["verdict"] != "normal" and mismatched_approvals:
                    baseline_id, approval_id = mismatched_approvals[0]
                    result.update(verdict="threat", reason="EXECUTION_SCOPE_MISMATCH",
                                  investigation_required=False, baseline_id=baseline_id,
                                  approval_id=approval_id, execution_status="mismatch")
            result["context_digest"] = digest({
                "capture_digest": entry["payload"]["input_digest"],
                "session_context": {key: snapshot[key] for key in (
                    "binding_valid", "normal_session_eligible", "current_status",
                    "session_version", "capture_source_digest",
                )},
                "context_entries": [digest(item) for item in tx.entries
                                    if item["kind"] in {"capture", "baseline", "approval", "revocation", "execution"}
                                    and item["tenant_id"] == principal.tenant_id],
                "decision": result,
            })
            saved = tx.put("evaluation", principal.tenant_id, result["context_digest"], result,
                           actor=principal.subject, now=now)
            return result | {"duplicate": saved["duplicate"]}

    def history(self, principal):
        require(principal, Role.VIEWER)
        # Avoid returning raw telemetry or signatures from the audit-list endpoint.
        return [{key: entry[key] for key in ("kind", "record_id", "actor", "created_at")}
                for entry in self.store.read(principal.tenant_id)]

    def readiness(self):
        try:
            with self.store.transaction() as tx:
                count = len(tx.entries)
            return {"ok": True, "enabled": True, "records": count,
                    "remaining_records": self.store.max_records - count}
        except ContextStoreUnavailable:
            return {"ok": False, "enabled": True}
