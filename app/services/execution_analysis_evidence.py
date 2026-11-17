"""Read-only execution/policy facts for an exact current-session LLM review.

This does not evaluate/admit a capture, consume approval quota, authorize access,
or give the LLM a detector verdict. Missing observations remain missing.
"""

import json
from datetime import UTC, datetime

from app.behavior_context_models import SignedBehaviorCapture
from app.behavior_execution_models import SignedExecutionEvidence
from app.services.behavior_context import active, activity_profile, digest, profile_fits
from app.services.behavior_context_trust import behavior_snapshot
from app.services.behavior_execution import execution_snapshot
from app.services.session_analysis_evidence import VerifiedSessionContext, collect_session_evidence
from app.services.trusted_signals import SignalRejected


def collect_session_execution_evidence(
    operations, behavior, signal, principal, capture_id, *, now=None
):
    now = now or datetime.now(UTC)
    context = collect_session_evidence(operations, signal, principal, now=now)
    facts = context.for_event(signal.event, now=now)
    if behavior is None or behavior.operations is not operations:
        raise SignalRejected("execution analysis store is not bound to this session service")
    expires = context.expires_at
    with behavior.store.transaction() as tx:
        entries = tx.entries
        entry = tx.get("capture", principal.tenant_id, capture_id)
        if entry is None:
            raise SignalRejected("execution analysis capture is unavailable")
        capture = SignedBehaviorCapture.model_validate(entry["payload"]["capture"])
        if (
            capture.session_id != signal.session_id
            or capture.session_version != facts["session"]["version"]
            or capture.session_input_sha256 != facts["session"]["input_digest_sha256"]
            or capture.expires_at <= now
            or datetime.fromisoformat(entry["created_at"]) > now
        ):
            raise SignalRejected("execution analysis requires the current exact session revision")
        snapshot = behavior_snapshot(operations, capture, principal, now)
        if (
            not snapshot["binding_valid"]
            or snapshot["capture_input_digest_sha256"] != entry["payload"]["input_digest"]
            or snapshot["capture_source_digest"] != entry["payload"]["source_digest"]
        ):
            raise SignalRejected("execution analysis capture authority changed")
        observed = execution_snapshot(
            entries,
            capture,
            entry["payload"]["input_digest"],
            operations.signal_verifier,
            principal,
            now,
        )
        expires = min(expires, capture.expires_at)
        # Positive assertions cannot outlive any of the reports supporting them.
        if observed["status"] == "complete":
            for item in entries:
                if (
                    item["kind"] == "execution"
                    and item["tenant_id"] == principal.tenant_id
                    and item["record_id"] in observed["evidence_ids"]
                ):
                    report = SignedExecutionEvidence.model_validate(item["payload"]["evidence"])
                    expires = min(expires, report.expires_at)
        policies = []
        unresolved_policies = 0
        start = min(event.timestamp for event in capture.activity.events)
        end = max(event.timestamp for event in capture.activity.events)
        profile = activity_profile(capture.activity)
        event_ids = {event.id for event in capture.activity.events}
        features = {f["feature"] for f in behavior.detector.evaluate(capture.activity)["findings"]}
        for approval in entries:
            if (
                approval["kind"] != "approval"
                or approval["tenant_id"] != principal.tenant_id
                or tx.revoked("approval", principal.tenant_id, approval["record_id"])
                or approval["payload"]["scope"] != capture.scope.model_dump(mode="json")
                or not active(approval, now, start, end)
            ):
                continue
            request = approval["payload"]["request"]
            policy = request.get("execution_policy")
            admitted = {
                item["payload"]["capture_id"]
                for item in entries
                if item["kind"] == "evaluation"
                and item["tenant_id"] == principal.tenant_id
                and item["payload"].get("verdict") == "normal"
                and item["payload"].get("approval_id") == approval["record_id"]
            }
            if capture_id not in admitted and len(admitted) >= request.get("max_uses", 1):
                continue
            baseline = tx.get("baseline", principal.tenant_id, request["baseline_id"])
            if (
                baseline is None
                or tx.revoked("baseline", principal.tenant_id, request["baseline_id"])
                or not active(baseline, now, start, end)
            ):
                continue
            payload = baseline["payload"]
            if (
                payload["scope"] != capture.scope.model_dump(mode="json")
                or approval["payload"]["baseline_digest"] != digest(payload)
                or event_ids & set(payload["training_event_ids"])
                or capture.activity.original_group_id in payload["training_groups"]
                or not features <= set(payload["features"])
                or not profile_fits(profile, payload["profile"])
            ):
                continue
            expires = min(
                expires,
                datetime.fromisoformat(request["valid_until"]),
                datetime.fromisoformat(payload["request"]["valid_until"]),
            )
            if policy is None:
                unresolved_policies += 1
            else:
                policies.append({"approval_id": approval["record_id"], "execution_policy": policy})
            if len(policies) + unresolved_policies > 8:
                raise SignalRejected("execution analysis policy context exceeds bounded capacity")
        comparisons = []
        if observed["status"] == "complete":
            actor = observed["actor"].model_dump(mode="json")
            destinations = [d.model_dump(mode="json") for d in observed["destinations"]]
            for item in policies:
                policy = item["execution_policy"]
                actor_checks = {key: value == policy["actor"][key] for key, value in actor.items()}
                destination_checks = [d in policy["destinations"] for d in destinations]
                comparisons.append(
                    {
                        "approval_id": item["approval_id"],
                        "actor_field_equalities": actor_checks,
                        "each_destination_is_in_this_policy": destination_checks,
                        "one_coherent_policy_matches": all(actor_checks.values())
                        and all(destination_checks),
                    }
                )
        facts["execution"] = {
            "capture_id": capture_id,
            "capture_input_sha256": entry["payload"]["input_digest"],
            "session_revision_bound": True,
            "capture_signature_verified": True,
            "observation_status": observed["status"],
            "observed_actor": observed["actor"].model_dump(mode="json")
            if observed["status"] == "complete"
            else None,
            "observed_destinations": [d.model_dump(mode="json") for d in observed["destinations"]]
            if observed["status"] == "complete"
            else None,
            "reviewed_execution_policies": policies,
            "policy_count": len(policies),
            "unresolved_execution_policy_count": unresolved_policies,
            "exact_field_comparisons": comparisons,
            "comparison_scope_complete": observed["status"] == "complete"
            and bool(policies)
            and not unresolved_policies,
            "comparison_meaning": "Exact equality/membership of verified claims and server policies; no classification output or physical attestation",
            "policy_applicability": "server-reviewed scope/window/baseline/profile/quota; not an access grant",
            "collector_provenance_only": True,
            "approval_quota_consumed_by_this_read": False,
            "raw_commands_or_credentials_forwarded": False,
        }
    facts["valid_until"] = expires.isoformat()
    encoded = json.dumps(facts, sort_keys=True, ensure_ascii=False).encode()
    if len(encoded) > 16384:
        raise SignalRejected("execution analysis evidence exceeds bounded capacity")
    return VerifiedSessionContext(context.event_digest_sha256, expires, encoded)
