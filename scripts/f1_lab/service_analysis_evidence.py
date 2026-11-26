"""Trusted internal bridge from managed service execution to advisory LLM review.

Native service provenance is kept separate from Cowrie/CloudTrail behavior scopes.
No HTTP input accepts this context, registry path, or executable command. The caller
must supply server-owned stores and an authenticated principal, not model claims.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature

from app.services.policy import enforce_verified_review_safety
from app.services.session_analysis_evidence import VerifiedSessionContext, collect_session_evidence
from app.services.trusted_signals import SignalRejected
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_caller_identity import CallerReceipt, ServiceRequest, verify_receipt
from scripts.f1_lab.shared_execution_evidence import ServiceEvent, ServiceProof, digest


def collect_service_analysis_evidence(
    operations,
    signal,
    principal,
    joiner,
    caller_registry,
    request,
    event,
    proofs,
    receipt,
    *,
    now=None,
    caller_authority_check=None,
):
    """Collect/recheck an exact recorded execution without consuming another grant.

    Snapshots expire with the shortest supporting proof (at most 30 seconds after
    execution). Revalidation must also run after inference and before delivery.
    Optional caller_authority_check is a trusted server account revalidator.
    """
    # Own immutable copies; subsequent caller mutation cannot change what is checked.
    signal = SignedSessionSignal.model_validate(signal.model_dump(mode="json"))
    request = ServiceRequest.model_validate(request.model_dump(mode="json"))
    event = ServiceEvent.model_validate(event.model_dump(mode="json"))
    receipt = CallerReceipt.model_validate(receipt.model_dump(mode="json"))
    proofs = tuple(ServiceProof.model_validate(p.model_dump(mode="json")) for p in proofs)

    def collect(when):
        if caller_authority_check is not None:
            caller_authority_check()
        try:
            context = collect_session_evidence(operations, signal, principal, now=when)
            facts = context.for_event(signal.event, now=when)
            require(
                event.mode == "systemd"
                and event.collection_basis == "ptrace_exec"
                and event.tenant_id == principal.tenant_id
                and facts["session"]["decision"] == "ALLOW"
                and facts["session"]["status"] == "ACTIVE",
                "native_analysis_managed_execution_scope",
            )
            service_registry = joiner.registry.current(when)
            caller = caller_registry.current(when)
            require(
                service_registry.policy_sha256 == operations.policy_digest,
                "native_analysis_current_app_policy",
            )
            observed = joiner.inspect(event, proofs, now=when)
            verified = verify_receipt(receipt, caller_registry, request, event, now=when)
            require(
                observed.state == "consistent"
                and observed.duplicate
                and observed.evidence_sha256 == verified.service_evidence_sha256
                and verified.caller_ref_sha256
                == digest([caller.issuer, principal.tenant_id, principal.subject]),
                "native_analysis_receipt_provenance",
            )
            runtime = next(p for p in proofs if p.observation.kind == "runtime")
            authorization = next(p for p in proofs if p.observation.kind == "authorization")
            process = runtime.observation
            require(
                process.executable_sha256 == request.executable_sha256
                and process.command_sha256 == request.command_sha256,
                "native_analysis_requested_command",
            )
            access = operations.analysis_execution_access(
                signal.session_id,
                principal,
                request.authentication_nonce,
                expected_version=facts["session"]["version"],
            )
            access_time = datetime.fromisoformat(access["recorded_at"])
            require(
                request.issued_at <= access_time <= authorization.observed_at <= event.observed_at,
                "native_analysis_access_order",
            )
            authority_expiries = [
                a.expires_at
                for a in service_registry.authorities
                if any(
                    (a.tenant_id, a.source_id, a.key_id, a.kind)
                    == (p.tenant_id, p.source_id, p.key_id, p.observation.kind)
                    for p in proofs
                )
            ]
            expires = min(
                context.expires_at,
                request.expires_at,
                caller.expires_at,
                service_registry.expires_at,
                event.observed_at + timedelta(seconds=30),
                *(p.expires_at for p in proofs),
                *authority_expiries,
            )
            require(when < expires, "native_analysis_expired")
            facts["native_execution"] = {
                "scope": "managed_unit_first_successful_exec_not_full_host_or_network_audit",
                "mode": event.mode,
                "collection_basis": event.collection_basis,
                "server_id": event.server_id,
                "unit": event.unit,
                "boot_id": event.boot_id,
                "invocation_id": event.invocation_id,
                "observed_at": event.observed_at.isoformat(),
                "event_sha256": event.sha256,
                "raw_sha256": event.raw_sha256,
                "process": process.model_dump(mode="json", exclude={"kind"}),
                "runtime_source": {"source_id": runtime.source_id, "key_id": runtime.key_id},
                "authorization_source": {
                    "source_id": authorization.source_id,
                    "key_id": authorization.key_id,
                },
                "request_ref_sha256": request.authentication_nonce,
                "evidence_sha256": observed.evidence_sha256,
                "caller_ref_sha256": verified.caller_ref_sha256,
                "caller_environment": verified.environment,
                "caller_relationship": verified.relationship,
                "caller_identity_scope": "execution_request_operator_only_not_event_subject",
                "caller_authenticated_at": verified.authenticated_at.isoformat(),
                "receipt_bound_at": verified.bound_at.isoformat(),
                "service_registry_sha256": joiner.registry.expected_sha256,
                "caller_registry_sha256": caller_registry.sha256,
                "app_access": access,
                "current_policy_digest_sha256": operations.policy_digest,
                "signatures_and_exact_bindings_verified": True,
                "app_grant_already_consumed": True,
                "collector_provenance_only": True,
                "observed_destinations": None,
                "event_subject_identity_or_mfa_verified_by_this_receipt": False,
                "raw_commands_or_credentials_forwarded": False,
                "access_or_evidence_mutated_by_this_read": False,
            }
            facts["valid_until"] = expires.isoformat()
            encoded = json.dumps(facts, sort_keys=True, ensure_ascii=False).encode()
            require(len(encoded) <= 16384, "native_analysis_capacity")
            return VerifiedSessionContext(context.event_digest_sha256, expires, encoded)
        except (ValueError, LookupError, TypeError, InvalidSignature) as error:
            raise SignalRejected("native execution analysis evidence rejected") from error

    context = collect(datetime.now(UTC) if now is None else now)

    def current():
        latest = collect(datetime.now(UTC))
        original, updated = json.loads(context.facts_json), json.loads(latest.facts_json)
        original.pop("collected_at")
        updated.pop("collected_at")
        if original != updated:
            raise SignalRejected("native execution analysis authority changed")

    return replace(context, verify_current=current)


def publish_service_analysis(
    registry,
    operations,
    signal,
    principal,
    joiner,
    caller_registry,
    request,
    event,
    proofs,
    receipt,
):
    """Trusted collector publication; HTTP callers only receive the opaque reference.

    Keeps original signed inputs private and re-collects with the actual HTTP caller.
    Either registry backend must belong to the publishing application's PDP;
    shared readers rebuild contexts with their own serving PDP and pinned sources.
    """
    if registry.operations is not operations:
        raise SignalRejected("native publisher and HTTP application stores differ")
    signal = SignedSessionSignal.model_validate(signal.model_dump(mode="json"))
    request = ServiceRequest.model_validate(request.model_dump(mode="json"))
    event = ServiceEvent.model_validate(event.model_dump(mode="json"))
    receipt = CallerReceipt.model_validate(receipt.model_dump(mode="json"))
    proofs = tuple(ServiceProof.model_validate(p.model_dump(mode="json")) for p in proofs)

    from app.services.shared_native_analysis import SharedNativeAnalysisRegistry

    if isinstance(registry, SharedNativeAnalysisRegistry):
        from scripts.f1_lab.shared_service_analysis import NativeServiceBundle

        bundle = NativeServiceBundle(
            signal=signal, request=request, event=event, proofs=list(proofs), receipt=receipt,
        )
        return registry.publish_bundle(bundle.model_dump_json().encode(), principal)

    def collect(caller):
        return collect_service_analysis_evidence(
            operations, signal, caller, joiner, caller_registry, request, event, proofs, receipt
        )

    return registry.publish(signal, principal, collect)


async def review_service_execution(analyzer, signal, context):
    """Internal advisory entrypoint; no response execution and no paid call of its own.

    The injected grounded analyzer may be the existing OpenAI/Hybrid analyzer.
    The HTTP route separately uses app.main's existing audited delivery pipeline;
    this internal helper does not persist an audit record.
    """
    if context.verify_current is None:
        raise SignalRejected("live native execution evidence revalidation required")
    context.verify_current()
    facts = context.for_event(signal.event)
    if "native_execution" not in facts:
        raise SignalRejected("native execution context required")
    assessment = await analyzer.analyze_with_evidence(signal.event, context)
    context.verify_current()
    facts = context.for_event(signal.event)
    safe, _ = enforce_verified_review_safety(assessment, facts)
    return safe.model_copy(update={"requires_human_review": True})
