"""Trusted publisher isolation/capacity. There is no HTTP publication endpoint."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from test_service_analysis_evidence import executed as executed  # noqa: PLC0414

from app.services.native_analysis_registry import NativeAnalysisMissing, NativeAnalysisRegistry
from app.services.trusted_signals import SignalRejected
from scripts.f1_lab.service_analysis_evidence import (
    collect_service_analysis_evidence,
    publish_service_analysis,
)


@pytest.mark.parametrize("capacity", [True, 0, -1, 1025, "128"])
def test_invalid_capacity_cannot_create_unbounded_reference_store(executed, capacity):
    lab, _, _ = executed
    with pytest.raises(ValueError):
        NativeAnalysisRegistry(lab.operations, capacity=capacity)


def test_capacity_never_evicts_live_evidence_and_revocation_releases_slot(executed):
    lab, args, _ = executed
    store = NativeAnalysisRegistry(lab.operations, capacity=1)
    first = publish_service_analysis(store, **args)
    with pytest.raises(ValueError, match="capacity"):
        publish_service_analysis(store, **args)
    store.resolve(first, args["principal"])
    store.revoke(first)
    second = publish_service_analysis(store, **args)
    assert second != first
    with pytest.raises(NativeAnalysisMissing):
        store.resolve(first, args["principal"])
    store.resolve(second, args["principal"])


def test_restart_drops_ephemeral_reference_and_requires_fresh_trusted_publication(executed):
    lab, args, _ = executed
    first = publish_service_analysis(NativeAnalysisRegistry(lab.operations), **args)
    restarted = NativeAnalysisRegistry(lab.operations)
    with pytest.raises(NativeAnalysisMissing):
        restarted.resolve(first, args["principal"])
    new = publish_service_analysis(restarted, **args)
    assert new != first


def test_publisher_cannot_attach_evidence_from_another_application(executed):
    _, args, _ = executed
    with pytest.raises(SignalRejected):
        publish_service_analysis(NativeAnalysisRegistry(object()), **args)


def test_original_caller_mutation_cannot_replace_published_signed_inputs(executed):
    lab, args, _ = executed
    registry = NativeAnalysisRegistry(lab.operations)
    ref = publish_service_analysis(registry, **args)
    original = args["signal"].event.event_id
    args["signal"].event.event_id = "mutated-after-publication"
    args["request"].nonce = "e" * 43
    args["receipt"].signature = "e" * 86
    signal, context = registry.resolve(ref, args["principal"])
    assert signal.event.event_id == original
    signal.event.event_id = "mutated-resolved-copy"
    again, _ = registry.resolve(ref, args["principal"])
    assert again.event.event_id == original
    context.verify_current()


@pytest.mark.parametrize("kind", ["no_live_callback", "long_window", "wrong_event"])
def test_invalid_collector_contract_never_publishes_an_http_reference(executed, kind):
    lab, args, _ = executed
    context = collect_service_analysis_evidence(**args)
    if kind == "no_live_callback":
        context = replace(context, verify_current=None)
    elif kind == "long_window":
        context = replace(context, expires_at=datetime.now(UTC) + timedelta(seconds=31))
    else:
        context = replace(context, event_digest_sha256="e" * 64)
    registry = NativeAnalysisRegistry(lab.operations)
    with pytest.raises(SignalRejected):
        registry.publish(args["signal"], args["principal"], lambda _: context)
