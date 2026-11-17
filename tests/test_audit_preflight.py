"""Known audit corruption must block analysis before any provider invocation."""

import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from app import main
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.scenarios import synthetic_events
from app.security import Principal, Role
from app.services.audit import AuditStore
from tests.test_audit_cancellation import record


@pytest.mark.parametrize("failure", ["loaded_corruption", "failed_append"])
def test_known_corrupt_audit_blocks_provider_and_returns_capacity(tmp_path, monkeypatch, failure):
    path = tmp_path / "audit.jsonl"
    if failure == "loaded_corruption":
        path.write_text('{"broken":\n', encoding="utf-8")
    store = AuditStore(path)
    if failure == "failed_append":

        def broken(_):
            path.write_text('{"partial":', encoding="utf-8")
            raise OSError("controlled local append failure")

        monkeypatch.setattr(store, "_append_jsonl", broken)
        with pytest.raises(OSError):
            asyncio.run(store.save(record(1)))
    assert store.integrity()["ok"] is False
    before = path.read_bytes()
    event = synthetic_events()[0].model_copy(update={"ground_truth": None})
    provider = Mock()
    provider.name = "openai"
    provider.analyze = AsyncMock(return_value=RuleBasedAnalyzer().assess(event))
    capacity = asyncio.Semaphore(1)
    monkeypatch.setattr(main, "audit_store", store)
    monkeypatch.setattr(main, "analysis_capacity", capacity)
    principal = Principal("unit-operator", "local", frozenset({Role.ADMIN}), "api_key")
    with pytest.raises(RuntimeError, match="audit log integrity"):
        asyncio.run(main._analyze_event(event, provider, principal, "audit-preflight-test"))
    assert provider.analyze.await_count == 0
    assert path.read_bytes() == before and capacity._value == 1


def test_healthy_local_audit_keeps_analysis_and_persisted_result(tmp_path, monkeypatch):
    store = AuditStore(tmp_path / "audit.jsonl")
    event = synthetic_events()[0].model_copy(update={"ground_truth": None})
    provider = Mock()
    provider.name = "openai"
    provider.analyze = AsyncMock(return_value=RuleBasedAnalyzer().assess(event))
    monkeypatch.setattr(main, "audit_store", store)
    monkeypatch.setattr(main, "analysis_capacity", asyncio.Semaphore(1))
    principal = Principal("unit-operator", "local", frozenset({Role.ADMIN}), "api_key")
    result = asyncio.run(main._analyze_event(event, provider, principal, "audit-preflight-test"))
    assert provider.analyze.await_count == 1
    assert store.get(event.event_id).analysis_id == result.analysis_id
    assert store.integrity()["ok"] is True
