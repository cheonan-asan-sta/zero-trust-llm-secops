"""Explicitly injected adapters must never trigger an implicit real provider."""

import asyncio

import pytest

from app.analyzers import hybrid
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.scenarios import synthetic_events


@pytest.mark.parametrize("false_by", ["bool", "length"])
def test_falsey_injected_adapter_is_used_without_creating_or_closing_another_provider(
    monkeypatch, false_by
):
    created, analyzed, closed = [], [], []

    class Injected(RuleBasedAnalyzer):
        async def analyze(self, event):
            analyzed.append(event.event_id)
            return await super().analyze(event)

        async def close(self):
            closed.append(True)

    if false_by == "bool":
        Injected.__bool__ = lambda self: False
    else:
        Injected.__len__ = lambda self: 0
    injected = Injected()

    def construct(_):
        created.append(True)
        return RuleBasedAnalyzer()

    monkeypatch.setattr(hybrid, "OpenAIAnalyzer", construct)
    model = hybrid.HybridAnalyzer(Settings(_env_file=None, hybrid_review_all=True), llm=injected)
    assert model._llm is injected and not created

    async def run():
        result = await model.analyze(synthetic_events()[0])
        assert result is not None
        await model.close()

    asyncio.run(run())
    assert len(analyzed) == 1 and not closed and not created
