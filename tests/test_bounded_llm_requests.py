from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.analyzers.structured_response import ResponseDiagnostics, StructuredResponseFailure
from app.models import SecurityAssessment
from scripts import bounded_llm_requests as bounded


@pytest.fixture
def anyio_backend():
    return "asyncio"


def ledger(tmp_path, **options):
    (tmp_path / "private").mkdir()
    return bounded.BoundedRequests(
        tmp_path,
        max_budget=options.get("max_budget", 0.2),
        max_requests=2,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
    )


def arguments():
    return {
        "input": [{"role": "user", "content": "local"}],
        "text_format": SecurityAssessment,
        "max_output_tokens": 2400,
    }


@pytest.mark.anyio
async def test_known_usage_releases_reservation_and_request_limit_is_hard(tmp_path, monkeypatch):
    target = ledger(tmp_path)

    async def provider(*args, **kwargs):
        assert target.pending is not None
        return SimpleNamespace(), ResponseDiagnostics(
            "completed", input_tokens=100, output_tokens=20
        )

    monkeypatch.setattr(bounded, "parse_structured_response", provider)
    for _ in range(2):
        await target.capture(None, **arguments())
    known, unknown = target.totals()
    assert known == pytest.approx(0.00033) and unknown == 0
    assert target.pending is None
    with pytest.raises(ValueError, match="budget_or_request_limit"):
        await target.capture(None, **arguments())
    assert len(target.receipts) == 2


@pytest.mark.anyio
async def test_error_with_unknown_usage_keeps_full_reservation(tmp_path, monkeypatch):
    target = ledger(tmp_path)

    async def provider(*args, **kwargs):
        raise RuntimeError("must_not_persist_secret_message")

    monkeypatch.setattr(bounded, "parse_structured_response", provider)
    with pytest.raises(RuntimeError):
        await target.capture(None, **arguments())
    known, unknown = target.totals()
    assert known == 0 and unknown == target.receipts[0]["reserved_usd"] > 0
    assert "must_not_persist_secret_message" not in (tmp_path / "receipts.json").read_text()


@pytest.mark.anyio
async def test_incomplete_usage_is_still_accounted_without_retry(tmp_path, monkeypatch):
    target = ledger(tmp_path)

    async def provider(*args, **kwargs):
        raise StructuredResponseFailure(
            "response_not_completed",
            ResponseDiagnostics("incomplete", "max_output_tokens", 100, 2400),
        )

    monkeypatch.setattr(bounded, "parse_structured_response", provider)
    with pytest.raises(StructuredResponseFailure):
        await target.capture(None, **arguments())
    assert target.totals() == pytest.approx((0.010875, 0))
    assert len(target.receipts) == 1


@pytest.mark.anyio
async def test_budget_refuses_provider_before_request_and_pending_is_conservative(
    tmp_path, monkeypatch
):
    target = ledger(tmp_path, max_budget=0.00001)

    async def forbidden(*args, **kwargs):
        raise AssertionError("paid call forbidden")

    monkeypatch.setattr(bounded, "parse_structured_response", forbidden)
    with pytest.raises(ValueError, match="budget_or_request_limit"):
        await target.capture(None, **arguments())
    assert not target.receipts and target.pending is None
