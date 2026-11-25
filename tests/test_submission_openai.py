import asyncio

import httpx
import pytest

from scripts.verify_submission_openai import LIMIT, BoundedProvider


def request(**body):
    return httpx.Request(
        "POST", "https://api.openai.com/v1/responses",
        json={"store": False, "max_output_tokens": 800} | body,
    )


def test_paid_submission_requests_are_capped():
    provider = BoundedProvider()
    for _ in range(LIMIT):
        asyncio.run(provider.request(request()))
    with pytest.raises(RuntimeError, match="request cap"):
        asyncio.run(provider.request(request()))
    assert len(provider.receipts) == LIMIT == 8


def test_submission_provider_guard_rejects_wrong_origin_and_payload():
    provider = BoundedProvider()
    with pytest.raises(RuntimeError, match="endpoint"):
        asyncio.run(provider.request(httpx.Request("POST", "http://127.0.0.1/v1/responses")))
    for request_body in ({"store": True}, {"max_output_tokens": 801}, {"max_output_tokens": None}):
        with pytest.raises(RuntimeError, match="budget"):
            asyncio.run(provider.request(request(**request_body)))
    assert provider.receipts == []
