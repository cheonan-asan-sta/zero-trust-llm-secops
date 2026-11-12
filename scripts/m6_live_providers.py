"""Provider transport for the M6 live, classification-only comparison."""

import re

import httpx

MODELS = ("gpt-6.1-sol", "claude-sonnet-5-5")
CREDENTIAL_ENV = {MODELS[0]: "OPENAI_API_KEY", MODELS[1]: "ANTHROPIC_API_KEY"}
INPUT_LIMIT = 4096
OUTPUT_LIMIT = 1024
SCHEMA = {
    "type": "object",
    "properties": {
        "case_id": {"type": "string"},
        "predicted_label": {"type": "string", "enum": ["normal", "threat", "unknown"]},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["case_id", "predicted_label", "evidence_ids"],
    "additionalProperties": False,
}

OPENAI_URL = "https://api.openai.com/v1/responses"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2026-10-21"
MAX_RESPONSE_BYTES = 65_536
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class ProviderError(ValueError):
    """A safe provider failure code without response text or credentials."""


def _request(model, key, payload, *, count):
    text = payload.decode("utf-8")
    if model == MODELS[0]:
        headers = {"Authorization": f"Bearer {key}"}
        body = {
            "model": model,
            "input": [{"role": "user", "content": text}],
            "reasoning": {"effort": "low"},
            "text": {"format": {
                "type": "json_schema", "name": "m6_classification", "schema": SCHEMA, "strict": True,
            }},
            "truncation": "disabled",
        }
        if count:
            return OPENAI_URL + "/input_tokens", headers, body
        body.update(store=False, service_tier="default", max_output_tokens=OUTPUT_LIMIT)
        return OPENAI_URL, headers, body

    if model == MODELS[1]:
        headers = {"x-api-key": key, "anthropic-version": ANTHROPIC_VERSION}
        body = {
            "model": model,
            "messages": [{"role": "user", "content": text}],
            "output_config": {
                "effort": "low", "format": {"type": "json_schema", "schema": SCHEMA},
            },
        }
        if count:
            return ANTHROPIC_URL + "/count_tokens", headers, body
        body.update(max_tokens=OUTPUT_LIMIT, service_tier="standard_only")
        return ANTHROPIC_URL, headers, body

    raise ProviderError("unsupported_provider_model")


async def _post(client, model, key, payload, timeout, *, count):
    url, headers, body = _request(model, key, payload, count=count)
    try:
        return await client.post(
            url, headers=headers, json=body, timeout=timeout, follow_redirects=False,
        )
    except httpx.TimeoutException:
        raise ProviderError("timeout") from None
    except httpx.HTTPError:
        raise ProviderError("transport_error") from None


def _http_status(response):
    if response.status_code == 429:
        return "rate_limit"
    return None if response.is_success else "http_error"


def _json_object(response):
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise ProviderError("response_error")
    try:
        value = response.json()
    except (ValueError, RecursionError):
        raise ProviderError("response_error") from None
    if not isinstance(value, dict):
        raise ProviderError("response_error")
    return value


def _tokens(value):
    return value if type(value) is int and value >= 0 else None


async def count_input(client: httpx.AsyncClient, model, key, payload: bytes, timeout: float) -> int:
    """Count input with the provider's non-generating endpoint and matching schema."""
    response = await _post(client, model, key, payload, timeout, count=True)
    status = _http_status(response)
    if status:
        raise ProviderError(status)
    count = _tokens(_json_object(response).get("input_tokens"))
    if not count:
        raise ProviderError("response_error")
    return count


def _safe_id(value):
    return value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else None


def _output_text(blocks, text_type, skipped=()):
    if not isinstance(blocks, list) or any(not isinstance(block, dict) for block in blocks):
        return "response_error", None
    if any(block.get("type") == "refusal" for block in blocks):
        return "refusal", None
    parts = []
    for block in blocks:
        kind = block.get("type")
        if kind in skipped:
            continue
        if kind != text_type or not isinstance(block.get("text"), str):
            return "response_error", None
        parts.append(block["text"])
    raw = "".join(parts)
    return ("completed", raw) if raw.strip() else ("response_error", None)


def _openai_output(body):
    if body.get("status") == "incomplete":
        details = body.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, dict) else None
        if reason == "max_output_tokens":
            return "output_limit", None
        if reason == "content_filter":
            return "refusal", None
    if body.get("status") != "completed":
        return "response_error", None
    output = body.get("output")
    if not isinstance(output, list) or any(not isinstance(item, dict) for item in output):
        return "response_error", None
    messages = [item for item in output if item.get("type") != "reasoning"]
    if len(messages) != 1:
        return "response_error", None
    message = messages[0]
    if message.get("type") != "message" or message.get("role") != "assistant":
        return "response_error", None
    return _output_text(message.get("content"), "output_text")


def _anthropic_output(body):
    reason = body.get("stop_reason")
    if reason == "refusal":
        return "refusal", None
    if reason in ("max_tokens", "model_context_window_exceeded"):
        return "output_limit", None
    if reason != "end_turn":
        return "response_error", None
    return _output_text(body.get("content"), "text", ("thinking", "redacted_thinking"))


def _usage(body, model):
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None, None
    if model == MODELS[1] and any(
        usage.get(name) not in (None, 0)
        for name in ("cache_creation_input_tokens", "cache_read_input_tokens")
    ):
        # These requests do not enable caching. Keep the reservation if billing is unclear.
        return None, None
    return _tokens(usage.get("input_tokens")), _tokens(usage.get("output_tokens"))


async def infer(client: httpx.AsyncClient, model, key, payload: bytes, timeout: float) -> dict:
    """Make one attempt. Return classification text only when generation completed."""
    receipt = {"raw": None, "resolved_model": None, "input_tokens": None, "output_tokens": None,
               "http_status": None, "request_id": None}
    try:
        response = await _post(client, model, key, payload, timeout, count=False)
    except ProviderError as exc:
        return receipt | {"status": str(exc)}
    receipt["http_status"] = response.status_code
    receipt["request_id"] = _safe_id(response.headers.get("x-request-id")
                                     or response.headers.get("request-id"))
    status = _http_status(response)
    if status:
        return receipt | {"status": status}
    try:
        body = _json_object(response)
    except ProviderError as exc:
        return receipt | {"status": str(exc)}
    receipt["resolved_model"] = _safe_id(body.get("model"))
    receipt["input_tokens"], receipt["output_tokens"] = _usage(body, model)
    status, raw = _openai_output(body) if model == MODELS[0] else _anthropic_output(body)
    if status == "completed" and receipt["resolved_model"] is None:
        return receipt | {"status": "response_error"}
    return receipt | {"status": status, "raw": raw}
