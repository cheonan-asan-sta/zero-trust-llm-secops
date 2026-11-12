"""Provider transport for the M6 public evidence holdout."""

import json
import re

import httpx

from scripts import evaluate_m6 as m6
from scripts import m6_live_providers as live

OPENAI_MODELS = ("gpt-5.4-mini", "gpt-6.1-sol")
JEV_MODEL = "jev-1.14.0"
MODELS = (*OPENAI_MODELS, JEV_MODEL)
CREDENTIAL_ENV = {
    **dict.fromkeys(OPENAI_MODELS, "OPENAI_API_KEY"),
    JEV_MODEL: "TYPESAFE_API_KEY",
}
JEV_URL = "https://api.typesafe.ai/v1/systemone"
ProviderError = live.ProviderError


def _jev_body(payload):
    request = json.loads(payload)
    return {
        "model": JEV_MODEL,
        "state": payload.decode(),
        "questions": {
            "classification": {
                "type": "choice",
                "instructions": request["question"],
                "criteria": dict.fromkeys(request["labels"]),
            },
        },
    }


def jev_wire_size(payload: bytes) -> int:
    return len(m6.canonical(_jev_body(payload)))


async def _post(client, model, key, payload, timeout, *, count=False):
    if model in OPENAI_MODELS:
        url, headers, body = live._request(live.MODELS[0], key, payload, count=count)
        body["model"] = model
    elif model == JEV_MODEL and not count:
        url = JEV_URL
        headers = {"Authorization": f"Bearer {key}"}
        body = _jev_body(payload)
    else:
        raise ProviderError("unsupported_provider_model")

    try:
        return await client.post(
            url, headers=headers | {"Content-Type": "application/json"},
            content=m6.canonical(body), timeout=timeout,
            follow_redirects=False,
        )
    except httpx.TimeoutException:
        raise ProviderError("timeout") from None
    except httpx.HTTPError:
        raise ProviderError("transport_error") from None


def _http_error(response):
    if response.status_code == 200:
        return None
    return {
        401: "authentication",
        402: "insufficient_credits",
        403: "authentication",
        422: "request_validation",
        429: "rate_limit",
    }.get(response.status_code, "http_error")


def _response_object(response):
    if len(response.content) > live.MAX_RESPONSE_BYTES:
        raise ProviderError("response_error")
    try:
        value = response.json(object_pairs_hook=m6.unique_fields)
    except (ValueError, RecursionError):
        raise ProviderError("response_error") from None
    if not isinstance(value, dict):
        raise ProviderError("response_error")
    return value


async def count_input(client: httpx.AsyncClient, model, key, payload: bytes, timeout: float) -> int:
    """Count an OpenAI request using the same input and output schema."""
    response = await _post(client, model, key, payload, timeout, count=True)
    status = _http_error(response)
    if status:
        raise ProviderError(status)
    count = live._tokens(_response_object(response).get("input_tokens"))
    if not count:
        raise ProviderError("response_error")
    return count


def _resolved_model(value, model):
    if value == model:
        return model
    if model in OPENAI_MODELS and isinstance(value, str):
        snapshot = re.escape(model) + r"-\d{4}-\d{2}-\d{2}"
        if re.fullmatch(snapshot, value, re.ASCII):
            return value
    return None


def _probability(value):
    return type(value) in (int, float) and 0 <= value <= 1


def _jev_result(body, payload):
    answers = body.get("answers")
    if not isinstance(answers, dict) or set(answers) != {"classification"}:
        raise ProviderError("jev_answer_id_mismatch")
    answer = answers["classification"]
    if not isinstance(answer, dict) or answer.get("type") != "choice":
        raise ProviderError("jev_invalid_answer_type")

    label = answer.get("choice")
    confidence = answer.get("confidence")
    probabilities = answer.get("probabilities")
    if (label not in m6.LABELS or not _probability(confidence)
            or not isinstance(probabilities, dict) or set(probabilities) != set(m6.LABELS)
            or not all(map(_probability, probabilities.values()))):
        raise ProviderError("jev_invalid_choice")
    # The API can round each probability to two decimal places.
    if abs(sum(probabilities.values()) - 1) > 0.02 or probabilities[label] < max(probabilities.values()):
        raise ProviderError("jev_invalid_probability_distribution")

    normalized = {
        "case_id": json.loads(payload)["case_id"],
        "predicted_label": label,
        "evidence_ids": [],
    }
    return {
        "status": "completed",
        "raw": m6.canonical(normalized).decode(),
        "confidence": confidence,
        "probabilities": probabilities,
    }


async def infer(client: httpx.AsyncClient, model, key, payload: bytes, timeout: float) -> dict:
    """Make one inference attempt and keep provider errors free of response text."""
    receipt = {
        "raw": None,
        "resolved_model": None,
        "input_tokens": None,
        "output_tokens": None,
        "http_status": None,
        "request_id": None,
    }
    try:
        response = await _post(client, model, key, payload, timeout)
    except ProviderError as exc:
        return receipt | {"status": str(exc)}
    receipt["http_status"] = response.status_code
    receipt["request_id"] = live._safe_id(
        response.headers.get("x-request-id") or response.headers.get("request-id")
    )
    status = _http_error(response)
    if status:
        return receipt | {"status": status}
    try:
        body = _response_object(response)
    except ProviderError as exc:
        return receipt | {"status": "response_error", "validation_error": str(exc)}

    receipt["resolved_model"] = _resolved_model(body.get("model"), model)
    receipt["input_tokens"], receipt["output_tokens"] = live._usage(body, model)
    if receipt["resolved_model"] is None:
        return receipt | {"status": "response_error", "validation_error": "resolved_model_mismatch"}
    if model == JEV_MODEL:
        if not receipt["input_tokens"] or receipt["output_tokens"] is None:
            return receipt | {"status": "response_error", "validation_error": "jev_invalid_usage"}
        try:
            return receipt | _jev_result(body, payload)
        except ProviderError as exc:
            return receipt | {"status": "response_error", "validation_error": str(exc)}

    status, raw = live._openai_output(body)
    return receipt | {"status": status, "raw": raw}
