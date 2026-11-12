"""Exercise each provider's HTTP request and response format entirely in process."""

import json
from collections import defaultdict

import httpx

from scripts import evaluate_m6 as m6
from scripts import m6_live_providers as live
from scripts import m6_public_providers as providers
from scripts.prepare_m7_paired import EVENT_FIELDS, REQUEST_FIELDS

MOCK_KEY = "m6-paired-local-transport-only"
COUNT_URL = live.OPENAI_URL + "/input_tokens"
HEADERS = {
    "host", "accept", "accept-encoding", "connection", "user-agent",
    "authorization", "content-type", "content-length",
}


def _fixture_outcomes(requests):
    groups = defaultdict(list)
    for request in requests:
        first, last = request["events"][0], request["events"][-1]
        caller = last["endpoint_account"] or last["registered_account"]
        label = "normal" if caller == first["verified_account"] else "threat"
        groups[label].append(request["case_id"])

    outcomes = {}
    # Inject the same test faults for every provider, without consulting scoring labels.
    for label, case_ids in groups.items():
        opposite = "threat" if label == "normal" else "normal"
        for index, case_id in enumerate(sorted(case_ids)):
            outcomes[case_id] = {0: opposite, 1: "unknown", 2: "invalid"}.get(index % 20, label)
    return outcomes


def _openai_envelope(model, content, *, count):
    body = {
        "model": model,
        "input": [{"role": "user", "content": content}],
        "reasoning": {"effort": "low"},
        "text": {"format": {
            "type": "json_schema", "name": "m6_classification", "schema": live.SCHEMA, "strict": True,
        }},
        "truncation": "disabled",
    }
    if not count:
        body.update(store=False, service_tier="default", max_output_tokens=live.OUTPUT_LIMIT)
    return body


def _fixture_response(model, request, label, tokens):
    usage = {"input_tokens": tokens, "output_tokens": 8}
    if model == providers.JEV_MODEL:
        answer = {
            "type": "invalid" if label == "invalid" else "choice",
            "choice": label,
            "confidence": 1,
            "probabilities": {option: int(option == label) for option in request["labels"]},
        }
        return {"model": model, "usage": usage, "answers": {"classification": answer}}

    classification = {
        "case_id": request["case_id"], "predicted_label": label,
        "evidence_ids": request["evidence_ids"],
    }
    return {
        "model": model, "usage": usage, "status": "completed",
        "output": [{
            "type": "message", "role": "assistant",
            "content": [{
                "type": "output_text",
                "text": "{" if label == "invalid" else m6.canonical(classification).decode(),
            }],
        }],
    }


class PairedMock:
    """Verify provider envelopes against canonical inputs, with no access to answer files."""

    def __init__(self, inputs):
        self._inputs = {}
        requests = []
        for request, payload in inputs:
            case_id = request["case_id"]
            if (case_id in self._inputs or set(request) != REQUEST_FIELDS
                    or tuple(request["labels"]) != m6.LABELS or m6.canonical(request) != payload
                    or any(set(event) != EVENT_FIELDS for event in request["events"])):
                raise ValueError("m6_paired_mock_input_shape")
            self._inputs[case_id] = payload
            requests.append(request)
        self._outcomes = _fixture_outcomes(requests)
        self._generated = {model: set() for model in providers.MODELS}
        self._counted = {model: set() for model in providers.OPENAI_MODELS}
        self.credentials = dict.fromkeys(providers.MODELS, MOCK_KEY)
        self.transport = httpx.MockTransport(self._handle)

    def _handle(self, http_request):
        if (http_request.method != "POST"
                or http_request.headers.get("authorization") != f"Bearer {MOCK_KEY}"
                or set(http_request.headers) - HEADERS):
            raise ValueError("m6_paired_mock_http_shape")
        body = json.loads(http_request.content, object_pairs_hook=m6.unique_fields)
        url, model = str(http_request.url), body["model"]
        count = url == COUNT_URL
        if model == providers.JEV_MODEL and url == providers.JEV_URL:
            content = body["state"]
        elif model in providers.OPENAI_MODELS and url in {live.OPENAI_URL, COUNT_URL}:
            content = body["input"][0]["content"]
        else:
            raise ValueError("m6_paired_mock_endpoint")

        request = json.loads(content, object_pairs_hook=m6.unique_fields)
        case_id = request["case_id"]
        if content.encode() != self._inputs.get(case_id):
            raise ValueError("m6_paired_mock_payload_changed")
        if model == providers.JEV_MODEL:
            envelope = {"model": model, "state": content, "questions": {"classification": {
                "type": "choice", "instructions": request["question"],
                "criteria": dict.fromkeys(request["labels"]),
            }}}
        else:
            envelope = _openai_envelope(model, content, count=count)
        if body != envelope:
            raise ValueError("m6_paired_mock_provider_envelope")

        seen = self._counted[model] if count else self._generated[model]
        if case_id in seen:
            raise ValueError("m6_paired_mock_duplicate")
        seen.add(case_id)
        tokens = (len(self._inputs[case_id]) + 3) // 4
        if count:
            return httpx.Response(200, json={"input_tokens": tokens})
        response = _fixture_response(model, request, self._outcomes[case_id], tokens)
        return httpx.Response(200, json=response)

    def verify(self):
        expected = set(self._inputs)
        if any(seen != expected for seen in (*self._generated.values(), *self._counted.values())):
            raise ValueError("m6_paired_mock_missing_requests")
        per_model = {model: len(seen) for model, seen in self._generated.items()}
        return {
            "matched_input_sessions": len(expected),
            "verified_generation_requests": sum(per_model.values()),
            "verified_openai_token_count_requests": sum(len(seen) for seen in self._counted.values()),
            "generation_requests_by_model": per_model,
            "same_input_bytes_per_model": True,
            "scoring_fields_present": False,
        }
