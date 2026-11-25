"""Inspect provider envelope before schema parsing, without retaining model text.

The SDK raw-response API delays its Pydantic post-parser. This lets us preserve
usage and distinguish an incomplete response from a malformed completed response.
No additional API request, retry, or schema relaxation is performed here.
"""

from dataclasses import asdict, dataclass

from openai import AsyncOpenAI
from pydantic import ValidationError

from app.analysis_metrics import ANALYSIS_PHASE_DURATION


@dataclass(frozen=True)
class ResponseDiagnostics:
    status: str
    incomplete_reason: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    refusal: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


class StructuredResponseFailure(RuntimeError):
    def __init__(self, code: str, diagnostics: ResponseDiagnostics):
        super().__init__(code)
        self.code = code
        self.diagnostics = diagnostics


def _tokens(value):
    return value if type(value) is int and value >= 0 else None


def _diagnostics(body: object) -> ResponseDiagnostics:
    if not isinstance(body, dict):
        return ResponseDiagnostics(status="invalid_envelope")
    status = body.get("status")
    if not isinstance(status, str) or status not in {
        "completed", "incomplete", "failed", "cancelled", "queued", "in_progress",
    }:
        status = "unknown"
    details = body.get("incomplete_details")
    reason = details.get("reason") if isinstance(details, dict) else None
    if reason is not None and (
        not isinstance(reason, str) or reason not in {"max_output_tokens", "content_filter"}
    ):
        reason = "other"
    usage = body.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    output = body.get("output")
    refusal = (
        any(
            isinstance(part, dict) and part.get("type") == "refusal"
            for item in output
            if isinstance(item, dict)
            for part in (item.get("content") if isinstance(item.get("content"), list) else [])
        )
        if isinstance(output, list)
        else False
    )
    return ResponseDiagnostics(
        status=status,
        incomplete_reason=reason,
        input_tokens=_tokens(usage.get("input_tokens")),
        output_tokens=_tokens(usage.get("output_tokens")),
        refusal=refusal,
    )


async def parse_structured_response(client: AsyncOpenAI, *, allow_tool_calls=False, **kwargs):
    """Return (SDK parsed response, safe diagnostics); preserve SDK HTTP errors.

    All diagnostics are local to this invocation, including concurrent invocations.
    Provider error/refusal text, output text, headers, and request IDs are excluded.
    """
    with ANALYSIS_PHASE_DURATION.labels("provider_request").time():
        raw = await client.responses.with_raw_response.parse(**kwargs)
    with ANALYSIS_PHASE_DURATION.labels("structured_validation").time():
        return _parse_completed_response(raw, allow_tool_calls)


def _completed_body(raw):
    try:
        body = raw.http_response.json()
    except (ValueError, TypeError):
        raise StructuredResponseFailure(
            "invalid_response_envelope", ResponseDiagnostics(status="invalid_envelope")
        ) from None
    diagnostics = _diagnostics(body)
    if diagnostics.status == "invalid_envelope":
        raise StructuredResponseFailure("invalid_response_envelope", diagnostics)
    if diagnostics.status != "completed":
        raise StructuredResponseFailure("response_not_completed", diagnostics)
    if diagnostics.refusal:
        raise StructuredResponseFailure("response_refused", diagnostics)
    return body, diagnostics


async def parse_single_structured_response(client: AsyncOpenAI, *, text_format, **kwargs):
    """Keep the SDK's strict request schema and validate one tool-free answer directly."""
    with ANALYSIS_PHASE_DURATION.labels("provider_request").time():
        raw = await client.responses.with_raw_response.parse(text_format=text_format, **kwargs)
    with ANALYSIS_PHASE_DURATION.labels("structured_validation").time():
        body, diagnostics = _completed_body(raw)
        output = body.get("output")
        if not isinstance(output, list):
            raise StructuredResponseFailure("structured_output_invalid", diagnostics)
        if any(not isinstance(item, dict) for item in output):
            raise StructuredResponseFailure("structured_output_invalid", diagnostics)
        messages = [item for item in output if item.get("type") != "reasoning"]
        if any(item.get("type") != "message" for item in messages):
            raise StructuredResponseFailure("unexpected_tool_output", diagnostics)
        if not messages:
            raise StructuredResponseFailure("structured_output_missing", diagnostics)
        if len(messages) != 1:
            raise StructuredResponseFailure("structured_output_invalid", diagnostics)
        message = messages[0]
        content = message.get("content")
        if (
            message.get("role") != "assistant"
            or message.get("status") != "completed"
            or not isinstance(content, list)
            or len(content) != 1
            or not isinstance(content[0], dict)
            or content[0].get("type") != "output_text"
            or not isinstance(content[0].get("text"), str)
        ):
            raise StructuredResponseFailure("structured_output_invalid", diagnostics)
        try:
            return text_format.model_validate_json(content[0]["text"]), diagnostics
        except ValidationError:
            raise StructuredResponseFailure("structured_output_invalid", diagnostics) from None


def _parse_completed_response(raw, allow_tool_calls):
    _, diagnostics = _completed_body(raw)
    try:
        response = raw.parse()
    except (ValidationError, ValueError, TypeError):
        raise StructuredResponseFailure("structured_output_invalid", diagnostics) from None
    calls = [item for item in response.output if item.type == "function_call"]
    if calls and (not allow_tool_calls or len(calls) != 1 or response.output_parsed is not None):
        raise StructuredResponseFailure("unexpected_tool_output", diagnostics)
    if response.output_parsed is None and not calls:
        raise StructuredResponseFailure("structured_output_missing", diagnostics)
    return response, diagnostics
