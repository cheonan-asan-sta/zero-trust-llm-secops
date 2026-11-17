"""Inspect provider envelope before schema parsing, without retaining model text.

The SDK raw-response API delays its Pydantic post-parser. This lets us preserve
usage and distinguish an incomplete response from a malformed completed response.
No additional API request, retry, or schema relaxation is performed here.
"""

from dataclasses import asdict, dataclass

from openai import AsyncOpenAI
from pydantic import ValidationError


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
    if status not in {"completed", "incomplete", "failed", "cancelled", "queued", "in_progress"}:
        status = "unknown"
    details = body.get("incomplete_details")
    reason = details.get("reason") if isinstance(details, dict) else None
    if reason is not None and reason not in {"max_output_tokens", "content_filter"}:
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


async def parse_structured_response(client: AsyncOpenAI, **kwargs):
    """Return (SDK parsed response, safe diagnostics); preserve SDK HTTP errors.

    All diagnostics are local to this invocation, including concurrent invocations.
    Provider error/refusal text, output text, headers, and request IDs are excluded.
    """
    raw = await client.responses.with_raw_response.parse(**kwargs)
    try:
        diagnostics = _diagnostics(raw.http_response.json())
    except (ValueError, TypeError):
        raise StructuredResponseFailure(
            "invalid_response_envelope", ResponseDiagnostics(status="invalid_envelope")
        ) from None
    if diagnostics.status == "invalid_envelope":
        raise StructuredResponseFailure("invalid_response_envelope", diagnostics)
    if diagnostics.status != "completed":
        raise StructuredResponseFailure("response_not_completed", diagnostics)
    if diagnostics.refusal:
        raise StructuredResponseFailure("response_refused", diagnostics)
    try:
        response = raw.parse()
    except (ValidationError, ValueError, TypeError):
        raise StructuredResponseFailure("structured_output_invalid", diagnostics) from None
    if response.output_parsed is None:
        raise StructuredResponseFailure("structured_output_missing", diagnostics)
    return response, diagnostics
