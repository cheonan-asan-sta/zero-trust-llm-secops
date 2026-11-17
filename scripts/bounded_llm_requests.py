"""Crash-conservative, serial request accounting for optional paid local labs."""

import json
import math
from datetime import UTC, datetime

from app.analyzers.structured_response import StructuredResponseFailure, parse_structured_response
from scripts.evaluate_llm_development import write_json
from scripts.evaluate_llm_grounded import INPUT_RATE, OUTPUT_RATE


class BoundedRequests:
    def __init__(self, directory, *, max_budget, max_requests, deadline):
        if not math.isfinite(max_budget) or not 0 < max_budget <= 1:
            raise ValueError("budget")
        if not 1 <= max_requests <= 72 or deadline.tzinfo is None:
            raise ValueError("limits")
        self.directory, self.limit, self.maximum = directory, max_budget, max_requests
        self.deadline = deadline
        self.receipts, self.pending, self.fatal = [], None, None
        self.checkpoint()

    def totals(self):
        known = sum(
            r["input_tokens"] * INPUT_RATE + r["output_tokens"] * OUTPUT_RATE
            for r in self.receipts
            if r["input_tokens"] is not None and r["output_tokens"] is not None
        )
        unknown = sum(
            r["reserved_usd"]
            for r in self.receipts
            if r["input_tokens"] is None or r["output_tokens"] is None
        )
        return known, unknown

    def checkpoint(self):
        known, unknown = self.totals()
        write_json(
            self.directory / "cost-checkpoint.json",
            {
                "known_usage_estimated_usd": known,
                "unknown_usage_reserved_usd": unknown,
                "pending_request": self.pending,
                "max_budget_usd": self.limit,
                "requests": len(self.receipts),
                "fatal": self.fatal,
            },
        )
        write_json(self.directory / "receipts.json", self.receipts)

    async def capture(self, provider, **kwargs):
        if self.pending is not None:
            raise ValueError("concurrent_paid_requests_forbidden")
        schema = kwargs["text_format"].model_json_schema()
        serialized = json.dumps(
            {"input": kwargs["input"], "tools": kwargs.get("tools", []), "schema": schema},
            ensure_ascii=False,
        ).encode()
        # UTF-8 bytes exceed token count; include tool and dynamic output schemas too.
        if len(serialized) > 98304:
            raise ValueError("paid_request_input_capacity")
        reserved = (len(serialized) + 16384) * INPUT_RATE + kwargs[
            "max_output_tokens"
        ] * OUTPUT_RATE
        known, unknown = self.totals()
        if (
            self.fatal
            or len(self.receipts) >= self.maximum
            or known + unknown + reserved > self.limit
        ):
            self.fatal = self.fatal or "budget_or_request_limit"
        elif (self.deadline - datetime.now(UTC)).total_seconds() <= 40:
            self.fatal = "deadline"
        if self.fatal:
            self.checkpoint()
            raise ValueError(self.fatal)
        self.pending = {"request": len(self.receipts) + 1, "reserved_usd": reserved}
        self.checkpoint()
        receipt = {**self.pending, "input_tokens": None, "output_tokens": None}
        with (self.directory / "private" / "requests.jsonl").open("ab") as stream:
            stream.write(serialized + b"\n")
        try:
            response, diagnostic = await parse_structured_response(provider, **kwargs)
            receipt.update(diagnostic.as_dict())
            return response, diagnostic
        except Exception as error:
            receipt["error"] = type(error).__name__
            if isinstance(error, StructuredResponseFailure):
                receipt.update(error.diagnostics.as_dict(), error_code=error.code)
            if type(error).__name__ in {
                "AuthenticationError",
                "PermissionDeniedError",
                "RateLimitError",
                "NotFoundError",
            }:
                self.fatal = type(error).__name__
            raise
        finally:
            self.receipts.append(receipt)
            self.pending = None
            known, unknown = self.totals()
            if known + unknown > self.limit:
                self.fatal = "usage_exceeded_reservation"
            self.checkpoint()
