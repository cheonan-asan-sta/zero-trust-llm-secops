"""Strict public probe envelopes; never publish subprocess text or credentials."""

import json
import ssl
import subprocess
from http.client import HTTPException
from typing import Literal

from pydantic import Field, model_validator

from app.models import StrictModel
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.f1_lab.native_jsonl import decode

MAX_REPORT = 32768
PROBE_ERRORS = (
    OSError,
    ValueError,
    TypeError,
    KeyError,
    RuntimeError,
    HTTPException,
    subprocess.SubprocessError,
    OverflowError,
)
Stage = Literal[
    "input",
    "probe",
    "mint",
    "request",
    "replay",
    "command",
    "counter_before",
    "counter_after",
    "response_validation",
    "replay_validation",
    "health",
    "recovery",
    "prepare",
    "complete",
]
Code = Literal[
    "timeout",
    "connection",
    "tls_certificate",
    "tls",
    "http_protocol",
    "io",
    "invalid_data",
    "runtime_control",
    "internal",
    "mint_rejected",
    "command_exit",
    "invalid_report",
    "scope_mismatch",
    "incomplete_probe",
]


class Failure(StrictModel):
    stage: Stage
    code: Code
    request_index: int | None = Field(default=None, strict=True, ge=0, le=15)


def failure(error, stage, index=None):
    # No str/repr, exception class name, argv, stdout, stderr, URL or payload.
    code = "internal"
    for kind, value in (
        (ssl.SSLCertVerificationError, "tls_certificate"),
        (ssl.SSLError, "tls"),
        ((TimeoutError, subprocess.TimeoutExpired), "timeout"),
        (HTTPException, "http_protocol"),
        (ConnectionError, "connection"),
        (OSError, "io"),
        (RuntimeFailure, "runtime_control"),
        ((ValueError, KeyError, TypeError, OverflowError), "invalid_data"),
    ):
        if isinstance(error, kind):
            code = value
            break
    return Failure(stage=stage, code=code, request_index=index).model_dump(mode="json")


class Row(StrictModel):
    request_index: int = Field(strict=True, ge=0, le=15)
    status: int | None = Field(default=None, strict=True, ge=100, le=599)
    body_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    tls_version: Literal["TLSv1.2", "TLSv1.3"] | None = None
    http_ms: float = Field(strict=True, ge=0, allow_inf_nan=False)
    error: Failure | None = None

    @model_validator(mode="after")
    def response_or_error(self):
        if self.error is None:
            if self.status is None or self.body_sha256 is None or self.tls_version is None:
                raise ValueError("selection_row_incomplete")
        elif any(v is not None for v in (self.status, self.body_sha256, self.tls_version)):
            raise ValueError("selection_error_not_response")
        return self


class Wave(StrictModel):
    rows: list[Row] = Field(max_length=16)
    wave_seconds: float = Field(strict=True, ge=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def ordered(self):
        if [r.request_index for r in self.rows] != list(range(len(self.rows))):
            raise ValueError("selection_row_order")
        return self


class Probe(Wave):
    schema_version: Literal["infra-load-probe-2"] = "infra-load-probe-2"
    kind: Literal["valid", "shared", "missing"]
    concurrency: Literal[1, 4, 8]
    probe_completed: bool = Field(strict=True)
    minted: int = Field(strict=True, ge=0, le=16)
    mint_status: int | None = Field(default=None, strict=True, ge=100, le=599)
    replay: Wave | None = None
    failure: Failure | None = None

    @model_validator(mode="after")
    def consistent(self):
        expected = {"valid": 16, "shared": 1, "missing": 0}[self.kind]
        if self.minted > expected:
            raise ValueError("selection_mint_bound")
        errors = [r.error for r in self.rows if r.error is not None]
        if self.replay is not None:
            if self.kind != "shared" or len(self.replay.rows) != 16:
                raise ValueError("selection_replay_shape")
            errors += [r.error for r in self.replay.rows if r.error is not None]
        if self.probe_completed:
            if (
                self.failure is not None
                or errors
                or self.minted != expected
                or len(self.rows) != 16
                or (self.kind == "shared" and self.replay is None)
            ):
                raise ValueError("selection_completion_mismatch")
        elif self.failure is None:
            raise ValueError("selection_failure_missing")
        return self


class TerminalFailure(StrictModel):
    schema_version: Literal["infra-load-probe-terminal-failure-1"] = (
        "infra-load-probe-terminal-failure-1"
    )
    probe_completed: bool = Field(strict=True)
    failure: Failure

    @model_validator(mode="after")
    def failed_only(self):
        if self.probe_completed:
            raise ValueError("selection_terminal_success_forbidden")
        return self


def report_value(raw):
    if not isinstance(raw, (bytes, str)):
        raise TypeError("selection_report_bound")
    raw = raw.encode("utf8") if isinstance(raw, str) else raw
    if not 0 < len(raw) <= MAX_REPORT:
        raise ValueError("selection_report_bound")
    return decode(raw)


def validate_report(raw, kind, concurrency):
    value = report_value(raw)
    if (
        type(value) is not dict
        or value.get("kind") != kind
        or type(value.get("concurrency")) is not int
        or value["concurrency"] != concurrency
    ):
        raise ValueError("selection_report_scope")
    return Probe.model_validate(value).model_dump(mode="json")


def execute_probe(runtime, kind, concurrency):
    """One fixed child, unchanged 120s budget; raw output stays private in RAM."""
    try:
        container = runtime.container("operator")  # validates owned label/service
        result = subprocess.run(
            [
                "docker",
                "exec",
                "--interactive",
                container,
                "python",
                "-m",
                "scripts.infra_load_probe",
            ],
            input=json.dumps({"kind": kind, "concurrency": concurrency}).encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=120,
            check=False,
        )
    except PROBE_ERRORS as error:
        return {"exit_code": None, "report": None, "failure": failure(error, "command")}
    try:
        if result.returncode != 0 and not result.stdout:
            return {
                "exit_code": result.returncode,
                "report": None,
                "failure": Failure(stage="command", code="command_exit").model_dump(mode="json"),
            }
        report = validate_report(result.stdout, kind, concurrency)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        try:
            terminal = TerminalFailure.model_validate(report_value(result.stdout))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            issue = Failure(stage="command", code="invalid_report").model_dump(mode="json")
        else:
            issue = terminal.failure.model_dump(mode="json")
        return {
            "exit_code": result.returncode,
            "report": None,
            "failure": issue,
        }
    issue = report["failure"]
    if result.returncode != 0 and issue is None:
        issue = Failure(stage="command", code="command_exit").model_dump(mode="json")
    return {"exit_code": result.returncode, "report": report, "failure": issue}
