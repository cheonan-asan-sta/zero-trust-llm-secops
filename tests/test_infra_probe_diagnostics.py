import copy
import json
import ssl
import subprocess
import sys
from http.client import RemoteDisconnected
from types import SimpleNamespace

import pytest

from scripts import infra_load_probe as probe
from scripts import infra_probe_diagnostics as diagnostics
from scripts import test_infra_selection_runtime as driver
from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.pep_lab import DOCUMENT_HASH

SECRET = "private-fixture-token-and-raw-message-must-not-be-published"


@pytest.fixture
def normal(monkeypatch):
    monkeypatch.setattr(
        probe,
        "mint",
        lambda *a: {
            "status": 200,
            "body": {"session": {"status": "ACTIVE"}, "grant_token": SECRET},
        },
    )
    monkeypatch.setattr(
        probe,
        "_request",
        lambda *a: {
            "status": 200,
            "body_sha256": DOCUMENT_HASH,
            "tls_version": "TLSv1.3",
            "body": SECRET,
        },
    )
    return probe.run("valid", 4)


@pytest.mark.parametrize(
    "error,expected",
    [
        (TimeoutError(SECRET), "timeout"),
        (ConnectionResetError(SECRET), "connection"),
        (ssl.SSLCertVerificationError(SECRET), "tls_certificate"),
        (ssl.SSLError(SECRET), "tls"),
        (RemoteDisconnected(SECRET), "http_protocol"),
        (OSError(SECRET), "io"),
        (ValueError(SECRET), "invalid_data"),
        (RuntimeFailure(SECRET), "runtime_control"),
        (Exception(SECRET), "internal"),
    ],
)
def test_error_projection_never_uses_exception_message_or_unknown_class_name(error, expected):
    result = diagnostics.failure(error, "request", 3)
    assert result == {"stage": "request", "code": expected, "request_index": 3}
    assert SECRET not in json.dumps(result)


def test_mint_failure_keeps_stage_and_count_without_starting_resource_requests(monkeypatch):
    count = []

    def mint(_):
        count.append(1)
        if len(count) == 3:
            raise TimeoutError(SECRET)
        return {"status": 200, "body": {"session": {"status": "ACTIVE"}, "grant_token": SECRET}}

    monkeypatch.setattr(probe, "mint", mint)
    monkeypatch.setattr(
        probe, "_request", lambda *a: pytest.fail("no request after incomplete mint")
    )
    result = probe.run("valid", 8)
    assert not result["probe_completed"] and result["minted"] == 2 and result["rows"] == []
    assert result["failure"] == {"stage": "mint", "code": "timeout", "request_index": 2}
    assert SECRET not in json.dumps(result)


def test_rejected_mint_does_not_publish_body_or_token(monkeypatch):
    monkeypatch.setattr(probe, "mint", lambda *a: {"status": 503, "body": SECRET})
    result = probe.run("shared", 8)
    assert not result["probe_completed"] and result["failure"]["stage"] == "mint"
    assert SECRET not in json.dumps(result)


def test_partial_wave_keeps_successes_and_failed_index_without_retrying_or_faking_denial(
    monkeypatch,
):
    calls = []

    def request(_):
        calls.append(1)
        if len(calls) == 4:
            raise RemoteDisconnected(SECRET)
        return {"status": 403, "body_sha256": "0" * 64, "tls_version": "TLSv1.3"}

    monkeypatch.setattr(probe, "_request", request)
    result = probe.run("missing", 1)
    assert len(calls) == 16 and len(result["rows"]) == 16
    assert not result["probe_completed"] and result["failure"]["request_index"] == 3
    assert sum(r["status"] == 403 for r in result["rows"]) == 15
    assert (
        result["rows"][3]["status"] is None
        and result["rows"][3]["error"]["code"] == "http_protocol"
    )
    with pytest.raises(ValueError, match="response_contract"):
        probe.validate_rows(result["rows"], 0, 0)
    assert SECRET not in json.dumps(result)


def test_replay_transport_failure_is_separate_and_never_retried(monkeypatch, normal):
    count = []

    def request(_):
        count.append(1)
        if len(count) == 18:
            raise ConnectionResetError(SECRET)
        return {"status": 403, "body_sha256": "0" * 64, "tls_version": "TLSv1.3"}

    monkeypatch.setattr(probe, "_request", request)
    result = probe.run("shared", 1)
    assert len(count) == 32 and len(result["replay"]["rows"]) == 16
    assert result["failure"]["stage"] == "replay" and result["failure"]["request_index"] == 1
    assert not result["probe_completed"] and SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "row_extra",
        "secret_hash",
        "bool_concurrency",
        "wrong_scope",
        "false_completion",
        "row_order",
        "nan_timing",
        "incomplete_rows",
        "string_completion",
    ],
)
def test_malformed_or_secret_bearing_child_report_is_refused(normal, fault):
    value = copy.deepcopy(normal)
    kind, concurrency = "valid", 4
    if fault == "extra":
        value["authorization"] = SECRET
    elif fault == "row_extra":
        value["rows"][0]["headers"] = {"Authorization": SECRET}
    elif fault == "secret_hash":
        value["rows"][0]["body_sha256"] = SECRET
    elif fault == "bool_concurrency":
        value["concurrency"] = True
    elif fault == "wrong_scope":
        kind = "missing"
    elif fault == "false_completion":
        value["failure"] = {"stage": "mint", "code": "timeout"}
    elif fault == "row_order":
        value["rows"][0]["request_index"] = 2
    elif fault == "nan_timing":
        value["rows"][0]["http_ms"] = float("nan")
    elif fault == "string_completion":
        value["probe_completed"] = "true"
    else:
        value["rows"].pop()
    with pytest.raises(ValueError):
        diagnostics.validate_report(json.dumps(value), kind, concurrency)


@pytest.mark.parametrize("mode", ["raw_error", "too_big", "timeout", "nonzero_complete"])
def test_child_failure_never_publishes_subprocess_text_and_nonzero_cannot_pass(
    monkeypatch, normal, mode
):
    def execute(argv, **kwargs):
        assert kwargs["stderr"] is subprocess.DEVNULL and kwargs["timeout"] == 120
        assert argv[4:] == ["python", "-m", "scripts.infra_load_probe"]
        if mode == "timeout":
            raise subprocess.TimeoutExpired(
                [SECRET], 120, output=SECRET.encode(), stderr=SECRET.encode()
            )
        raw = (
            SECRET.encode()
            if mode == "raw_error"
            else b"x" * 32769
            if mode == "too_big"
            else json.dumps(normal).encode()
        )
        return SimpleNamespace(returncode=1, stdout=raw, stderr=SECRET)

    monkeypatch.setattr(diagnostics.subprocess, "run", execute)
    result = diagnostics.execute_probe(SimpleNamespace(container=lambda _: "f" * 64), "valid", 4)
    assert result["failure"] is not None and SECRET not in json.dumps(result)
    if mode == "nonzero_complete":
        assert result["report"]["probe_completed"] and result["failure"]["code"] == "command_exit"


def checks(tmp_path):
    obj = object.__new__(driver.SelectionChecks)
    obj.report, obj.path = {"workloads": [], "checks": []}, tmp_path / "verification.json"
    obj.runtime = SimpleNamespace()
    return obj


def test_counter_failure_is_saved_before_probe_and_never_guesses_zero(tmp_path, monkeypatch):
    obj = checks(tmp_path)
    obj.served = lambda: (_ for _ in ()).throw(RuntimeFailure(SECRET))
    monkeypatch.setattr(driver, "execute_probe", lambda *a: pytest.fail("no probe without counter"))
    with pytest.raises(RuntimeFailure):
        obj.workload(1, 8, "valid")
    value = json.loads(obj.path.read_bytes())
    assert value["workloads"][0]["stage"] == "counter_before"
    assert "delivered" not in value["workloads"][0] and SECRET not in json.dumps(value)


def test_probe_failure_preserves_partial_rows_counts_and_original_error_if_counter_also_fails(
    tmp_path, monkeypatch
):
    obj = checks(tmp_path)
    counter = iter([0, RuntimeFailure(SECRET)])

    def served():
        result = next(counter)
        if isinstance(result, Exception):
            raise result
        return result

    obj.served = served
    issue = {"stage": "request", "code": "timeout", "request_index": 0}
    monkeypatch.setattr(
        driver, "execute_probe", lambda *a: {"exit_code": 1, "report": None, "failure": issue}
    )
    with pytest.raises(RuntimeFailure, match="selection_probe_failed"):
        obj.workload(3, 8, "shared")
    value = json.loads(obj.path.read_bytes())["workloads"][0]
    assert value["stage"] == "command" and value["probe_failure"] == issue
    assert "delivered" not in value and value["counter_after_failure"]["stage"] == "counter_after"
    assert SECRET not in json.dumps(value)


def test_healthy_transport_does_not_bypass_original_delivery_or_monitor_checks(
    tmp_path, monkeypatch, normal
):
    obj = checks(tmp_path)
    counter = iter([0, 16])
    obj.served, obj.healthy = lambda: next(counter), lambda: False
    monkeypatch.setattr(
        driver, "execute_probe", lambda *a: {"exit_code": 0, "report": normal, "failure": None}
    )
    with pytest.raises(RuntimeFailure, match="monitoring_not_healthy"):
        obj.workload(1, 4, "valid")
    row = json.loads(obj.path.read_bytes())["workloads"][0]
    assert row["stage"] == "health" and row["passed"] is False and row["delivered"] == 16


def test_invalid_cli_input_is_bounded_and_never_echoes_data_or_traceback():
    result = subprocess.run(
        [sys.executable, "-m", "scripts.infra_load_probe"],
        input=(SECRET * 30).encode(),
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1 and SECRET.encode() not in result.stdout + result.stderr
    assert b"Traceback" not in result.stderr
    assert json.loads(result.stdout)["failure"]["stage"] == "input"


def test_duplicate_report_keys_are_refused(normal):
    raw = json.dumps(normal).replace(
        '"probe_completed": true', '"probe_completed": false,"probe_completed": true'
    )
    with pytest.raises(ValueError, match="duplicate_key"):
        diagnostics.validate_report(raw, "valid", 4)


@pytest.mark.parametrize("mode", ["safe", "extra", "string_flag", "false_success"])
def test_terminal_failure_metadata_is_retained_without_accepting_extra_fields_or_success(
    monkeypatch, mode
):
    value = {
        "schema_version": "infra-load-probe-terminal-failure-1",
        "probe_completed": False,
        "failure": {"stage": "probe", "code": "internal", "request_index": None},
    }
    if mode == "extra":
        value["stderr"] = SECRET
    elif mode == "string_flag":
        value["probe_completed"] = "false"
    elif mode == "false_success":
        value["probe_completed"] = True
    monkeypatch.setattr(
        diagnostics.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout=json.dumps(value).encode()),
    )
    result = diagnostics.execute_probe(SimpleNamespace(container=lambda _: "f" * 64), "valid", 4)
    assert (
        result["report"] is None and result["exit_code"] == 1 and SECRET not in json.dumps(result)
    )
    assert result["failure"]["code"] == ("internal" if mode == "safe" else "invalid_report")


def test_nonzero_child_exit_cannot_pass_even_with_complete_rows_and_correct_counter(
    tmp_path, monkeypatch, normal
):
    obj = checks(tmp_path)
    counter = iter([0, 16])
    obj.served, obj.healthy = lambda: next(counter), lambda: True
    issue = {"stage": "command", "code": "command_exit", "request_index": None}
    monkeypatch.setattr(
        driver, "execute_probe", lambda *a: {"exit_code": 1, "report": normal, "failure": issue}
    )
    with pytest.raises(RuntimeFailure, match="selection_probe_failed"):
        obj.workload(1, 4, "valid")
    value = json.loads(obj.path.read_bytes())["workloads"][0]
    assert value["passed"] is False and value["delivered"] == 16 and value["probe_failure"] == issue
