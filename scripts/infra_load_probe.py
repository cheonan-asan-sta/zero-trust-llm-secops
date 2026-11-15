"""Bounded synthetic requests inside the existing operator; credentials stay in RAM."""

import json
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from scripts.continuous_mtls_assets import _request, mint
from scripts.infra_probe_diagnostics import PROBE_ERRORS, Failure, Probe, Row, failure
from scripts.measure_signal_infrastructure import distribution
from scripts.pep_lab import DOCUMENT_HASH


def validate_rows(rows, expected, delivered):
    if (
        not isinstance(rows, list)
        or len(rows) != 16
        or type(expected) is not int
        or not 0 <= expected <= 16
        or type(delivered) is not int
        or delivered != expected
    ):
        raise ValueError("selection_delivery_count")
    allowed = 0
    for row in rows:
        if (
            type(row.get("status")) is not int
            or row["status"] not in {200, 403}
            or row.get("tls_version") not in {"TLSv1.2", "TLSv1.3"}
            or type(row.get("http_ms")) not in {int, float}
            or (row.get("body_sha256") == DOCUMENT_HASH) != (row["status"] == 200)
        ):
            raise ValueError("selection_response_contract")
        allowed += row["status"] == 200
    if allowed != expected:
        raise ValueError("selection_allowed_count")
    return distribution([row["http_ms"] for row in rows])


def run(kind, concurrency):
    if (
        kind not in {"valid", "shared", "missing"}
        or type(concurrency) is not int
        or concurrency not in {1, 4, 8}
    ):
        raise ValueError("selection_workload_scope")
    pairs = []
    base = {
        "schema_version": "infra-load-probe-2",
        "kind": kind,
        "concurrency": concurrency,
        "probe_completed": False,
        "minted": 0,
        "rows": [],
        "wave_seconds": 0.0,
        "replay": None,
        "failure": None,
    }
    for index in range(16 if kind == "valid" else int(kind == "shared")):
        session = "selection-" + uuid.uuid4().hex
        try:
            value = mint({"session_id": session})
            status = value.get("status") if type(value) is dict else None
            if type(status) is int and 100 <= status <= 599:
                base["mint_status"] = status
            if status != 200:
                base["failure"] = Failure(
                    stage="mint", code="mint_rejected", request_index=index
                ).model_dump(mode="json")
                return Probe.model_validate(base).model_dump(mode="json")
            accepted = (
                type(value["status"]) is int
                and value["status"] == 200
                and value["body"]["session"]["status"] == "ACTIVE"
                and type(value["body"]["grant_token"]) is str
                and bool(value["body"]["grant_token"])
            )
            if not accepted:
                base["failure"] = Failure(
                    stage="mint", code="mint_rejected", request_index=index
                ).model_dump(mode="json")
                return Probe.model_validate(base).model_dump(mode="json")
        except PROBE_ERRORS as error:
            base["failure"] = failure(error, "mint", index)
            return Probe.model_validate(base).model_dump(mode="json")
        pairs.append((session, value["body"]["grant_token"]))
        base["minted"] += 1
    headers = [{"X-Session-ID": pair[0], "X-Grant-Token": pair[1]} for pair in pairs]
    if kind == "shared":
        headers *= 16
    if kind == "missing":
        headers = [{} for _ in range(16)]

    def request(item, stage):
        index, header = item
        started = time.perf_counter()
        try:
            result = _request({"profile": "frontend", "path": "/documents", "headers": header})
            row = Row(
                request_index=index,
                **{name: result[name] for name in ("status", "body_sha256", "tls_version")},
                http_ms=(time.perf_counter() - started) * 1000,
            )
        except PROBE_ERRORS as error:
            row = Row(
                request_index=index,
                http_ms=(time.perf_counter() - started) * 1000,
                error=failure(error, stage, index),
            )
        return row.model_dump(mode="json")

    def wave(stage):
        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            rows = list(pool.map(lambda item: request(item, stage), enumerate(headers)))
        return {"rows": rows, "wave_seconds": time.perf_counter() - started}

    base.update(wave("request"))
    errors = [row["error"] for row in base["rows"] if row["error"] is not None]
    if kind == "shared" and not errors:
        base["replay"] = wave("replay")
        errors = [row["error"] for row in base["replay"]["rows"] if row["error"] is not None]
    base["probe_completed"] = not errors
    base["failure"] = errors[0] if errors else None
    return Probe.model_validate(base).model_dump(mode="json")


if __name__ == "__main__":
    stage = "input"
    try:
        raw = sys.stdin.buffer.read(1025)
        if len(raw) > 1024:
            raise ValueError("selection_input_bound")
        value = json.loads(raw)
        if type(value) is not dict or set(value) != {"kind", "concurrency"}:
            raise ValueError("selection_input_shape")
        stage = "probe"
        result = run(value["kind"], value["concurrency"])
    except Exception as error:  # noqa: BLE001 -- CLI privacy boundary returns fixed metadata and exit 1.
        result = {
            "schema_version": "infra-load-probe-terminal-failure-1",
            "probe_completed": False,
            "failure": failure(error, stage),
        }
    print(json.dumps(result, allow_nan=False))
    raise SystemExit(0 if result["probe_completed"] else 1)
