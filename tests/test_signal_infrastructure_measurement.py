"""Measurement evidence must reject corrupt counters and keep outage timing separate."""

import json

import pytest

from scripts import measure_signal_infrastructure as measure


@pytest.mark.parametrize(("value", "expected"), [("1.5MiB", 1572864), ("1.5MB", 1500000),
                                                ("0B", 0), ("1.25GiB", 1342177280),
                                                ("1e+03kB", 1000000), ("1e+03KiB", 1024000),
                                                ("1E3MB", 1000000000), ("1e-03B", 0),
                                                *[("1" + unit, scale) for unit, scale in measure.UNITS.items()
                                                  if unit in {"PB", "EB", "ZB", "YB", "PiB", "EiB", "ZiB", "YiB"}]])
def test_display_units_distinguish_decimal_and_binary_scales(value, expected):
    assert measure.size_estimate(value) == pytest.approx(expected, rel=1e-15, abs=0)


@pytest.mark.parametrize("value", ["", "--", "NaNMiB", "-3B", "1XB", "1e999MB", "9" * 400 + "B",
                                 "1e+MB", "1e3PRIVATE_KEY", "-1e3B", "infB"])
def test_invalid_or_nonfinite_resource_values_are_not_silently_zero(value):
    with pytest.raises(ValueError):
        measure.size_estimate(value)


@pytest.mark.parametrize("value", ["NaN%", "inf%", "-1%", "", "9" * 400 + "%"])
def test_nonfinite_cpu_values_are_not_reported_as_valid_samples(value):
    with pytest.raises(ValueError):
        measure.percent(value)


def stats_row():
    return {"ID": "a" * 64, "CPUPerc": "101.25%", "MemUsage": "4MiB / 256MiB",
            "NetIO": "2kB / 3kB", "BlockIO": "1MB / 2MB", "PIDs": "4"}


def test_resource_rows_keep_counter_direction_and_only_accept_owned_containers():
    row = measure.parse_stats(stats_row(), {"a" * 64: "app"})
    assert row["cpu_percent"] == 101.25
    assert row["memory_limit_bytes_estimate"] == 268435456
    assert row["network_rx_bytes_estimate"] == 2000 and row["network_tx_bytes_estimate"] == 3000
    assert row["block_read_bytes_estimate"] == 1000000 and row["block_written_bytes_estimate"] == 2000000
    with pytest.raises(ValueError, match="unowned_container"):
        measure.parse_stats(stats_row(), {"b" * 64: "unrelated"})
    for bad in ("", "not-a-container"):
        with pytest.raises(ValueError):
            measure.parse_stats({**stats_row(), "ID": bad}, {"a" * 64: "app"})


@pytest.mark.parametrize('invalid', ['--', 'PRIVATE_KEY_SENTINEL'])
def test_sampler_preserves_missing_field_reason_without_fabricating_zero_or_leaking_raw_values(tmp_path, monkeypatch, invalid):
    sampler = measure.Sampler({'a' * 64: 'app'}, tmp_path / 'samples.jsonl', 1)

    def snapshot(*args, **kwargs):
        sampler.stopped.set()
        return json.dumps(stats_row() | {'PIDs': invalid})

    monkeypatch.setattr(measure, 'docker', snapshot)
    sampler.collect()
    assert sampler.rows == [] and len(sampler.errors) == 1
    error = sampler.errors[0]
    assert error['error_type'] == 'ValueError' and error['reason'] == 'invalid_pids'
    assert error['unavailable_fields'] == (['PIDs'] if invalid == '--' else [])
    assert 'SENTINEL' not in json.dumps(error)


def test_small_samples_show_empirical_rank_and_empty_samples_remain_unknown():
    assert measure.distribution([]) == {"n": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    assert measure.distribution([3, 1, 2]) == {"n": 3, "p50_ms": 2, "p95_ms": 3, "max_ms": 3}
    for values in ([float("nan")], [float("inf")], [-1]):
        with pytest.raises(ValueError):
            measure.distribution(values)


def test_docker_general_format_rounding_boundary_keeps_valid_resource_snapshot():
    # go-units HumanSizeWithPrecision uses %.*g after scaling; BytesSize uses %.4g.
    network = format(999999 / 1000, '.3g') + 'kB'
    memory = format(1024 * 1023.99 / 1024, '.4g') + 'KiB'
    assert network == '1e+03kB' and memory == '1024KiB'
    row = measure.parse_stats(stats_row() | {'NetIO': network + ' / 0B',
        'MemUsage': memory + ' / 256MiB'}, {'a' * 64: 'app'})
    assert row['network_rx_bytes_estimate'] == 1000000
    assert row['memory_bytes_estimate'] == 1048576


@pytest.mark.parametrize('invalid, display', [('PRIVATE_KEY_SENTINEL', None), ('1e999B', '1e999B')])
def test_bad_size_diagnostic_names_direction_and_only_records_bounded_numeric_display(tmp_path, monkeypatch, invalid, display):
    sampler = measure.Sampler({'a' * 64: 'app'}, tmp_path / 'samples.jsonl', 1)

    def snapshot(*args, **kwargs):
        sampler.stopped.set()
        return json.dumps(stats_row() | {'NetIO': '0B / ' + invalid})

    monkeypatch.setattr(measure, 'docker', snapshot)
    sampler.collect()
    assert not sampler.rows and len(sampler.errors) == 1
    error = sampler.errors[0]
    assert error['invalid_size_field'] == 'NetIO.tx'
    assert error['numeric_size_display'] == display
    assert error['reason'] == ('unsupported_size' if display is None else 'nonfinite_size')
    assert 'SENTINEL' not in json.dumps(error)


def test_summarize_never_pools_planned_outage_or_counts_restored_receipt_twice():
    receipt = {"received_at": "2026-11-03T00:00:00+00:00", "completed_at": "2026-11-03T00:00:01+00:00"}
    outage = {"received_at": receipt["received_at"], "completed_at": "2026-11-03T00:00:20+00:00"}
    report = {"status": "passed", "http": [], "checks": [{"status": "passed"}],
              "resource_samples": [], "receipts": {"first_completed": receipt,
              "resumed_completed": outage, "after_both_restart": outage}, "denial_latency": [
                  {"group": "normal_worker", "client_post_start_to_first_confirmed_denial_ms": 1200},
                  {"group": "worker_outage", "client_post_start_to_first_confirmed_denial_ms": 20200}]}
    result = measure.summarize([report])
    assert result["server_received_to_completed"]["normal_worker"] == measure.distribution([1000])
    assert result["server_received_to_completed"]["worker_outage"] == measure.distribution([20000])
    assert result["client_post_start_to_denial"]["worker_outage"]["n"] == 1


def test_failed_workload_is_redacted_and_still_cleans_its_own_stack(tmp_path, monkeypatch):
    cleanup = []

    class FailedCompose:
        def __init__(self, *args):
            pass

        def run(self, *args, **kwargs):
            raise RuntimeError("PRIVATE KEY must never appear in evidence")

        def cleanup(self):
            cleanup.append(True)

    monkeypatch.setattr(measure.flow, "Compose", FailedCompose)
    monkeypatch.setattr(measure, "docker", lambda *args, **kwargs: '[{"Id":"sha256:test"}]')
    report = measure.run_repeat(1, tmp_path / "own-run", "own-image", 1, 10, ["docker", "compose"], False)
    assert report["status"] == "failed" and report["error_code"] == "unexpected_RuntimeError"
    assert cleanup == [True] and report["cleanup"]["volume_removed"]
    assert "PRIVATE KEY" not in json.dumps(report)


def test_client_denial_interval_includes_polling_and_http_durations_use_high_resolution_clock(monkeypatch):
    clock = iter([1.0, 1.00025, 2.0, 2.1, 2.2, 2.25])
    monkeypatch.setattr(measure.time, "perf_counter", lambda: next(clock))
    report = {"http": [], "denial_latency": []}

    def fake_request(self, method, path, payload=None, **options):
        label = options["label"]
        self.report["http"].append({"label": label, "elapsed_ms": 15.0})
        if label == "access_m3-first-a":
            return 403, {"reason_code": "SESSION_NOT_AUTHORIZED"}
        return 202 if label == "risk_intake" else 200, {}

    monkeypatch.setattr(measure.flow.Api, "request", fake_request)
    api = measure.MeasuredApi(43122, report)
    api.request("POST", "/inbox", label="risk_intake")
    api.request("GET", "/receipt", label="receipt")
    api.request("POST", "/access", label="access_m3-first-a")
    assert report["http"][0]["elapsed_ms"] == 0.25
    assert report["denial_latency"][0]["client_post_start_to_first_confirmed_denial_ms"] == 1250
