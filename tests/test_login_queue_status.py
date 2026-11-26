"""Queue-only aggregates, protected metrics, and fresh/unavailable transitions."""

import json
import os
from contextlib import closing
from datetime import UTC, datetime, timedelta
from sqlite3 import connect
from time import monotonic, sleep
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import httpx
import pytest
from test_signal_metrics_exporter import serve

from app.models import SecurityEvent
from app.scenarios import synthetic_events
from app.zero_trust_models import LoginDeliveryRequest
from scripts import signal_metrics_exporter
from scripts.f1_lab import login_queue_status as status
from scripts.keycloak_login_evidence import KeycloakLoginAnalysisCollector
from scripts.login_delivery_spool import LoginDeliverySpool, LoginRetryPolicy

pytestmark = pytest.mark.skipif(os.name != "posix", reason="public file publication uses POSIX trust checks")
ORIGIN = "http://127.0.0.1/"
TENANT = "private-test-tenant"
COLLECTOR = "private-collector"
POLICY = LoginRetryPolicy(success_interval=0)


def body(event_id):
    payload = synthetic_events()[0].analysis_payload()
    payload["action"] = "LOGIN"
    payload["event_id"] = event_id
    event = SecurityEvent.model_validate(payload)
    return LoginDeliveryRequest(tenant_id=TENANT, collector_subject=COLLECTOR, event=event)


@pytest.fixture
def setup(tmp_path):
    queue = LoginDeliverySpool(tmp_path / "queue.sqlite3", origin=ORIGIN, tenant_id=TENANT, collector_subject=COLLECTOR)
    path = tmp_path / "queue-status.json"
    profile_file = tmp_path / "profile.json"
    profile_file.write_text(json.dumps({
        "schema": status.PROFILE_SCHEMA, "scope_sha256": queue.status_scope_sha256, "status_file": str(path),
        "max_pending_age_seconds": 120, "capacity_warning_records": 2,
    }), encoding="utf-8")
    return queue, path, status.load_profile(profile_file)


def test_published_metrics_track_pressure_hold_and_recovery_without_using_event_time(setup):
    queue, path, profile = setup
    now = datetime.now(UTC)
    pending = body("private-pending-event")
    held = body("private-held-event")
    queue.enqueue(pending, now=(now - timedelta(seconds=120)).timestamp())
    queue.enqueue(held, now=(now - timedelta(seconds=240)).timestamp())
    queue.fail(held, now=(now - timedelta(seconds=35)).timestamp(), policy=POLICY,
               code="http_403", status=403, permanent=True)
    status.publish_queue_status(queue, path, now=now)
    metrics = status.metrics(profile, now=now + timedelta(seconds=1))
    for name, value in (
        ("pending", "1"), ("held", "1"), ("oldest_pending_age_seconds", "121.0"),
        ("oldest_held_age_seconds", "36.0"), ("pending_attention", "1"), ("capacity_pressure", "1"),
    ):
        assert f"secops_login_queue_{name} {value}\n" in metrics
    for private in (TENANT, COLLECTOR, pending.event.event_id, held.event.event_id, "http_403", "auth_context"):
        assert private not in metrics and private not in path.read_text(encoding="utf-8")

    queue.acknowledge(pending, now=now.timestamp(), policy=POLICY)
    assert queue.requeue(held.event.event_id, now=now.timestamp())
    queue.acknowledge(held, now=now.timestamp(), policy=POLICY)
    status.publish_queue_status(queue, path, now=now + timedelta(seconds=2))
    metrics = status.metrics(profile, now=now + timedelta(seconds=2))
    for name in ("pending", "held", "pending_attention", "capacity_pressure"):
        assert f"secops_login_queue_{name} 0\n" in metrics


def test_legacy_rows_report_unknown_age_and_missing_database_is_not_empty(setup):
    queue, path, profile = setup
    now = datetime.now(UTC)
    queue.enqueue(body("pre-upgrade-log"), now=now.timestamp())
    with closing(connect(queue.path)) as con, con:
        con.execute("UPDATE login_queue SET enqueued_at=NULL")
    status.publish_queue_status(queue, path, now=now)
    metrics = status.metrics(profile, now=now)
    assert "secops_login_queue_pending_age_unknown 1\n" in metrics
    assert "secops_login_queue_pending_attention 1\n" in metrics
    assert "secops_login_queue_oldest_pending_age_seconds" not in metrics

    queue.path.rename(queue.path.with_suffix(".offline"))
    status.publish_queue_status(queue, path, now=now + timedelta(seconds=1))
    metrics = status.metrics(profile, now=now + timedelta(seconds=1))
    assert "secops_login_queue_status_success 0\n" in metrics
    assert "secops_login_queue_pending " not in metrics
    assert not queue.path.exists()


@pytest.mark.parametrize("failure", ["stale", "future", "binding", "corrupt", "missing"])
def test_report_validation_fails_closed_without_reusing_counts(setup, failure):
    queue, path, profile = setup
    now = datetime.now(UTC)
    status.publish_queue_status(queue, path, now=now)
    assert "secops_login_queue_status_success 1\n" in status.metrics(profile, now=now)
    if failure == "stale":
        now += status.REPORT_TTL
    elif failure == "future":
        now -= timedelta(seconds=1)
    elif failure == "binding":
        profile = {**profile, "scope_sha256": "0" * 64}
    elif failure == "corrupt":
        path.write_text('{"unexpected":"private-original-body"}', encoding="utf-8")
    else:
        path.unlink()
    metrics = status.metrics(profile, now=now)
    assert "secops_login_queue_status_success 0\n" in metrics
    assert "secops_login_queue_pending " not in metrics and "private-original-body" not in metrics


def test_replay_worker_publishes_to_authenticated_exporter_during_api_outage(setup):
    queue, path, profile = setup
    with httpx.Client(base_url=ORIGIN, transport=httpx.MockTransport(
        lambda _: httpx.Response(503, headers={"Retry-After": "120"})
    )) as client:
        collector = KeycloakLoginAnalysisCollector(
            client, settings=None, authority=None, registry=None, gateway_id="local",
            source_id="local", key_id="local", signing_key=None, spool_path=queue.path,
            tenant_id=TENANT, collector_subject=COLLECTOR,
        )
        assert collector.submit(body("private-gateway-login").event, None).evidence_state == "queued"
        with collector.replaying(status_path=path):
            deadline = monotonic() + 5
            while not path.exists():
                assert monotonic() < deadline, "worker did not publish"
                sleep(0.02)
            handler = signal_metrics_exporter.handler(
                "http://127.0.0.1:1/zero-trust/signals/inbox", "fixture", "test-scrape-token",
                login_queue_profile=profile,
            )
            with serve(handler) as base:
                with pytest.raises(HTTPError) as denied:
                    urlopen(base + "/metrics", timeout=2)
                assert denied.value.code == 401
                request = Request(base + "/metrics", headers={"Authorization": "Bearer test-scrape-token"})
                with urlopen(request, timeout=2) as reply:
                    output = reply.read().decode()
                assert "secops_signal_collection_success 0" in output
                assert "secops_login_queue_status_success 1" in output
                assert "secops_login_queue_pending 1" in output
                assert "secops_login_queue_retry_wait_seconds " in output
                assert "private-gateway-login" not in output
        assert queue.counts() == {"pending": 1, "held": 0}
