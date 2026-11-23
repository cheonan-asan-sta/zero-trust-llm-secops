"""Exercise a real held Keycloak login queue from Prometheus to operator replay."""

import hashlib
import json
import re
import secrets
import socket
import subprocess
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Event, Thread
from time import monotonic, sleep
from unittest.mock import patch
from uuid import uuid4

import httpx

from app.services.login_delivery import LoginDeliveryIdentity
from app.services.sqlite_audit import SQLiteAuditStore
from app.zero_trust_models import LoginDeliveryRequest
from scripts.evaluate_local_remote_holdout import write
from scripts.f1_lab.login_queue_status import PROFILE_SCHEMA, publish_queue_status
from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.mtls_transport import Quiet
from scripts.signal_metrics_exporter import handler as metrics_handler

MONITOR_IMAGE = "c03-f67136ddf24a-monitoring:latest"
TARGET = "127.0.0.1:9101"
ALERT = "C01LoginQueueHeld"
REVIEWER = "fixture-queue-reviewer"
NOTE = "분석 경로 복구 확인"
FIELDS = ("detection", "assessment", "review_status")


@contextmanager
def serve(handler):
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            worker.join()


def need(check, label, *, seconds=16):
    deadline = monotonic() + seconds
    while monotonic() < deadline:
        try:
            if value := check():
                return value
        except (httpx.TransportError, OSError):
            pass
        sleep(0.2)
    raise AssertionError(label)


def docker(*args):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=35).stdout.strip()


def run_monitor():
    """Inside Docker, publish the host's aggregate through the real POSIX bridge."""
    root = Path("/tmp/login-dashboard-monitor")
    root.mkdir(mode=0o700)
    feed_config = json.loads(Path("/feed/scope.json").read_bytes())
    snapshot_file = Path("/feed/snapshot.json")
    public_file = root / "public-login-queue.json"

    class Feed:
        status_scope_sha256 = feed_config["scope_sha256"]

        @staticmethod
        def status_snapshot():
            return json.loads(snapshot_file.read_bytes())

    token = secrets.token_urlsafe(32)
    (root / "scrape-token").write_text(token, encoding="utf-8")
    write(root / "prometheus.json", {
        "global": {"scrape_interval": "1s", "evaluation_interval": "1s"},
        "rule_files": ["/repo/infra/observability/alerts.yaml"],
        "scrape_configs": [{
            "job_name": "zt-signals",
            "authorization": {"type": "Bearer", "credentials_file": str(root / "scrape-token")},
            "static_configs": [{"targets": [TARGET]}],
        }],
    })
    exporter = metrics_handler(
        "http://127.0.0.1:1/zero-trust/signals/inbox", "unused-local", token,
        login_queue_profile=feed_config | {
            "schema": PROFILE_SCHEMA, "status_file": str(public_file),
            "max_pending_age_seconds": 120, "capacity_warning_records": 8000,
        },
    )
    with ThreadingHTTPServer(("127.0.0.1", 9101), exporter) as server:
        Thread(target=server.serve_forever, daemon=True).start()
        with subprocess.Popen([
            "/tools/prometheus", f"--config.file={root / 'prometheus.json'}", f"--storage.tsdb.path={root / 'tsdb'}",
            "--web.listen-address=0.0.0.0:9090", "--log.level=warn",
        ]) as prometheus:
            try:
                while prometheus.poll() is None:
                    publish_queue_status(Feed(), public_file)
                    sleep(1)
                raise RuntimeError("Local Prometheus stopped")
            finally:
                prometheus.terminate()
                server.shutdown()


@contextmanager
def monitoring(feed, spool):
    feed.mkdir()
    write(feed / "scope.json", {"scope_sha256": spool.status_scope_sha256})
    stop = Event()
    errors = []

    def publish_summary():
        while not stop.is_set():
            try:
                staged = feed / "snapshot.new"
                staged.write_text(json.dumps(spool.status_snapshot()), encoding="utf-8")
                staged.replace(feed / "snapshot.json")
            except OSError as error:
                errors.append(type(error).__name__)
            stop.wait(0.5)

    publisher = Thread(target=publish_summary, daemon=True)
    publisher.start()
    name = "zt-login-dashboard-" + uuid4().hex[:12]
    try:
        docker(
            "run", "-d", "--rm", "--pull=never", "--name", name,
            "--publish", "127.0.0.1::9090",
            "--mount", f"type=bind,source={Path(__file__).resolve().parents[1]},target=/repo,readonly",
            "--mount", f"type=bind,source={feed},target=/feed,readonly",
            "--workdir", "/tmp", "--env", "PYTHONPATH=/repo", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint", "python", MONITOR_IMAGE, "-c",
            "from scripts.local_keycloak_dashboard_recovery import run_monitor; run_monitor()",
        )
        address = docker("port", name, "9090/tcp")
        if not re.fullmatch(r"127\.0\.0\.1:\d{1,5}", address):
            raise AssertionError("Unexpected local Prometheus endpoint")
        with httpx.Client(base_url=f"http://{address}", trust_env=False, timeout=1) as client:
            need(lambda: client.get("/-/ready").is_success, "Prometheus readiness", seconds=25)
            yield str(client.base_url)
            assert not errors, errors
    finally:
        stop.set()
        publisher.join()
        if name in docker("ps", "--format", "{{.Names}}").splitlines():
            docker("stop", "--time", "5", name)


@contextmanager
def dashboard_page(browser, base, key):
    if browser is None:
        yield None
        return
    from playwright.sync_api import sync_playwright

    with sync_playwright() as playwright:
        chrome = playwright.chromium.launch(executable_path=str(browser), args=["--disable-background-networking"])
        try:
            page = chrome.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route("**/*", lambda route: route.continue_() if route.request.url.startswith(base + "/") else route.abort())
            page.goto(base + "/#evidence")
            connect_dashboard(page, key)
            yield page
            assert not errors, errors
        finally:
            chrome.close()


def connect_dashboard(page, key):
    from playwright.sync_api import expect

    page.locator("#autoRefresh").uncheck()
    page.locator("#connectionButton").click()
    page.locator("#credentialType").select_option("api_key")
    page.locator("#credential").fill(key)
    page.get_by_role("button", name="적용하고 조회").click()
    expect(page.locator("#loginQueueRefresh")).to_be_enabled(timeout=15000)


def open_replay_detail(page, body):
    from playwright.sync_api import expect

    analysis_id = LoginDeliveryIdentity.from_request(body).analysis_id
    page.get_by_role("button", name=body.event.event_id + " 분석 기록 보기", exact=True).click()
    expect(page.locator("#detailTitle")).to_have_text("재전송 분석 기록")
    detail = page.locator("#detailBody")
    expect(detail).to_contain_text(analysis_id)
    return detail


def check_replay_detail(page, body):
    from playwright.sync_api import expect

    detail = open_replay_detail(page, body)
    expect(detail).to_contain_text("인증 근거가 만료")
    expect(detail.get_by_role("button", name="검토 상태 변경")).to_be_visible()
    expect(detail.get_by_role("status")).to_have_text("검토 대기")
    assert page.locator("#detailDialog").evaluate("e => e.scrollWidth <= e.clientWidth + 1")
    page.locator("#closeDetail").click()


def check_replay_review(page, analysis_api, records):
    from playwright.sync_api import expect

    bodies = {case.name: body for case, body, *_ in records}

    def return_to_queue():
        page.locator('a[data-page="evidence"]').click()

    def prepare(body):
        detail = open_replay_detail(page, body)
        detail.get_by_role("button", name="검토 상태 변경").click()
        field = page.locator("#op-path-event_id")
        expect(field).to_have_value(body.event.event_id)
        expect(field).to_be_disabled()
        page.locator("#op-body-status").select_option("IN_REVIEW")
        page.locator("#op-body-note").fill("실제 회수 기기 근거 검토 중")
        page.locator("#operationPrepare").click()
        expect(page.locator("#operationConfirmation")).to_be_visible()
        page.locator("#operationAcknowledge").check()
        return f"/results/{body.event.event_id}/review"

    def save(path):
        with page.expect_response(lambda response: response.url.endswith(path) and response.request.method == "PATCH") as reply:
            page.locator("#operationExecute").click()
        return reply.value

    normal = open_replay_detail(page, bodies["dashboard_outage_normal"])
    expect(normal.get_by_role("status")).to_have_text("검토 불필요")
    expect(normal.get_by_role("button", name="검토 상태 변경")).to_have_count(0)
    page.locator("#closeDetail").click()

    specific = bodies["dashboard_outage_device_only"]
    accepted = save(prepare(specific))
    assert accepted.status == 200, accepted.text()
    latest = accepted.json()
    assert latest["analysis_id"] == LoginDeliveryIdentity.from_request(specific).analysis_id
    assert latest["review_status"] == "IN_REVIEW" and latest["reviewer"] == REVIEWER
    expect(page.locator("#operationMessage")).to_contain_text("서버 처리 완료")
    return_to_queue()
    updated = open_replay_detail(page, specific)
    expect(updated.get_by_role("status")).to_have_text("조사 중")
    expect(updated).to_contain_text(REVIEWER)
    expect(updated).to_contain_text("검토 대기")
    page.locator("#closeDetail").click()

    stale_body = bodies["dashboard_outage_existing_high_risk"]
    stale_path = prepare(stale_body)
    newer = analysis_api.post("/analysis", json=stale_body.event.analysis_payload())
    newer.raise_for_status()
    assert newer.json()["analysis_id"] != LoginDeliveryIdentity.from_request(stale_body).analysis_id
    rejected = save(stale_path)
    assert rejected.status == 412
    expect(page.locator("#operationMessage")).to_contain_text("버전이 변경")
    page.locator("#operationPrepare").click()
    expect(page.locator("#operationMessage")).to_contain_text("재전송 분석 기록을 다시 열어")
    expect(page.locator("#operationConfirmation")).to_be_hidden()
    assert analysis_api.get(stale_path.removesuffix("/review")).json() == newer.json()
    return_to_queue()
    stale_detail = open_replay_detail(page, stale_body)
    expect(stale_detail.get_by_role("status")).to_contain_text("이 이벤트에 새 분석이 있습니다")
    expect(stale_detail.get_by_role("button", name="검토 상태 변경")).to_have_count(0)
    expect(stale_detail.get_by_role("link", name="로그 탐색")).to_be_visible()
    page.locator("#closeDetail").click()


def approve(reviewer, review, row, page):
    headers = {"If-Match": row["etag"], "X-Review-Identity": review["identity"]}
    body = {"event_id": row["event_id"], "hold_id": row["hold_id"], "note": NOTE}
    route = "/dashboard/login-queue/approvals"
    if page is None:
        response = reviewer.post(route, headers=headers, json=body)
        response.raise_for_status()
        first = response.json()
    else:
        action = page.get_by_role("button", name=row["event_id"] + " 보류 검토", exact=True)
        action.click()
        cause = "HTTP 503" if row["http_status"] == 503 else "전송 중 연결 중단"
        assert cause in page.locator("#loginQueueSelected").inner_text()
        page.locator("#loginQueueNote").fill(NOTE)
        with page.expect_response(lambda response: response.url.endswith(route) and response.request.method == "POST") as submitted:
            page.locator("#loginQueueApprove").click()
        assert submitted.value.status == 200, submitted.value.text()
        first = submitted.value.json()
    assert first == {"approval_id": row["hold_id"], "duplicate": False}
    replay = reviewer.post(route, headers=headers, json=body)
    replay.raise_for_status()
    assert replay.json() == {"approval_id": row["hold_id"], "duplicate": True}


def exercise(root, *, cases, analysis_api, settings, audit, analysis_runs, start_collector, submit_login, browser):
    from app import login_queue_api, main

    root.mkdir()
    fault = "unavailable"
    lost = []
    baselines = SQLiteAuditStore(root / "baseline.sqlite3")
    operator_key = secrets.token_urlsafe(32)
    accounts = root / "dashboard-accounts.json"
    write(accounts, {"schema": "api-key-accounts-1", "accounts": [{
        "sha256": hashlib.sha256(operator_key.encode()).hexdigest(), "tenant_id": settings.api_key_tenant_id,
        "subject": REVIEWER, "roles": ["responder"],
    }]})

    class FaultProxy(Quiet):
        def do_POST(self):
            assert self.path == "/analysis/login-delivery"
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            if fault == "unavailable":
                self.reply(503)
                return
            answer = analysis_api.post(self.path, content=raw, headers={
                "Content-Type": "application/json", "X-API-Key": self.headers.get("X-API-Key", ""),
            })
            if fault == "restored":
                self.reply(answer.status_code, answer.content)
                return
            answer.raise_for_status()
            lost.append(answer.json()["duplicate"])
            self.connection.shutdown(socket.SHUT_WR)
            self.close_connection = True

    def dashboard(reviewer):
        view = reviewer.get("/dashboard/login-queue")
        view.raise_for_status()
        return view.json()

    observations = []
    review_workflow = {}
    with ExitStack() as stack:
        origin = stack.enter_context(serve(FaultProxy))
        client = stack.enter_context(httpx.Client(
            base_url=origin, trust_env=False, timeout=8, headers={"X-API-Key": analysis_api.headers["X-API-Key"]},
        ))
        collector = start_collector(client, root / "queue.sqlite3")
        queue = collector.spool
        monitor = stack.enter_context(monitoring(root / "feed", queue))
        profile = root / "dashboard-profile.json"
        write(profile, {
            "queue_file": str(queue.path), "analysis_origin": str(client.base_url),
            "tenant_id": queue.tenant_id, "collector_subject": queue.collector_subject,
            "prometheus_origin": monitor, "scrape_instance": TARGET,
        })
        stack.enter_context(patch.object(settings, "api_key_accounts_path", accounts))
        stack.enter_context(patch.object(settings, "dashboard_login_queue_profile", profile))
        stack.enter_context(patch.object(login_queue_api, "get_settings", return_value=settings))
        reviewer = stack.enter_context(httpx.Client(
            base_url=analysis_api.base_url, trust_env=False, headers={"X-API-Key": operator_key}, timeout=8,
        ))
        writes_before = audit.integrity()["verified_lines"]
        records = []
        for index, case in enumerate(cases):
            committed = index == len(cases) - 1
            if committed:
                # The last login commits at the analysis service, but its proxy drops the receipt.
                fault = "drop_receipt"
            event = submit_login(case, committed=committed)
            with queue._transaction(read_only=True) as con:
                raw, = con.execute("SELECT payload FROM login_queue WHERE event_id=?", (event.event_id,)).fetchone()
            body = LoginDeliveryRequest.model_validate_json(raw)
            assert body.evidence is not None
            # Compare the same signed input to both healthy paths using a separate DB.
            prior_runs = analysis_runs[event.event_id]
            with patch.object(main, "audit_store", baselines):
                fresh = analysis_api.post("/analysis/verified-login", json={
                    "event": event.analysis_payload(), "evidence": body.evidence.model_dump(mode="json"),
                })
                basic = analysis_api.post("/analysis", json=event.analysis_payload())
                fresh.raise_for_status()
                basic.raise_for_status()
            analysis_runs[event.event_id] = prior_runs
            records.append((case, body, committed, fresh.json(), basic.json()))
            with collector.replaying(interval=0.05):
                expected_queue = {"pending": 0, "held": index + 1}
                need(lambda expected=expected_queue: queue.counts() == expected, f"Login did not reach hold: {case.name}")
            sleep(collector.retry_policy.max_delay + 0.05)

        stack.enter_context(collector.replaying(interval=0.05))
        need(lambda: queue.counts() == {"pending": 0, "held": len(records)}, "All login attempts held")
        assert audit.integrity()["verified_lines"] == writes_before + 1
        print("Keycloak OTP logins reached hold; waiting for the real 30-second Prometheus alert.", flush=True)

        def held_alert():
            view = dashboard(reviewer)
            expected = {"name": ALERT, "state": "firing"}
            return view["review"] if expected in view["alerts"]["entries"] else None

        review = need(held_alert, "Dashboard did not see a firing held-login alert", seconds=48)
        assert len(review["held"]) == len(records)
        assert {row["failure_code"] for row in review["held"]} == {"http_503", "transport_interrupted"}
        assert all(row["attempts"] == 2 for row in review["held"])
        assert len(review["history"]) == 0
        assert all(row["hold_id"] and row["etag"] for row in review["held"])
        assert all(row["http_status"] in {503, None} for row in review["held"])
        assert lost == [False, True]
        last_expiry = max(body.evidence.expires_at for _, body, *_ in records)
        need(lambda: last_expiry <= datetime.now(UTC), "Held login evidence did not reach real expiry", seconds=32)
        print("Dashboard read the firing alert; restoring the analysis route and approving held events.", flush=True)
        with dashboard_page(browser, str(analysis_api.base_url).rstrip("/"), operator_key) as page:
            if page:
                from playwright.sync_api import expect

                expect(page.locator("#loginQueueAlerts")).to_contain_text("보류 항목 확인 필요 · 발화 중")
            fault = "restored"
            sleep(0.5)
            assert queue.counts()["held"] == len(records), "API recovery bypassed the operator hold"
            for row in review["held"]:
                approve(reviewer, review, row, page)
                if page:
                    expect(page.locator("#loginQueueStatus")).to_contain_text("승인을 기록하고")
            need(lambda: queue.counts() == {"pending": 0, "held": 0}, "Approved login queue did not drain")
            if page:
                page.locator("#loginQueueRefresh").click()
                for width in (1440, 390):
                    page.set_viewport_size({"width": width, "height": 1000})
                    history_rows = page.locator("#loginQueueHistoryRows")
                    expect(history_rows.get_by_text("우선 검토 · 당시 회수 기기", exact=True)).to_have_count(2)
                    expect(history_rows.get_by_text("우선 검토 · 검증된 회수 기기", exact=True)).to_have_count(1)
                    expect(history_rows.get_by_text("분석 당시 검토 불필요", exact=True)).to_have_count(1)
                    expect(history_rows.get_by_text("인증 근거 만료", exact=True)).to_have_count(3)
                    expect(history_rows.get_by_text("인증 근거 검증됨", exact=True)).to_have_count(1)
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    if width == 390:
                        assert page.locator("#loginQueueHistoryTable").evaluate("e => e.scrollWidth <= e.clientWidth + 1")
                    body = next(body for case, body, *_ in records if case.name == "dashboard_outage_device_only")
                    check_replay_detail(page, body)
                page.reload()
                connect_dashboard(page, operator_key)
                check_replay_detail(page, body)
            def alert_cleared():
                status = dashboard(reviewer)["alerts"]
                return status["state"] == "ready" and not any(item["name"] == ALERT for item in status["entries"])

            need(alert_cleared, "Held-login alert did not clear")

        history = dashboard(reviewer)["review"]["history"]
        assert len(history) == 2 * len(records)
        classified_fresh, classified_after = counts(), counts()
        for case, body, committed, fresh, basic in records:
            event_id = body.event.event_id
            verify = analysis_api.post("/analysis/login-delivery", json=body.model_dump(mode="json"))
            verify.raise_for_status()
            receipt = verify.json()
            assert receipt["duplicate"]
            assert receipt["evidence_state"] == ("verified" if committed else "expired")
            saved = audit.login_delivery(LoginDeliveryIdentity.from_request(body).analysis_id)
            outcome = receipt["result"]
            assert outcome == saved.model_dump(mode="json")
            assert analysis_runs[event_id] == 1, (case.name, analysis_runs[event_id])
            assert outcome["detection"] == fresh["detection"] == basic["detection"]
            historical = not committed and body.evidence.device_state == "revoked_verified_device"
            reference = fresh if committed or historical else basic
            assert all(outcome[field] == reference[field] for field in FIELDS), case.name
            assert outcome.get("verified_login_detection") == (fresh["verified_login_detection"] if committed else None)
            marker = outcome.get("delayed_login_review")
            policy = outcome["policy_decision"].copy()
            if historical:
                assert marker == {
                    "reason": "expired_revoked_device_observation",
                    "source_id": fresh["verified_login_detection"]["source_id"],
                    "source_digest_sha256": fresh["verified_login_detection"]["source_digest_sha256"],
                    "observed_at": fresh["verified_login_detection"]["observed_at"],
                    "evidence_expired_at": body.evidence.model_dump(mode="json")["expires_at"],
                }
                assert "인증 근거가 만료" in policy["reason"]
                policy["reason"] = reference["policy_decision"]["reason"]
            else:
                assert marker is None
            assert policy == reference["policy_decision"], case.name
            matched_history = [item for item in history if item["event_id"] == event_id]
            assert [item["outcome"] for item in matched_history] == ["delivered", "approved"]
            delivery, approval = matched_history
            assert delivery["analysis_id"] == outcome["analysis_id"] and delivery["duplicate"] is committed
            assert delivery["evidence_state"] == receipt["evidence_state"]
            expected_kind = (
                "expired_device_priority" if historical else "verified_priority" if committed else "not_required"
            )
            assert delivery["review_kind"] == expected_kind
            assert approval["evidence_state"] is None and approval["review_kind"] is None
            detail = reviewer.get(f"/dashboard/login-queue/deliveries/{delivery['analysis_id']}")
            assert detail.status_code == 200 and detail.json() == outcome
            assert approval["actor"] == REVIEWER and approval["note"] == NOTE
            expected_fresh = fresh["policy_decision"]["requires_human_review"]
            actual = outcome["policy_decision"]["requires_human_review"]
            assert expected_fresh == case.priority
            assert actual == case.priority
            record(classified_fresh, case.priority, expected_fresh)
            record(classified_after, case.priority, actual)
            observations.append({
                "case": case.name, "expected_priority": case.priority, "fresh_priority": expected_fresh,
                "after_priority": actual, "evidence_state": receipt["evidence_state"],
                "historical_review": historical,
                "history_evidence_state": delivery["evidence_state"],
                "history_review_kind": delivery["review_kind"],
                "held_cause": approval["failure_code"], "worker_reused_committed_result": delivery["duplicate"],
                "analysis_runs": analysis_runs[event_id], "analysis_audit_rows": 1, "approval_history_rows": len(matched_history),
                "sigma_equal": True, "result_matches_applicable_baseline": True,
            })
        assert audit.integrity()["verified_lines"] == writes_before + len(records)
        if browser:
            with dashboard_page(browser, str(analysis_api.base_url).rstrip("/"), operator_key) as page:
                check_replay_review(page, analysis_api, records)
            assert audit.integrity()["verified_lines"] == writes_before + len(records) + 2
            review_workflow = {
                "normal_without_review_has_no_edit_action": True,
                "changed_review_keeps_the_original_analysis_id": True,
                "original_review_status_preserved_alongside_current_status": True,
                "review_revisions_appended": 1,
                "controlled_newer_analyses_added": 1,
                "superseded_write_http_status": 412,
                "superseded_replay_cannot_rebind_or_modify_the_newer_analysis": True,
            }

    return {
        "keycloak_mfa_and_mtls": len(observations),
        "held_alert_fired_and_cleared": ALERT,
        "prometheus_read_as_dashboard_reviewer": True,
        "dashboard_approval_mode": "chrome" if browser else "authenticated_dashboard_api",
        "browser_history_viewports_px": [1440, 390] if browser else [],
        "browser_replay_detail_after_reload": browser is not None,
        "exact_replay_details_matched": len(observations),
        **({"browser_replay_review": review_workflow} if review_workflow else {}),
        "duplicate_approvals_reused": len(observations),
        "analysis_and_audit_duplicates": 0,
        "analysis_audit_rows": len(observations),
        "approval_and_delivery_history_rows": len(history),
        "fresh_verified_baseline": metrics(classified_fresh),
        "after_approval": metrics(classified_after),
        "cases": observations,
        "aws_calls": 0,
        "paid_api_calls": 0,
    }
