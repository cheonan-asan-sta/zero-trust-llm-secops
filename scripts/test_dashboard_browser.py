"""Browser acceptance against a fresh local server plus explicit failure fixtures.

Requires the separate browser test requirements and a Playwright Chromium browser.
No model API or external service is called. Output contains synthetic data only.
"""

import argparse
import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import Error as BrowserError
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def run(args, directory, report):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    log = (args.output_dir / "server.log").open("w")
    command = [
        args.app_python, "-m", "scripts.serve_dashboard_demo", "--seed",
        "--data-dir", str(directory / "data"), "--port", str(port),
    ]
    process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                               env=os.environ | {
                                   "APP_ENVIRONMENT": "production", "ANALYZER_MODE": "openai",
                                   "audit_backend": "dynamodb",
                                   "OPENAI_API_KEY": "synthetic-must-never-be-used",
                               })

    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        deadline = time.monotonic() + 40
        while True:
            if process.poll() is not None:
                raise RuntimeError("Demo process exited; inspect server.log")
            try:
                with urlopen(base + "/health", timeout=1) as response:
                    health = json.load(response)
                break
            except (URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Demo process did not start") from None
                time.sleep(0.1)
        check("isolated_rule_only_local_server", health["analyzer_mode"] == "rule"
              and health["environment"] == "local" and health["audit_backend"] == "jsonl")
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**({"channel": args.browser_channel}
                                           if args.browser_channel else {}))
            context = browser.new_context(viewport={"width": 1440, "height": 1080})
            page = context.new_page()
            page.set_default_timeout(10000)
            errors = []
            external = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: external.append(request.url)
                    if not request.url.startswith(base + "/") else None)
            page.goto(base)
            expect(page.locator("#metricTotal")).to_have_text("24")
            metrics = page.request.get(base + "/metrics").json()
            expect(page.locator("#modeBadge")).to_contain_text("합성 시연 데이터")
            page.locator("#autoRefresh").uncheck()
            check("real_api_metrics_and_synthetic_scope")
            page.screenshot(path=str(args.output_dir / "overview-desktop.png"), full_page=True)
            page.get_by_role("link", name="로그 탐색").click()
            page.locator(".skip-link").focus()
            page.keyboard.press("Enter")
            expect(page.locator('[data-view="logs"]')).to_be_visible()
            check("keyboard_skip_link_preserves_current_page")
            expect(page.locator("#logRows tr")).to_have_count(12)
            page.locator("#nextPage").click()
            expect(page.locator("#pageLabel")).to_have_text("2 / 2 페이지")
            check("bounded_recent_logs_pagination")
            page.locator("#riskFilter").select_option("CRITICAL")
            critical = metrics["risk_counts"].get("CRITICAL", 0)
            expect(page.locator("#logCount")).to_have_text(f"{critical}건 표시 / 조회 24건")
            page.locator("#logSearch").fill("no-such-synthetic-event")
            expect(page.locator("#logRows")).to_contain_text("조건에 맞는 분석 기록이 없습니다")
            page.locator("#logSearch").fill("")
            page.locator("#riskFilter").select_option("")
            page.locator("#reviewFilter").select_option("PENDING")
            pending = metrics["pending_review_count"]
            expect(page.locator("#logCount")).to_have_text(f"{pending}건 표시 / 조회 24건")
            check("risk_search_and_review_filters")
            if not pending:
                page.locator("#reviewFilter").select_option("")
            page.locator("#logRows button").first.click()
            expect(page.locator("#detailBody")).to_contain_text("판단 근거")
            expect(page.locator("#detailBody")).to_contain_text("정책과 대응 제안")
            check("legacy_analysis_does_not_invent_verified_context", page.locator(".analysis-evidence").count() == 0)
            page.screenshot(path=str(args.output_dir / "log-detail.png"), full_page=True)
            page.locator("#closeDetail").click()
            with page.expect_download() as downloaded:
                page.locator("#exportLogs").click()
            exported = json.loads(Path(downloaded.value.path()).read_text(encoding="utf-8"))
            check("filtered_json_export", len(exported["records"]) == (pending or 24)
                  and (not pending or all(row["review_status"] == "PENDING"
                                          for row in exported["records"])))
            page.locator("#reviewFilter").select_option("")
            page.screenshot(path=str(args.output_dir / "logs-desktop.png"), full_page=True)

            page.get_by_role("link", name="세션과 접근").click()
            page.locator("#sessionFilter").select_option("DENY")
            expect(page.locator("#sessionRows tr")).to_have_count(1)
            page.locator("#sessionRows button").first.click()
            expect(page.locator("#detailBody")).to_contain_text("DEVICE_COMPROMISED")
            page.locator("#closeDetail").click()
            check("session_filter_and_server_history")
            page.get_by_role("link", name="증거와 승인").click()
            expect(page.locator("#responseList")).to_contain_text("승인 0명 / 필요 2명")
            page.locator("#responseList button").first.click()
            expect(page.locator("#detailBody")).to_contain_text("요청 사유")
            page.locator("#closeDetail").click()
            check("real_approval_records_read_only")

            page.get_by_role("link", name="시연 시나리오").click()
            page.locator("#demoStart").click()
            expect(page.locator("#demoHistory")).to_contain_text("ALLOW / ACTIVE")
            page.locator("#demoAccess").click()
            expect(page.locator("#demoHistory")).to_contain_text("HTTP 200")
            check("actual_normal_protected_access_200")
            page.locator("#demoAccess").click()
            expect(page.locator("#demoHistory")).to_contain_text("GRANT_ALREADY_USED")
            check("actual_consumed_grant_denied_403")
            page.locator("#demoStart").click()
            expect(page.locator("#demoCompromise")).to_be_enabled()
            page.locator("#demoCompromise").click()
            expect(page.locator("#demoHistory")).to_contain_text("DENY / REVOKED")
            page.locator("#demoAccess").click()
            expect(page.locator("#demoHistory")).to_contain_text("SESSION_NOT_AUTHORIZED")
            check("actual_revoked_unused_grant_denied_403")
            expect(page.locator("#toast")).to_be_hidden()
            page.screenshot(path=str(args.output_dir / "guided-demo.png"), full_page=True)

            # A hostile stored value stays text; token-shaped fields are redacted.
            record = copy.deepcopy(page.request.get(base + "/results?limit=1").json()[0])
            record["assessment"]["rationale"] = '<img src=x onerror="window.uiInjected=true">'
            record["grant_token"] = "SYNTHETIC_SECRET_MUST_NOT_EXPORT"
            record["event_id"] = "hostile-fixture"
            record["analyzed_at"] = "2025-01-02T12:34:56+00:00"
            logs_pattern = "**/results?limit=100"
            page.route(logs_pattern, lambda route: route.fulfill(json=[record]))
            page.route("**/results/hostile-fixture", lambda route: route.fulfill(json=record))
            page.locator("#refresh").click()
            expect(page.locator("#refresh")).to_be_enabled()
            page.get_by_role("link", name="로그 탐색").click()
            expect(page.locator("#logRows")).to_contain_text("hostile-fixture")
            expect(page.locator("#logRows")).to_contain_text("2025")
            check("historical_logs_show_calendar_year")
            page.locator("#logRows button").click()
            expect(page.locator("#detailBody")).to_contain_text("<img src=x")
            check("stored_markup_is_text", page.locator("#detailBody img").count() == 0
                  and page.evaluate("() => window.uiInjected !== true"))
            page.locator("#closeDetail").click()
            with page.expect_download() as downloaded:
                page.locator("#exportLogs").click()
            exported = Path(downloaded.value.path()).read_text(encoding="utf-8")
            check("token_fields_redacted_from_export", "SYNTHETIC_SECRET" not in exported
                  and "[REDACTED]" in exported)
            page.unroute(logs_pattern)
            page.unroute("**/results/hostile-fixture")

            # Explicit synthetic response fixtures exercise presentation only.
            # They are not a paid model evaluation or actual verified OS/person evidence.
            evidence_record = copy.deepcopy(record)
            evidence_record["event_id"] = "verified-evidence-fixture"
            evidence_record["analyzer"] = "openai"
            evidence_record["verification_context"] = {
                "not_an_access_grant": True,
                "collected_at": "2026-11-17T01:00:00+00:00",
                "valid_until": "2026-11-17T01:00:30+00:00",
                "signal": {"signature_verified": True, "mfa_observation": "unknown"},
                "caller": {
                    "authentication_method": "oidc",
                    "session_operator_binding_verified": True,
                    "event_subject_mfa_independently_verified": False,
                    "bearer": "SYNTHETIC_EVIDENCE_BEARER_MUST_NOT_DISPLAY",
                },
                "policy": {"mfa_required": True},
                "execution": {
                    "observation_status": "complete",
                    "comparison_scope_complete": True,
                    "exact_field_comparisons": [{"one_coherent_policy_matches": False}],
                    "observed_actor": {
                        "workload_id": '<img src=x onerror="window.evidenceInjected=true">'
                    },
                },
            }
            evidence_record["llm_trace"] = {
                "mode": "bounded_read_only_evidence_review",
                "provider_calls": 2,
                "maximum_provider_calls": 3,
                "tools_executed": ["read_bound_execution_evidence"],
                "write_tools_available": False,
                "receipts": [
                    {"input_tokens": 1000, "output_tokens": 20},
                    {"input_tokens": 2000, "output_tokens": 30},
                ],
            }
            evidence_record["assessment"]["evidence"] = [
                "verified_session.execution.observed_actor.workload_id",
                "verified_session.caller.bearer",
            ]
            active_evidence = {"record": evidence_record}
            page.route(logs_pattern, lambda route: route.fulfill(json=[active_evidence["record"]]))
            page.route(
                "**/results/verified-evidence-fixture",
                lambda route: route.fulfill(json=active_evidence["record"]),
            )

            def open_evidence():
                page.locator("#refresh").click()
                expect(page.locator("#refresh")).to_be_enabled()
                page.locator("#logRows button").click()
                return page.locator(".analysis-evidence")

            evidence = open_evidence()
            expect(evidence).to_contain_text("분석 시점의 검증 근거")
            expect(evidence).to_contain_text("현재 접근 허용은 자원 요청에서 별도로 판단")
            expect(evidence).to_contain_text("OIDC / 세션 요청자와 일치")
            expect(evidence).to_contain_text("대상 사람의 독립 MFA 검증")
            expect(evidence).to_contain_text("확인되지 않음")
            expect(evidence).to_contain_text("관측 미확인")
            expect(evidence).to_contain_text("한 정책 안에서 모두 일치하지 않음")
            expect(evidence).to_contain_text("2회 / 최대 3회")
            expect(evidence).to_contain_text("입력 3,000 / 출력 50 토큰")
            expect(evidence).to_contain_text("LLM 요청 후 제공")
            check("verified_evidence_distinguishes_caller_mfa_scope_and_advisory_result")
            evidence.get_by_text("LLM이 인용한 검증 근거", exact=True).click()
            expect(evidence).to_contain_text("<img src=x")
            expect(evidence).to_contain_text("[REDACTED]")
            check(
                "evidence_citations_never_execute_markup_or_expose_bearer",
                "SYNTHETIC_EVIDENCE_BEARER" not in page.content()
                and evidence.locator("img").count() == 0
                and page.evaluate("() => window.evidenceInjected !== true"),
            )
            page.locator("#closeDetail").click()

            inline_record = copy.deepcopy(evidence_record)
            inline_record["llm_trace"].update(
                provider_calls=1,
                tools_executed=[],
                prefetched_evidence=["execution"],
                receipts=[{"input_tokens": 1234, "output_tokens": 456}],
            )
            inline_record["verified_review_controls"] = {
                "scope": "verified_review_advisory_only", "action_before_guard": "ALLOW",
                "action_after_guard": "HOLD_FOR_REVIEW", "action_adjusted": True,
                "allow_recommendation_supported": False, "restrictions": ["execution_scope_not_proven"],
            }
            active_evidence["record"] = inline_record
            evidence = open_evidence()
            expect(evidence).to_contain_text("처음부터 제공")
            expect(evidence).to_contain_text("없음 · 기본 근거 사용")
            expect(evidence).to_contain_text("1회 / 최대 3회")
            expect(evidence).to_contain_text("서버가 허용 권고를 검토 대기로 제한했습니다")
            expect(evidence).to_contain_text("실행 주체·목적지의 허용 범위를 입증하지 못함")
            check("inline_evidence_does_not_invent_a_tool_read")
            for width in (390, 768, 1440):
                page.set_viewport_size({"width": width, "height": 1000 if width > 390 else 844})
                evidence.scroll_into_view_if_needed()
                check(
                    f"evidence_detail_{width}_no_horizontal_overflow",
                    evidence.evaluate("element => element.scrollWidth <= element.clientWidth"),
                )
                if width in (390, 1440):
                    evidence.evaluate("element => element.scrollIntoView({block: 'start'})")
                    page.screenshot(path=str(args.output_dir / f"llm-evidence-{width}.png"))
            page.evaluate("document.body.style.zoom = '2'")
            check(
                "evidence_detail_200_percent_zoom_no_horizontal_overflow",
                evidence.evaluate("element => element.scrollWidth <= element.clientWidth"),
            )
            page.evaluate("document.body.style.zoom = ''")
            page.locator("#closeDetail").click()

            partial_record = copy.deepcopy(inline_record)
            partial_record["llm_trace"]["receipts"][0]["input_tokens"] = None
            partial_record["verification_context"]["signal"]["signature_verified"] = "true"
            partial_record["verification_context"]["policy"]["mfa_required"] = "false"
            partial_record["verification_context"]["execution"]["comparison_scope_complete"] = False
            active_evidence["record"] = partial_record
            evidence = open_evidence()
            expect(evidence).to_contain_text("서명 또는 요청자 연결의 검증 상태가 불완전")
            expect(evidence).to_contain_text("일부 사용량 미확인")
            expect(evidence).to_contain_text("비교 근거 불완전")
            check("invalid_booleans_missing_tokens_and_incomplete_comparisons_stay_unknown")
            page.locator("#closeDetail").click()

            malformed_record = copy.deepcopy(inline_record)
            malformed_record["verification_context"] = []
            active_evidence["record"] = malformed_record
            evidence = open_evidence()
            expect(evidence).to_contain_text("연결된 검증 근거의 형식을 확인할 수 없습니다")
            expect(page.locator("#detailBody")).to_contain_text("판단 근거")
            check("malformed_optional_evidence_does_not_hide_the_original_assessment")
            page.locator("#closeDetail").click()
            malformed_trace = copy.deepcopy(inline_record)
            malformed_trace["llm_trace"]["provider_calls"] = "1"
            active_evidence["record"] = malformed_trace
            evidence = open_evidence()
            expect(evidence).to_contain_text("LLM 조회 이력의 형식을 확인할 수 없습니다")
            check("malformed_optional_trace_never_becomes_verified_usage")
            page.locator("#closeDetail").click()
            page.unroute(logs_pattern)
            page.unroute("**/results/verified-evidence-fixture")

            # Explicit failures never look like an empty successful query.
            def failure_reply(status):
                return lambda route: route.fulfill(
                    status=status, json={"detail": "synthetic failure"})

            for status in (401, 403, 503):
                page.route(logs_pattern, failure_reply(status))
                page.locator("#refresh").click()
                expect(page.locator("#refresh")).to_be_enabled()
                expect(page.locator("#notice")).to_be_visible()
                expect(page.locator("#exportLogs")).to_be_disabled()
                check(f"http_{status}_removes_stale_logs", "demo-log-" not in
                      page.locator("#logRows").inner_text())
                page.unroute(logs_pattern)
            page.route("**/metrics", lambda route: route.fulfill(json={"bad": "shape"}))
            page.locator("#refresh").click()
            expect(page.locator("#metricTotal")).to_have_text("—")
            expect(page.locator("#notice")).to_contain_text("서버 응답 형식")
            check("malformed_metrics_not_presented_as_zero")
            page.unroute("**/metrics")
            page.route(logs_pattern, lambda route: route.fulfill(json=[]))
            page.locator("#refresh").click()
            expect(page.locator("#logCount")).to_have_text("0건 표시 / 조회 0건")
            expect(page.locator("#notice")).to_be_hidden()
            check("successful_empty_result_distinct_from_failure")
            page.unroute(logs_pattern)

            # Retain an old pending response while changing identity. The new
            # credential must clear DOM state and cancel/ignore the old response.
            held = []
            observed_headers = []
            test_key = "synthetic-dashboard-viewer-key"

            def tenant_route(route):
                key = route.request.headers.get("x-api-key")
                observed_headers.append(key == test_key)
                if key == test_key:
                    route.fulfill(json=[])
                else:
                    held.append(route)

            page.route(logs_pattern, tenant_route)
            with page.expect_request(lambda request: "/results?limit=100" in request.url):
                page.locator("#refresh").click()
            page.locator("#connectionButton").click()
            page.locator("#credential").fill(test_key)
            page.get_by_role("button", name="적용하고 조회").click()
            expect(page.locator("#logCount")).to_have_text("0건 표시 / 조회 0건")
            for route in held:
                try:
                    route.fulfill(json=[record])
                except BrowserError:
                    pass  # Aborted fetches cannot be fulfilled on every browser.
            expect(page.locator("#logRows")).not_to_contain_text("hostile-fixture")
            check("identity_switch_cancels_old_tenant_results", any(observed_headers))
            check("credential_not_in_dom_or_browser_storage", test_key not in page.content()
                  and page.evaluate("() => localStorage.length === 0 && sessionStorage.length === 0")
                  and page.locator("#credential").input_value() == "")
            page.unroute(logs_pattern)
            page.reload()
            expect(page.locator("#authLabel")).to_have_text("local-operator")
            check("reload_forgets_credential")
            page.locator("#autoRefresh").uncheck()

            page.route("**/response/requests?limit=50", lambda route: route.fulfill(status=503))
            page.get_by_role("link", name="증거와 승인").click()
            expect(page.locator("#responseList")).to_contain_text("HTTP 503")
            check("unavailable_approval_service_not_empty_approval_list")
            page.unroute("**/response/requests?limit=50")

            for width in (390, 768, 1440):
                page.set_viewport_size({"width": width, "height": 844})
                for section in ("overview", "logs", "sessions", "evidence", "demo"):
                    page.goto(base + "/#" + section)
                    expect(page.locator("#metricTotal")).to_have_text("24")
                    check(f"layout_{width}_{section}_no_document_overflow",
                          page.evaluate("() => document.documentElement.scrollWidth <= innerWidth"))
                if width == 390:
                    page.goto(base)
                    expect(page.locator("#metricTotal")).to_have_text("24")
                    page.screenshot(path=str(args.output_dir / "overview-mobile.png"), full_page=True)
            page.goto(base + "/static/workbench.html")
            expect(page.get_by_role("link", name="관제 대시보드로 돌아가기")).to_be_visible()
            check("legacy_workbench_preserved_with_return_link")
            page.goto(base)
            expect(page.locator("#metricTotal")).to_have_text("24")
            event = page.request.post(base + "/events/simulate", data={
                "scenario_id": "NORMAL-01", "count": 1,
            }).json()[0]
            event.pop("ground_truth", None)
            event["event_id"] = "demo-auto-refresh-event"
            created = page.request.post(base + "/analysis", data=event)
            check("new_log_created_through_actual_rule_api", created.status == 200)
            expect(page.locator("#metricTotal")).to_have_text("25", timeout=15000)
            expect(page.locator("#recentLogs")).to_contain_text("demo-auto-refresh-event")
            check("automatic_refresh_displays_new_server_records")
            check("no_browser_script_errors", not errors)
            check("no_external_browser_requests", not external)
            browser.close()

        process.terminate()
        process.wait(timeout=10)
        process = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 40
        while True:
            if process.poll() is not None:
                raise RuntimeError("Restarted demo process exited")
            try:
                with urlopen(base + "/metrics", timeout=1) as response:
                    metrics = json.load(response)
                break
            except (URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Demo restart did not complete") from None
                time.sleep(0.1)
        check("restart_preserves_records_without_duplicate_seeding", metrics["total_analyses"] == 25)
        with urlopen(base + "/zero-trust/sessions", timeout=1) as response:
            sessions = json.load(response)
        check("restart_preserves_demo_session_revocation",
              sum(row["status"] == "REVOKED" for row in sessions) == 2)

        foreign = directory / "foreign"
        foreign.mkdir()
        sentinel = foreign / "existing.txt"
        sentinel.write_text("preserve me")
        rejected = subprocess.run([
            args.app_python, "-m", "scripts.serve_dashboard_demo", "--data-dir", str(foreign),
        ], cwd=ROOT, capture_output=True, timeout=10, check=False)
        check("unowned_data_directory_rejected_without_modification",
              rejected.returncode != 0 and sentinel.read_text() == "preserve me"
              and list(foreign.iterdir()) == [sentinel])
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-python", default=sys.executable)
    parser.add_argument("--browser-channel", default=None, help="Use chrome for installed Chrome")
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/dashboard-browser"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"schema": "dashboard-browser-1", "synthetic": True, "checks": [], "passed": False}
    try:
        with tempfile.TemporaryDirectory(prefix="secops-ui-") as temp:
            run(args, Path(temp), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
