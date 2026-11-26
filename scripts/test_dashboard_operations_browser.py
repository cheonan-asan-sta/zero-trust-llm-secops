"""Exercise authenticated dashboard writes against real isolated APIs, without paid calls."""

import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def run(args, directory, report):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    log = (args.output_dir / "server.log").open("w")
    process = subprocess.Popen([
        args.app_python, "-m", "tests.dashboard_operations_fixture", "--directory",
        str(directory / "data"), "--port", str(port), "--sqlite-audit",
    ], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)

    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        deadline = time.monotonic() + 40
        while True:
            if process.poll() is not None:
                raise RuntimeError("Synthetic server failed; inspect server.log")
            try:
                with urlopen(base + "/health", timeout=1):
                    break
            except (URLError, TimeoutError):
                if time.monotonic() > deadline:
                    raise RuntimeError("Synthetic server did not start") from None
                time.sleep(0.1)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(**({"channel": args.browser_channel} if args.browser_channel else {}))
            errors, external = [], []

            def login(subject):
                context = browser.new_context(viewport={"width": 1440, "height": 1080})
                page = context.new_page()
                page.set_default_timeout(12000)
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("request", lambda req: external.append(req.url) if not req.url.startswith(base + "/") else None)
                page.goto(base)
                page.locator("#autoRefresh").uncheck()
                page.locator("#connectionButton").click()
                page.locator("#credentialType").select_option("api_key")
                page.locator("#credential").fill("synthetic-" + subject + "-key")
                page.get_by_role("button", name="적용하고 조회").click()
                expect(page.locator("#connectionDialog")).not_to_be_visible()
                expect(page.locator("#refresh")).to_be_enabled()
                return page

            page = login("requester")
            headers = {"X-API-Key": "synthetic-requester-key"}
            metadata = page.request.get(base + "/auth/dashboard-catalog", headers=headers).json()

            def operation(target, path, method="POST"):
                entry = next(o for o in metadata["operations"] if o["path"] == path and o["method"] == method)
                target.locator('a[href="#' + entry["group"] + '"]').click()
                target.locator('[data-operation="' + entry["id"] + '"]').click()
                expect(target.locator("#operationPrepare")).to_be_visible()

            def fill(target, body):
                for name, value in body.items():
                    field = target.locator("#op-body-" + name)
                    if field.evaluate("e=>e.tagName") == "SELECT":
                        field.select_option(str(value))
                    else:
                        field.fill(json.dumps(value) if isinstance(value, (dict, list)) else str(value))

            def execute(target, path, status=200):
                target.locator("#operationPrepare").click()
                expect(target.locator("#operationConfirmation")).to_be_visible()
                target.locator("#operationAcknowledge").check()
                with target.expect_response(lambda response: response.url == base + path and response.request.method != "GET") as received:
                    target.locator("#operationExecute").click()
                check("actual_" + path + "_" + str(len(report["checks"])), received.value.status == status)
                expected_message = ("접근 거부" if path == "/zero-trust/protected-access" and status == 403 else
                                    "모의 실행 결과" if path.endswith("/execute") else "처리 완료")
                expect(target.locator("#operationMessage")).to_contain_text(expected_message)
                return received.value.json()

            # Every available backend contract renders, including nested JSON fields.
            for width in (1440, 390):
                page.set_viewport_size({"width": width, "height": 1080})
                for op in metadata["operations"]:
                    operation(page, op["path"], op["method"])
                    check(f"form_{width}_{op['id']}", page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth + 1"))
            page.set_viewport_size({"width": 1440, "height": 1080})
            operation(page, "/detections/context/baselines")
            check("baseline_start_leaves_review_time", page.locator("#op-body-valid_from").evaluate(
                "e => Date.parse(e.value) > Date.now() + 240000"))
            fill(page, {"capture_ids": ["capture-a", "capture-b", "capture-c"],
                        "note": "Synthetic baseline time validation", "valid_from": "2020-01-01T00:00:00Z"})
            page.locator("#operationPrepare").click()
            expect(page.locator("#operationMessage")).to_contain_text("소급 등록은 허용되지 않습니다")
            check("backdated_baseline_not_submitted")
            operation(page, "/analysis")
            page.locator("#operationScenario").select_option("ZT-S01")
            page.get_by_role("button", name="합성 예제 불러오기").click()
            expect(page.locator("#operationMessage")).to_contain_text("정답 라벨을 제거")
            result = execute(page, "/analysis")
            check("rule_analysis_saved", result["event_id"])
            page.screenshot(path=str(args.output_dir / "analysis-operation.png"), full_page=True)

            # Preview only: these signed-body placeholders are never submitted.
            # The explicit LLM endpoints require a cost acknowledgement even when
            # the generic server health currently reports the rule analyzer.
            sample = page.request.post(
                base + "/events/simulate",
                headers=headers | {"Content-Type": "application/json"},
                data=json.dumps({"scenario_id": "NORMAL-01", "count": 1}),
            ).json()[0]
            attempted_reviews = []
            page.on(
                "request",
                lambda req: (
                    attempted_reviews.append(req.url)
                    if req.method == "POST" and "/analysis/" in req.url
                    else None
                ),
            )
            for review_path in ("/analysis/verified-session", "/analysis/evidence-review"):
                operation(page, review_path)
                fill(
                    page,
                    {
                        "session_id": "preview-session",
                        "expected_version": 0,
                        "tenant_id": "tenant-a",
                        "source_id": "preview-collector",
                        "key_id": "preview-key",
                        "event": sample,
                        "signature": "A" * 86,
                    },
                )
                page.locator("#operationPrepare").click()
                expect(page.locator("#operationConfirmation")).to_contain_text(
                    "실제 모델 호출로 비용"
                )
                expect(page.locator("#operationExecute")).to_be_disabled()
                check("explicit_llm_review_cost_acknowledgement_" + review_path)
            check("llm_review_preview_does_not_submit_or_call_provider", not attempted_reviews)

            operation(page, "/results/{event_id}/review", "PATCH")
            page.locator("#op-path-event_id").fill(result["event_id"])
            fill(page, {"status": "RESOLVED", "note": "Checked synthetic event evidence"})
            execute(page, "/results/" + result["event_id"] + "/review")

            operation(page, "/zero-trust/sessions/evaluate")
            page.get_by_role("button", name="합성 예제 불러오기").click()
            expect(page.locator("#operationMessage")).to_contain_text("정답 라벨을 제거")
            event = json.loads(page.locator("#op-body-event").input_value())
            event["user"]["role"] = "employee"
            event["resource"] = {"resource_id": "zt-demo-documents", "resource_type": "document", "sensitivity": "internal"}
            event["auth_context"].update(authentication_result="success", mfa="success")
            fill(page, {"event": event})
            session = execute(page, "/zero-trust/sessions/evaluate")
            session_id = session["session"]["session_id"]
            check("allow_and_private_grant", session["session"]["decision"] == "ALLOW"
                  and session["grant_token"] not in page.locator("#operationResult").inner_text())

            operation(page, "/response/requests")
            fill(page, {"session_id": session_id, "action": "reduce_privilege", "reason": "Review synthetic least privilege proposal"})
            response = execute(page, "/response/requests", 201)
            identifier = response["request_id"]
            request_url = "/response/requests/" + identifier
            operation(page, "/response/requests/{identifier}/approvals")
            page.locator("#op-path-identifier").fill(identifier)
            fill(page, {"reason": "Self approval must fail"})
            page.locator("#operationPrepare").click()
            expect(page.locator("#operationMessage")).to_contain_text("자기 요청을 승인할 수 없습니다")
            check("requester_cannot_self_approve")

            review_pages = []
            for reviewer in ("reviewer-a", "reviewer-b"):
                review_page = login(reviewer)
                operation(review_page, "/response/requests/{identifier}/approvals")
                review_page.locator("#op-path-identifier").fill(identifier)
                fill(review_page, {"reason": "Independent target and evidence review"})
                review_page.locator("#operationPrepare").click()
                expect(review_page.locator("#operationConfirmation")).to_be_visible()
                review_page.locator("#operationAcknowledge").check()
                review_pages.append(review_page)
            for index, review_page in enumerate(review_pages):
                with review_page.expect_response(lambda r: r.url == base + request_url + "/approvals") as received:
                    review_page.locator("#operationExecute").click()
                if index == 0:
                    check("first_approval_uses_reviewed_version", received.value.status == 200)
                else:
                    check("stale_review_rejected", received.value.status == 409)
                    expect(review_page.locator("#operationMessage")).to_contain_text("기록이 변경")
                    expect(review_page.locator("#operationConfirmation")).not_to_be_visible()
                    response = execute(review_page, request_url + "/approvals")
                review_page.context.close()
            check("two_distinct_reviews", response["status"] == "APPROVED"
                  and set(response["approved_by"]) == {"reviewer-a", "reviewer-b"})
            operation(page, "/response/requests/{identifier}/execute")
            page.locator("#op-path-identifier").fill(identifier)
            executed = execute(page, request_url + "/execute")
            check("simulated_response_no_external_effect", executed["status"] == "EXECUTED"
                  and executed["simulation_only"] and not executed["result"]["effect_applied"])
            page.screenshot(path=str(args.output_dir / "response-operation.png"), full_page=True)

            operation(page, "/zero-trust/sessions/{session_id}/revoke")
            page.locator("#op-path-session_id").fill(session_id)
            fill(page, {"note": "Manual revocation acceptance"})
            execute(page, "/zero-trust/sessions/" + session_id + "/revoke")
            operation(page, "/zero-trust/protected-access")
            fill(page, {"session_id": session_id, "resource_id": "zt-demo-documents", "action": "READ",
                        "grant_token": session["grant_token"]})
            denied = execute(page, "/zero-trust/protected-access", 403)
            check("manual_revoke_denies_unused_token", not denied["allowed"])

            viewer = login("viewer")
            operation(viewer, "/response/requests")
            expect(viewer.locator("#operationPrepare")).to_be_disabled()
            check("viewer_write_controls_disabled")
            viewer.context.close()
            foreign = login("foreign")
            operation(foreign, "/response/requests/{identifier}", "GET")
            foreign.locator("#op-path-identifier").fill(identifier)
            foreign.locator("#operationPrepare").click()
            expect(foreign.locator("#operationMessage")).not_to_have_text("조회 완료")
            check("foreign_request_hidden", foreign.request.get(base + request_url,
                  headers={"X-API-Key": "synthetic-foreign-key"}).status == 404)
            foreign.context.close()

            page.locator('a[href="#operations"]').click()
            capabilities = page.request.get(base + "/dashboard/jobs/capabilities", headers=headers).json()
            if not capabilities["enabled"]:
                expect(page.locator("#operationMessage")).to_contain_text("호스트 작업을 사용할 수 없습니다")
                report["excluded"] = [{"name": "POSIX host jobs", "reason": "Host job capability unavailable on this platform"}]
                check("unsupported_host_jobs_fail_closed", page.locator("#jobRun").count() == 0)
                check("no_credential_persistence", page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
                      and "synthetic-requester-key" not in page.content())
                check("no_javascript_errors", not errors)
                check("no_external_network_calls", not external)
                browser.close()
                return
            expect(page.locator("#jobAction")).to_be_visible()
            page.locator("#jobAction").select_option("m6-mock")
            page.locator("#jobReason").fill("Browser acceptance mock evaluation")
            page.locator("#jobConfirm").check()
            with page.expect_response(lambda r: r.url == base + "/dashboard/jobs" and r.request.method == "POST") as received:
                page.locator("#jobRun").click()
            check("durable_job_accepted", received.value.status == 202)
            expect(page.locator("#operationJobs")).to_contain_text("SUCCEEDED", timeout=45000)
            page.screenshot(path=str(args.output_dir / "operations-job.png"), full_page=True)
            check("real_m6_mock_job_completed")
            jobs_before = page.request.get(base + "/dashboard/jobs", headers=headers).json()
            page.locator("#jobConfirm").check()
            page.locator("#jobRun").click()
            expect(page.locator("#jobRun")).to_be_enabled()
            check("same_job_retry_is_not_reexecuted", len(page.request.get(base + "/dashboard/jobs", headers=headers).json()) == len(jobs_before))
            lost_ids = []

            def drop_accepted_response(route):
                if route.request.method != "POST":
                    route.continue_()
                    return
                lost_ids.append(route.request.post_data_json["request_id"])
                route.fetch()
                route.abort("failed")

            page.route("**/dashboard/jobs", drop_accepted_response)
            page.locator("#jobReason").fill("Recover an accepted job with a lost response")
            page.locator("#jobConfirm").check()
            page.locator("#jobRun").click()
            expect(page.locator("#operationMessage")).to_contain_text("처리 결과를 확인하지 못했습니다")
            page.unroute("**/dashboard/jobs", drop_accepted_response)
            page.locator("#jobRun").click()
            expect(page.locator("#operationMessage")).to_contain_text("접수됨")
            after = page.request.get(base + "/dashboard/jobs", headers=headers).json()
            check("lost_response_retry_recovers_original_job", len(after) == len(jobs_before) + 1
                  and sum(row["id"] == lost_ids[0] for row in after) == 1)
            expect(page.locator("#operationJobs")).not_to_contain_text("RUNNING", timeout=45000)
            expect(page.locator("#operationJobs")).not_to_contain_text("QUEUED", timeout=45000)
            check("no_credential_persistence", page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
                  and "synthetic-requester-key" not in page.content())
            check("no_javascript_errors", not errors)
            check("no_external_network_calls", not external)
            browser.close()
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
    parser.add_argument("--browser-channel", default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/dashboard-operations-browser"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"schema": "dashboard-operations-browser-1", "synthetic": True, "checks": [], "passed": False}
    try:
        with tempfile.TemporaryDirectory(prefix="secops-operations-") as temp:
            run(args, Path(temp).resolve(), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
