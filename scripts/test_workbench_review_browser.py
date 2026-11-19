"""Real local workbench reviews with version/caller binding and connection races.

Only synthetic accounts, isolated stores and rule analysis are used. No model
provider, cloud system or Docker resource is accessed.
"""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import Error as BrowserError
from playwright.sync_api import expect, sync_playwright

from scripts.local_process_runtime import direct_python

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def server(directory, output, report, *, anonymous=False, caller_bound_reviews=False):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    executable, environment = direct_python(os.environ)
    command = [executable, *(["-S"] if os.name == "nt" else []), "-m"]
    if anonymous:
        command += [
            "scripts.serve_dashboard_demo",
            "--seed",
            "--data-dir",
            str(directory),
            "--port",
            str(port),
        ]
    else:
        command += [
            "tests.dashboard_operations_fixture",
            "--directory",
            str(directory),
            "--port",
            str(port),
            "--sqlite-audit",
            *(["--caller-bound-reviews"] if caller_bound_reviews else []),
        ]
    with (output / ("anonymous-server.log" if anonymous else "server.log")).open(
        "w", encoding="utf-8"
    ) as log:
        process = subprocess.Popen(
            command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT
        )
        base = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 45
            while True:
                if process.poll() is not None:
                    raise RuntimeError("Isolated fixture exited; inspect server log")
                try:
                    with urlopen(base + "/health", timeout=1) as response:
                        health = json.load(response)
                    break
                except (URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Isolated fixture did not start") from None
                    time.sleep(0.1)
            assert health["analyzer_mode"] == "rule" and health["environment"] == "local"
            yield base
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            report.setdefault("owned_servers_stopped", []).append(process.poll() is not None)


def run(args, directory, report):
    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    with (
        server(
            directory / "data",
            args.output_dir,
            report,
            caller_bound_reviews=args.caller_bound_reviews,
        ) as base,
        sync_playwright() as pw,
    ):
        browser = pw.chromium.launch(
            **({"executable_path": args.browser_executable} if args.browser_executable else {})
        )
        errors, external, patches, analyses = [], [], [], []

        def login(subject="reviewer-a"):
            context = browser.new_context(
                viewport={"width": 1440, "height": 1080}, reduced_motion="reduce"
            )
            page = context.new_page()
            page.set_default_timeout(15000)
            page.on("pageerror", lambda error: errors.append(str(error)))

            def requested(req):
                if not req.url.startswith(base + "/"):
                    external.append(req.url)
                if req.method == "PATCH" and req.url.endswith("/review"):
                    patches.append(req)
                if req.method == "POST" and req.url == base + "/analysis":
                    analyses.append(req)

            page.on("request", requested)
            page.goto(base + "/static/workbench.html")
            connect(page, subject)
            return page

        def connect(page, subject):
            page.locator("#workbenchCredentialType").select_option("api_key")
            page.locator("#workbenchCredential").fill("synthetic-" + subject + "-key")
            page.get_by_role("button", name="적용하고 조회", exact=True).click()
            expect(page.locator("#workbenchIdentity")).to_contain_text(
                "operator" if subject == "requester" else subject
            )
            expect(page.locator("#scenarioCount")).not_to_have_text("0개")

        page = login()
        headers = {"X-API-Key": "synthetic-reviewer-a-key"}
        admin = {"X-API-Key": "synthetic-requester-key"}
        sample = page.request.post(
            base + "/events/simulate", headers=admin, data={"scenario_id": "ZT-S01", "count": 1}
        ).json()[0]
        sample.pop("ground_truth", None)
        sample["event_id"] = "workbench-observed-event"
        created = page.request.post(base + "/analysis", headers=admin, data=sample)
        assert created.ok and created.json()["review_status"] == "PENDING"
        event_id = sample["event_id"]
        url, review_url = base + "/results/" + event_id, base + "/results/" + event_id + "/review"
        if args.caller_bound_reviews:
            policy_read = page.request.get(url, headers=admin)
            denied = page.request.patch(
                review_url,
                headers=admin | {"If-Match": policy_read.headers["etag"]},
                data={"status": "IN_REVIEW", "note": "Missing caller binding must fail"},
            )
            check("server_requires_caller_binding", denied.status == 428)
            check(
                "denied_write_preserves_observed_version",
                page.request.get(url, headers=admin).headers["etag"] == policy_read.headers["etag"],
            )

        def latest():
            response = page.request.get(url, headers=headers)
            assert response.ok
            return response

        def opened(target=page):
            target.locator("#refreshButton").click()
            row = target.locator("#historyBody tr").filter(has_text=event_id)
            expect(row).to_have_count(1)
            with target.expect_response(
                lambda r: r.url == url and r.request.method == "GET"
            ) as received:
                row.get_by_role("button", name="열기", exact=True).click()
            expect(target.locator("#reviewReload")).to_be_enabled()
            expect(target.locator("#resultAnalyzer")).to_contain_text(event_id)
            return received.value

        def prepare(target=page, note="Review observed execution evidence"):
            target.locator("#reviewNoteInput").fill(note)
            target.locator('[data-review-status="IN_REVIEW"]').click()
            expect(target.locator("#reviewConfirmation")).to_be_visible()
            target.locator("#reviewAcknowledge").check()

        def execute(target=page, status=200):
            with target.expect_response(
                lambda r: r.url == review_url and r.request.method == "PATCH"
            ) as received:
                target.locator("#reviewExecute").click()
            assert received.value.status == status
            expect(target.locator("#reviewConfirmation")).not_to_be_visible()
            expect(target.locator("#reviewReload")).to_be_enabled()
            return received.value

        def elsewhere(note):
            observed = page.request.get(url, headers=admin)
            assert observed.ok
            response = page.request.patch(
                review_url,
                headers=admin
                | {
                    "If-Match": observed.headers["etag"],
                    "X-Review-Identity": observed.headers["x-review-identity"],
                },
                data={"status": "IN_REVIEW", "note": note},
            )
            assert response.ok
            return response

        observed = opened()
        prepare()
        check(
            "confirmation_names_observed_analysis_caller_and_change",
            event_id in page.locator("#resultAnalyzer").inner_text()
            and "reviewer-a" in page.locator("#reviewConfirmationSummary").inner_text()
            and observed.json()["analysis_id"]
            in page.locator("#reviewConfirmationSummary").inner_text()
            and page.locator("#reviewerInput").get_attribute("readonly") is not None,
        )
        for width, height, name in ((1440, 1080, "desktop"), (390, 844, "mobile")):
            page.set_viewport_size({"width": width, "height": height})
            check(
                "no_horizontal_overflow_" + name,
                page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
            )
            page.locator(".workbench-connection").screenshot(
                path=str(args.output_dir / ("workbench-connection-" + name + ".png"))
            )
            page.locator("#reviewWorkflow").screenshot(
                path=str(args.output_dir / ("workbench-confirmation-" + name + ".png"))
            )
        page.set_viewport_size({"width": 1440, "height": 1080})
        response = execute()
        check(
            "actual_patch_uses_observed_etag_and_caller_binding",
            patches[-1].headers.get("if-match") == observed.headers["etag"]
            and patches[-1].headers.get("x-review-identity")
            == observed.headers["x-review-identity"],
        )
        check(
            "server_owns_reviewer_and_body_cannot_spoof_it",
            response.json()["reviewer"] == "reviewer-a"
            and "reviewer" not in patches[-1].post_data_json,
        )
        check(
            "successful_review_requires_another_read_before_more_writes",
            page.locator('[data-review-status="IN_REVIEW"]').is_disabled(),
        )

        # The history array is not a review snapshot: opening reads fresh detail.
        elsewhere("Changed after history listing")
        fresh = opened()
        check(
            "history_open_fetches_current_detail",
            fresh.json()["review_note"] == "Changed after history listing"
            and page.locator("#reviewNoteInput").input_value() == "Changed after history listing",
        )
        winner = elsewhere("Changed after detail was opened")
        prepare()
        execute(status=412)
        expect(page.locator("#reviewFeedback")).to_contain_text("버전이 변경")
        check(
            "old_detail_is_not_rebased_when_preparing_review",
            latest().json()["review_note"] == winner.json()["review_note"],
        )
        page.locator("#reviewWorkflow").screenshot(
            path=str(args.output_dir / "workbench-stale.png")
        )
        page.locator("#reviewReload").click()
        expect(page.locator('[data-review-status="IN_REVIEW"]')).to_be_enabled()
        prepare()
        execute()
        check("explicit_reload_recovers_from_conflict")

        second = login("reviewer-b")
        opened()
        opened(second)
        prepare()
        prepare(second)
        execute(second)
        winning = latest().headers["etag"]
        execute(status=412)
        check(
            "two_workbenches_preserve_first_committed_review",
            latest().headers["etag"] == winning and latest().json()["reviewer"] == "reviewer-b",
        )
        second.context.close()

        opened()
        prepare()
        page.locator("#reviewNoteInput").fill("Edited after confirmation")
        expect(page.locator("#reviewConfirmation")).not_to_be_visible()
        check("editing_discards_confirmation")
        prepare()
        held = []

        def hold_first_identity(route):
            if held:
                route.continue_()
            else:
                held.append(route)

        identity = page.request.get(base + "/auth/me", headers=headers).json()
        page.route("**/auth/me", hold_first_identity)
        before = len(patches)
        with page.expect_request(lambda req: req.url == base + "/auth/me"):
            page.locator("#reviewExecute").click()
        deadline = time.monotonic() + 3
        while not held:
            assert time.monotonic() < deadline
            page.wait_for_timeout(10)
        page.locator("#reviewNoteInput").fill("Changed during final caller lookup")
        held[0].fulfill(json=identity)
        expect(page.locator("#reviewReload")).to_be_enabled()
        page.unroute("**/auth/me", hold_first_identity)
        check("editing_during_identity_check_prevents_old_patch", len(patches) == before)

        alternate = dict(sample, event_id="workbench-second-event")
        assert page.request.post(base + "/analysis", headers=admin, data=alternate).ok
        opened()
        alternate_row = page.locator("#historyBody tr").filter(has_text=alternate["event_id"])
        expect(alternate_row).to_have_count(1)
        held.clear()
        page.route("**/auth/me", hold_first_identity)
        before = len(patches)
        page.locator("#reviewNoteInput").fill("Pending preparation for the first target")
        with page.expect_request(lambda req: req.url == base + "/auth/me"):
            page.locator('[data-review-status="IN_REVIEW"]').click()
        deadline = time.monotonic() + 3
        while not held:
            assert time.monotonic() < deadline
            page.wait_for_timeout(10)
        alternate_row.get_by_role("button", name="열기", exact=True).click()
        expect(page.locator("#resultAnalyzer")).to_contain_text(alternate["event_id"])
        expect(page.locator("#reviewReload")).to_be_enabled()
        held[0].fulfill(json=identity)
        page.wait_for_load_state("networkidle")
        page.unroute("**/auth/me", hold_first_identity)
        check(
            "changing_target_discards_pending_preparation_without_locking_new_target",
            len(patches) == before
            and not page.locator("#reviewConfirmation").is_visible()
            and page.locator('[data-review-status="IN_REVIEW"]').is_enabled(),
        )

        accounts = directory / "data" / "accounts.json"
        original = accounts.read_bytes()

        def remap():
            data = json.loads(original)
            data["accounts"][0]["subject"] = "replacement-reviewer"
            candidate = accounts.with_suffix(".candidate")
            candidate.write_text(json.dumps(data), encoding="utf-8")
            candidate.replace(accounts)

        def restore():
            candidate = accounts.with_suffix(".candidate")
            candidate.write_bytes(original)
            candidate.replace(accounts)

        opened()
        prepare()
        remap()
        before = len(patches)
        page.locator("#reviewExecute").click()
        expect(page.locator("#reviewFeedback")).to_contain_text("신원 또는 권한")
        expect(page.locator("#reviewReload")).to_be_enabled()
        check("same_key_identity_remap_prevents_patch", len(patches) == before)
        restore()
        opened()
        prepare()
        old_identity = page.request.get(base + "/auth/me", headers=headers).json()
        changed = []

        def remap_after_lookup(route):
            if changed:
                route.continue_()
            else:
                changed.append(True)
                remap()
                route.fulfill(json=old_identity)

        page.route("**/auth/me", remap_after_lookup)
        version = latest().headers["etag"]
        execute(status=403)
        page.unroute("**/auth/me", remap_after_lookup)
        restore()
        check(
            "server_rejects_caller_change_after_browser_check", latest().headers["etag"] == version
        )

        def metadata_handler(kind):
            fetched = latest()
            body, modified = fetched.body(), dict(fetched.headers)
            modified.pop("content-length", None)
            if kind == "weak":
                modified["etag"] = 'W/"weak"'
            elif kind == "missing":
                modified.pop("etag", None)
            elif kind == "identity":
                modified.pop("x-review-identity", None)
            elif kind == "backend":
                modified["x-review-mode"] = "unavailable"
            return lambda route: route.fulfill(status=200, headers=modified, body=body)

        for kind in ("weak", "missing", "identity", "backend"):
            handler = metadata_handler(kind)
            page.route(url, handler)
            opened()
            before = len(patches)
            expect(page.locator('[data-review-status="IN_REVIEW"]')).to_be_disabled()
            page.locator('[data-review-status="IN_REVIEW"]').dispatch_event("click")
            check(
                "invalid_" + kind + "_cannot_downgrade_to_unconditional_write",
                len(patches) == before,
            )
            page.unroute(url, handler)

        opened()
        prepare(note="Committed before response was lost")

        def lose_response(route):
            assert route.fetch().ok
            route.abort("failed")

        page.route(review_url, lose_response, times=1)
        before = len(patches)
        page.locator("#reviewExecute").click()
        expect(page.locator("#reviewFeedback")).to_contain_text("자동 재전송하지 않았습니다")
        expect(page.locator("#reviewReload")).to_be_enabled()
        check(
            "lost_response_keeps_committed_history_without_retry",
            len(patches) == before + 1
            and latest().json()["review_note"] == "Committed before response was lost",
        )
        opened()
        prepare()
        execute()
        check("manual_read_after_uncertain_outcome_is_required_and_works")

        opened()
        prepare()
        before = len(patches)
        connect(page, "reviewer-b")
        expect(page.locator("#resultContent")).to_be_hidden()
        check(
            "connection_change_discards_result_and_confirmation",
            not page.locator("#reviewConfirmation").is_visible()
            and event_id not in page.locator("#resultSection").inner_text()
            and len(patches) == before,
        )
        connect(page, "reviewer-a")
        opened()
        held_details = []
        current = latest()
        page.route(url, lambda route: held_details.append(route))
        with page.expect_request(lambda req: req.url == url):
            page.locator("#reviewReload").click()
        deadline = time.monotonic() + 3
        while not held_details:
            assert time.monotonic() < deadline
            page.wait_for_timeout(10)
        page.unroute(url)
        connect(page, "foreign")
        for route in held_details:
            try:
                route.fulfill(
                    status=200,
                    json=current.json(),
                    headers={k: v for k, v in current.headers.items() if k != "content-length"},
                )
            except BrowserError:
                pass
        expect(page.locator("#historyBody")).not_to_contain_text(event_id)
        check(
            "late_previous_tenant_result_cannot_reappear",
            event_id not in page.locator("main").inner_text()
            and not page.locator("#resultContent").is_visible(),
        )
        connect(page, "viewer")
        opened()
        expect(page.locator('[data-review-status="IN_REVIEW"]')).to_be_disabled()
        check(
            "viewer_has_read_only_review_ui",
            "검토 권한이 없습니다" in page.locator("#reviewFeedback").inner_text(),
        )
        check(
            "credentials_are_memory_only_and_not_rendered",
            page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
            and page.locator("#workbenchCredential").input_value() == ""
            and "synthetic-viewer-key" not in page.content(),
        )

        # Existing rule analysis and local access demonstrations stay usable.
        connect(page, "requester")
        held_simulation = []
        page.route("**/events/simulate", lambda route: held_simulation.append(route))
        page.locator('[data-scenario-id="ZT-S01"]').click()
        with page.expect_request(lambda req: req.url == base + "/events/simulate"):
            page.locator("#analyzeButton").click()
        deadline = time.monotonic() + 3
        while not held_simulation:
            assert time.monotonic() < deadline
            page.wait_for_timeout(10)
        before = len(analyses)
        connect(page, "reviewer-a")
        for route in held_simulation:
            try:
                route.fulfill(json=[sample])
            except BrowserError:
                pass
        page.unroute("**/events/simulate")
        page.wait_for_load_state("networkidle")
        report["analysis_connection_race"] = {
            "requests_before": before,
            "requests_after": len(analyses),
            "result_visible_after_connection_change": page.locator("#resultContent").is_visible(),
            "continued_with_new_credentials": any(
                req.headers.get("x-api-key") == "synthetic-reviewer-a-key"
                for req in analyses[before:]
            ),
        }
        check(
            "old_analysis_workflow_cannot_continue_with_new_credentials",
            len(analyses) == before and not page.locator("#resultContent").is_visible(),
        )
        connect(page, "requester")
        page.locator('[data-scenario-id="ZT-S01"]').click()
        page.locator("#analyzeButton").click()
        expect(page.locator("#runState")).to_contain_text("분석이 완료됐습니다")
        expect(page.locator('[data-review-status="IN_REVIEW"]')).to_be_enabled()
        check("new_rule_analysis_acquires_a_real_review_observation")
        page.locator("#ztStart").click()
        expect(page.locator("#ztAccess")).to_be_enabled()
        page.locator("#ztCompromise").click()
        expect(page.locator("#ztStatus")).to_contain_text("회수")
        page.locator("#ztAccess").click()
        expect(page.locator("#ztFeedback")).to_contain_text("접근 거부 (403)")
        check("legacy_access_demo_uses_current_authenticated_request")
        check("no_javascript_errors", not errors)
        check("no_external_requests", not external)
        browser.close()

    with (
        server(directory / "anonymous", args.output_dir, report, anonymous=True) as base,
        sync_playwright() as pw,
    ):
        browser = pw.chromium.launch(
            **({"executable_path": args.browser_executable} if args.browser_executable else {})
        )
        page = browser.new_page(viewport={"width": 1440, "height": 1080})
        page.goto(base + "/static/workbench.html")
        expect(page.locator("#historyBody button").first).to_be_visible()
        page.locator("#historyBody button").first.click()
        expect(page.locator("#resultContent")).to_be_visible()
        check("anonymous_demo_remains_readable")
        check(
            "anonymous_or_nontransactional_demo_cannot_submit_reviews",
            page.locator('[data-review-status="IN_REVIEW"]').is_disabled(),
        )
        browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable")
    parser.add_argument("--caller-bound-reviews", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/workbench-review-browser"))
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    paths = [
        "app/static/app.js",
        "app/static/workbench.html",
        "app/static/styles.css",
        "app/main.py",
        "app/config.py",
        "tests/dashboard_operations_fixture.py",
        "app/services/audit_review_preconditions.py",
        __file__,
    ]
    report = {
        "schema": "workbench-review-browser-1",
        "synthetic": True,
        "caller_bound_policy_required": args.caller_bound_reviews,
        "paid_calls": 0,
        "passed": False,
        "checks": [],
        "source_sha256": {
            str(Path(p).resolve().relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                (ROOT / p).read_bytes()
            ).hexdigest()
            for p in paths
        },
    }
    try:
        with tempfile.TemporaryDirectory(prefix="secops-workbench-") as temp:
            run(args, Path(temp).resolve(), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
