"""Real loopback browser acceptance for observed-version, caller-bound reviews.

Uses an isolated, strict SQLite fixture and rule analysis only. No paid models,
external systems, production files or Docker resources are used.
"""

import argparse
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

from scripts.local_process_runtime import direct_python

ROOT = Path(__file__).resolve().parents[1]


def run(args, directory, report):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    executable, environment = direct_python(os.environ)
    log = (args.output_dir / "server.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        [
            executable,
            *(["-S"] if os.name == "nt" else []),
            "-m",
            "tests.dashboard_operations_fixture",
            "--directory",
            str(directory / "data"),
            "--port",
            str(port),
            "--sqlite-audit",
        ],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        env=environment,
    )

    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        if not condition:
            raise AssertionError(name)

    try:
        deadline = time.monotonic() + 40
        while True:
            if process.poll() is not None:
                raise RuntimeError("Fixture exited; inspect server.log")
            try:
                with urlopen(base + "/health", timeout=1) as response:
                    health = json.load(response)
                break
            except (URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Fixture did not start") from None
                time.sleep(0.1)
        check(
            "isolated_local_rule_sqlite",
            health["analyzer_mode"] == "rule"
            and health["environment"] == "local"
            and health["audit_backend"] == "sqlite",
        )
        accounts = directory / "data" / "accounts.json"
        original_accounts = accounts.read_bytes()

        def remap():
            data = json.loads(original_accounts)
            data["accounts"][0]["subject"] = "replacement-reviewer"
            # Atomic replacement avoids accidentally testing half-written config.
            candidate = accounts.with_suffix(".candidate")
            candidate.write_text(json.dumps(data), encoding="utf-8")
            candidate.replace(accounts)

        def restore():
            candidate = accounts.with_suffix(".candidate")
            candidate.write_bytes(original_accounts)
            candidate.replace(accounts)

        with sync_playwright() as pw:
            options = (
                {"executable_path": args.browser_executable} if args.browser_executable else {}
            )
            browser = pw.chromium.launch(**options)
            errors, external, patches = [], [], []

            def login(subject="reviewer-a"):
                context = browser.new_context(viewport={"width": 1440, "height": 1080})
                page = context.new_page()
                page.set_default_timeout(12000)
                page.on("pageerror", lambda error: errors.append(str(error)))

                def requested(req):
                    if not req.url.startswith(base + "/"):
                        external.append(req.url)
                    if req.method == "PATCH" and req.url.endswith("/review"):
                        patches.append(req)

                page.on("request", requested)
                page.goto(base)
                page.locator("#autoRefresh").uncheck()
                page.locator("#connectionButton").click()
                page.locator("#credentialType").select_option("api_key")
                page.locator("#credential").fill("synthetic-" + subject + "-key")
                page.get_by_role("button", name="적용하고 조회").click()
                expect(page.locator("#connectionDialog")).not_to_be_visible()
                expect(page.locator("#refresh")).to_be_enabled()
                return page

            page = login()
            headers = {"X-API-Key": "synthetic-reviewer-a-key"}
            admin = {"X-API-Key": "synthetic-requester-key"}
            sample = page.request.post(
                base + "/events/simulate", headers=admin, data={"scenario_id": "ZT-S01", "count": 1}
            ).json()[0]
            sample.pop("ground_truth", None)
            created = page.request.post(base + "/analysis", headers=admin, data=sample)
            check(
                "real_rule_analysis_review_required",
                created.ok and created.json()["review_status"] == "PENDING",
            )
            event_id = created.json()["event_id"]
            url = base + "/results/" + event_id
            review_url = url + "/review"
            metadata = page.request.get(base + "/auth/dashboard-catalog", headers=headers).json()
            operation = next(
                o for o in metadata["operations"] if o["path"] == "/results/{event_id}/review"
            )

            def latest():
                response = page.request.get(url, headers=headers)
                assert response.ok
                return response

            def fresh_form(target):
                expect(target.locator("#refresh")).to_be_enabled()
                target.wait_for_load_state("networkidle")
                target.locator('a[href="#' + operation["group"] + '"]').click()
                target.locator('[data-operation="' + operation["id"] + '"]').click()
                target.locator("#op-path-event_id").fill(event_id)
                target.locator("#op-body-status").select_option("IN_REVIEW")
                target.locator("#op-body-note").fill("Fresh evidence explicitly checked")

            def detail_form(target):
                target.locator("#refresh").click()
                expect(target.locator("#refresh")).to_be_enabled()
                target.locator('a[data-page="logs"]').click()
                target.locator("#logRows").get_by_role(
                    "button", name=event_id + " 상세", exact=True
                ).click()
                expect(target.locator("#detailBody")).to_contain_text(event_id)
                target.get_by_role("button", name="검토 상태 변경", exact=True).click()
                target.locator("#op-body-status").select_option("IN_REVIEW")
                target.locator("#op-body-note").fill("Reviewed the opened detail snapshot")

            def prepare(target):
                target.locator("#operationPrepare").click()
                expect(target.locator("#operationConfirmation")).to_be_visible()
                target.locator("#operationAcknowledge").check()

            def execute(target, status=200):
                with target.expect_response(
                    lambda r: r.url == review_url and r.request.method == "PATCH"
                ) as received:
                    target.locator("#operationExecute").click()
                assert received.value.status == status
                expect(target.locator("#operationConfirmation")).not_to_be_visible()
                expect(target.locator("#operationPrepare")).to_be_enabled()
                expect(target.locator("#refresh")).to_be_enabled()
                return received.value

            def change_elsewhere(note):
                observation = latest()
                response = page.request.patch(
                    review_url,
                    headers=admin
                    | {
                        "If-Match": observation.headers["etag"],
                    },
                    data={"status": "IN_REVIEW", "note": note},
                )
                assert response.ok
                return response

            observation = latest()
            detail_form(page)
            prepare(page)
            check(
                "detail_confirmation_shows_evidence_and_caller",
                "reviewer-a" in page.locator("#operationConfirmation").inner_text()
                and page.locator("#op-body-reviewer").input_value() == "reviewer-a"
                and page.locator("#op-body-reviewer").get_attribute("readonly") is not None,
            )
            for width, height, name in ((1440, 1080, "desktop"), (390, 844, "mobile")):
                page.set_viewport_size({"width": width, "height": height})
                check(
                    "confirmation_no_horizontal_overflow_" + name,
                    page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                )
                page.screenshot(
                    path=str(args.output_dir / ("review-confirmation-" + name + ".png")),
                    full_page=True,
                )
            page.set_viewport_size({"width": 1440, "height": 1080})
            response = execute(page)
            check(
                "detail_patch_uses_exact_read_headers",
                patches[-1].headers.get("if-match") == observation.headers["etag"]
                and patches[-1].headers.get("x-review-identity")
                == observation.headers["x-review-identity"],
            )
            check(
                "server_owns_reviewer_and_issues_new_etag",
                response.json()["reviewer"] == "reviewer-a"
                and response.headers["etag"] != observation.headers["etag"]
                and "reviewer" not in patches[-1].post_data_json,
            )

            # A record changed after opening detail must not be silently refreshed on prepare.
            detail_form(page)
            winner = change_elsewhere("Other operator won before prepare")
            prepare(page)
            execute(page, 412)
            expect(page.locator("#operationMessage")).to_contain_text("다시 조회")
            check(
                "old_detail_does_not_rebase_at_prepare",
                latest().json()["review_note"] == winner.json()["review_note"],
            )
            page.screenshot(path=str(args.output_dir / "review-stale-desktop.png"), full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(args.output_dir / "review-stale-mobile.png"), full_page=True)
            page.set_viewport_size({"width": 1440, "height": 1080})
            prepare(page)  # Explicit new preparation after conflict reads the current record.
            execute(page)
            check("explicit_re_read_after_conflict_succeeds")

            other = login("reviewer-b")
            fresh_form(page)
            fresh_form(other)
            prepare(page)
            prepare(other)
            execute(other)
            winning = latest().headers["etag"]
            execute(page, 412)
            check(
                "two_browser_review_cas_preserves_winner",
                latest().headers["etag"] == winning and latest().json()["reviewer"] == "reviewer-b",
            )
            other.context.close()

            fresh_form(page)
            prepare(page)
            remap()
            before = len(patches)
            page.locator("#operationExecute").click()
            expect(page.locator("#operationMessage")).to_contain_text("검토 신원이 변경")
            expect(page.locator("#operationPrepare")).to_be_enabled()
            check("identity_change_stops_patch_before_network", len(patches) == before)
            restore()

            fresh_form(page)
            prepare(page)
            page.wait_for_load_state("networkidle")

            def change_after_identity_lookup(route):
                fetched = route.fetch()
                remap()
                route.fulfill(response=fetched)

            page.route("**/auth/me", change_after_identity_lookup, times=1)
            before_version = latest().headers["etag"]
            execute(page, 403)
            expect(page.locator("#operationMessage")).to_contain_text("신원 또는 권한")
            restore()
            check(
                "server_rejects_identity_change_after_browser_lookup",
                latest().headers["etag"] == before_version,
            )

            def metadata_handler(invalid):
                # Fetch outside interception: this case changes only response
                # metadata, not the live backend or its request scheduling.
                fetched = latest()
                body = fetched.body()
                modified = dict(fetched.headers)
                modified.pop("content-length", None)
                if invalid == "missing-identity":
                    modified.pop("x-review-identity", None)
                elif invalid == "unavailable":
                    modified["x-review-mode"] = "unavailable"
                elif invalid is None:
                    modified.pop("etag", None)
                else:
                    modified["etag"] = invalid

                def invalid_metadata(route):
                    route.fulfill(status=200, headers=modified, body=body)

                return invalid_metadata

            for invalid, name in (
                (None, "missing_etag"),
                ('W/"weak"', "weak_etag"),
                ("missing-identity", "missing_identity"),
                ("unavailable", "nontransactional_backend"),
            ):
                fresh_form(page)
                handler = metadata_handler(invalid)
                page.route(url, handler)
                before = len(patches)
                page.locator("#operationPrepare").click()
                expect(page.locator("#operationPrepare")).to_be_enabled(timeout=20000)
                expect(page.locator("#operationMessage")).to_contain_text("검토")
                expect(page.locator("#operationConfirmation")).not_to_be_visible()
                check(name + "_never_sends_unconditional_patch", len(patches) == before)
                page.unroute(url, handler)

            fresh_form(page)
            prepare(page)
            page.locator("#op-body-note").fill("Changed after confirming")
            expect(page.locator("#operationConfirmation")).not_to_be_visible()
            check("editing_invalidates_confirmation")
            prepare(page)

            def edit_during_final_lookup(route):
                fetched = route.fetch()
                page.locator("#op-body-note").fill("Changed while caller check was in flight")
                route.fulfill(response=fetched)

            page.route("**/auth/me", edit_during_final_lookup, times=1)
            before = len(patches)
            page.locator("#operationExecute").click()
            expect(page.locator("#operationPrepare")).to_be_enabled()
            check("edit_during_async_caller_check_never_submits_old_input", len(patches) == before)

            fresh_form(page)
            prepare(page)
            page.locator("#connectionButton").click()
            page.locator("#credential").fill("synthetic-reviewer-b-key")
            page.get_by_role("button", name="적용하고 조회").click()
            expect(page.locator("#connectionDialog")).not_to_be_visible()
            expect(page.locator("#operationConfirmation")).not_to_be_visible()
            check("connection_change_discards_prepared_review")
            page.context.close()
            page = login()

            fresh_form(page)
            page.locator("#op-body-note").fill("Committed with response deliberately lost")
            prepare(page)

            def lose_response(route):
                assert route.fetch().ok
                route.abort("failed")

            page.route(review_url, lose_response, times=1)
            before = len(patches)
            page.locator("#operationExecute").click()
            expect(page.locator("#operationMessage")).to_contain_text("자동 재전송하지 않았습니다")
            expect(page.locator("#operationPrepare")).to_be_enabled()
            check(
                "lost_response_preserves_commit_without_retry",
                len(patches) == before + 1
                and latest().json()["review_note"] == "Committed with response deliberately lost",
            )
            expect(page.locator("#operationConfirmation")).not_to_be_visible()
            check(
                "status_message_accessible",
                page.locator("#operationMessage").get_attribute("role") == "status",
            )
            prepare(page)
            execute(page)
            check("explicit_review_after_uncertain_outcome_reads_current_version")
            check(
                "credentials_not_persisted_or_displayed",
                page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
                and "synthetic-reviewer-a-key" not in page.content(),
            )
            viewer = login("viewer")
            fresh_form(viewer)
            expect(viewer.locator("#operationPrepare")).to_be_disabled()
            check("viewer_cannot_prepare_review")
            foreign = login("foreign")
            check(
                "other_tenant_cannot_observe_result",
                foreign.request.get(url, headers={"X-API-Key": "synthetic-foreign-key"}).status
                == 404,
            )
            check("no_javascript_errors", not errors)
            check("no_external_requests", not external)
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()
        report["owned_server_stopped"] = process.poll() is not None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable")
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/dashboard-review-browser"))
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sources = (
        "app/main.py",
        "app/services/audit_review_preconditions.py",
        "app/static/dashboard.js",
        "app/static/dashboard-operations.js",
        "tests/dashboard_operations_fixture.py",
        __file__,
    )
    report = {
        "schema": "dashboard-review-browser-1",
        "synthetic": True,
        "paid_calls": 0,
        "passed": False,
        "checks": [],
        "source_sha256": {
            str(Path(path).resolve().relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                (ROOT / path).read_bytes()
            ).hexdigest()
            for path in sources
        },
    }
    try:
        with tempfile.TemporaryDirectory(prefix="secops-review-") as temp:
            run(args, Path(temp).resolve(), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
