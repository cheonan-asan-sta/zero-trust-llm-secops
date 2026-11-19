"""Real workbench cursor navigation and identity isolation with synthetic data."""

import argparse
import copy
import hashlib
import json
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import Error as BrowserError
from playwright.sync_api import expect, sync_playwright

from scripts.test_workbench_review_browser import ROOT, server

PATTERN = "**/audit/results?*"


def run(args, directory, report):
    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        assert condition, name

    with (
        server(
            directory / "data",
            args.output_dir,
            report,
            caller_bound_reviews=True,
            audit_records=136,
        ) as base,
        sync_playwright() as pw,
    ):
        browser = (
            pw.chromium.launch(executable_path=args.browser_executable)
            if args.browser_executable
            else pw.chromium.launch()
        )
        try:
            page = browser.new_page(
                viewport={"width": 1440, "height": 1080}, reduced_motion="reduce"
            )
            page.set_default_timeout(15000)
            errors, external, requests, legacy = [], [], [], []
            page.on("pageerror", lambda error: errors.append(str(error)))

            def requested(req):
                if not req.url.startswith(base + "/"):
                    external.append(req.url)
                if "/audit/results?" in req.url:
                    requests.append(req.url)
                if urlparse(req.url).path == "/results":
                    legacy.append(req.url)

            page.on("request", requested)
            page.goto(base + "/static/workbench.html")
            headers = {"X-API-Key": "synthetic-reviewer-a-key"}
            admin = {"X-API-Key": "synthetic-requester-key"}

            def settled():
                expect(page.locator("#historyBody")).to_have_attribute("aria-busy", "false")

            def read(action, subject="reviewer-a"):
                with page.expect_response(
                    lambda r: (
                        "/audit/results?" in r.url
                        and r.status == 200
                        and r.request.headers.get("x-api-key") == "synthetic-" + subject + "-key"
                    )
                ) as received:
                    action()
                settled()
                return received.value.json()

            def connect(subject="reviewer-a"):
                page.locator("#workbenchCredentialType").select_option("api_key")
                page.locator("#workbenchCredential").fill("synthetic-" + subject + "-key")
                page.get_by_role("button", name="적용하고 조회", exact=True).click()

            def reload():
                return read(lambda: page.locator("#historyReload").click())

            def intercepted(routes):
                deadline = time.monotonic() + 4
                while not routes:
                    assert time.monotonic() < deadline, "browser interception not received"
                    page.wait_for_timeout(10)

            first = read(connect)
            ids = [r["analysis_id"] for r in first["items"]]
            check(
                "first_page_is_bounded_and_tenant_scoped",
                len(ids) == 12
                and first["total_matches"] == 136
                and all(r["tenant_id"] == "tenant-a" for r in first["items"]),
            )
            expect(page.locator("#historyPage")).to_have_text("1 / 12 페이지")
            check("first_previous_disabled", page.locator("#historyPrevious").is_disabled())

            observation = page.request.get(base + "/results/page-event-136", headers=admin)
            winner = page.request.patch(
                base + "/results/page-event-136/review",
                headers=admin
                | {
                    "If-Match": observation.headers["etag"],
                    "X-Review-Identity": observation.headers["x-review-identity"],
                },
                data={"status": "IN_REVIEW", "note": "Committed after list snapshot"},
            )
            assert winner.ok
            sample = page.request.post(
                base + "/events/simulate", headers=admin, data={"scenario_id": "ZT-S01", "count": 1}
            ).json()[0]
            sample.pop("ground_truth", None)
            sample["event_id"] = "workbench-new-after-snapshot"
            assert page.request.post(base + "/analysis", headers=admin, data=sample).ok
            second = read(lambda: page.locator("#historyNext").click())
            check(
                "next_retains_original_snapshot_and_expiry",
                all(
                    first[k] == second[k]
                    for k in (
                        "snapshot_id",
                        "total_matches",
                        "snapshot_created_at",
                        "snapshot_expires_at",
                    )
                ),
            )
            previous = read(lambda: page.locator("#historyPrevious").click())
            check(
                "previous_uses_saved_current_page_cursor",
                [r["analysis_id"] for r in previous["items"]] == ids
                and previous["items"][0]["review_status"] == "PENDING",
            )
            row = page.locator("#historyBody tr").filter(has_text="page-event-136")
            row.get_by_role("button", name="열기", exact=True).click()
            expect(page.locator("#reviewNoteInput")).to_have_value("Committed after list snapshot")
            check(
                "historical_list_opens_current_detail_for_review",
                page.locator("#reviewStatusBadge").inner_text() == "조사 중",
            )
            before = len(requests)
            with page.expect_response(lambda r: r.url == base + "/metrics"):
                page.locator("#refreshButton").click()
            check(
                "summary_refresh_preserves_snapshot_without_list_request",
                len(requests) == before
                and page.locator("#historyPage").inner_text() == "1 / 12 페이지",
            )

            current = reload()
            check(
                "explicit_reload_includes_new_analysis_and_review",
                current["total_matches"] == 137 and current["snapshot_id"] != first["snapshot_id"],
            )
            visited = [r["analysis_id"] for r in current["items"]]
            count = 1
            while current["next_cursor"]:
                current = read(lambda: page.locator("#historyNext").click())
                visited.extend(r["analysis_id"] for r in current["items"])
                count += 1
            check(
                "all_137_rows_visited_once_across_12_pages",
                count == 12 and len(visited) == len(set(visited)) == 137,
            )
            check("last_next_disabled", page.locator("#historyNext").is_disabled())
            report["traversal"] = {
                "rows": len(visited),
                "unique": len(set(visited)),
                "pages": count,
            }
            oldest = read(lambda: page.locator("#historyRisk").select_option("CRITICAL"))
            check(
                "server_filter_finds_oldest_outside_recent_100",
                any(row["event_id"] == "page-event-001" for row in oldest["items"])
                and all(row["assessment"]["risk_level"] == "CRITICAL" for row in oldest["items"]),
            )
            read(lambda: page.locator("#historyRisk").select_option(""))
            investigated = read(lambda: page.locator("#historyReview").select_option("IN_REVIEW"))
            check(
                "review_filter_applies_to_whole_audit",
                investigated["total_matches"] == 1
                and investigated["items"][0]["event_id"] == "page-event-136",
            )
            empty = read(lambda: page.locator("#historyReview").select_option("RESOLVED"))
            check(
                "empty_filter_has_no_navigation",
                empty["total_matches"] == 0
                and page.locator("#historyNext").is_disabled()
                and page.locator("#historyPrevious").is_disabled(),
            )
            read(lambda: page.locator("#historyReview").select_option(""))

            held = []
            high = page.request.get(
                base + "/audit/results", headers=headers, params={"limit": 12, "risk_level": "HIGH"}
            ).json()

            def hold_high(route):
                if parse_qs(urlparse(route.request.url).query).get("risk_level") == ["HIGH"]:
                    held.append(route)
                else:
                    route.continue_()

            page.route(PATTERN, hold_high)
            page.locator("#historyRisk").select_option("HIGH")
            intercepted(held)
            read(lambda: page.locator("#historyRisk").select_option("CRITICAL"))
            for route in held:
                try:
                    route.fulfill(json=high)
                except BrowserError:
                    pass
            page.unroute(PATTERN, hold_high)
            check(
                "late_previous_filter_cannot_replace_current_rows",
                "page-event-001" in page.locator("#historyBody").inner_text()
                and page.locator("#historyCount")
                .inner_text()
                .endswith(f"전체 조건 일치 {oldest['total_matches']}건"),
            )
            current = read(lambda: page.locator("#historyRisk").select_option(""))

            for status in (400, 409, 410, 501, 503):

                def failure(route, _request=None, status=status):
                    route.fulfill(status=status, json={"detail": "synthetic failure"})

                page.route(PATTERN, failure)
                before = len(requests)
                page.locator("#historyNext").click()
                settled()
                check(
                    f"http_{status}_clears_rows_without_retry",
                    len(requests) == before + 1
                    and page.locator("#historyBody button").count() == 0
                    and page.locator("#historyNext").is_disabled()
                    and page.locator("#historyPrevious").is_disabled(),
                )
                if status == 410:
                    page.locator("#historyStatus").screenshot(
                        path=str(args.output_dir / "history-expired.png")
                    )
                page.unroute(PATTERN, failure)
                current = reload()

            next_page = page.request.get(
                base + "/audit/results",
                headers=headers,
                params={"limit": 12, "cursor": current["next_cursor"]},
            ).json()
            mutations = [
                ("snapshot_id", "f" * 64),
                ("snapshot_expires_at", "2099-01-01T00:00:00Z"),
                ("snapshot_created_at", "2001-01-01T00:00:00Z"),
                ("page_cursor", "bad cursor"),
                ("total_matches", 1),
                ("historical_audit_snapshot", False),
                ("snapshot_mode", "unknown"),
            ]
            for field, value in mutations:
                payload = copy.deepcopy(next_page)
                payload[field] = value

                def inject(route, _request=None, payload=payload):
                    route.fulfill(json=payload)

                page.route(PATTERN, inject)
                page.locator("#historyNext").click()
                settled()
                check(
                    "invalid_" + field + "_fails_closed",
                    "응답을 확인할 수 없습니다" in page.locator("#historyStatus").inner_text()
                    and page.locator("#historyBody button").count() == 0,
                )
                page.unroute(PATTERN, inject)
                current = reload()
                next_page = page.request.get(
                    base + "/audit/results",
                    headers=headers,
                    params={"limit": 12, "cursor": current["next_cursor"]},
                ).json()

            for kind in (
                "tenant",
                "duplicate",
                "row_shape",
                "numeric_time",
                "previous_page_overlap",
            ):
                payload = copy.deepcopy(next_page)
                if kind == "tenant":
                    payload["items"][0]["tenant_id"] = "tenant-b"
                elif kind == "duplicate":
                    payload["items"][1] = copy.deepcopy(payload["items"][0])
                elif kind == "row_shape":
                    payload["items"][0]["analyzed_at"] = "not-a-time"
                elif kind == "numeric_time":
                    payload["items"][0]["analyzed_at"] = 0
                else:
                    payload["items"] = copy.deepcopy(current["items"])

                def inject_row(route, _request=None, payload=payload):
                    route.fulfill(json=payload)

                page.route(PATTERN, inject_row)
                page.locator("#historyNext").click()
                settled()
                check(
                    "invalid_rows_" + kind + "_fail_closed",
                    page.locator("#historyBody button").count() == 0
                    and page.locator("#historyNext").is_disabled(),
                )
                page.unroute(PATTERN, inject_row)
                current = reload()
                next_page = page.request.get(
                    base + "/audit/results",
                    headers=headers,
                    params={"limit": 12, "cursor": current["next_cursor"]},
                ).json()

            wrong_filter = copy.deepcopy(current)
            wrong_filter["items"][0]["assessment"]["risk_level"] = "LOW"
            page.route(PATTERN, lambda route: route.fulfill(json=wrong_filter))
            page.locator("#historyRisk").select_option("HIGH")
            settled()
            check(
                "response_rows_must_match_requested_filter",
                page.locator("#historyBody button").count() == 0
                and "응답을 확인할 수 없습니다" in page.locator("#historyStatus").inner_text(),
            )
            page.unroute(PATTERN)
            current = read(lambda: page.locator("#historyRisk").select_option(""))

            expiring = copy.deepcopy(current)
            expiring["snapshot_expires_at"] = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()
            page.route(PATTERN, lambda route: route.fulfill(json=expiring))
            reload()
            expect(page.locator("#historyStatus")).to_contain_text("만료됐습니다", timeout=6000)
            check(
                "local_expiry_clears_rows_and_navigation",
                page.locator("#historyBody button").count() == 0
                and page.locator("#historyNext").is_disabled(),
            )
            page.unroute(PATTERN)
            current = reload()

            for width, height, name in ((1440, 1080, "desktop"), (390, 844, "mobile")):
                page.set_viewport_size({"width": width, "height": height})
                page.locator("#historyReload").scroll_into_view_if_needed()
                check(
                    "no_horizontal_overflow_" + name,
                    page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                )
                page.locator("#historyReload").locator("xpath=../..").screenshot(
                    path=str(args.output_dir / ("history-" + name + ".png"))
                )
            page.set_viewport_size({"width": 1440, "height": 1080})
            page.locator("#historyRisk").focus()
            page.keyboard.press("Tab")
            expect(page.locator("#historyReview")).to_be_focused()
            page.keyboard.press("Tab")
            expect(page.locator("#historyReload")).to_be_focused()
            check("filters_and_reload_follow_keyboard_order")
            page.locator("#historyBody button").first.click()
            expect(page.locator("#reviewReload")).to_be_enabled()
            registry = directory / "data/accounts.json"
            original_registry = registry.read_bytes()
            accounts = json.loads(original_registry)
            accounts["accounts"][0]["subject"] = "remapped-with-same-key"
            registry.write_text(json.dumps(accounts), encoding="utf-8")
            before = len(requests)
            page.locator("#historyNext").click()
            settled()
            expect(page.locator("#workbenchIdentity")).to_contain_text("신원")
            check(
                "same_key_remap_clears_all_old_views_without_audit_read",
                len(requests) == before
                and page.locator("#historyBody button").count() == 0
                and page.locator("#resultContent").is_hidden()
                and "workbench-new-after-snapshot" not in page.locator("main").inner_text(),
            )
            registry.write_bytes(original_registry)
            current = read(connect)

            def remap_after_page(route):
                response = route.fetch()
                registry.write_text(json.dumps(accounts), encoding="utf-8")
                route.fulfill(response=response)

            page.route(PATTERN, remap_after_page)
            page.locator("#historyNext").click()
            settled()
            check(
                "caller_rechecked_after_page_response",
                page.locator("#historyBody button").count() == 0
                and "신원" in page.locator("#workbenchIdentity").inner_text(),
            )
            page.unroute(PATTERN, remap_after_page)
            registry.write_bytes(original_registry)
            current = read(connect)

            held = []
            payload = copy.deepcopy(next_page)
            page.route(PATTERN, lambda route: held.append(route))
            page.locator("#historyNext").click()
            intercepted(held)
            page.unroute(PATTERN)
            foreign = read(lambda: connect("foreign"), subject="foreign")
            for route in held:
                try:
                    route.fulfill(json=payload)
                except BrowserError:
                    pass
            report["tenant_race"] = {
                "total": foreign["total_matches"],
                "tenants": [row["tenant_id"] for row in foreign["items"]],
                "rows": page.locator("#historyBody").inner_text(),
                "identity": page.locator("#workbenchIdentity").inner_text(),
                "detail_visible": page.locator("#resultContent").is_visible(),
            }
            check(
                "late_previous_tenant_page_cannot_reappear",
                foreign["total_matches"] == 1
                and "page-event-" not in page.locator("#historyBody").inner_text()
                and page.locator("#resultContent").is_hidden(),
            )
            read(connect)
            for status in (401, 403):
                page.route(
                    PATTERN,
                    lambda route, _request=None, status=status: route.fulfill(
                        status=status, json={"detail": "authority withdrawn"}
                    ),
                )
                page.locator("#historyNext").click()
                settled()
                check(
                    f"http_{status}_requires_explicit_reconnect",
                    page.locator("#historyBody button").count() == 0
                    and page.locator("#resultContent").is_hidden()
                    and "연결 및 인증" in page.locator("#workbenchIdentity").inner_text(),
                )
                page.unroute(PATTERN)
                read(connect)
            check("no_legacy_recent_results_fallback", not legacy)
            check(
                "credentials_not_persisted_or_rendered",
                page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
                and "synthetic-reviewer-a-key" not in page.content(),
            )
            check("no_javascript_errors", not errors)
            check("no_external_requests", not external)
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable")
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/workbench-paging-browser"))
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sources = [
        "app/static/app.js",
        "app/static/workbench.html",
        "app/static/styles.css",
        "app/main.py",
        "app/config.py",
        "app/services/audit_paging.py",
        "tests/dashboard_operations_fixture.py",
        "scripts/test_workbench_review_browser.py",
        __file__,
    ]
    report = {
        "schema": "workbench-paging-browser-1",
        "synthetic": True,
        "paid_calls": 0,
        "caller_bound_policy_required": True,
        "passed": False,
        "checks": [],
        "source_sha256": {
            str(Path(p).resolve().relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                (ROOT / p).read_bytes()
            ).hexdigest()
            for p in sources
        },
    }
    try:
        with tempfile.TemporaryDirectory(prefix="secops-workbench-paging-") as temp:
            run(args, Path(temp).resolve(), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
