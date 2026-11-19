"""Verify real dashboard audit cursors, caller changes and bounded page exports.

The server uses isolated synthetic SQLite records and rule analysis. No paid
provider, cloud resources, Docker, or production files are accessed.
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
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

from playwright.sync_api import Error as BrowserError
from playwright.sync_api import expect, sync_playwright

from scripts.local_process_runtime import direct_python

ROOT = Path(__file__).resolve().parents[1]
PATTERN = "**/audit/results?*"


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
            "--audit-records",
            "136",
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
        deadline = time.monotonic() + 45
        while True:
            if process.poll() is not None:
                raise RuntimeError("Isolated server exited; inspect server.log")
            try:
                with urlopen(base + "/health", timeout=1) as response:
                    health = json.load(response)
                break
            except (URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Isolated server did not start") from None
                time.sleep(0.1)
        check(
            "isolated_rule_sqlite_server",
            health["environment"] == "local"
            and health["analyzer_mode"] == "rule"
            and health["audit_backend"] == "sqlite",
        )
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                **({"executable_path": args.browser_executable} if args.browser_executable else {})
            )
            context = browser.new_context(viewport={"width": 1440, "height": 1080})
            page = context.new_page()
            page.set_default_timeout(15000)
            errors, external, audit_requests, downloads = [], [], [], []
            network_tail = []
            report["network_tail"] = network_tail

            def network(kind, req, status=None):
                path = urlparse(req.url).path
                if path in {"/auth/me", "/audit/results"}:
                    network_tail.append(
                        {"event": kind, "path": path, "request": id(req), "status": status}
                    )
                    del network_tail[:-45]

            page.on(
                "response", lambda response: network("response", response.request, response.status)
            )
            page.on("requestfailed", lambda req: network("failed", req))
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("download", lambda download: downloads.append(download))

            def requested(req):
                network("request", req)
                if not req.url.startswith(base + "/"):
                    external.append(req.url)
                if req.url.startswith(base + "/audit/results?"):
                    audit_requests.append(req)

            page.on("request", requested)
            page.goto(base)
            page.locator("#autoRefresh").uncheck()

            def connect(key):
                page.locator("#connectionButton").click()
                page.locator("#credentialType").select_option("api_key")
                page.locator("#credential").fill(key)
                page.get_by_role("button", name="적용하고 조회").click()
                expect(page.locator("#connectionDialog")).not_to_be_visible()
                expect(page.locator("#refresh")).to_be_enabled()

            connect("synthetic-reviewer-a-key")
            headers = {"X-API-Key": "synthetic-reviewer-a-key"}
            admin = {"X-API-Key": "synthetic-requester-key"}

            def settled():
                expect(page.locator("#logRows")).to_have_attribute(
                    "aria-busy", "false", timeout=20000
                )

            def intercepted(routes):
                deadline = time.monotonic() + 3
                while not routes:
                    if time.monotonic() >= deadline:
                        raise AssertionError("Expected browser request was not intercepted")
                    page.wait_for_timeout(10)

            def read(action):
                with page.expect_response(
                    lambda response: (
                        response.url.startswith(base + "/audit/results?") and response.status == 200
                    )
                ) as received:
                    action()
                settled()
                return received.value.json()

            def reload():
                return read(lambda: page.locator("#reloadAudit").click())

            first = read(lambda: page.locator('a[data-page="logs"]').click())
            original_ids = [row["analysis_id"] for row in first["items"]]
            check(
                "first_page_is_bounded_and_not_recent_window",
                len(original_ids) == 12 and first["total_matches"] == 136,
            )
            expect(page.locator("#pageLabel")).to_have_text("1 / 12 페이지")
            check(
                "explicit_filter_and_export_scope",
                "현재 페이지" in page.locator("#exportLogs").inner_text()
                and "현재 페이지" in page.locator("#logSearch").get_attribute("placeholder"),
            )
            latest = page.request.get(base + "/results/page-event-136", headers=admin)
            winner = page.request.patch(
                base + "/results/page-event-136/review",
                headers=admin
                | {
                    "If-Match": latest.headers["etag"],
                },
                data={"status": "IN_REVIEW", "note": "Another operator reviewed after list lookup"},
            )
            assert winner.ok
            sample = page.request.post(
                base + "/events/simulate", headers=admin, data={"scenario_id": "ZT-S01", "count": 1}
            ).json()[0]
            sample.pop("ground_truth", None)
            sample["event_id"] = "new-after-audit-snapshot"
            assert page.request.post(base + "/analysis", headers=admin, data=sample).ok
            second = read(lambda: page.locator("#nextPage").click())
            back = read(lambda: page.locator("#prevPage").click())
            check(
                "next_and_back_keep_original_snapshot",
                first["snapshot_id"] == second["snapshot_id"] == back["snapshot_id"]
                and first["snapshot_expires_at"] == back["snapshot_expires_at"]
                and back["total_matches"] == 136
                and [row["analysis_id"] for row in back["items"]] == original_ids,
            )
            check(
                "historical_review_is_not_silently_rebased",
                back["items"][0]["review_status"] == "PENDING",
            )
            with page.expect_download() as downloaded:
                page.locator("#exportLogs").click()
            exported = json.loads(Path(downloaded.value.path()).read_text(encoding="utf-8"))
            settled()
            check(
                "export_is_one_revalidated_snapshot_page",
                exported["scope"] == "current_tenant_audit_snapshot_page_filtered"
                and exported["historical_audit_snapshot"]
                and exported["snapshot_id"] == first["snapshot_id"]
                and len(exported["records"]) == 12
                and "cursor" not in json.dumps(exported),
            )
            check(
                "export_preserves_snapshot_under_new_writes",
                [row["analysis_id"] for row in exported["records"]] == original_ids,
            )

            # A list's historical row opens current detail, then binds review to that detail.
            page.locator("#logRows").get_by_role(
                "button", name="page-event-136 상세", exact=True
            ).click()
            expect(page.locator("#detailBody")).to_contain_text("조사 중")
            check("historical_list_detail_reads_current_review")
            page.locator("#closeDetail").click()
            fresh = reload()
            check(
                "explicit_reload_starts_new_snapshot",
                fresh["total_matches"] == 137
                and fresh["snapshot_id"] != first["snapshot_id"]
                and fresh["items"][0]["event_id"] == sample["event_id"],
            )
            legacy = page.request.get(base + "/results?limit=100", headers=headers).json()
            critical = read(lambda: page.locator("#riskFilter").select_option("CRITICAL"))
            check(
                "server_filter_finds_match_older_than_recent100",
                all(r["event_id"] != "page-event-001" for r in legacy)
                and any(r["event_id"] == "page-event-001" for r in critical["items"]),
            )
            check(
                "risk_filter_applied_before_limit",
                all(r["assessment"]["risk_level"] == "CRITICAL" for r in critical["items"]),
            )
            read(lambda: page.locator("#riskFilter").select_option(""))
            reviewed = read(lambda: page.locator("#reviewFilter").select_option("IN_REVIEW"))
            check(
                "review_filter_is_server_wide",
                reviewed["total_matches"] == 1
                and reviewed["items"][0]["event_id"] == "page-event-136",
            )
            current = read(lambda: page.locator("#reviewFilter").select_option(""))
            traversed = [row["analysis_id"] for row in current["items"]]
            while current["next_cursor"]:
                current = read(lambda: page.locator("#nextPage").click())
                traversed.extend(row["analysis_id"] for row in current["items"])
            check(
                "browser_traverses_all_records_once_including_older100",
                len(traversed) == len(set(traversed)) == 137,
            )
            expect(page.locator("#pageLabel")).to_have_text("12 / 12 페이지")
            check("last_page_has_no_next", page.locator("#nextPage").is_disabled())
            current = reload()
            page.locator("#logSearch").fill("no-such-local-record")
            expect(page.locator("#logRows")).to_contain_text("조건에 맞는 분석 기록이 없습니다")
            check(
                "local_search_does_not_claim_whole_dataset",
                "전체 조건 일치 137건" in page.locator("#logCount").inner_text()
                and page.locator("#exportLogs").is_disabled(),
            )
            page.locator("#logSearch").fill("")
            page.locator("#analyzerFilter").select_option("openai")
            expect(page.locator("#logRows")).to_contain_text("조건에 맞는 분석 기록이 없습니다")
            page.locator("#analyzerFilter").select_option("")
            expect(page.locator("#toast")).to_be_hidden(timeout=6000)

            for width, height, name in ((1440, 1080, "desktop"), (390, 844, "mobile")):
                page.set_viewport_size({"width": width, "height": height})
                check(
                    "no_horizontal_overflow_" + name,
                    page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                )
                page.screenshot(
                    path=str(args.output_dir / ("audit-page-" + name + ".png")), full_page=True
                )
            page.set_viewport_size({"width": 1440, "height": 1080})

            # Periodic overview refresh must not silently replace a paged view.
            read(lambda: page.locator("#nextPage").click())
            before = len(audit_requests)
            with page.expect_response(lambda r: r.url == base + "/auth/me"):
                page.locator("#autoRefresh").check()
            expect(page.locator("#refresh")).to_be_enabled()
            page.locator("#autoRefresh").uncheck()
            check(
                "periodic_refresh_preserves_page_without_restarting_snapshot",
                len(audit_requests) == before
                and page.locator("#pageLabel").inner_text() == "2 / 12 페이지",
            )
            current = reload()

            # A filter change must discard an older response, even if the old
            # server work finishes after the new filtered page is visible.
            held_filter = []
            high = page.request.get(
                base + "/audit/results", headers=headers, params={"limit": 12, "risk_level": "HIGH"}
            ).json()

            def hold_high(route):
                if parse_qs(urlparse(route.request.url).query).get("risk_level") == ["HIGH"]:
                    held_filter.append(route)
                else:
                    route.continue_()

            page.route(PATTERN, hold_high)
            with page.expect_request(
                lambda req: parse_qs(urlparse(req.url).query).get("risk_level") == ["HIGH"]
            ):
                page.locator("#riskFilter").select_option("HIGH")
            intercepted(held_filter)
            critical = read(lambda: page.locator("#riskFilter").select_option("CRITICAL"))
            for route in held_filter:
                try:
                    route.fulfill(json=high)
                except BrowserError:
                    pass
            check(
                "late_filter_response_cannot_replace_current_scope",
                "page-event-001" in page.locator("#logRows").inner_text()
                and all(r["assessment"]["risk_level"] == "CRITICAL" for r in critical["items"]),
            )
            page.unroute(PATTERN, hold_high)
            current = read(lambda: page.locator("#riskFilter").select_option(""))

            identity = page.request.get(base + "/auth/me", headers=headers).json()
            held_export = []

            def hold_first_export_identity(route):
                if held_export:
                    route.continue_()
                else:
                    held_export.append(route)

            page.route("**/auth/me", hold_first_export_identity)
            before = len(downloads)
            with page.expect_request(lambda req: req.url == base + "/auth/me"):
                page.locator("#exportLogs").click()
            page.locator("#logSearch").fill("changed-during-export")
            intercepted(held_export)
            for route in held_export:
                route.fulfill(json=identity)
            settled()
            report["export_race_state"] = {
                "held_requests": len(held_export),
                "status": page.locator("#logSnapshot").inner_text(),
                "page": page.locator("#pageLabel").inner_text(),
            }
            expect(page.locator("#toast")).to_contain_text("검색 조건이 변경됐습니다")
            page.unroute("**/auth/me", hold_first_export_identity)
            check(
                "edit_during_export_cannot_download_old_filter",
                len(downloads) == before
                and page.locator("#exportLogs").is_disabled()
                and page.locator("#pageLabel").inner_text() == "1 / 12 페이지",
            )
            page.locator("#logSearch").fill("")

            # Explicit page errors clear stale rows and never fall back/retry.
            def failure(status):
                return lambda route: route.fulfill(
                    status=status, json={"detail": "synthetic page failure"}
                )

            for status in (400, 409, 410, 501, 503):
                handler = failure(status)
                page.route(PATTERN, handler)
                before = len(audit_requests)
                page.locator("#nextPage").click()
                settled()
                expect(page.locator("#exportLogs")).to_be_disabled()
                expect(page.locator("#nextPage")).to_be_disabled()
                expect(page.locator("#prevPage")).to_be_disabled()
                check(
                    f"http_{status}_clears_rows_without_retry",
                    len(audit_requests) == before + 1
                    and "page-event-" not in page.locator("#logRows").inner_text()
                    and page.locator("#reloadAudit").is_enabled(),
                )
                if status == 410:
                    page.screenshot(path=str(args.output_dir / "audit-expired.png"), full_page=True)
                page.unroute(PATTERN, handler)
                current = reload()

            def injected(payload):
                return lambda route: route.fulfill(json=payload)

            for field, value in (
                ("snapshot_id", "f" * 64),
                ("snapshot_expires_at", "2099-01-01T00:00:00Z"),
                ("page_cursor", "bad cursor"),
                ("total_matches", 1),
                ("historical_audit_snapshot", False),
            ):
                payload = page.request.get(
                    base + "/audit/results",
                    headers=headers,
                    params={"limit": 12, "cursor": current["next_cursor"]},
                ).json()
                payload[field] = value
                handler = injected(payload)
                page.route(PATTERN, handler)
                page.locator("#nextPage").click()
                settled()
                expect(page.locator("#exportLogs")).to_be_disabled()
                check(
                    "malformed_or_changed_" + field + "_fails_closed",
                    "응답을 확인할 수 없습니다" in page.locator("#logSnapshot").inner_text(),
                )
                page.unroute(PATTERN, handler)
                current = reload()
            payload = page.request.get(
                base + "/audit/results",
                headers=headers,
                params={"limit": 12, "cursor": current["next_cursor"]},
            ).json()
            payload["items"][0]["tenant_id"] = "tenant-b"
            handler = injected(payload)
            page.route(PATTERN, handler)
            page.locator("#nextPage").click()
            settled()
            check(
                "mixed_tenant_page_is_not_displayed",
                "응답을 확인할 수 없습니다" in page.locator("#logSnapshot").inner_text()
                and "page-event-" not in page.locator("#logRows").inner_text(),
            )
            page.unroute(PATTERN, handler)
            current = reload()
            handler = injected(current)
            page.route(PATTERN, handler)
            page.locator("#nextPage").click()
            settled()
            check(
                "repeated_rows_cannot_masquerade_as_next_page",
                "응답을 확인할 수 없습니다" in page.locator("#logSnapshot").inner_text(),
            )
            page.unroute(PATTERN, handler)
            reload()

            # The same key may be remapped externally: even a cached-page export
            # has to verify the live principal, not just its in-memory key epoch.
            accounts = directory / "data" / "accounts.json"
            original = accounts.read_bytes()
            remapped = json.loads(original)
            remapped["accounts"][0]["subject"] = "replacement-reader"
            candidate = accounts.with_suffix(".candidate")
            candidate.write_text(json.dumps(remapped), encoding="utf-8")
            candidate.replace(accounts)
            before = len(downloads)
            page.locator("#exportLogs").click()
            settled()
            expect(page.locator("#logSnapshot")).to_contain_text("조회 신원이 변경")
            check(
                "same_key_identity_remap_blocks_cached_export",
                len(downloads) == before
                and "page-event-" not in page.locator("#logRows").inner_text(),
            )
            candidate.write_bytes(original)
            candidate.replace(accounts)
            reload()

            held = []

            def hold_page(route):
                held.append(route)

            page.route(PATTERN, hold_page)
            with page.expect_request(lambda req: req.url.startswith(base + "/audit/results?")):
                page.locator("#nextPage").click()
            intercepted(held)
            page.unroute(PATTERN, hold_page)
            connect("synthetic-foreign-key")
            settled()
            for route in held:
                try:
                    route.fulfill(json=current)
                except BrowserError:
                    pass  # An aborted former identity's fetch may already be gone.
            expect(page.locator("#logRows")).to_contain_text("audit-cancel-999")
            check(
                "connection_switch_discards_old_page_and_cursor",
                "page-event-" not in page.locator("#logRows").inner_text()
                and page.locator("#prevPage").is_disabled()
                and page.locator("#nextPage").is_disabled(),
            )
            check(
                "no_browser_credential_or_cursor_persistence",
                page.evaluate("localStorage.length === 0 && sessionStorage.length === 0")
                and "synthetic-foreign-key" not in page.content()
                and "synthetic-reviewer-a-key" not in page.content(),
            )
            check("no_javascript_errors", not errors)
            check("no_external_requests", not external)
            check(
                "all_page_requests_bounded",
                all(
                    parse_qs(urlparse(req.url).query).get("limit") == ["12"]
                    for req in audit_requests
                ),
            )
            browser.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        report["owned_server_stopped"] = process.poll() is not None
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable")
    parser.add_argument("--output-dir", type=Path, default=Path("runtime/dashboard-paging-browser"))
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sources = (
        "app/models.py",
        "app/services/audit_paging.py",
        "app/static/dashboard.js",
        "app/static/index.html",
        "tests/dashboard_operations_fixture.py",
        __file__,
    )
    report = {
        "schema": "dashboard-paging-browser-1",
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
        with tempfile.TemporaryDirectory(prefix="secops-paging-") as temp:
            run(args, Path(temp).resolve(), report)
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
