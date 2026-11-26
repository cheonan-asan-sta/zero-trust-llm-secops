"""Server search on both real UIs with an old record outside recent100."""

import argparse
import json
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import expect, sync_playwright

from scripts.test_workbench_review_browser import server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    report = {"passed": False, "checks": [], "paid_calls": 0}

    def check(name, condition=True):
        report["checks"].append({"name": name, "passed": bool(condition)})
        assert condition, name

    try:
        with (
            tempfile.TemporaryDirectory(prefix="audit-search-") as temp,
            server(
                Path(temp) / "data",
                args.output_dir,
                report,
                caller_bound_reviews=True,
                audit_records=136,
            ) as base,
            sync_playwright() as pw,
        ):
            browser = pw.chromium.launch(
                **({"executable_path": args.browser_executable} if args.browser_executable else {})
            )
            try:
                for kind in ("workbench", "dashboard"):
                    page = browser.new_page(viewport={"width": 1440, "height": 1080})
                    errors = []
                    page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))
                    page.goto(base + ("/static/workbench.html" if kind == "workbench" else "/"))
                    if kind == "workbench":
                        page.locator("#workbenchCredentialType").select_option("api_key")
                        page.locator("#workbenchCredential").fill("synthetic-reviewer-a-key")
                        page.get_by_role("button", name="적용하고 조회", exact=True).click()
                        expect(page.locator("#historyBody")).to_have_attribute("aria-busy", "false")
                        query, analyzer, rows, next_button = (
                            "historySearch",
                            "historyAnalyzer",
                            "historyBody",
                            "historyNext",
                        )
                    else:
                        page.locator("#autoRefresh").uncheck()
                        page.locator("#connectionButton").click()
                        page.locator("#credentialType").select_option("api_key")
                        page.locator("#credential").fill("synthetic-reviewer-a-key")
                        page.get_by_role("button", name="적용하고 조회", exact=True).click()
                        expect(page.locator("#connectionDialog")).not_to_be_visible()
                        expect(page.locator("#refresh")).to_be_enabled()
                        page.locator('a[data-page="logs"]').click()
                        expect(page.locator("#logRows")).to_have_attribute("aria-busy", "false")
                        query, analyzer, rows, next_button = (
                            "auditQuery",
                            "auditAnalyzer",
                            "logRows",
                            "nextPage",
                        )

                    def search(
                        text,
                        engine="rule",
                        *,
                        page=page,
                        query=query,
                        analyzer=analyzer,
                        rows=rows,
                        next_button=next_button,
                    ):
                        page.locator("#" + query).fill(text)
                        page.locator("#" + analyzer).select_option(engine)
                        expect(page.locator("#" + next_button)).to_be_disabled()
                        with page.expect_response(
                            lambda r: "/audit/results?" in r.url and r.status == 200
                        ) as received:
                            page.get_by_role("button", name="전체 기록 검색", exact=True).click()
                        expect(page.locator("#" + rows)).to_have_attribute("aria-busy", "false")
                        return received.value.json()

                    found = search("page-event-001")
                    check(
                        kind + "_old_record_found_by_server",
                        found["total_matches"] == 1
                        and found["items"][0]["event_id"] == "page-event-001",
                    )
                    expect(page.locator("#" + rows)).to_contain_text("page-event-001")
                    empty = search("page-event-001", "openai")
                    check(kind + "_combined_analyzer_filter", empty["total_matches"] == 0)
                    first = search("page-event-")
                    check(kind + "_all_server_matches", first["total_matches"] == 136)
                    with page.expect_response(
                        lambda r: "/audit/results?" in r.url and r.status == 200
                    ) as received:
                        page.locator("#" + next_button).click()
                    second = received.value.json()
                    params = parse_qs(urlparse(received.value.url).query)
                    check(
                        kind + "_search_scope_retained_across_pages",
                        second["snapshot_id"] == first["snapshot_id"]
                        and params["q"] == ["page-event-"]
                        and params["analyzer"] == ["rule"],
                    )
                    page.locator("#" + query).fill("not-applied-yet")
                    check(
                        kind + "_edit_discards_old_page",
                        page.locator("#" + rows + " button").count() == 0
                        and page.locator("#" + next_button).is_disabled(),
                    )
                    found = search("page-event-001")
                    wrong = json.loads(json.dumps(found))
                    wrong["items"][0]["analyzer"] = "openai"
                    page.route(
                        "**/audit/results?*",
                        lambda route, _request=None, payload=wrong: route.fulfill(json=payload),
                    )
                    search("page-event-001")
                    check(
                        kind + "_wrong_analyzer_response_rejected",
                        page.locator("#" + rows + " button").count() == 0,
                    )
                    page.unroute("**/audit/results?*")
                    search("page-event-001")
                    for width, height, label in ((1440, 1080, "desktop"), (390, 844, "mobile")):
                        page.set_viewport_size({"width": width, "height": height})
                        page.locator("#" + query).scroll_into_view_if_needed()
                        check(
                            kind + "_no_page_overflow_" + label,
                            page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                        )
                        page.screenshot(path=str(args.output_dir / (kind + "-" + label + ".png")))
                    check(kind + "_no_javascript_errors", not errors)
                    page.close()
            finally:
                browser.close()
        report["passed"] = True
    finally:
        (args.output_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"passed": report["passed"], "checks": len(report["checks"])}))


if __name__ == "__main__":
    main()
