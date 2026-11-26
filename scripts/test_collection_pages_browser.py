"""Real UI live-collection pages backed by signed sessions and local case chains."""

import argparse
import json
import tempfile
import time
from pathlib import Path

from playwright.sync_api import Error as BrowserError
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
            tempfile.TemporaryDirectory(prefix="collection-pages-ui-") as temp,
            server(
                Path(temp) / "data",
                args.output_dir,
                report,
                caller_bound_reviews=True,
                collection_records=True,
            ) as base,
            sync_playwright() as pw,
        ):
            browser = pw.chromium.launch(
                **({"executable_path": args.browser_executable} if args.browser_executable else {})
            )
            try:
                for name, route, prefix, body, total, id_field in [
                    ("cases", "/case-pages", "casePages", "caseBody", 27, "case_id"),
                    (
                        "dashboard_cases",
                        "/case-pages",
                        "caseDashboardPages",
                        "caseRows",
                        27,
                        "case_id",
                    ),
                    (
                        "signed",
                        "/zero-trust/session-pages",
                        "signedPages",
                        "ztSignedSessions",
                        103,
                        "session_id",
                    ),
                    (
                        "dashboard",
                        "/zero-trust/session-pages",
                        "sessionPages",
                        "sessionRows",
                        103,
                        "session_id",
                    ),
                ]:
                    page = browser.new_page(viewport={"width": 1440, "height": 1080})
                    errors, external, requests = [], [], []
                    page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))

                    def requested(req, external=external, requests=requests, route=route):
                        if not req.url.startswith(base + "/"):
                            external.append(req.url)
                        if req.url.startswith(base + route + "?"):
                            requests.append(req.url)

                    page.on("request", requested)
                    active_subject = {"value": "reviewer-a"}
                    page.goto(
                        base + ("/" if name.startswith("dashboard") else "/static/workbench.html")
                    )

                    def connect(
                        subject="reviewer-a", *, page=page, name=name, subject_ref=active_subject
                    ):
                        subject_ref["value"] = subject
                        if name.startswith("dashboard"):
                            page.locator("#autoRefresh").uncheck()
                            page.locator("#connectionButton").click()
                            page.locator("#credentialType").select_option("api_key")
                            page.locator("#credential").fill("synthetic-" + subject + "-key")
                            page.get_by_role("button", name="적용하고 조회", exact=True).click()
                            expect(page.locator("#connectionDialog")).not_to_be_visible()
                            expect(page.locator("#refresh")).to_be_enabled()
                            page.locator(
                                'a[data-page="cases"]'
                                if name == "dashboard_cases"
                                else 'a[data-page="sessions"]'
                            ).click()
                        else:
                            page.locator("#workbenchCredentialType").select_option("api_key")
                            page.locator("#workbenchCredential").fill(
                                "synthetic-" + subject + "-key"
                            )
                            page.get_by_role("button", name="적용하고 조회", exact=True).click()
                            expect(page.locator("#workbenchIdentity")).to_contain_text(subject)

                    connect()

                    def read(
                        action, *, page=page, route=route, body=body, subject_ref=active_subject
                    ):
                        expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                        with page.expect_response(
                            lambda r: (
                                r.url.startswith(base + route + "?")
                                and r.status == 200
                                and r.request.headers.get("x-api-key")
                                == "synthetic-" + subject_ref["value"] + "-key"
                            )
                        ) as received:
                            action()
                        expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                        return received.value.json()

                    first = read(
                        lambda page=page, prefix=prefix: page.locator(
                            "#" + prefix + "Reload"
                        ).click()
                    )
                    check(
                        name + "_full_collection_total",
                        first["total_matches"] == total
                        and first["snapshot_mode"] == "unchanged_live_view",
                    )
                    seen = []
                    current = first
                    while True:
                        dom_ids = page.locator("#" + body + " tr[data-collection-id]").evaluate_all(
                            "rows => rows.map(row => row.dataset.collectionId)"
                        )
                        check(
                            name + "_page_dom_matches_api_" + str(len(seen)),
                            dom_ids == [row[id_field] for row in current["items"]],
                        )
                        seen.extend(dom_ids)
                        if not current["next_cursor"]:
                            break
                        current = read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Next"
                            ).click()
                        )
                        assert current["snapshot_id"] == first["snapshot_id"]
                    check(
                        name + "_all_ids_visited_without_duplicates",
                        len(seen) == len(set(seen)) == total,
                    )
                    check(
                        name + "_last_next_disabled",
                        page.locator("#" + prefix + "Next").is_disabled(),
                    )
                    current = read(
                        lambda page=page, prefix=prefix: page.locator(
                            "#" + prefix + "Previous"
                        ).click()
                    )
                    check(
                        name + "_previous_page_works",
                        current["snapshot_id"] == first["snapshot_id"],
                    )
                    current = read(
                        lambda page=page, prefix=prefix: page.locator(
                            "#" + prefix + "Reload"
                        ).click()
                    )
                    pattern = "**" + route + "?*"
                    admin = {"X-API-Key": "synthetic-requester-key"}
                    if route == "/case-pages":
                        selected = current["items"][0]
                        target = "TRIAGED" if selected["status"] == "NEW" else "INVESTIGATING"
                        changed = page.request.patch(
                            base + "/cases/" + selected["case_id"],
                            headers=admin,
                            data={
                                "status": target,
                                "expected_version": selected["version"],
                                "note": "Local live collection change fixture",
                            },
                        )
                    else:
                        selected = next(
                            row for row in current["items"] if row["status"] != "REVOKED"
                        )
                        changed = page.request.post(
                            base + "/zero-trust/sessions/" + selected["session_id"] + "/revoke",
                            headers=admin,
                            data={
                                "expected_version": selected["version"],
                                "note": "Local live collection revoke fixture",
                            },
                        )
                    assert changed.ok
                    with page.expect_response(
                        lambda r, route=route: (
                            r.url.startswith(base + route + "?") and r.status == 409
                        )
                    ):
                        page.locator("#" + prefix + "Next").click()
                    expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                    check(
                        name + "_actual_change_refuses_stale_view",
                        page.locator("#" + body + " tr[data-collection-id]").count() == 0
                        and "변경" in page.locator("#" + prefix + "Status").inner_text(),
                    )
                    current = read(
                        lambda page=page, prefix=prefix: page.locator(
                            "#" + prefix + "Reload"
                        ).click()
                    )
                    for status in (400, 409, 410, 501, 503):

                        def fail(route_obj, _request=None, status=status):
                            route_obj.fulfill(
                                status=status, json={"detail": "synthetic collection failure"}
                            )

                        page.route(pattern, fail)
                        before = len(requests)
                        page.locator("#" + prefix + "Next").click()
                        expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                        check(
                            name + "_http_" + str(status) + "_clears_without_retry",
                            len(requests) == before + 1
                            and page.locator("#" + body + " tr[data-collection-id]").count() == 0
                            and page.locator("#" + prefix + "Next").is_disabled(),
                        )
                        page.unroute(pattern, fail)
                        current = read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Reload"
                            ).click()
                        )
                    for field, value in (
                        ("snapshot_id", "f" * 64),
                        ("snapshot_mode", "sqlite_prefix"),
                        ("historical_audit_snapshot", True),
                        ("page_cursor", "bad cursor"),
                    ):
                        params = {"limit": 12, "cursor": current["next_cursor"]}
                        if name == "signed":
                            params["signal_trust"] = "verified_source"
                        payload = page.request.get(
                            base + route,
                            headers={"X-API-Key": "synthetic-reviewer-a-key"},
                            params=params,
                        ).json()
                        payload[field] = value

                        def inject(route_obj, _request=None, payload=payload):
                            route_obj.fulfill(json=payload)

                        page.route(pattern, inject)
                        page.locator("#" + prefix + "Next").click()
                        expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                        check(
                            name + "_invalid_" + field + "_discarded",
                            page.locator("#" + body + " tr[data-collection-id]").count() == 0,
                        )
                        page.unroute(pattern, inject)
                        current = read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Reload"
                            ).click()
                        )
                    for width, height, size in ((1440, 1080, "desktop"), (390, 844, "mobile")):
                        page.set_viewport_size({"width": width, "height": height})
                        page.locator("#" + prefix + "Reload").scroll_into_view_if_needed()
                        check(
                            name + "_no_overflow_" + size,
                            page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
                        )
                        page.locator("#" + body).locator("xpath=../../..").screenshot(
                            path=str(args.output_dir / (name + "-" + size + ".png"))
                        )
                    page.set_viewport_size({"width": 1440, "height": 1080})
                    for status in (401, 403):

                        def withdrawn(route_obj, _request=None, status=status):
                            route_obj.fulfill(status=status, json={"detail": "caller withdrawn"})

                        page.route(pattern, withdrawn)
                        page.locator("#" + prefix + "Next").click()
                        expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                        check(
                            name + "_http_" + str(status) + "_requires_new_connection",
                            page.locator("#" + body + " tr[data-collection-id]").count() == 0,
                        )
                        page.unroute(pattern, withdrawn)
                        connect()
                        current = read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Reload"
                            ).click()
                        )
                    registry = Path(temp) / "data/accounts.json"
                    original_registry = registry.read_bytes()
                    accounts = json.loads(original_registry)
                    accounts["accounts"][0]["subject"] = "remapped-collection-caller"
                    registry.write_text(json.dumps(accounts), encoding="utf-8")
                    before = len(requests)
                    page.locator("#" + prefix + "Next").click()
                    expect(page.locator("#" + body)).to_have_attribute("aria-busy", "false")
                    check(
                        name + "_same_key_remap_rejected_before_page_request",
                        len(requests) == before
                        and page.locator("#" + body + " tr[data-collection-id]").count() == 0,
                    )
                    registry.write_bytes(original_registry)
                    connect()
                    current = read(
                        lambda page=page, prefix=prefix: page.locator(
                            "#" + prefix + "Reload"
                        ).click()
                    )
                    held = []
                    page.route(
                        pattern, lambda route_obj, _request=None, held=held: held.append(route_obj)
                    )
                    page.locator("#" + prefix + "Next").click()
                    deadline = time.monotonic() + 4
                    while not held:
                        assert time.monotonic() < deadline
                        page.wait_for_timeout(10)
                    page.unroute(pattern)
                    connect("foreign")
                    if name == "signed":
                        foreign = read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Reload"
                            ).click()
                        )
                        assert foreign["total_matches"] == 0
                    else:
                        read(
                            lambda page=page, prefix=prefix: page.locator(
                                "#" + prefix + "Reload"
                            ).click()
                        )
                    for held_route in held:
                        try:
                            held_route.fulfill(json=current)
                        except BrowserError:
                            pass
                    check(
                        name + "_old_tenant_response_cannot_return",
                        not set(
                            page.locator("#" + body + " tr[data-collection-id]").evaluate_all(
                                "rows => rows.map(r => r.dataset.collectionId)"
                            )
                        )
                        & set(seen),
                    )
                    check(name + "_no_javascript_errors", not errors)
                    check(name + "_no_external_requests", not external)
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
