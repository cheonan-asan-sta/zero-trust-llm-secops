"""Navigation metadata must describe actual guarded HTTP contracts."""

from test_audit_query_admission import api as api  # noqa: PLC0414

from app import main
from app.dashboard_catalog import catalog


def test_native_analysis_and_audit_pages_are_discoverable_without_granting_permissions(api):
    entries = {(item["path"], item["method"]): item for item in catalog(main.app)["operations"]}
    native = entries["/analysis/native-service", "POST"]
    assert native["role"] == "analyst"
    page = entries["/audit/results", "GET"]
    assert page["role"] == "viewer"
    assert {item["name"] for item in page["parameters"]} >= {
        "limit",
        "cursor",
        "review_status",
        "risk_level",
    }
    main.settings.api_key_roles = "viewer"
    denied = api.client.post(
        "/analysis/native-service",
        headers=api.headers,
        json={"execution_ref": "0" * 64},
    )
    assert denied.status_code == 403
    viewed = api.client.get("/audit/results?limit=1", headers=api.headers)
    assert viewed.status_code == 200 and len(viewed.json()["items"]) == 1
    assert all(item["tenant_id"] == "local" for item in viewed.json()["items"])


def test_assurance_catalog_roles_match_actual_admin_http_dependencies(api):
    entries = {item["path"]: item for item in catalog(main.app)["operations"]}
    assert entries["/assurance/controls"]["role"] == "admin"
    assert entries["/assurance/controls/{control_id}"]["role"] == "admin"
    control_id = main.assurance_registry.controls[0].control_id
    urls = ["/assurance/controls", "/assurance/controls/" + control_id]
    main.settings.api_key_roles = "viewer"
    assert all(api.client.get(url, headers=api.headers).status_code == 403 for url in urls)
    main.settings.api_key_roles = "admin"
    assert all(api.client.get(url, headers=api.headers).status_code == 200 for url in urls)
