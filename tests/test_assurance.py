import json
from datetime import date
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.main import app
from app.models import ControlRecord
from app.services.assurance import get_assurance_registry

client = TestClient(app)


def test_control_registry_is_structurally_valid_and_evidence_files_exist() -> None:
    registry = get_assurance_registry()

    assert registry.validation_issues == []
    assert registry.validate_evidence_locations(Path(__file__).parents[1]) == []
    assert len(registry.controls) == 18


def test_implemented_control_requires_code_and_automated_test_evidence() -> None:
    payload = get_assurance_registry().get("ZT-02").model_dump(mode="json")
    payload["evidence"] = []

    with pytest.raises(ValidationError, match="automated test evidence"):
        ControlRecord.model_validate(payload)


def test_assurance_summary_is_reproducible_and_does_not_claim_full_compliance() -> None:
    registry = get_assurance_registry()
    summary = registry.summary(as_of=date(2026, 9, 16))

    assert summary.valid is True
    assert summary.total_controls == 18
    assert summary.status_counts == {
        "implemented": 9,
        "partially_implemented": 5,
        "planned": 4,
        "not_applicable": 0,
    }
    assert summary.implementation_rate == pytest.approx(0.6389)
    assert summary.evidence_count == 32
    assert summary.overdue_control_ids == []
    assert summary.registry_digest_sha256 == sha256(
        json.dumps(
            registry.payload.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        .encode("utf-8")
    ).hexdigest()


def test_assurance_summary_and_admin_control_api() -> None:
    summary = client.get("/assurance/summary")
    filtered = client.get(
        "/assurance/controls",
        params={"status": "implemented", "domain": "data_quality"},
    )
    detail = client.get("/assurance/controls/ai-02")

    assert summary.status_code == 200
    assert summary.json()["total_controls"] == 18
    assert filtered.status_code == 200
    assert [control["control_id"] for control in filtered.json()] == ["DATA-01"]
    assert detail.status_code == 200
    assert detail.json()["status"] == "implemented"


def test_control_evidence_details_require_admin_role(monkeypatch) -> None:
    api_key = "viewer-assurance-key"
    protected_settings = Settings(
        auth_mode="api_key",
        api_key_sha256=sha256(api_key.encode()).hexdigest(),
        api_key_roles="viewer",
        api_key_tenant_id="tenant-a",
    )
    monkeypatch.setattr("app.security.get_settings", lambda: protected_settings)

    summary = client.get("/assurance/summary", headers={"X-API-Key": api_key})
    details = client.get("/assurance/controls", headers={"X-API-Key": api_key})

    assert summary.status_code == 200
    assert details.status_code == 403


def test_readiness_includes_control_registry_integrity() -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assurance = response.json()["assurance"]
    assert assurance["valid"] is True
    assert assurance["total_controls"] == 18
    assert len(assurance["registry_digest_sha256"]) == 64
