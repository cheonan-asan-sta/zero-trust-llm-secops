import json
from types import SimpleNamespace

from app.analyzers.structured_response import ResponseDiagnostics
from app.models import SecurityAssessment
from scripts import smoke_verified_session_api as smoke


def test_oidc_smoke_uses_real_jwks_and_preserves_audit_without_saving_bearer(tmp_path, monkeypatch):
    monkeypatch.setattr(
        smoke, "dotenv_values", lambda _: {"OPENAI_API_KEY": "local-test-placeholder"}
    )

    async def fake(client, **kwargs):
        catalog = json.loads(kwargs["input"][1]["content"])["evidence_catalog"]
        required = catalog["verified_session.policy.mfa_required"]
        assessment = SecurityAssessment(
            risk_score=35 if required else 0,
            risk_level="MEDIUM" if required else "LOW",
            violation_type="ACCESS_POLICY_VIOLATION" if required else "NORMAL",
            rationale="로컬 경로 시험",
            evidence=["verified_session.policy.mfa_required"],
            recommended_action="HOLD_FOR_REVIEW",
            confidence=0.8,
            requires_human_review=True,
        )
        return SimpleNamespace(output_parsed=assessment, model="local-test"), ResponseDiagnostics(
            "completed",
            input_tokens=100,
            output_tokens=100,
        )

    monkeypatch.setattr(smoke, "parse_structured_response", fake)
    report = smoke.run(tmp_path / "smoke", "unused", use_oidc=True)
    assert report["completed"] and report["attempts"] == 2
    assert report["real_loopback_jwks_fetches"] >= 1
    assert report["local_principal_injected"] is False
    assert report["bearer_token_persisted"] is False
    assert report["enterprise_identity_verified"] is False
    for row in report["rows"]:
        assert row["response"]["verification_context"]["caller"]["authentication_method"] == "oidc"
    for path in (tmp_path / "smoke").rglob("*.json*"):
        assert "Bearer " not in path.read_text(encoding="utf-8")
