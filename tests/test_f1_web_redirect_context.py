from datetime import timedelta

import pytest

from scripts.f1_lab.web_context_controls import NOW, OPERATOR, WebControls, sign
from scripts.f1_lab.web_verified_context import (
    RedirectBundle,
    RedirectRequest,
    ServerProof,
    digest_raw,
)


@pytest.fixture
def context(tmp_path):
    controls = WebControls(tmp_path / "controls")
    policy = controls.registry["resources"][0]
    policy["redirect_location_sha256"] = digest_raw("/account")
    controls.repin()
    redirect = RedirectRequest(
        tenant_id="web-lab", server_id="web-server", request_id="redirect-1", case_id="a" * 64,
        subject_id="web-user", session_id="web-session", session_version=0, resource_id="uploaded-script",
        method="GET", target_sha256=digest_raw("/continue"), body_sha256=digest_raw(""),
        raw_line_sha256=digest_raw("server log projection"), observed_at=NOW, status=303,
        location_sha256=policy["redirect_location_sha256"],
    )
    return controls, policy, redirect


def bundle(controls, challenge, policy, *, action="redirect", mfa="success", decision="allow"):
    observations = (
        {"kind": "authentication", "result": "success", "mfa": mfa},
        {"kind": "authorization", "decision": decision, "action": action,
         "policy_sha256": policy["authorization_policy_sha256"], "policy_version": 1},
    )
    proofs = []
    for observation in observations:
        role = observation["kind"]
        proof = ServerProof(schema_version="zt-web-server-proof-1", tenant_id="web-lab", source_id=role,
                            key_id="key-1", request_sha256=challenge.sha256, observed_at=NOW, issued_at=NOW,
                            expires_at=NOW + timedelta(seconds=30), observation=observation, signature="A" * 86)
        proofs.append(sign(proof, controls.keys[role]))
    return RedirectBundle(proofs=proofs)


@pytest.mark.parametrize(("mfa", "decision", "wanted"), [
    ("success", "allow", "consistent"),
    ("not_used", "allow", "review"),
    ("failure", "allow", "adverse"),
    ("success", "deny", "adverse"),
])
def test_redirect_auth_and_policy_stay_bound_to_one_response(context, mfa, decision, wanted):
    controls, policy, redirect = context
    challenge = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    facts = bundle(controls, challenge, policy, mfa=mfa, decision=decision)
    result = controls.bridge.check_redirect(challenge.nonce, facts, redirect, OPERATOR, now=NOW)
    assert result.state == wanted
    assert len(result.evidence_sha256) == 64
    assert controls.bridge.check_redirect(challenge.nonce, facts, redirect, OPERATOR, now=NOW).state == "unavailable"


@pytest.mark.parametrize("changes", [
    {"request_id": "other"}, {"session_version": 1}, {"body_sha256": "b" * 64},
    {"status": 307}, {"location_sha256": "b" * 64},
])
def test_redirect_proofs_do_not_transfer_to_different_response(context, changes):
    controls, policy, redirect = context
    old = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    facts = bundle(controls, old, policy)
    other = redirect.model_copy(update=changes)
    assert controls.bridge.check_redirect(old.nonce, facts, other, OPERATOR, now=NOW).state == "unavailable"
    new = controls.bridge.issue(other, OPERATOR, now=NOW)
    assert controls.bridge.check_redirect(new.nonce, facts, other, OPERATOR, now=NOW).state == "unavailable"


def test_valid_signature_still_requires_redirect_scope_and_pinned_destination(context):
    controls, policy, redirect = context
    challenge = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    execution = bundle(controls, challenge, policy, action="execute_uploaded_script")
    assert controls.bridge.check_redirect(challenge.nonce, execution, redirect, OPERATOR, now=NOW).state == "unavailable"
    redirect = redirect.model_copy(update={"location_sha256": "b" * 64})
    challenge = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    facts = bundle(controls, challenge, policy)
    assert controls.bridge.check_redirect(challenge.nonce, facts, redirect, OPERATOR, now=NOW).state == "unavailable"



def test_missing_proof_or_expired_challenge_leaves_context_unavailable(context):
    controls, policy, redirect = context
    challenge = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    facts = bundle(controls, challenge, policy)
    missing = facts.model_copy(update={"proofs": facts.proofs[:1]})
    assert controls.bridge.check_redirect(challenge.nonce, missing, redirect, OPERATOR, now=NOW).state == "unavailable"

    challenge = controls.bridge.issue(redirect, OPERATOR, now=NOW)
    facts = bundle(controls, challenge, policy)
    late = NOW + timedelta(seconds=30)
    assert controls.bridge.check_redirect(challenge.nonce, facts, redirect, OPERATOR, now=late).state == "unavailable"
