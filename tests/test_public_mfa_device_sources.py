from scripts.audit_public_mfa_device_sources import (
    complete_identity,
    count_links,
    entra_mfa_completed,
    instant,
    okta,
)


def test_entra_requires_a_completed_factor_instead_of_a_claim_or_pending_attempt():
    def evidence(method, detail, succeeded):
        return {
            "properties": {
                "authenticationDetails": [
                    {
                        "authenticationMethod": method,
                        "authenticationStepResultDetail": detail,
                        "succeeded": succeeded,
                    }
                ]
            }
        }

    assert entra_mfa_completed(
        evidence("Mobile app notification", "MFA successfully completed", True)
    )
    assert not entra_mfa_completed(
        evidence("Previously satisfied", "MFA requirement satisfied by claim in the token", True)
    )
    assert not entra_mfa_completed(
        evidence("Mobile app notification", "Authentication in progress", False)
    )


def test_enrollment_join_requires_the_same_scope_and_strictly_prior_time():
    key = ("tenant", "subject", "device")
    old = instant("2026-01-01T00:00:00Z")
    same = instant("2026-01-01T00:10:00Z")
    assert complete_identity("tenant", "subject", "") is None
    logins = [(key, same), (("tenant", "other", "device"), same), (None, same)]
    assert count_links(logins, [(key, same), (("other", "subject", "device"), old)]) == 0
    assert count_links(logins, [(key, old)]) == 1


def test_okta_fingerprint_or_factor_success_does_not_supply_device_or_session_evidence():
    report = okta(
        [
            {
                "eventType": "user.authentication.auth_via_mfa",
                "outcome": {"result": "SUCCESS"},
                "debugContext": {"debugData": {"deviceFingerprint": "observed-profile"}},
            }
        ]
    )
    assert report["mfa_factor_outcomes"] == {"SUCCESS": 1}
    assert report["mfa_outcomes_with_authoritative_device_id"] == 0
    assert report["session_start_rows"] == 0
