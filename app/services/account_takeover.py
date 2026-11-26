"""Keep repeated failures and corroborated account takeover evidence distinct."""

from dataclasses import dataclass
from enum import StrEnum

from app.models import VerifiedLoginDetection


class Factor(StrEnum):
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    REJECTED_REQUIRED_FACTOR = "rejected_required_factor"


class Device(StrEnum):
    UNKNOWN = "unknown"
    KNOWN = "known"
    NEW = "new_verified_device"
    REVOKED = "revoked_verified_device"


class Takeover(StrEnum):
    NO_SIGNAL = "no_signal"
    REVIEW = "review"
    PRIORITY_REVIEW = "priority_review"


@dataclass(frozen=True, slots=True)
class LoginTriage:
    repeated_failure_warning: bool
    takeover: Takeover


def assess_login(
    *, warning, success, environment_change, factor=Factor.UNKNOWN, device=Device.UNKNOWN
):
    """Accept factor and device facts already bound to the same login by a trusted source."""
    if success is not True or not environment_change:
        return LoginTriage(warning, Takeover.NO_SIGNAL)
    if (
        factor is Factor.REJECTED_REQUIRED_FACTOR
        or device is Device.NEW
        or (factor is Factor.VERIFIED and device is Device.REVOKED)
    ):
        return LoginTriage(warning, Takeover.PRIORITY_REVIEW)
    return LoginTriage(warning, Takeover.REVIEW)


def detect_verified_login(event, proof, source_digest):
    decision = assess_login(
        warning=event.auth_context.failed_attempts >= 3,
        success=True,
        environment_change=event.network.location_anomaly,
        factor=Factor.VERIFIED,
        device=Device(proof.device_state),
    )
    return VerifiedLoginDetection(
        disposition=decision.takeover.value,
        device_state=proof.device_state,
        source_id=proof.source_id,
        source_digest_sha256=source_digest,
        observed_at=proof.issued_at,
    )
