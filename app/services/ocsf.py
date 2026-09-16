import json
from functools import lru_cache
from hashlib import sha256

from app.models import (
    OCSFAPI,
    EventAction,
    NormalizationProvenance,
    NormalizedSecurityEvent,
    OCSFActor,
    OCSFDevice,
    OCSFEndpoint,
    OCSFEvent,
    OCSFFingerprint,
    OCSFMetadata,
    OCSFProduct,
    OCSFResource,
    OCSFService,
    OCSFUser,
    SecurityEvent,
)

OCSF_SCHEMA_VERSION = "1.9.0"
TRANSFORMER_VERSION = "0.14.0"

_MAPPING_SPEC = {
    "schema": f"OCSF {OCSF_SCHEMA_VERSION}",
    "authentication": {
        "actions": [EventAction.LOGIN.value],
        "category_uid": 3,
        "class_uid": 3002,
        "activity": {EventAction.LOGIN.value: 1},
        "status_source": "auth_context.authentication_result",
    },
    "api_activity": {
        "actions": [
            EventAction.READ.value,
            EventAction.DOWNLOAD.value,
            EventAction.ADMIN.value,
            EventAction.REMOTE_ACCESS.value,
        ],
        "category_uid": 6,
        "class_uid": 6003,
        "activity": {
            EventAction.READ.value: 2,
            EventAction.DOWNLOAD.value: 2,
            EventAction.ADMIN.value: 3,
            EventAction.REMOTE_ACCESS.value: 99,
        },
    },
    "unmapped_fields": [
        "auth",
        "behavior",
        "device",
        "network",
        "resource",
        "source_action",
        "user",
    ],
}


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


MAPPING_DIGEST_SHA256 = sha256(_canonical_json(_MAPPING_SPEC)).hexdigest()


class OCSFNormalizer:
    schema_version = OCSF_SCHEMA_VERSION
    transformer_version = TRANSFORMER_VERSION
    mapping_digest_sha256 = MAPPING_DIGEST_SHA256

    def normalize(self, source: SecurityEvent) -> NormalizedSecurityEvent:
        source_payload = source.analysis_payload()
        source_digest = sha256(_canonical_json(source_payload)).hexdigest()
        user = OCSFUser(uid=source.user.user_id, role=source.user.role)
        service = OCSFService(name="Zero Trust Access Gateway")

        if source.action == EventAction.LOGIN:
            category_uid = 3
            category_name = "Identity & Access Management"
            class_uid = 3002
            class_name = "Authentication"
            activity_id = 1
            activity_name = "Logon"
            api = None
            authentication_user = user
            authentication_service = service
        else:
            category_uid = 6
            category_name = "Application Activity"
            class_uid = 6003
            class_name = "API Activity"
            activity_id, activity_name = {
                EventAction.READ: (2, "Read"),
                EventAction.DOWNLOAD: (2, "Read"),
                EventAction.ADMIN: (3, "Update"),
                EventAction.REMOTE_ACCESS: (99, "Remote Access"),
            }[source.action]
            api = OCSFAPI(operation=source.action.value, service=service)
            authentication_user = None
            authentication_service = None

        authentication_failed = (
            source.auth_context.authentication_result == "failure"
            or source.auth_context.mfa == "failed"
        )
        status_id = 2 if authentication_failed else 1
        status = "Failure" if status_id == 2 else "Success"
        event = OCSFEvent(
            time=int(source.timestamp.timestamp() * 1000),
            category_uid=category_uid,
            category_name=category_name,
            class_uid=class_uid,
            class_name=class_name,
            activity_id=activity_id,
            activity_name=activity_name,
            type_uid=class_uid * 100 + activity_id,
            type_name=f"{class_name}: {activity_name}",
            severity_id=1,
            status_id=status_id,
            status=status,
            message=(
                f"User {source.user.user_id} requested {source.action.value} on "
                f"{source.resource.resource_id}."
            ),
            metadata=OCSFMetadata(
                uid=source.event_id,
                correlation_uid=source.event_id,
                original_time=source.timestamp.isoformat(),
                product=OCSFProduct(
                    name="Zero Trust LLM SecOps",
                    vendor_name="Cheonan-Asan Team",
                    version=TRANSFORMER_VERSION,
                ),
            ),
            actor=OCSFActor(user=user),
            user=authentication_user,
            src_endpoint=OCSFEndpoint(
                ip=source.network.ip,
                location=source.network.location,
            ),
            device=OCSFDevice(
                uid=source.device.device_id,
                name=source.device.device_id,
            ),
            resources=[
                OCSFResource(
                    uid=source.resource.resource_id,
                    type=source.resource.resource_type,
                )
            ],
            api=api,
            service=authentication_service,
            is_mfa=source.auth_context.mfa in {"success", "failed"},
            is_remote=source.network.access_method in {"remote", "vpn"},
            raw_data_hash=OCSFFingerprint(value=source_digest),
            unmapped={
                "source_action": source.action.value,
                "user": {
                    "active": source.user.active,
                    "department": source.user.department,
                },
                "auth": source.auth_context.model_dump(mode="json"),
                "behavior": source.behavior.model_dump(mode="json"),
                "device": {
                    "managed": source.device.managed,
                    "security_posture": source.device.security_posture,
                },
                "network": {
                    "access_method": source.network.access_method,
                    "location_anomaly": source.network.location_anomaly,
                },
                "resource": {
                    "sensitivity": source.resource.sensitivity,
                    "required_role": source.resource.required_role,
                },
            },
        )
        return NormalizedSecurityEvent(
            event=event,
            provenance=NormalizationProvenance(
                source_format="zero-trust-security-event-v1",
                source_event_id=source.event_id,
                source_sha256=source_digest,
                target_schema="OCSF",
                schema_version=OCSF_SCHEMA_VERSION,
                transformer_name="zero-trust-ocsf-mapper",
                transformer_version=TRANSFORMER_VERSION,
                mapping_digest_sha256=MAPPING_DIGEST_SHA256,
            ),
        )


@lru_cache
def get_ocsf_normalizer() -> OCSFNormalizer:
    return OCSFNormalizer()
