"""Freeze authored operational labels before evaluation; never imports a detector."""

import copy
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.models import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "app/data/benchmark"
RULES = {
    "credential": "8a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d",
    "device": "9b2c3d4e-5f60-4b7c-9d8e-9f0a1b2c3d4e",
    "privilege": "ac3d4e5f-6071-4c8d-ae9f-0a1b2c3d4e5f",
    "lateral": "bd4e5f60-7182-4d9e-bf0a-1b2c3d4e5f60",
    "exfiltration": "ce5f6071-8293-4eaf-801b-2c3d4e5f6071",
    "remote": "d1e2f3a4-b5c6-4d7e-8f90-a1b2c3d4e5f6",
}


def families():
    result = []

    def add(domain, split, threat, name, rationale, patch, *, vary=None, approval=False, rules=None):
        result.append({
            "family_id": f"{domain}-{name}", "domain": domain, "split": split,
            "threat": threat, "rationale": rationale, "patch": patch,
            "variations": vary or {}, "approval": approval,
            "expected_rule_ids": sorted(RULES[key] for key in (rules or [domain])) if threat else [],
        })

    add("credential", "development", True, "geo-burst", "Unauthorized password guesses from an anomalous location.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "network.location_anomaly": True},
        vary={"auth_context.failed_attempts": [3, 4, 5]})
    add("credential", "development", True, "local-burst", "Unauthorized automated guesses from a familiar address.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.request_rate": "high"},
        vary={"auth_context.failed_attempts": [6, 7, 8]})
    add("credential", "development", True, "mfa-fatigue", "Repeated rejected MFA prompts during account takeover.",
        {"action": "LOGIN", "auth_context.mfa": "failed", "behavior.request_rate": "high"},
        vary={"auth_context.failed_attempts": [9, 10, 11]})
    add("credential", "development", False, "typing-errors", "Legitimate user makes one or two typing errors without anomalous activity.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.request_rate": "normal"},
        vary={"auth_context.failed_attempts": [1, 2]})
    add("credential", "development", False, "travel-success", "Authorized traveler completes MFA despite a location change.",
        {"action": "LOGIN", "network.location_anomaly": True})
    add("credential", "development", False, "approved-health-retry", "Approved service-health retry burst; an alert here is operational noise.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.request_rate": "high"},
        vary={"auth_context.failed_attempts": [3, 4, 5]}, approval=True)
    add("credential", "holdout", True, "distributed-slow", "Distributed attacker stays below the per-source failure threshold.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.unusual_time": True},
        vary={"auth_context.failed_attempts": [1, 2]})
    add("credential", "holdout", True, "credential-stuffing", "High-volume credential stuffing against an account.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.request_rate": "high"},
        vary={"auth_context.failed_attempts": [12, 15, 17]})
    add("credential", "holdout", True, "stolen-success", "Stolen password succeeds without verified MFA; the missing signal is not proof of safety.",
        {"action": "LOGIN", "auth_context.mfa": "unknown", "network.location_anomaly": True})
    add("credential", "holdout", False, "vpn-mfa", "Authorized VPN authentication succeeds with MFA.",
        {"action": "LOGIN", "network.access_method": "vpn"})
    add("credential", "holdout", False, "authorized-drill", "Explicitly approved authentication load drill generates failures.",
        {"action": "LOGIN", "auth_context.authentication_result": "failure", "behavior.request_rate": "high"},
        vary={"auth_context.failed_attempts": [18, 20, 22]}, approval=True)
    add("credential", "holdout", False, "recovered-success", "User succeeds after prior failures; historical attempts alone do not mean an active attack.",
        {"action": "LOGIN"}, vary={"auth_context.failed_attempts": [4, 5, 6]})

    add("device", "development", True, "unregistered-document", "Unapproved new unmanaged endpoint requests internal data.",
        {"device.managed": False, "device.security_posture": "unknown", "behavior.new_device": True})
    add("device", "development", True, "unregistered-admin", "Unapproved new unmanaged endpoint invokes an otherwise role-matched admin operation.",
        {"action": "ADMIN", "device.managed": False, "device.security_posture": "unknown", "behavior.new_device": True})
    add("device", "development", True, "unregistered-login", "Unapproved new unmanaged endpoint attempts authentication.",
        {"action": "LOGIN", "device.managed": False, "device.security_posture": "unknown", "behavior.new_device": True})
    add("device", "development", False, "managed-document", "Healthy managed endpoint reads an authorized internal document.", {})
    add("device", "development", False, "registered-byod", "Known healthy BYOD device is permitted for this resource.",
        {"device.managed": False})
    add("device", "development", False, "approved-enrollment", "A scoped enrollment window explicitly permits this new BYOD endpoint.",
        {"device.managed": False, "device.security_posture": "unknown", "behavior.new_device": True}, approval=True)
    add("device", "holdout", True, "managed-compromise", "A previously managed endpoint is now compromised.",
        {"device.security_posture": "compromised"})
    add("device", "holdout", True, "unmanaged-at-risk", "An unapproved unmanaged endpoint has known adverse posture rather than unknown posture.",
        {"device.managed": False, "device.security_posture": "at_risk", "behavior.new_device": True})
    add("device", "holdout", True, "unregistered-download", "Unapproved new unmanaged endpoint requests a download.",
        {"action": "DOWNLOAD", "device.managed": False, "device.security_posture": "unknown", "behavior.new_device": True})
    add("device", "holdout", False, "inventory-refresh", "Managed enrollment is approved while inventory posture is being refreshed.",
        {"device.security_posture": "unknown", "behavior.new_device": True}, approval=True)
    add("device", "holdout", False, "healthy-byod-enrollment", "Approved healthy new BYOD device accesses a limited resource.",
        {"device.managed": False, "behavior.new_device": True}, approval=True)
    add("device", "holdout", False, "managed-local-logon", "Healthy managed local logon with a verified device identity.",
        {"action": "LOGIN", "behavior.new_device": True})

    add("privilege", "development", True, "employee-admin", "Employee attempts an admin-only operation.",
        {"action": "ADMIN", "resource.required_role": "administrator"})
    add("privilege", "development", True, "analyst-backup-admin", "Analyst attempts a backup-operator-only administration operation.",
        {"action": "ADMIN", "user.role": "analyst", "resource.required_role": "backup-operator"})
    add("privilege", "development", True, "guest-operator", "Guest attempts operator administration.",
        {"action": "ADMIN", "user.role": "guest", "resource.required_role": "operator"})
    add("privilege", "development", False, "administrator", "Administrator performs role-matched administration.",
        {"action": "ADMIN", "user.role": "administrator", "resource.required_role": "administrator"})
    add("privilege", "development", False, "employee-read", "Employee reads public data within their role.",
        {"resource.sensitivity": "public"})
    add("privilege", "development", False, "approved-emergency", "Approved short-lived emergency role activation permits the operation.",
        {"action": "ADMIN", "resource.required_role": "administrator"}, approval=True)
    add("privilege", "holdout", True, "security-admin", "Employee attempts a security-admin-only configuration change.",
        {"action": "ADMIN", "resource.required_role": "security-admin"})
    add("privilege", "holdout", True, "unauthorized-download", "Employee reads data reserved for administrators through a download operation.",
        {"action": "DOWNLOAD", "resource.required_role": "administrator", "behavior.download_volume_mb": 10})
    add("privilege", "holdout", True, "missing-resource-role", "External resource policy denies this admin action but its required role is missing from the log.",
        {"action": "ADMIN", "resource.required_role": None})
    add("privilege", "holdout", False, "analyst-admin", "Analyst performs an explicitly role-matched administration operation.",
        {"action": "ADMIN", "user.role": "analyst", "resource.required_role": "analyst"})
    add("privilege", "holdout", False, "backup-admin", "Backup operator manages its own authorized backup resource.",
        {"action": "ADMIN", "user.role": "backup-operator", "resource.required_role": "backup-operator"})
    add("privilege", "holdout", False, "viewer-read", "Viewer performs an authorized document read.",
        {"user.role": "viewer", "resource.required_role": "viewer"})

    add("remote", "development", True, "unapproved-rdp", "Unauthorized remote desktop connection is established.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote"})
    add("remote", "development", True, "vpn-fanout", "Unauthorized VPN remote session rapidly accesses many resources.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "behavior.request_rate": "high"},
        vary={"behavior.distinct_resources_10m": [8, 9, 10]}, rules=["remote", "lateral"])
    add("remote", "development", True, "unverified-mfa", "Unauthorized remote session lacks verified MFA.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "auth_context.mfa": "unknown"})
    add("remote", "development", False, "vpn-read", "Approved VPN user reads a role-matched document.",
        {"network.access_method": "vpn"})
    add("remote", "development", False, "remote-login", "Authorized remote user completes a normal authentication event.",
        {"action": "LOGIN", "network.access_method": "remote"})
    add("remote", "development", False, "approved-support", "Scoped remote support is authorized; alerting alone does not make this malicious.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote"}, approval=True)
    add("remote", "holdout", True, "compromised-vpn", "Compromised endpoint establishes an unauthorized VPN remote session.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "device.security_posture": "compromised"})
    add("remote", "holdout", True, "misclassified-activity", "Unauthorized remote work is logged as READ, exposing a source-action observability gap.",
        {"network.access_method": "remote", "auth_context.mfa": "unknown"})
    add("remote", "holdout", True, "unmanaged-existing", "Unauthorized remote session originates from a known unmanaged endpoint.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "device.managed": False,
         "device.security_posture": "unknown"})
    add("remote", "holdout", False, "approved-vpn-maintenance", "Scoped VPN maintenance is approved for a healthy administrator.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "user.role": "administrator",
         "resource.required_role": "administrator"}, approval=True)
    add("remote", "holdout", False, "approved-night-support", "Authorized remote support occurs outside normal working hours.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.unusual_time": True}, approval=True)
    add("remote", "holdout", False, "local-night-login", "Approved local login outside normal working hours.",
        {"action": "LOGIN", "behavior.unusual_time": True})

    add("lateral", "development", True, "threshold-fanout", "Unauthorized remote fanout reaches the distinct-resource boundary.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.request_rate": "high",
         "behavior.distinct_resources_10m": 8}, rules=["lateral", "remote"])
    add("lateral", "development", True, "vpn-scanning", "Unauthorized VPN scanning touches many resources.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "behavior.request_rate": "high"},
        vary={"behavior.distinct_resources_10m": [11, 12, 13]}, rules=["lateral", "remote"])
    add("lateral", "development", True, "compromised-fanout", "Compromised endpoint rapidly fans out through remote access.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.request_rate": "high",
         "device.security_posture": "compromised"},
        vary={"behavior.distinct_resources_10m": [14, 15, 16]}, rules=["lateral", "remote"])
    add("lateral", "development", False, "approved-deployment", "Approved deployment automation legitimately fans out.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.request_rate": "high",
         "behavior.distinct_resources_10m": 10}, approval=True)
    add("lateral", "development", False, "small-workflow", "Routine work touches a small number of resources.",
        {"behavior.distinct_resources_10m": 2})
    add("lateral", "development", False, "local-admin-workflow", "Role-matched local administration uses a limited set of resources.",
        {"action": "ADMIN", "user.role": "administrator", "resource.required_role": "administrator",
         "resource.sensitivity": "high", "behavior.distinct_resources_10m": 3})
    add("lateral", "holdout", True, "slow-fanout", "Attacker spreads remote traversal over time to avoid the high-rate flag.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.distinct_resources_10m": 9,
         "behavior.request_rate": "normal"},
        rules=["lateral", "remote"])
    add("lateral", "holdout", True, "below-resource-limit", "Attacker stays just below the distinct-resource threshold.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "behavior.request_rate": "high",
         "behavior.distinct_resources_10m": 7}, rules=["lateral", "remote"])
    add("lateral", "holdout", True, "api-traversal", "Unauthorized cross-resource traversal uses READ rather than REMOTE_ACCESS.",
        {"network.access_method": "vpn", "behavior.request_rate": "high", "behavior.distinct_resources_10m": 20})
    add("lateral", "holdout", False, "fleet-deployment", "Approved fleet deployment touches many endpoints over VPN.",
        {"action": "REMOTE_ACCESS", "network.access_method": "vpn", "behavior.request_rate": "high",
         "behavior.distinct_resources_10m": 25}, approval=True)
    add("lateral", "holdout", False, "incident-response", "Approved response personnel inspect multiple resources.",
        {"action": "REMOTE_ACCESS", "network.access_method": "remote", "behavior.request_rate": "high",
         "behavior.distinct_resources_10m": 18, "user.role": "responder",
         "resource.required_role": "responder"}, approval=True)
    add("lateral", "holdout", False, "bounded-reporting", "Authorized report generation touches seven resources at normal rate.",
        {"behavior.distinct_resources_10m": 7})

    add("exfiltration", "development", True, "at-volume-limit", "Unauthorized critical-data export at the detection boundary.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.download_volume_mb": 500})
    add("exfiltration", "development", True, "bulk-critical", "Unauthorized large export of critical data.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical"},
        vary={"behavior.download_volume_mb": [750, 1000, 1500]})
    add("exfiltration", "development", True, "multiple-critical", "Unauthorized critical exports span several resources.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.distinct_resources_10m": 4},
        vary={"behavior.download_volume_mb": [501, 502, 503]})
    add("exfiltration", "development", False, "small-critical", "Authorized bounded transfer stays below the bulk threshold.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical"},
        vary={"behavior.download_volume_mb": [498, 499, 499.999]})
    add("exfiltration", "development", False, "public-export", "Authorized bulk export of public information.",
        {"action": "DOWNLOAD", "resource.sensitivity": "public", "behavior.download_volume_mb": 2000})
    add("exfiltration", "development", False, "approved-backup", "Scoped backup approval covers this critical-data transfer.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.download_volume_mb": 1800}, approval=True)
    add("exfiltration", "holdout", True, "high-sensitivity-export", "Unauthorized export of high-sensitivity rather than critical data.",
        {"action": "DOWNLOAD", "resource.sensitivity": "high", "behavior.download_volume_mb": 2500})
    add("exfiltration", "holdout", True, "low-and-slow", "Attacker splits a critical-data export into smaller off-hours transfers.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.unusual_time": True},
        vary={"behavior.download_volume_mb": [450, 475, 490]})
    add("exfiltration", "holdout", True, "rapid-critical", "Unauthorized critical-data export at high request rate.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.request_rate": "high"},
        vary={"behavior.download_volume_mb": [3000, 4000, 5000]})
    add("exfiltration", "holdout", False, "approved-migration", "Scoped migration approval covers an exact-capacity critical export.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.download_volume_mb": 6000}, approval=True)
    add("exfiltration", "holdout", False, "internal-report-export", "Authorized internal report export is within its business purpose.",
        {"action": "DOWNLOAD", "resource.sensitivity": "internal", "behavior.download_volume_mb": 3500})
    add("exfiltration", "holdout", False, "metadata-only", "A download request returns no data bytes.",
        {"action": "DOWNLOAD", "resource.sensitivity": "critical", "behavior.download_volume_mb": 0})
    return result


def set_field(event, path, value):
    target = event
    components = path.split(".")
    for key in components[:-1]:
        target = target[key]
    target[components[-1]] = value


def build():
    records = []
    specs = families()
    for index, spec in enumerate(specs):
        for variant in range(10):
            key = f"{spec['family_id']}-{variant:02}"
            opaque = hashlib.sha256(f"{index}:{variant}:benchmark-v1".encode()).hexdigest()[:20]
            when = datetime(2026, 10, 1 if spec["split"] == "development" else 20,
                            tzinfo=UTC) + timedelta(minutes=index * 30 + variant)
            event = {
                "event_id": f"evt-{opaque}", "timestamp": when.isoformat(),
                "user": {"user_id": f"u-{opaque}", "role": "employee", "department": f"team-{variant % 3}", "active": True},
                "device": {"device_id": f"d-{opaque}", "managed": True, "security_posture": "healthy"},
                "network": {"ip": f"{'192.0.2' if spec['split'] == 'development' else '198.51.100'}.{index + 1}",
                            "location": f"lab-region-{variant % 3}", "access_method": "office", "location_anomaly": False},
                "resource": {"resource_id": f"r-{opaque}", "resource_type": "document", "sensitivity": "internal", "required_role": "employee"},
                "action": "READ", "auth_context": {"authentication_result": "success", "mfa": "success", "failed_attempts": 0, "session_age_minutes": variant * 3},
                "behavior": {"new_device": False, "unusual_time": False, "request_rate": "normal", "download_volume_mb": 0,
                             "distinct_resources_10m": 1, "policy_exception_approved": False, "policy_exception": None, "event_text": None},
            }
            for path, value in spec["patch"].items():
                set_field(event, path, copy.deepcopy(value))
            for path, values in spec["variations"].items():
                set_field(event, path, values[variant % len(values)])
            # Cross secondary security contexts without changing a family's declared mechanism.
            # These vary actual observable inputs, rather than counting renamed IDs as new evidence.
            secondary = {
                "behavior.request_rate": ["normal", "high"][variant % 2],
                "behavior.distinct_resources_10m": 1 + variant // 2,
                "auth_context.failed_attempts": variant % 3,
                "resource.sensitivity": ["internal", "high", "critical"][variant % 3],
            }
            for path, value in secondary.items():
                if path not in spec["patch"] and path not in spec["variations"]:
                    set_field(event, path, value)
            if spec["approval"]:
                event["behavior"].update(policy_exception_approved=True, policy_exception={
                    "exception_id": f"EXC-BENCH-{index:03}-{variant:02}",
                    "approved_by": "synthetic-policy-owner", "reason": "Authored scoped business approval",
                    "valid_from": (when - timedelta(minutes=1)).isoformat(),
                    "valid_until": (when + timedelta(minutes=1)).isoformat(),
                    "scope": {"user_ids": [event["user"]["user_id"]], "resource_ids": [event["resource"]["resource_id"]],
                              "actions": [event["action"]], "max_download_volume_mb": max(1, event["behavior"]["download_volume_mb"])},
                })
            validated = SecurityEvent.model_validate(event)
            records.append({
                "case_id": key, "session_id": f"s-{opaque}", "family_id": spec["family_id"],
                "split": spec["split"], "domain": spec["domain"], "threat": spec["threat"],
                "expected_rule_ids": spec["expected_rule_ids"],
                "event": validated.model_dump(mode="json", exclude={"ground_truth"}),
            })
    OUTPUT.mkdir(parents=True, exist_ok=True)
    catalog_bytes = (json.dumps(specs, ensure_ascii=False, indent=2) + "\n").encode()
    case_bytes = ("\n".join(json.dumps(row, ensure_ascii=False, sort_keys=True) for row in records) + "\n").encode()
    manifest = {
        "version": "1.0.0", "source_kind": "authored_synthetic", "license": "MIT",
        "label_policy": "Operationally unauthorized or malicious activity; approved business activity is benign, even if an alert fires.",
        "review_status": "author_assigned_pending_independent_team_review",
        "family_count": len(specs), "case_count": len(records), "variants_per_family": 10,
        "generator_sha256": hashlib.sha256(Path(__file__).read_text(encoding="utf-8").encode()).hexdigest(),
        "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest(), "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
        "targets": {"minimum_precision": 0.95, "minimum_recall": 0.95, "minimum_f1": 0.95,
                    "maximum_false_positive_rate": 0.05, "minimum_positive_families_per_rule": 2,
                    "minimum_negative_families": 12},
    }
    (OUTPUT / "families.json").write_bytes(catalog_bytes)
    (OUTPUT / "cases.jsonl").write_bytes(case_bytes)
    (OUTPUT / "manifest.json").write_bytes((json.dumps(manifest, indent=2) + "\n").encode())
    print(f"Frozen {len(records)} cases in {len(specs)} families; labels were not derived from detector output")


if __name__ == "__main__":
    build()
