from copy import deepcopy

from app.models import (
    RecommendedAction,
    RiskLevel,
    ScenarioSummary,
    SecurityEvent,
)

SCENARIOS = [
    ScenarioSummary(
        scenario_id="NORMAL-01",
        name="관리 기기의 일반 문서 조회",
        attack_tactic="Normal",
        expected_risk=RiskLevel.LOW,
    ),
    ScenarioSummary(
        scenario_id="NORMAL-02",
        name="VPN 접속 후 MFA 성공",
        attack_tactic="Normal",
        expected_risk=RiskLevel.LOW,
    ),
    ScenarioSummary(
        scenario_id="NORMAL-03",
        name="승인된 대용량 백업",
        attack_tactic="Normal exception",
        expected_risk=RiskLevel.MEDIUM,
    ),
    ScenarioSummary(
        scenario_id="ZT-S01",
        name="탈취 계정의 비정상 접근",
        attack_tactic="Credential Access",
        expected_risk=RiskLevel.CRITICAL,
    ),
    ScenarioSummary(
        scenario_id="ZT-S02",
        name="관리되지 않은 기기의 접근",
        attack_tactic="Initial Access",
        expected_risk=RiskLevel.MEDIUM,
    ),
    ScenarioSummary(
        scenario_id="ZT-S03",
        name="권한 범위 초과",
        attack_tactic="Privilege Escalation",
        expected_risk=RiskLevel.HIGH,
    ),
    ScenarioSummary(
        scenario_id="ZT-S04",
        name="내부 횡단 이동 의심",
        attack_tactic="Lateral Movement",
        expected_risk=RiskLevel.HIGH,
    ),
    ScenarioSummary(
        scenario_id="ZT-S05",
        name="정책 위반 데이터 접근",
        attack_tactic="Collection / Exfiltration",
        expected_risk=RiskLevel.HIGH,
    ),
]


_BASE = {
    "timestamp": "2026-09-09T10:00:00+09:00",
    "user": {
        "user_id": "user-017",
        "role": "analyst",
        "department": "research",
        "active": True,
    },
    "device": {
        "device_id": "device-managed-01",
        "managed": True,
        "security_posture": "healthy",
    },
    "network": {
        "ip": "198.51.100.10",
        "location": "region-a",
        "access_method": "office",
        "location_anomaly": False,
    },
    "resource": {
        "resource_id": "document-internal-01",
        "resource_type": "document",
        "sensitivity": "internal",
        "required_role": "analyst",
    },
    "action": "READ",
    "auth_context": {
        "mfa": "success",
        "failed_attempts": 0,
        "session_age_minutes": 12,
    },
    "behavior": {
        "new_device": False,
        "unusual_time": False,
        "request_rate": "normal",
        "download_volume_mb": 2,
        "distinct_resources_10m": 1,
        "policy_exception_approved": False,
    },
}


def _build(event_id: str, scenario_id: str, **overrides) -> SecurityEvent:
    data = deepcopy(_BASE)
    for section, value in overrides.items():
        if isinstance(value, dict) and isinstance(data.get(section), dict):
            data[section].update(value)
        else:
            data[section] = value
    data["event_id"] = event_id
    data["ground_truth"] = _ground_truth(scenario_id)
    return SecurityEvent.model_validate(data)


def _ground_truth(scenario_id: str) -> dict:
    mapping = {
        "NORMAL-01": (RiskLevel.LOW, RecommendedAction.ALLOW),
        "NORMAL-02": (RiskLevel.LOW, RecommendedAction.ALLOW),
        "NORMAL-03": (RiskLevel.MEDIUM, RecommendedAction.REQUIRE_MFA),
        "ZT-S01": (RiskLevel.CRITICAL, RecommendedAction.HOLD_FOR_REVIEW),
        "ZT-S02": (RiskLevel.MEDIUM, RecommendedAction.REQUIRE_MFA),
        "ZT-S03": (RiskLevel.HIGH, RecommendedAction.REDUCE_PRIVILEGE),
        "ZT-S04": (RiskLevel.HIGH, RecommendedAction.HOLD_FOR_REVIEW),
        "ZT-S05": (RiskLevel.HIGH, RecommendedAction.HOLD_FOR_REVIEW),
    }
    risk, action = mapping[scenario_id]
    return {"scenario_id": scenario_id, "risk_level": risk, "expected_action": action}


def synthetic_events() -> list[SecurityEvent]:
    return [
        _build("evt-normal-01", "NORMAL-01"),
        _build(
            "evt-normal-02",
            "NORMAL-02",
            network={"access_method": "vpn", "location": "region-b"},
            auth_context={"session_age_minutes": 3},
        ),
        _build(
            "evt-normal-03",
            "NORMAL-03",
            user={"role": "backup-operator", "department": "operations"},
            resource={
                "resource_id": "backup-approved-01",
                "sensitivity": "high",
                "required_role": "backup-operator",
            },
            action="DOWNLOAD",
            behavior={"download_volume_mb": 700, "policy_exception_approved": True},
        ),
        _build(
            "evt-zt-s01",
            "ZT-S01",
            device={"device_id": "device-new-03", "managed": False, "security_posture": "unknown"},
            network={"location": "region-c", "access_method": "remote", "location_anomaly": True},
            resource={"resource_id": "data-sensitive-02", "sensitivity": "critical"},
            action="DOWNLOAD",
            auth_context={"mfa": "failed", "failed_attempts": 4},
            behavior={"new_device": True, "request_rate": "high", "download_volume_mb": 850},
        ),
        _build(
            "evt-zt-s02",
            "ZT-S02",
            device={
                "device_id": "device-unregistered-08",
                "managed": False,
                "security_posture": "unknown",
            },
            network={"access_method": "remote"},
            behavior={"new_device": True},
        ),
        _build(
            "evt-zt-s03",
            "ZT-S03",
            resource={
                "resource_id": "admin-console-01",
                "resource_type": "admin-console",
                "sensitivity": "critical",
                "required_role": "administrator",
            },
            action="ADMIN",
            auth_context={"failed_attempts": 4},
            behavior={"request_rate": "high"},
        ),
        _build(
            "evt-zt-s04",
            "ZT-S04",
            device={"security_posture": "at_risk"},
            network={"access_method": "remote", "location_anomaly": True},
            resource={"resource_id": "internal-service-07", "sensitivity": "high"},
            action="REMOTE_ACCESS",
            behavior={
                "new_device": True,
                "request_rate": "high",
                "distinct_resources_10m": 12,
            },
        ),
        _build(
            "evt-zt-s05",
            "ZT-S05",
            resource={"resource_id": "data-sensitive-09", "sensitivity": "critical"},
            action="DOWNLOAD",
            behavior={"unusual_time": True, "request_rate": "high", "download_volume_mb": 1600},
        ),
    ]


def generate_events(
    scenario_id: str | None = None, count: int | None = None
) -> list[SecurityEvent]:
    pool = synthetic_events()
    if scenario_id:
        pool = [
            event
            for event in pool
            if event.ground_truth and event.ground_truth.scenario_id == scenario_id
        ]
        if not pool:
            raise KeyError(scenario_id)

    requested = count or len(pool)
    generated: list[SecurityEvent] = []
    for index in range(requested):
        source = pool[index % len(pool)]
        if index < len(pool):
            generated.append(source)
        else:
            generated.append(
                source.model_copy(update={"event_id": f"{source.event_id}-copy-{index + 1}"})
            )
    return generated
