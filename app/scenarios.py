from copy import deepcopy

from app.models import (
    AttackTechnique,
    ConditionOperator,
    RecommendedAction,
    RiskLevel,
    ScenarioCategory,
    ScenarioCondition,
    ScenarioSummary,
    SecurityEvent,
)


def _condition(
    field: str,
    operator: ConditionOperator,
    value: object,
    description: str,
) -> ScenarioCondition:
    return ScenarioCondition(
        field=field,
        operator=operator,
        value=value,
        description=description,
    )

SCENARIOS = [
    ScenarioSummary(
        scenario_id="NORMAL-01",
        name="관리 기기의 일반 문서 조회",
        category=ScenarioCategory.NORMAL,
        description="관리 중인 건강한 기기에서 인증을 완료한 사용자가 업무 범위의 문서를 조회한다.",
        attack_tactic="Normal",
        observable_signals=[
            "device.managed = true",
            "device.security_posture = healthy",
            "auth_context.mfa = success",
            "resource.required_role = user.role",
            "network.access_method = office",
            "action = READ",
        ],
        detection_conditions=[
            _condition("device.managed", ConditionOperator.EQUALS, True, "관리 기기"),
            _condition(
                "device.security_posture", ConditionOperator.EQUALS, "healthy", "건강한 기기"
            ),
            _condition("auth_context.mfa", ConditionOperator.EQUALS, "success", "MFA 성공"),
            _condition("user.role", ConditionOperator.EQUALS, "analyst", "분석가 역할"),
            _condition(
                "resource.required_role",
                ConditionOperator.EQUALS,
                "analyst",
                "자원 요구 역할 일치",
            ),
            _condition(
                "network.access_method", ConditionOperator.EQUALS, "office", "사내망 접속"
            ),
            _condition("action", ConditionOperator.EQUALS, "READ", "일반 조회 요청"),
        ],
        expected_risk=RiskLevel.LOW,
        expected_action=RecommendedAction.ALLOW,
    ),
    ScenarioSummary(
        scenario_id="NORMAL-02",
        name="VPN 접속 후 MFA 성공",
        category=ScenarioCategory.NORMAL,
        description="승인된 VPN을 통해 접속한 사용자가 MFA를 완료하고 일반 자원을 조회한다.",
        attack_tactic="Normal",
        observable_signals=[
            "network.access_method = vpn",
            "network.location_anomaly = false",
            "auth_context.mfa = success",
            "behavior.request_rate = normal",
        ],
        detection_conditions=[
            _condition("network.access_method", ConditionOperator.EQUALS, "vpn", "VPN 접속"),
            _condition(
                "network.location_anomaly", ConditionOperator.EQUALS, False, "위치 이상 없음"
            ),
            _condition("auth_context.mfa", ConditionOperator.EQUALS, "success", "MFA 성공"),
            _condition(
                "behavior.request_rate", ConditionOperator.EQUALS, "normal", "정상 요청 빈도"
            ),
        ],
        expected_risk=RiskLevel.LOW,
        expected_action=RecommendedAction.ALLOW,
    ),
    ScenarioSummary(
        scenario_id="NORMAL-03",
        name="승인된 대용량 백업",
        category=ScenarioCategory.NORMAL_EXCEPTION,
        description="백업 담당자가 사전 승인된 예외 정책에 따라 민감 자료를 대용량으로 다운로드한다.",
        attack_tactic="Normal exception",
        observable_signals=[
            "user.role = backup-operator",
            "resource.required_role = backup-operator",
            "behavior.download_volume_mb >= 500",
            "behavior.policy_exception_approved = true",
        ],
        detection_conditions=[
            _condition("user.role", ConditionOperator.EQUALS, "backup-operator", "백업 담당자"),
            _condition(
                "resource.required_role",
                ConditionOperator.EQUALS,
                "backup-operator",
                "백업 자원 역할 일치",
            ),
            _condition(
                "behavior.download_volume_mb",
                ConditionOperator.GREATER_THAN_OR_EQUAL,
                500,
                "500MB 이상 다운로드",
            ),
            _condition(
                "behavior.policy_exception_approved",
                ConditionOperator.EQUALS,
                True,
                "유효한 정책 예외 승인",
            ),
        ],
        normal_exceptions=["승인된 백업 또는 데이터 이관 작업"],
        expected_risk=RiskLevel.MEDIUM,
        expected_action=RecommendedAction.REQUIRE_MFA,
    ),
    ScenarioSummary(
        scenario_id="ZT-S01",
        name="탈취 계정의 비정상 접근",
        category=ScenarioCategory.THREAT,
        description="새 기기와 비정상 위치에서 MFA가 반복 실패한 후 민감 자료에 접근하려는 사건을 검토한다.",
        attack_tactic="Credential Access",
        attack_techniques=[
            AttackTechnique(
                technique_id="T1110",
                name="Brute Force",
                reference_url="https://attack.mitre.org/techniques/T1110/",
            )
        ],
        observable_signals=[
            "auth_context.mfa = failed",
            "auth_context.failed_attempts >= 3",
            "device.managed = false",
            "network.location_anomaly = true",
            "resource.sensitivity = critical",
        ],
        detection_conditions=[
            _condition("auth_context.mfa", ConditionOperator.EQUALS, "failed", "MFA 실패"),
            _condition(
                "auth_context.failed_attempts",
                ConditionOperator.GREATER_THAN_OR_EQUAL,
                3,
                "로그인 3회 이상 실패",
            ),
            _condition("device.managed", ConditionOperator.EQUALS, False, "미관리 기기"),
            _condition(
                "network.location_anomaly", ConditionOperator.EQUALS, True, "비정상 위치"
            ),
            _condition(
                "resource.sensitivity", ConditionOperator.EQUALS, "critical", "치명 자원 접근"
            ),
        ],
        normal_exceptions=["출장이나 VPN 출구 변경으로 인한 위치 변화"],
        expected_risk=RiskLevel.CRITICAL,
        expected_action=RecommendedAction.HOLD_FOR_REVIEW,
    ),
    ScenarioSummary(
        scenario_id="ZT-S02",
        name="관리되지 않은 기기의 접근",
        category=ScenarioCategory.THREAT,
        description="등록되지 않은 새 기기가 원격 경로로 업무 자원에 접근하려는 사건을 검토한다.",
        attack_tactic="Initial Access",
        attack_techniques=[
            AttackTechnique(
                technique_id="T1133",
                name="External Remote Services",
                reference_url="https://attack.mitre.org/techniques/T1133/",
            )
        ],
        observable_signals=[
            "device.managed = false",
            "device.security_posture = unknown",
            "behavior.new_device = true",
            "network.access_method = remote",
        ],
        detection_conditions=[
            _condition("device.managed", ConditionOperator.EQUALS, False, "미관리 기기"),
            _condition(
                "device.security_posture", ConditionOperator.EQUALS, "unknown", "보안 상태 불명"
            ),
            _condition("behavior.new_device", ConditionOperator.EQUALS, True, "새 기기"),
            _condition(
                "network.access_method", ConditionOperator.EQUALS, "remote", "원격 접속"
            ),
        ],
        normal_exceptions=["아직 등록되지 않은 신규 지급 장비", "사전 승인된 BYOD 접근"],
        expected_risk=RiskLevel.MEDIUM,
        expected_action=RecommendedAction.REQUIRE_MFA,
    ),
    ScenarioSummary(
        scenario_id="ZT-S03",
        name="권한 범위 초과",
        category=ScenarioCategory.THREAT,
        description="일반 분석가 계정이 관리자 콘솔과 상위 권한을 반복해 요청하는 사건을 검토한다.",
        attack_tactic="Privilege Escalation",
        attack_techniques=[
            AttackTechnique(
                technique_id="T1098",
                name="Account Manipulation",
                reference_url="https://attack.mitre.org/techniques/T1098/",
            )
        ],
        observable_signals=[
            "resource.required_role != user.role",
            "action = ADMIN",
            "resource.sensitivity = critical",
            "auth_context.failed_attempts >= 3",
        ],
        detection_conditions=[
            _condition(
                "resource.required_role",
                ConditionOperator.NOT_EQUALS,
                "analyst",
                "요청자 역할과 다른 권한 필요",
            ),
            _condition("action", ConditionOperator.EQUALS, "ADMIN", "관리자 기능 요청"),
            _condition(
                "resource.sensitivity", ConditionOperator.EQUALS, "critical", "치명 자원 접근"
            ),
            _condition(
                "auth_context.failed_attempts",
                ConditionOperator.GREATER_THAN_OR_EQUAL,
                3,
                "로그인 3회 이상 실패",
            ),
        ],
        normal_exceptions=["사전 승인된 긴급 권한", "직무 변경 후 동기화 지연"],
        expected_risk=RiskLevel.HIGH,
        expected_action=RecommendedAction.REDUCE_PRIVILEGE,
    ),
    ScenarioSummary(
        scenario_id="ZT-S04",
        name="내부 횡단 이동 의심",
        category=ScenarioCategory.THREAT,
        description="원격 접근 상태에서 짧은 시간 동안 여러 내부 자원을 이동하며 요청하는 사건을 검토한다.",
        attack_tactic="Lateral Movement",
        attack_techniques=[
            AttackTechnique(
                technique_id="T1021",
                name="Remote Services",
                reference_url="https://attack.mitre.org/techniques/T1021/",
            )
        ],
        observable_signals=[
            "action = REMOTE_ACCESS",
            "behavior.distinct_resources_10m >= 8",
            "behavior.request_rate = high",
            "network.location_anomaly = true",
            "device.security_posture = at_risk",
        ],
        detection_conditions=[
            _condition("action", ConditionOperator.EQUALS, "REMOTE_ACCESS", "원격 접근 요청"),
            _condition(
                "behavior.distinct_resources_10m",
                ConditionOperator.GREATER_THAN_OR_EQUAL,
                8,
                "10분 내 8개 이상 자원 접근",
            ),
            _condition(
                "behavior.request_rate", ConditionOperator.EQUALS, "high", "높은 요청 빈도"
            ),
            _condition(
                "network.location_anomaly", ConditionOperator.EQUALS, True, "비정상 위치"
            ),
            _condition(
                "device.security_posture", ConditionOperator.EQUALS, "at_risk", "취약한 기기"
            ),
        ],
        normal_exceptions=["승인된 배포 자동화", "장애 대응을 위한 운영자의 원격 접근"],
        expected_risk=RiskLevel.HIGH,
        expected_action=RecommendedAction.HOLD_FOR_REVIEW,
    ),
    ScenarioSummary(
        scenario_id="ZT-S05",
        name="정책 위반 데이터 접근",
        category=ScenarioCategory.THREAT,
        description="비정상 시간대에 사전 예외 승인 없이 고민감 자료를 대용량으로 다운로드하는 사건을 검토한다.",
        attack_tactic="Exfiltration",
        attack_techniques=[
            AttackTechnique(
                technique_id="T1020",
                name="Automated Exfiltration",
                reference_url="https://attack.mitre.org/techniques/T1020/",
            )
        ],
        observable_signals=[
            "resource.sensitivity = critical",
            "action = DOWNLOAD",
            "behavior.download_volume_mb >= 500",
            "behavior.unusual_time = true",
            "behavior.policy_exception_approved = false",
        ],
        detection_conditions=[
            _condition(
                "resource.sensitivity", ConditionOperator.EQUALS, "critical", "치명 자원 접근"
            ),
            _condition("action", ConditionOperator.EQUALS, "DOWNLOAD", "다운로드 요청"),
            _condition(
                "behavior.download_volume_mb",
                ConditionOperator.GREATER_THAN_OR_EQUAL,
                500,
                "500MB 이상 다운로드",
            ),
            _condition(
                "behavior.unusual_time", ConditionOperator.EQUALS, True, "비정상 시간대"
            ),
            _condition(
                "behavior.policy_exception_approved",
                ConditionOperator.EQUALS,
                False,
                "정책 예외 미승인",
            ),
        ],
        normal_exceptions=["승인된 백업", "사전 검토를 거친 데이터 이관 작업"],
        expected_risk=RiskLevel.HIGH,
        expected_action=RecommendedAction.HOLD_FOR_REVIEW,
    ),
]

SCENARIO_INDEX = {scenario.scenario_id: scenario for scenario in SCENARIOS}
if len(SCENARIO_INDEX) != len(SCENARIOS):
    raise RuntimeError("scenario_id values must be unique")


def get_scenario(scenario_id: str) -> ScenarioSummary:
    try:
        return SCENARIO_INDEX[scenario_id]
    except KeyError:
        raise KeyError(scenario_id) from None


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
        "download_volume_mb": 0,
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
    scenario = get_scenario(scenario_id)
    return {
        "scenario_id": scenario_id,
        "risk_level": scenario.expected_risk,
        "expected_action": scenario.expected_action,
    }


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
            behavior={
                "download_volume_mb": 700,
                "policy_exception_approved": True,
                "policy_exception": {
                    "exception_id": "EXC-BACKUP-01",
                    "approved_by": "security-manager",
                    "reason": "정기 백업 작업 승인",
                    "valid_from": "2026-09-01T00:00:00+09:00",
                    "valid_until": "2026-09-30T23:59:59+09:00",
                    "scope": {
                        "roles": ["backup-operator"],
                        "resource_ids": ["backup-approved-01"],
                        "actions": ["DOWNLOAD"],
                        "max_download_volume_mb": 1000,
                    },
                },
            },
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
