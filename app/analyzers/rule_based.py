from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    SecurityEvent,
    ViolationType,
)


class RuleBasedAnalyzer:
    name = "rule"

    async def analyze(self, event: SecurityEvent) -> SecurityAssessment:
        return self.assess(event)

    def assess(self, event: SecurityEvent) -> SecurityAssessment:
        score, evidence, labels = self._score(event)
        risk_level = self._risk_level(score)
        violation = self._violation_type(event)
        action = self.recommended_action(risk_level, violation)

        if labels:
            rationale = "위험 판단에 사용한 신호: " + ", ".join(labels) + "."
        else:
            rationale = "등록된 기기와 정상 접근 패턴이 확인되어 위험 신호가 낮습니다."

        if not evidence:
            confidence = 0.95
        elif event.behavior.policy_exception is not None:
            confidence = 0.9
        else:
            confidence = min(0.72 + len(evidence) * 0.03, 0.93)

        return SecurityAssessment(
            risk_score=score,
            risk_level=risk_level,
            violation_type=violation,
            rationale=rationale,
            recommended_action=action,
            confidence=confidence,
            evidence=evidence,
            requires_human_review=risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL},
        )

    def _score(self, event: SecurityEvent) -> tuple[int, list[str], list[str]]:
        evidence: list[str] = []
        labels: list[str] = []

        def signal(key: str, label: str) -> None:
            evidence.append(key)
            labels.append(label)

        identity = min(event.auth_context.failed_attempts * 4, 16)
        if event.auth_context.failed_attempts >= 3:
            signal("auth_context.failed_attempts", "반복된 로그인 실패")
        if event.auth_context.mfa == "failed":
            identity += 9
            signal("auth_context.mfa", "MFA 실패")
        if not event.user.active:
            identity += 15
            signal("user.active", "비활성 계정")
        identity = min(identity, 25)

        device = 0
        if not event.device.managed:
            device += 14
            signal("device.managed", "미등록 기기")
        if event.device.security_posture == "unknown":
            device += 5
            signal("device.security_posture", "기기 보안 상태 불명")
        elif event.device.security_posture == "at_risk":
            device += 12
            signal("device.security_posture", "취약한 기기 상태")
        elif event.device.security_posture == "compromised":
            device += 20
            signal("device.security_posture", "침해된 기기")
        if event.behavior.new_device:
            device += 4
            signal("behavior.new_device", "새로운 기기")
        device = min(device, 20)

        behavior = 0
        if event.network.location_anomaly:
            behavior += 7
            signal("network.location_anomaly", "비정상 위치")
        if event.behavior.unusual_time:
            behavior += 5
            signal("behavior.unusual_time", "비정상 시간대")
        if event.behavior.request_rate == "high":
            behavior += 6
            signal("behavior.request_rate", "높은 요청 빈도")
        if event.behavior.download_volume_mb >= 500:
            behavior += 12
            signal("behavior.download_volume_mb", "대용량 다운로드")
        if event.behavior.distinct_resources_10m >= 8:
            behavior += 10
            signal("behavior.distinct_resources_10m", "다수 자원 접근")
        behavior = min(behavior, 25)

        sensitivity_score = {"public": 0, "internal": 5, "high": 14, "critical": 20}
        resource = sensitivity_score[event.resource.sensitivity]
        if event.resource.sensitivity in {"high", "critical"}:
            signal("resource.sensitivity", "민감 자원 접근")

        policy = 0
        role_mismatch = bool(
            event.resource.required_role and event.user.role != event.resource.required_role
        )
        if role_mismatch:
            policy += 10
            signal("resource.required_role", "요청 역할 불일치")
        elif event.action == "ADMIN" and event.user.role != "administrator":
            policy += 10
            signal("action", "관리자 기능 요청")
        elif (
            event.action == "DOWNLOAD"
            and event.resource.sensitivity in {"high", "critical"}
            and event.behavior.download_volume_mb >= 500
            and not event.behavior.policy_exception_approved
        ):
            policy += 10
            signal("behavior.policy_exception_approved", "승인되지 않은 대량 접근")

        return min(identity + device + behavior + resource + policy, 100), evidence, labels

    @staticmethod
    def _risk_level(score: int) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    @staticmethod
    def _violation_type(event: SecurityEvent) -> ViolationType:
        if (
            event.action == "DOWNLOAD"
            and event.behavior.download_volume_mb >= 500
            and not event.behavior.policy_exception_approved
        ):
            return ViolationType.DATA_EXFILTRATION
        if event.action == "ADMIN" or (
            event.resource.required_role and event.user.role != event.resource.required_role
        ):
            return ViolationType.PRIVILEGE_ESCALATION
        if event.behavior.distinct_resources_10m >= 8 or event.action == "REMOTE_ACCESS":
            return ViolationType.LATERAL_MOVEMENT
        if event.auth_context.failed_attempts >= 3 or event.network.location_anomaly:
            return ViolationType.CREDENTIAL_ANOMALY
        if not event.device.managed:
            return ViolationType.UNMANAGED_DEVICE
        return ViolationType.NORMAL

    @staticmethod
    def recommended_action(risk_level: RiskLevel, violation: ViolationType) -> RecommendedAction:
        if risk_level == RiskLevel.CRITICAL:
            return RecommendedAction.HOLD_FOR_REVIEW
        if risk_level == RiskLevel.HIGH:
            if violation == ViolationType.PRIVILEGE_ESCALATION:
                return RecommendedAction.REDUCE_PRIVILEGE
            return RecommendedAction.HOLD_FOR_REVIEW
        if risk_level == RiskLevel.MEDIUM:
            return RecommendedAction.REQUIRE_MFA
        return RecommendedAction.ALLOW
