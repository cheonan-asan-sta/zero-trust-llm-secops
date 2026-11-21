import asyncio

from openai import OpenAIError

from app.analyzers.base import Analyzer
from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.analyzers.rule_based import RuleBasedAnalyzer
from app.config import Settings
from app.models import (
    RecommendedAction,
    RiskLevel,
    SecurityAssessment,
    SecurityEvent,
    ViolationType,
)
from app.services.session_analysis_evidence import LIVE_SESSION_SCOPE, VerifiedSessionContext

_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}
_APPROVAL_EVIDENCE = frozenset(
    {
        "verified_session.policy.resource_registered",
        "verified_session.policy.role_permitted",
        "verified_session.policy.action_permitted",
        "verified_session.session.decision",
        "verified_session.session.status",
        "verified_session.session.approval_currently_usable",
    }
)
_GENERIC_STEP_UP_FIELDS = {
    "verified_session.session.decision",
    "verified_session.session.status",
    "verified_session.session.reason_codes",
    "verified_session.session.challenge_pending",
}
_GENERIC_REMOTE_RULE = "verified_session.session.only_generic_remote_logon_rule_matched"
_REMOTE_REVIEW_CONTEXT = (
    _APPROVAL_EVIDENCE
    | _GENERIC_STEP_UP_FIELDS
    | {
        _GENERIC_REMOTE_RULE,
        "action",
        "auth_context.authentication_result",
        "auth_context.mfa",
        "auth_context.failed_attempts",
        "behavior.distinct_resources_10m",
        "device.managed",
        "device.security_posture",
        "network.access_method",
        "resource.resource_type",
        "verified_session.scope",
        "verified_session.valid_until",
        "verified_session.not_an_access_grant",
        "verified_session.external_enterprise_identity_verified",
        "verified_session.caller.authentication_method",
        "verified_session.caller.identity_scope",
        "verified_session.caller.event_subject_mfa_independently_verified",
        "verified_session.caller.session_operator_binding_verified",
        "verified_session.policy.mfa_required",
        "verified_session.policy.managed_device_required",
        "verified_session.session.input_digest_sha256",
        "verified_session.session.same_scope_mfa_response_verified",
        "verified_session.signal.authentication_observation",
        "verified_session.signal.mfa_observation",
        "verified_session.signal.meaning",
        "verified_session.signal.signature_verified",
    }
)


def _active_server_approval(policy, signal, session):
    return (
        policy["origin"] == "server_owned_configuration"
        and policy["resource_registered"] is True
        and policy["role_permitted"] is True
        and policy["action_permitted"] is True
        and signal["signature_verified"] is True
        and session["decision"] == "ALLOW"
        and session["status"] == "ACTIVE"
        and session["approval_currently_usable"] is True
    )


def _approved_administrator_action(event, facts, baseline):
    return (
        event.action == "ADMIN"
        and event.user.role == "administrator"
        and baseline.violation_type == ViolationType.PRIVILEGE_ESCALATION
        and not baseline.evidence
        and event.auth_context.failed_attempts == 0
        and event.device.security_posture == "healthy"
        and facts["signal"]["authentication_observation"] == "success"
        and facts["session"]["reason_codes"] == ["POLICY_SATISFIED"]
        and "execution" not in facts
        and "native_execution" not in facts
        and _active_server_approval(facts["policy"], facts["signal"], facts["session"])
    )


def _verified_session_baseline(event, facts, baseline):
    if facts.get("scope") != LIVE_SESSION_SCOPE:
        return baseline
    policy, signal, session = facts["policy"], facts["signal"], facts["session"]
    if policy["origin"] != "server_owned_configuration" or signal["signature_verified"] is not True:
        return baseline

    violations = [
        (policy["resource_registered"] is False, ("policy.resource_registered",)),
        (policy["role_permitted"] is False, ("policy.role_permitted",)),
        (policy["action_permitted"] is False, ("policy.action_permitted",)),
        (
            session["status"] == "REVOKED" and "SESSION_ALREADY_REVOKED" in session["reason_codes"],
            ("session.status", "session.reason_codes"),
        ),
        (
            policy["mfa_required"] is True and signal["mfa_observation"] != "success",
            ("policy.mfa_required", "signal.mfa_observation"),
        ),
        (
            policy["mfa_required"] is True
            and session["challenge_pending"] is True
            and "SIGNED_MFA_CHALLENGE_REQUIRED" in session["reason_codes"],
            ("policy.mfa_required", "session.challenge_pending", "session.reason_codes"),
        ),
        (
            policy["managed_device_required"] is True and not event.device.managed,
            ("policy.managed_device_required",),
        ),
    ]
    paths = [
        f"verified_session.{path}" for applies, fields in violations if applies for path in fields
    ]
    if "IDENTITY_DENIED" in session["reason_codes"]:
        if not event.user.active:
            paths.append("user.active")
        if signal["authentication_observation"] == "failure":
            paths.append("verified_session.signal.authentication_observation")
    if (
        "DEVICE_COMPROMISED" in session["reason_codes"]
        and event.device.security_posture == "compromised"
    ):
        paths.append("device.security_posture")
    if paths:
        if policy["managed_device_required"] is True and not event.device.managed:
            paths.append("device.managed")
        violation = baseline.violation_type
        if violation == ViolationType.NORMAL or (
            violation == ViolationType.LATERAL_MOVEMENT
            and event.action == "REMOTE_ACCESS"
            and event.behavior.distinct_resources_10m < 8
        ):
            violation = ViolationType.ACCESS_POLICY_VIOLATION
        return baseline.model_copy(
            update={
                "violation_type": violation,
                "rationale": "검증한 세션 근거가 서버의 접근 요건을 충족하지 않습니다.",
                "evidence": list(dict.fromkeys([*paths, *baseline.evidence]))[:20],
                "recommended_action": RecommendedAction.HOLD_FOR_REVIEW,
                "requires_human_review": True,
            }
        )

    if _approved_administrator_action(event, facts, baseline):
        return baseline.model_copy(
            update={
                "violation_type": ViolationType.NORMAL,
                "rationale": "현재 서버의 유효한 관리자 작업 승인을 확인했습니다.",
                "evidence": ["verified_session.session.approval_currently_usable"],
                "recommended_action": RecommendedAction.HOLD_FOR_REVIEW,
                "requires_human_review": True,
            }
        )

    # The generic remote-logon match can call for step-up without showing lateral movement.
    followup_verified = (
        session.get("same_scope_mfa_response_verified") is True
        and "execution" not in facts
        and "native_execution" not in facts
    )
    allowed_rule_evidence = (
        {"device.managed"} if policy["managed_device_required"] is False else set()
    )
    if (
        event.action != "REMOTE_ACCESS"
        or event.network.access_method not in {"remote", "vpn"}
        or baseline.violation_type != ViolationType.LATERAL_MOVEMENT
        or event.behavior.distinct_resources_10m >= 8
        or not set(baseline.evidence) <= allowed_rule_evidence
        or event.auth_context.failed_attempts != 0
        or event.device.security_posture != "healthy"
        or signal["authentication_observation"] != "success"
        or (session["version"] != 1 and not followup_verified)
        or session["decision"] != "STEP_UP"
        or session["reason_codes"] != ["ELEVATED_RISK"]
        or session.get("only_generic_remote_logon_rule_matched") is not True
    ):
        return baseline
    evidence = [
        _GENERIC_REMOTE_RULE,
        "verified_session.session.reason_codes",
        *baseline.evidence,
    ]
    rationale = (
        "일반 원격 접속 신호로 추가 인증이 대기 중입니다. 별도 규칙 경보는 확인되지 않았습니다."
    )
    if followup_verified:
        evidence.append("verified_session.session.same_scope_mfa_response_verified")
        rationale = "같은 접근 범위의 MFA 응답을 확인했습니다. 일반 원격 접속 규칙만 일치해 검토를 유지합니다."
    return baseline.model_copy(
        update={
            "violation_type": ViolationType.NORMAL,
            "rationale": rationale,
            "evidence": evidence,
            "recommended_action": RecommendedAction.HOLD_FOR_REVIEW,
            "requires_human_review": True,
        }
    )


def _contradicted_policy_finding(facts, baseline, model):
    if (
        facts.get("scope") != LIVE_SESSION_SCOPE
        or baseline.violation_type != ViolationType.NORMAL
        or model.violation_type != ViolationType.ACCESS_POLICY_VIOLATION
        or not model.evidence
        or not set(model.evidence) <= _APPROVAL_EVIDENCE
    ):
        return False
    return _active_server_approval(facts["policy"], facts["signal"], facts["session"])


def _only_generic_remote_review(event, facts, baseline, model):
    if (
        baseline.violation_type != ViolationType.NORMAL
        or _GENERIC_REMOTE_RULE not in baseline.evidence
        or model.violation_type
        not in {ViolationType.ACCESS_POLICY_VIOLATION, ViolationType.UNKNOWN}
        or "execution" in facts
        or "native_execution" in facts
    ):
        return False
    observed = event.behavior
    benign = {
        "behavior.download_volume_mb": observed.download_volume_mb == 0,
        "behavior.new_device": not observed.new_device,
        "behavior.policy_exception_approved": not observed.policy_exception_approved,
        "behavior.request_rate": observed.request_rate == "normal",
        "behavior.unusual_time": not observed.unusual_time,
        "network.location_anomaly": not event.network.location_anomaly,
    }
    cited = set(model.evidence)
    return bool(
        cited & _GENERIC_STEP_UP_FIELDS
        and cited
        <= _REMOTE_REVIEW_CONTEXT | {field for field, ordinary in benign.items() if ordinary}
    )


class HybridAnalyzer:
    name = "hybrid"

    def __init__(self, settings: Settings, llm: Analyzer | None = None) -> None:
        self._rule = RuleBasedAnalyzer()
        self._owns_llm = llm is None
        self._llm = OpenAIAnalyzer(settings) if llm is None else llm
        self._confidence_threshold = settings.hybrid_confidence_threshold
        self._review_all = settings.hybrid_review_all
        self._llm_timeout_seconds = settings.hybrid_llm_timeout_seconds

    async def analyze(self, event: SecurityEvent) -> SecurityAssessment:
        return await self._analyze(event)

    async def close(self):
        if self._owns_llm:
            await self._llm.close()

    async def analyze_with_evidence(
        self, event: SecurityEvent, context: VerifiedSessionContext
    ) -> SecurityAssessment:
        # This explicit endpoint requests contextual LLM review even for confident rules.
        return await self._analyze(event, context)

    async def _analyze(
        self, event: SecurityEvent, context: VerifiedSessionContext | None = None
    ) -> SecurityAssessment:
        baseline = self._rule.assess(event)
        adjusted = False
        facts = None
        if context is not None:
            facts = context.for_event(event)
            verified = _verified_session_baseline(event, facts, baseline)
            adjusted = verified is not baseline
            baseline = verified
        if (
            context is None
            and not self._review_all
            and baseline.confidence >= self._confidence_threshold
        ):
            return baseline

        try:
            llm_assessment = await asyncio.wait_for(
                (
                    self._llm.analyze_with_evidence(event, context)
                    if context is not None
                    else self._llm.analyze(event)
                ),
                timeout=self._llm_timeout_seconds,
            )
        except (TimeoutError, OpenAIError, RuntimeError, TypeError, ValueError):
            return baseline.model_copy(
                update={
                    "violation_type": (
                        ViolationType.UNKNOWN
                        if adjusted and baseline.violation_type == ViolationType.NORMAL
                        else baseline.violation_type
                    ),
                    "rationale": baseline.rationale
                    + " LLM 교차 검토를 완료하지 못해 사람 검토로 전환합니다.",
                    "requires_human_review": True,
                }
            )
        if facts is not None and _contradicted_policy_finding(facts, baseline, llm_assessment):
            llm_assessment = llm_assessment.model_copy(
                update={
                    "violation_type": ViolationType.NORMAL,
                    "rationale": "모델이 인용한 현재 서버 정책과 세션 기록은 접근 요건 충족을 나타냅니다.",
                }
            )
            return self._merge(baseline, llm_assessment).model_copy(
                update={
                    "evidence": list(
                        dict.fromkeys(
                            [
                                "verified_session.session.approval_currently_usable",
                                *baseline.evidence,
                                *llm_assessment.evidence,
                            ]
                        )
                    )[:20],
                    "recommended_action": RecommendedAction.HOLD_FOR_REVIEW,
                    "requires_human_review": True,
                }
            )
        if (
            facts is not None
            and adjusted
            and _only_generic_remote_review(event, facts, baseline, llm_assessment)
        ):
            llm_assessment = llm_assessment.model_copy(
                update={
                    "violation_type": ViolationType.NORMAL,
                    "rationale": "모델이 인용한 근거는 일반 추가 인증 대기 상태를 설명합니다. 접근은 계속 검토합니다.",
                }
            )
        merged = self._merge(baseline, llm_assessment)
        if adjusted:
            return merged.model_copy(
                update={
                    "rationale": (baseline.rationale + " LLM 검토: " + llm_assessment.rationale)[
                        :1000
                    ],
                    "recommended_action": RecommendedAction.HOLD_FOR_REVIEW,
                    "requires_human_review": True,
                }
            )
        return merged

    def _merge(
        self,
        baseline: SecurityAssessment,
        llm_assessment: SecurityAssessment,
    ) -> SecurityAssessment:
        return self.merge_assessments(baseline, llm_assessment)

    @staticmethod
    def merge_assessments(
        baseline: SecurityAssessment, llm_assessment: SecurityAssessment
    ) -> SecurityAssessment:
        risk_level = max(
            (baseline.risk_level, llm_assessment.risk_level),
            key=lambda level: _RISK_ORDER[level],
        )
        violation = (
            baseline.violation_type
            if baseline.violation_type != ViolationType.NORMAL
            else llm_assessment.violation_type
        )
        action = RuleBasedAnalyzer.recommended_action(risk_level, violation)
        evidence = list(dict.fromkeys([*baseline.evidence, *llm_assessment.evidence]))[:20]
        return SecurityAssessment(
            risk_score=max(baseline.risk_score, llm_assessment.risk_score),
            risk_level=risk_level,
            violation_type=violation,
            rationale=("규칙 기준선과 LLM 심층 검토를 결합했습니다. " + llm_assessment.rationale)[
                :1000
            ],
            recommended_action=action,
            confidence=round((baseline.confidence + llm_assessment.confidence) / 2, 3),
            evidence=evidence,
            requires_human_review=(
                baseline.requires_human_review
                or llm_assessment.requires_human_review
                or baseline.violation_type != llm_assessment.violation_type
            ),
        )
