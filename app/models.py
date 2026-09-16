from datetime import UTC, date, datetime
from enum import Enum
from typing import Annotated, Literal, Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ViolationType(str, Enum):
    NORMAL = "NORMAL"
    CREDENTIAL_ANOMALY = "CREDENTIAL_ANOMALY"
    UNMANAGED_DEVICE = "UNMANAGED_DEVICE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    UNKNOWN = "UNKNOWN"


class RecommendedAction(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_MFA = "REQUIRE_MFA"
    REDUCE_PRIVILEGE = "REDUCE_PRIVILEGE"
    ISOLATE_SESSION = "ISOLATE_SESSION"
    HOLD_FOR_REVIEW = "HOLD_FOR_REVIEW"


class ReviewStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    IN_REVIEW = "IN_REVIEW"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class ControlStatus(str, Enum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partially_implemented"
    PLANNED = "planned"
    NOT_APPLICABLE = "not_applicable"


class ControlPriority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class EvidenceKind(str, Enum):
    AUTOMATED_TEST = "automated_test"
    CODE = "code"
    CONFIGURATION = "configuration"
    DOCUMENTATION = "documentation"


class EventAction(str, Enum):
    LOGIN = "LOGIN"
    READ = "READ"
    DOWNLOAD = "DOWNLOAD"
    ADMIN = "ADMIN"
    REMOTE_ACCESS = "REMOTE_ACCESS"


class ScenarioCategory(str, Enum):
    NORMAL = "NORMAL"
    NORMAL_EXCEPTION = "NORMAL_EXCEPTION"
    THREAT = "THREAT"


class ConditionOperator(str, Enum):
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN = "lt"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"


class ExceptionScope(StrictModel):
    user_ids: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list,
        max_length=20,
    )
    roles: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list,
        max_length=20,
    )
    resource_ids: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list,
        max_length=20,
    )
    resource_types: list[Annotated[str, Field(min_length=1, max_length=64)]] = Field(
        default_factory=list,
        max_length=20,
    )
    actions: list[EventAction] = Field(default_factory=list, max_length=5)
    max_download_volume_mb: float | None = Field(default=None, gt=0)


class PolicyException(StrictModel):
    exception_id: str = Field(pattern=r"^EXC-[A-Z0-9-]{3,48}$")
    approved_by: str = Field(min_length=2, max_length=64)
    reason: str = Field(min_length=5, max_length=300)
    valid_from: datetime
    valid_until: datetime
    scope: ExceptionScope

    @model_validator(mode="after")
    def validate_time_window(self) -> Self:
        for field_name, value in (
            ("valid_from", self.valid_from),
            ("valid_until", self.valid_until),
        ):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must include a timezone")
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be later than valid_from")
        return self

    def applies_to(
        self,
        *,
        timestamp: datetime,
        user_id: str,
        role: str,
        resource_id: str,
        resource_type: str,
        action: EventAction,
        download_volume_mb: float,
    ) -> bool:
        scope = self.scope
        checks = (
            self.valid_from <= timestamp <= self.valid_until,
            not scope.user_ids or user_id in scope.user_ids,
            not scope.roles or role in scope.roles,
            not scope.resource_ids or resource_id in scope.resource_ids,
            not scope.resource_types or resource_type in scope.resource_types,
            not scope.actions or action in scope.actions,
            scope.max_download_volume_mb is None
            or download_volume_mb <= scope.max_download_volume_mb,
        )
        return all(checks)


class UserContext(StrictModel):
    user_id: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=64)
    department: str | None = Field(default=None, max_length=64)
    active: bool = True


class DeviceContext(StrictModel):
    device_id: str = Field(min_length=1, max_length=64)
    managed: bool
    security_posture: Literal["healthy", "unknown", "at_risk", "compromised"]


class NetworkContext(StrictModel):
    ip: str = Field(min_length=1, max_length=64)
    location: str = Field(min_length=1, max_length=64)
    access_method: Literal["office", "vpn", "remote", "unknown"] = "unknown"
    location_anomaly: bool = False


class ResourceContext(StrictModel):
    resource_id: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(min_length=1, max_length=64)
    sensitivity: Literal["public", "internal", "high", "critical"]
    required_role: str | None = Field(default=None, max_length=64)


class AuthContext(StrictModel):
    mfa: Literal["not_required", "success", "failed", "unknown"] = "unknown"
    failed_attempts: int = Field(default=0, ge=0, le=100)
    session_age_minutes: int = Field(default=0, ge=0)


class BehaviorContext(StrictModel):
    new_device: bool = False
    unusual_time: bool = False
    request_rate: Literal["normal", "high"] = "normal"
    download_volume_mb: float = Field(default=0, ge=0)
    distinct_resources_10m: int = Field(default=1, ge=0)
    policy_exception_approved: bool = False
    policy_exception: PolicyException | None = None
    event_text: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def exception_requires_approval_flag(self) -> Self:
        if self.policy_exception_approved != (self.policy_exception is not None):
            raise ValueError(
                "policy_exception_approved must be true exactly when policy_exception is supplied"
            )
        return self


class GroundTruth(StrictModel):
    scenario_id: str
    risk_level: RiskLevel
    expected_action: RecommendedAction


class SecurityEvent(StrictModel):
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    user: UserContext
    device: DeviceContext
    network: NetworkContext
    resource: ResourceContext
    action: EventAction
    auth_context: AuthContext
    behavior: BehaviorContext
    ground_truth: GroundTruth | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_context_consistency(self) -> Self:
        if self.action != EventAction.DOWNLOAD and self.behavior.download_volume_mb > 0:
            raise ValueError("download_volume_mb must be zero unless action is DOWNLOAD")
        if self.auth_context.mfa == "failed" and self.auth_context.failed_attempts == 0:
            raise ValueError("failed MFA requires at least one failed attempt")
        if self.action == EventAction.REMOTE_ACCESS and self.network.access_method not in {
            "remote",
            "vpn",
        }:
            raise ValueError("REMOTE_ACCESS requires a remote or vpn access method")

        exception = self.behavior.policy_exception
        if exception and not exception.applies_to(
            timestamp=self.timestamp,
            user_id=self.user.user_id,
            role=self.user.role,
            resource_id=self.resource.resource_id,
            resource_type=self.resource.resource_type,
            action=self.action,
            download_volume_mb=self.behavior.download_volume_mb,
        ):
            raise ValueError("policy_exception does not apply to this event context")
        return self

    def analysis_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"ground_truth"})


class SecurityAssessment(StrictModel):
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    violation_type: ViolationType
    rationale: str = Field(min_length=5, max_length=1000)
    recommended_action: RecommendedAction
    confidence: float = Field(ge=0, le=1)
    evidence: list[Annotated[str, Field(min_length=1, max_length=160)]] = Field(
        default_factory=list,
        max_length=20,
    )
    requires_human_review: bool


class PolicyDecision(StrictModel):
    mode: Literal["simulation"] = "simulation"
    action: RecommendedAction
    allowed: bool
    requires_human_review: bool
    reason: str
    controls_applied: list[str] = Field(default_factory=list, max_length=20)
    exception_id: str | None = None


class AnalysisResult(StrictModel):
    analysis_id: str = Field(default_factory=lambda: uuid4().hex)
    event_id: str
    analyzer: Literal["rule", "openai", "hybrid"]
    assessment: SecurityAssessment
    policy_decision: PolicyDecision
    latency_ms: float = Field(ge=0)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = Field(default="local", pattern=r"^[a-zA-Z0-9._-]{1,64}$")
    actor_id: str = Field(default="local-operator", min_length=1, max_length=128)
    request_id: str = Field(default="legacy", min_length=1, max_length=128)
    review_status: ReviewStatus
    reviewer: str | None = Field(default=None, min_length=2, max_length=64)
    review_note: str | None = Field(default=None, min_length=3, max_length=500)
    review_updated_at: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def default_review_status(cls, value: object) -> object:
        if not isinstance(value, dict) or "review_status" in value:
            return value
        decision = value.get("policy_decision")
        if isinstance(decision, dict):
            requires_review = bool(decision.get("requires_human_review"))
        else:
            requires_review = bool(getattr(decision, "requires_human_review", False))
        return {
            **value,
            "review_status": (
                ReviewStatus.PENDING if requires_review else ReviewStatus.NOT_REQUIRED
            ),
        }

    @model_validator(mode="after")
    def validate_review_metadata(self) -> Self:
        active_statuses = {
            ReviewStatus.IN_REVIEW,
            ReviewStatus.RESOLVED,
            ReviewStatus.DISMISSED,
        }
        if self.review_status in active_statuses:
            if self.reviewer is None or self.review_updated_at is None:
                raise ValueError("reviewer and review_updated_at are required for reviewed results")
            if (
                self.review_status in {ReviewStatus.RESOLVED, ReviewStatus.DISMISSED}
                and not self.review_note
            ):
                raise ValueError("resolved or dismissed reviews require a note")
        elif any((self.reviewer, self.review_note, self.review_updated_at)):
            raise ValueError("unreviewed results cannot contain review metadata")
        if self.review_updated_at is not None and (
            self.review_updated_at.tzinfo is None
            or self.review_updated_at.utcoffset() is None
        ):
            raise ValueError("review_updated_at must include a timezone")
        return self


class ReviewUpdateRequest(StrictModel):
    status: ReviewStatus
    reviewer: str | None = Field(default=None, min_length=2, max_length=64)
    note: str | None = Field(default=None, min_length=3, max_length=500)

    @field_validator("reviewer")
    @classmethod
    def normalize_reviewer(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) < 2:
            raise ValueError("reviewer must contain at least two visible characters")
        return normalized

    @field_validator("note")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if len(normalized) < 3:
            raise ValueError("note must contain at least three visible characters")
        return normalized

    @model_validator(mode="after")
    def validate_review_transition_request(self) -> Self:
        if self.status in {ReviewStatus.NOT_REQUIRED, ReviewStatus.PENDING}:
            raise ValueError("review updates require an active or terminal status")
        if self.status in {ReviewStatus.RESOLVED, ReviewStatus.DISMISSED} and not self.note:
            raise ValueError("resolved or dismissed reviews require a note")
        return self


class BatchAnalysisRequest(StrictModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=20)


class BatchAnalysisResult(StrictModel):
    analyzer: Literal["rule", "openai", "hybrid"]
    requested: int = Field(ge=1, le=20)
    completed: int = Field(ge=0, le=20)
    results: list[AnalysisResult]


class MetricsSummary(StrictModel):
    total_analyses: int = Field(ge=0)
    risk_counts: dict[str, int]
    action_counts: dict[str, int]
    analyzer_counts: dict[str, int]
    review_counts: dict[str, int]
    pending_review_count: int = Field(default=0, ge=0)
    latest_event_id: str | None = None
    average_latency_ms: float = Field(default=0, ge=0)
    p95_latency_ms: float = Field(default=0, ge=0)


class ControlSource(StrictModel):
    framework: str = Field(min_length=2, max_length=120)
    reference: str = Field(min_length=2, max_length=200)
    url: str = Field(pattern=r"^https://", max_length=500)


class ControlEvidence(StrictModel):
    evidence_id: str = Field(pattern=r"^EVD-[A-Z0-9-]{3,64}$")
    kind: EvidenceKind
    location: str = Field(min_length=3, max_length=300)
    description: str = Field(min_length=5, max_length=300)


class ControlRecord(StrictModel):
    control_id: str = Field(pattern=r"^[A-Z][A-Z0-9]{1,7}-\d{2}$")
    title: str = Field(min_length=3, max_length=160)
    domain: str = Field(pattern=r"^[a-z][a-z0-9_]{2,39}$")
    priority: ControlPriority
    status: ControlStatus
    owner_role: str = Field(min_length=2, max_length=80)
    objective: str = Field(min_length=10, max_length=500)
    acceptance_criteria: list[Annotated[str, Field(min_length=5, max_length=300)]] = Field(
        min_length=1,
        max_length=12,
    )
    sources: list[ControlSource] = Field(min_length=1, max_length=12)
    evidence: list[ControlEvidence] = Field(default_factory=list, max_length=30)
    reviewed_on: date
    review_due_on: date
    target_version: str = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def validate_assurance_claim(self) -> Self:
        if self.review_due_on <= self.reviewed_on:
            raise ValueError("review_due_on must be later than reviewed_on")
        evidence_kinds = {item.kind for item in self.evidence}
        if self.status == ControlStatus.IMPLEMENTED:
            if EvidenceKind.AUTOMATED_TEST not in evidence_kinds:
                raise ValueError("implemented controls require automated test evidence")
            if not evidence_kinds.intersection(
                {EvidenceKind.CODE, EvidenceKind.CONFIGURATION}
            ):
                raise ValueError("implemented controls require code or configuration evidence")
        if self.status == ControlStatus.PARTIAL and not self.evidence:
            raise ValueError("partially implemented controls require evidence")
        return self


class ControlRegistryPayload(StrictModel):
    registry_version: str = Field(pattern=r"^\d{4}\.\d{2}\.\d+$")
    controls: list[ControlRecord] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def control_ids_must_be_unique(self) -> Self:
        identifiers = [control.control_id for control in self.controls]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("control IDs must be unique")
        return self


class AssuranceSummary(StrictModel):
    registry_version: str
    registry_digest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    as_of: date
    valid: bool
    total_controls: int = Field(ge=0)
    applicable_controls: int = Field(ge=0)
    implementation_rate: float = Field(ge=0, le=1)
    status_counts: dict[str, int]
    priority_counts: dict[str, int]
    domain_counts: dict[str, int]
    evidence_count: int = Field(ge=0)
    overdue_control_ids: list[str]


class SimulationRequest(StrictModel):
    scenario_id: str | None = None
    count: int | None = Field(default=None, ge=1, le=50)


class ResponsePreviewRequest(StrictModel):
    event_id: str
    assessment: SecurityAssessment
    event: SecurityEvent | None = None


ConditionScalar = bool | int | float | str


class ScenarioCondition(StrictModel):
    field: str = Field(
        pattern=(
            r"^(user|device|network|resource|auth_context|behavior)\."
            r"[a-z][a-z0-9_]*$|^action$"
        )
    )
    operator: ConditionOperator
    value: ConditionScalar | list[ConditionScalar]
    description: str = Field(min_length=3, max_length=160)

    @model_validator(mode="after")
    def operator_matches_value(self) -> Self:
        is_collection = isinstance(self.value, list)
        if self.operator in {ConditionOperator.IN, ConditionOperator.NOT_IN} and not is_collection:
            raise ValueError("in and not_in conditions require a list value")
        if self.operator not in {ConditionOperator.IN, ConditionOperator.NOT_IN} and is_collection:
            raise ValueError("only in and not_in conditions accept a list value")
        if self.operator in {
            ConditionOperator.GREATER_THAN,
            ConditionOperator.GREATER_THAN_OR_EQUAL,
            ConditionOperator.LESS_THAN,
            ConditionOperator.LESS_THAN_OR_EQUAL,
        } and (is_collection or isinstance(self.value, (bool, str))):
            raise ValueError("ordered comparisons require a numeric value")
        return self


class AttackTechnique(StrictModel):
    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")
    name: str = Field(min_length=1, max_length=128)
    reference_url: str = Field(
        pattern=r"^https://attack\.mitre\.org/techniques/T\d{4}(?:/\d{3})?/$"
    )


class ScenarioSummary(StrictModel):
    scenario_id: str
    name: str
    category: ScenarioCategory
    description: str = Field(min_length=10, max_length=500)
    attack_tactic: str
    attack_techniques: list[AttackTechnique] = Field(default_factory=list, max_length=5)
    observable_signals: list[Annotated[str, Field(min_length=1, max_length=160)]] = Field(
        min_length=1, max_length=20
    )
    detection_conditions: list[ScenarioCondition] = Field(min_length=1, max_length=20)
    detection_logic: Literal["all", "any"] = "all"
    normal_exceptions: list[Annotated[str, Field(min_length=1, max_length=160)]] = Field(
        default_factory=list, max_length=10
    )
    expected_risk: RiskLevel
    expected_action: RecommendedAction

    @model_validator(mode="after")
    def threat_requires_attack_mapping(self) -> Self:
        if self.category == ScenarioCategory.THREAT and not self.attack_techniques:
            raise ValueError("threat scenarios require at least one ATT&CK technique")
        if self.category != ScenarioCategory.THREAT and self.attack_techniques:
            raise ValueError("normal scenarios must not claim an ATT&CK technique")
        return self


class ScenarioMatch(StrictModel):
    scenario_id: str
    name: str
    matched: bool
    coverage: float = Field(ge=0, le=1)
    matched_conditions: list[str]
    unmet_conditions: list[str]


class EventScenarioEvaluation(StrictModel):
    event_id: str
    best_match: str | None
    matches: list[ScenarioMatch]


class EvaluationRequest(StrictModel):
    analyzer: Literal["rule", "openai", "hybrid"] = "rule"
    runs_per_scenario: int = Field(default=1, ge=1, le=10)
    concurrency: int = Field(default=4, ge=1, le=10)


class EvaluationCaseResult(StrictModel):
    event_id: str
    scenario_id: str
    expected_risk: RiskLevel
    actual_risk: RiskLevel | None
    expected_action: RecommendedAction
    actual_action: RecommendedAction | None
    risk_correct: bool
    action_correct: bool
    threat_expected: bool
    threat_detected: bool
    json_valid: bool = True
    latency_ms: float = Field(ge=0)
    error_category: Literal["timeout", "provider", "validation", "runtime"] | None = None


class ScenarioEvaluationSummary(StrictModel):
    scenario_id: str
    total_cases: int = Field(ge=1)
    risk_accuracy: float = Field(ge=0, le=1)
    action_accuracy: float = Field(ge=0, le=1)
    error_count: int = Field(ge=0)
    average_latency_ms: float = Field(ge=0)
    p95_latency_ms: float = Field(ge=0)


class EvaluationTargets(StrictModel):
    risk_accuracy: float = Field(default=0.7, ge=0, le=1)
    action_accuracy: float = Field(default=0.7, ge=0, le=1)
    threat_f1: float = Field(default=0.8, ge=0, le=1)
    json_valid_rate: float = Field(default=0.9, ge=0, le=1)
    maximum_error_rate: float = Field(default=0.05, ge=0, le=1)
    p95_latency_ms: float = Field(default=3000, gt=0)


class EvaluationSummary(StrictModel):
    analyzer: Literal["rule", "openai", "hybrid"]
    total_cases: int = Field(ge=1)
    risk_accuracy: float = Field(ge=0, le=1)
    action_accuracy: float = Field(ge=0, le=1)
    threat_precision: float = Field(ge=0, le=1)
    threat_recall: float = Field(ge=0, le=1)
    threat_f1: float = Field(ge=0, le=1)
    json_valid_rate: float = Field(ge=0, le=1)
    error_count: int = Field(ge=0)
    error_rate: float = Field(ge=0, le=1)
    error_categories: dict[str, int]
    duration_ms: float = Field(ge=0)
    throughput_per_second: float = Field(ge=0)
    average_latency_ms: float = Field(ge=0)
    p50_latency_ms: float = Field(ge=0)
    p95_latency_ms: float = Field(ge=0)
    p99_latency_ms: float = Field(ge=0)
    risk_confusion_matrix: dict[str, dict[str, int]]
    scenario_breakdown: list[ScenarioEvaluationSummary]
    targets: EvaluationTargets = Field(default_factory=EvaluationTargets)
    targets_met: dict[str, bool]
    cases: list[EvaluationCaseResult]
