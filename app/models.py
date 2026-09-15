from datetime import UTC, datetime
from enum import Enum
from typing import Annotated, Literal, Self

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


class ScenarioCategory(str, Enum):
    NORMAL = "NORMAL"
    NORMAL_EXCEPTION = "NORMAL_EXCEPTION"
    THREAT = "THREAT"


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
    event_text: str | None = Field(default=None, max_length=500)


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
    action: Literal["LOGIN", "READ", "DOWNLOAD", "ADMIN", "REMOTE_ACCESS"]
    auth_context: AuthContext
    behavior: BehaviorContext
    ground_truth: GroundTruth | None = None

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_have_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

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


class AnalysisResult(StrictModel):
    event_id: str
    analyzer: Literal["rule", "openai"]
    assessment: SecurityAssessment
    policy_decision: PolicyDecision
    latency_ms: float = Field(ge=0)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MetricsSummary(StrictModel):
    total_analyses: int = Field(ge=0)
    risk_counts: dict[str, int]
    action_counts: dict[str, int]
    analyzer_counts: dict[str, int]
    latest_event_id: str | None = None


class SimulationRequest(StrictModel):
    scenario_id: str | None = None
    count: int | None = Field(default=None, ge=1, le=50)


class ResponsePreviewRequest(StrictModel):
    event_id: str
    assessment: SecurityAssessment


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
