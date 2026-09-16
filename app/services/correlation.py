import json
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256

from app.models import (
    CorrelationPolicy,
    CorrelationResult,
    DetectionPipelineResult,
    IncidentFindingEvidence,
    OCSFIncidentFinding,
    SigmaDetectionMatch,
    SigmaRuleLevel,
)

CORRELATION_VERSION = "0.10.0"
_LEVEL_ORDER = {
    SigmaRuleLevel.INFORMATIONAL: 1,
    SigmaRuleLevel.LOW: 2,
    SigmaRuleLevel.MEDIUM: 3,
    SigmaRuleLevel.HIGH: 4,
    SigmaRuleLevel.CRITICAL: 5,
}


@dataclass(frozen=True)
class _Finding:
    pipeline: DetectionPipelineResult
    match: SigmaDetectionMatch

    @property
    def time(self) -> int:
        return self.pipeline.normalized.event.time

    @property
    def user_id(self) -> str:
        return self.pipeline.normalized.event.actor.user.uid

    @property
    def source_ip(self) -> str:
        return self.pipeline.normalized.event.src_endpoint.ip

    @property
    def resource_id(self) -> str:
        return self.pipeline.normalized.event.resources[0].uid


class CorrelationEngine:
    version = CORRELATION_VERSION

    def correlate(
        self,
        pipelines: list[DetectionPipelineResult],
        tenant_id: str,
        policy: CorrelationPolicy | None = None,
    ) -> CorrelationResult:
        active_policy = policy or CorrelationPolicy()
        groups: dict[tuple[str, str], list[_Finding]] = defaultdict(list)
        finding_count = 0

        for pipeline in pipelines:
            for match in pipeline.detection.matches:
                finding = _Finding(pipeline=pipeline, match=match)
                groups[(finding.user_id, finding.source_ip)].append(finding)
                finding_count += 1

        incidents: list[OCSFIncidentFinding] = []
        window_ms = active_policy.window_minutes * 60 * 1000
        for findings in groups.values():
            ordered = sorted(
                findings,
                key=lambda item: (
                    item.time,
                    item.pipeline.normalized.provenance.source_event_id,
                    item.match.rule_id,
                ),
            )
            for window in _partition_windows(ordered, window_ms):
                incident = _build_incident(window, tenant_id, active_policy)
                if incident is not None:
                    incidents.append(incident)

        incidents.sort(key=lambda item: (item.start_time, item.incident_uid))
        return CorrelationResult(
            correlation_version=CORRELATION_VERSION,
            analyzed_event_count=len(pipelines),
            finding_count=finding_count,
            incident_count=len(incidents),
            incidents=incidents,
        )


def _partition_windows(findings: list[_Finding], window_ms: int) -> list[list[_Finding]]:
    windows: list[list[_Finding]] = []
    current: list[_Finding] = []
    window_start = 0
    for finding in findings:
        if current and finding.time - window_start > window_ms:
            windows.append(current)
            current = []
        if not current:
            window_start = finding.time
        current.append(finding)
    if current:
        windows.append(current)
    return windows


def _build_incident(
    findings: list[_Finding],
    tenant_id: str,
    policy: CorrelationPolicy,
) -> OCSFIncidentFinding | None:
    event_ids = sorted(
        {item.pipeline.normalized.provenance.source_event_id for item in findings}
    )
    rule_ids = sorted({item.match.rule_id for item in findings})
    resources = sorted({item.resource_id for item in findings})
    reasons: list[str] = []
    if len(rule_ids) >= policy.minimum_distinct_rules:
        reasons.append("multi_rule_attack_chain")
    if (
        len(event_ids) >= policy.minimum_repeated_events
        and len(resources) >= policy.minimum_distinct_resources
    ):
        reasons.append("repeated_detection_across_resources")
    if len(event_ids) < 2 or not reasons:
        return None

    start_time = min(item.time for item in findings)
    end_time = max(item.time for item in findings)
    evidence = [
        IncidentFindingEvidence(
            source_event_id=item.pipeline.normalized.provenance.source_event_id,
            time=item.time,
            rule_id=item.match.rule_id,
            rule_title=item.match.title,
            level=item.match.level,
            source_sha256=item.pipeline.normalized.provenance.source_sha256,
            resource_uid=item.resource_id,
        )
        for item in findings
    ]
    evidence.sort(key=lambda item: (item.time, item.source_event_id, item.rule_id))
    users = sorted({item.user_id for item in findings})
    source_ips = sorted({item.source_ip for item in findings})
    devices = sorted({item.pipeline.normalized.event.device.uid for item in findings})
    attack_tags = sorted(
        {
            tag
            for item in findings
            for tag in item.match.tags
            if tag.startswith("attack.")
        }
    )
    highest_level = max(
        (item.match.level for item in findings),
        key=lambda level: _LEVEL_ORDER[level],
    )
    severity_id = max(3, _LEVEL_ORDER[highest_level])
    confidence_score = min(
        99,
        45 + len(rule_ids) * 10 + len(event_ids) * 5 + len(resources) * 5,
    )
    incident_material = {
        "tenant_id": tenant_id,
        "event_ids": event_ids,
        "rule_ids": rule_ids,
        "start_time": start_time,
        "end_time": end_time,
        "users": users,
        "source_ips": source_ips,
    }
    digest = sha256(
        json.dumps(
            incident_material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    rule_titles = sorted({item.match.title for item in findings})
    return OCSFIncidentFinding(
        time=end_time,
        severity_id=severity_id,
        incident_uid=f"inc-{digest[:32]}",
        title=f"Correlated security activity for {users[0]}",
        desc=(
            f"Correlated {len(event_ids)} events and {len(rule_ids)} distinct rules: "
            + ", ".join(rule_titles)
        ),
        confidence_score=confidence_score,
        start_time=start_time,
        end_time=end_time,
        finding_info_list=evidence,
        event_ids=event_ids,
        user_ids=users,
        source_ips=source_ips,
        device_ids=devices,
        resource_ids=resources,
        attack_tags=attack_tags,
        correlation_reasons=reasons,
        tenant_id=tenant_id,
    )


@lru_cache
def get_correlation_engine() -> CorrelationEngine:
    return CorrelationEngine()
