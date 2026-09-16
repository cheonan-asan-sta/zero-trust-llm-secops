import json
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from typing import Literal

from app.models import (
    CorrelationEntityEdge,
    CorrelationEntityGraph,
    CorrelationEntityNode,
    CorrelationPolicy,
    CorrelationResult,
    CorrelationWindowSummary,
    DetectionPipelineResult,
    IncidentFindingEvidence,
    OCSFIncidentFinding,
    SigmaDetectionMatch,
    SigmaRuleLevel,
)

CORRELATION_VERSION = "0.14.0"
_LEVEL_ORDER = {
    SigmaRuleLevel.INFORMATIONAL: 1,
    SigmaRuleLevel.LOW: 2,
    SigmaRuleLevel.MEDIUM: 3,
    SigmaRuleLevel.HIGH: 4,
    SigmaRuleLevel.CRITICAL: 5,
}
_EntityType = Literal["user", "source_ip", "device", "resource", "detection_rule"]
_Relationship = Literal[
    "originated_from",
    "used_device",
    "accessed_resource",
    "triggered_rule",
]
_ENTITY_RELATIONSHIPS: tuple[tuple[_EntityType, _EntityType, _Relationship], ...] = (
    ("user", "source_ip", "originated_from"),
    ("user", "device", "used_device"),
    ("user", "resource", "accessed_resource"),
    ("resource", "detection_rule", "triggered_rule"),
)


@dataclass(frozen=True)
class _Finding:
    pipeline: DetectionPipelineResult
    match: SigmaDetectionMatch

    @property
    def time(self) -> int:
        return self.pipeline.normalized.event.time

    @property
    def event_id(self) -> str:
        return self.pipeline.normalized.provenance.source_event_id

    @property
    def user_id(self) -> str:
        return self.pipeline.normalized.event.actor.user.uid

    @property
    def source_ip(self) -> str:
        return self.pipeline.normalized.event.src_endpoint.ip

    @property
    def device_id(self) -> str:
        return self.pipeline.normalized.event.device.uid

    @property
    def resource_id(self) -> str:
        return self.pipeline.normalized.event.resources[0].uid


@dataclass
class _Observation:
    first_seen: int
    last_seen: int
    event_ids: set[str]

    def add(self, time: int, event_id: str) -> None:
        self.first_seen = min(self.first_seen, time)
        self.last_seen = max(self.last_seen, time)
        self.event_ids.add(event_id)


class CorrelationEngine:
    version = CORRELATION_VERSION

    def correlate(
        self,
        pipelines: list[DetectionPipelineResult],
        tenant_id: str,
        policy: CorrelationPolicy | None = None,
    ) -> CorrelationResult:
        active_policy = policy or CorrelationPolicy()
        findings: list[_Finding] = []

        for pipeline in pipelines:
            for match in pipeline.detection.matches:
                finding = _Finding(pipeline=pipeline, match=match)
                findings.append(finding)

        ordered_groups = [
            sorted(
                group,
                key=lambda item: (item.time, item.event_id, item.match.rule_id),
            )
            for group in _group_connected_findings(findings)
        ]
        incidents: list[OCSFIncidentFinding] = []
        incident_uids: set[str] = set()
        window_summaries: list[CorrelationWindowSummary] = []
        windows = active_policy.effective_windows_minutes

        for window_minutes in windows:
            candidate_count = 0
            accepted_count = 0
            deduplicated_count = 0
            window_ms = window_minutes * 60 * 1000
            for group in ordered_groups:
                for window in _partition_windows(group, window_ms):
                    incident = _build_incident(
                        window,
                        tenant_id,
                        active_policy,
                        window_minutes,
                    )
                    if incident is None:
                        continue
                    candidate_count += 1
                    if incident.incident_uid in incident_uids:
                        deduplicated_count += 1
                        continue
                    incident_uids.add(incident.incident_uid)
                    incidents.append(incident)
                    accepted_count += 1
            window_summaries.append(
                CorrelationWindowSummary(
                    window_minutes=window_minutes,
                    evaluated_group_count=len(ordered_groups),
                    candidate_count=candidate_count,
                    incident_count=accepted_count,
                    deduplicated_count=deduplicated_count,
                )
            )

        incidents.sort(key=lambda item: (item.start_time, item.incident_uid))
        return CorrelationResult(
            correlation_version=CORRELATION_VERSION,
            analyzed_event_count=len(pipelines),
            finding_count=len(findings),
            incident_count=len(incidents),
            windows_evaluated=windows,
            window_summaries=window_summaries,
            entity_graph=_build_entity_graph(findings, tenant_id),
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


def _group_connected_findings(findings: list[_Finding]) -> list[list[_Finding]]:
    parents = list(range(len(findings)))
    first_by_entity: dict[tuple[str, str], int] = {}

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    for index, finding in enumerate(findings):
        for entity in _correlation_entities(finding):
            previous = first_by_entity.setdefault(entity, index)
            union(index, previous)

    grouped: dict[int, list[_Finding]] = {}
    for index, finding in enumerate(findings):
        grouped.setdefault(find(index), []).append(finding)
    return sorted(
        grouped.values(),
        key=lambda group: min((item.time, item.event_id, item.match.rule_id) for item in group),
    )


def _build_incident(
    findings: list[_Finding],
    tenant_id: str,
    policy: CorrelationPolicy,
    window_minutes: int,
) -> OCSFIncidentFinding | None:
    event_ids = sorted({item.event_id for item in findings})
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
            source_event_id=item.event_id,
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
    devices = sorted({item.device_id for item in findings})
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
    digest = _canonical_digest(incident_material)
    rule_titles = sorted({item.match.title for item in findings})
    entity_uids = sorted(
        {
            _entity_uid(tenant_id, entity_type, value)
            for item in findings
            for entity_type, value in _finding_entities(item)
        }
    )
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
        window_minutes=window_minutes,
        start_time=start_time,
        end_time=end_time,
        finding_info_list=evidence,
        event_ids=event_ids,
        user_ids=users,
        source_ips=source_ips,
        device_ids=devices,
        resource_ids=resources,
        attack_tags=attack_tags,
        entity_uids=entity_uids,
        correlation_reasons=reasons,
        tenant_id=tenant_id,
    )


def _build_entity_graph(findings: list[_Finding], tenant_id: str) -> CorrelationEntityGraph:
    node_observations: dict[tuple[_EntityType, str], _Observation] = {}
    edge_observations: dict[tuple[str, str, _Relationship], _Observation] = {}

    for finding in findings:
        entities = dict(_finding_entities(finding))
        for entity_type, value in entities.items():
            key = (entity_type, value)
            observation = node_observations.setdefault(
                key,
                _Observation(finding.time, finding.time, set()),
            )
            observation.add(finding.time, finding.event_id)

        for source_type, target_type, relationship in _ENTITY_RELATIONSHIPS:
            source_uid = _entity_uid(tenant_id, source_type, entities[source_type])
            target_uid = _entity_uid(tenant_id, target_type, entities[target_type])
            key = (source_uid, target_uid, relationship)
            observation = edge_observations.setdefault(
                key,
                _Observation(finding.time, finding.time, set()),
            )
            observation.add(finding.time, finding.event_id)

    nodes = [
        CorrelationEntityNode(
            entity_uid=_entity_uid(tenant_id, entity_type, value),
            entity_type=entity_type,
            value=value,
            first_seen=observation.first_seen,
            last_seen=observation.last_seen,
            event_ids=sorted(observation.event_ids),
        )
        for (entity_type, value), observation in node_observations.items()
    ]
    nodes.sort(key=lambda node: (node.entity_type, node.value, node.entity_uid))
    edges = [
        CorrelationEntityEdge(
            edge_uid=_edge_uid(tenant_id, source_uid, target_uid, relationship),
            source_entity_uid=source_uid,
            target_entity_uid=target_uid,
            relationship=relationship,
            first_seen=observation.first_seen,
            last_seen=observation.last_seen,
            event_ids=sorted(observation.event_ids),
            observation_count=len(observation.event_ids),
        )
        for (source_uid, target_uid, relationship), observation in edge_observations.items()
    ]
    edges.sort(key=lambda edge: (edge.relationship, edge.source_entity_uid, edge.target_entity_uid))
    graph_material = {
        "nodes": [node.model_dump(mode="json") for node in nodes],
        "edges": [edge.model_dump(mode="json") for edge in edges],
    }
    return CorrelationEntityGraph(
        node_count=len(nodes),
        edge_count=len(edges),
        nodes=nodes,
        edges=edges,
        graph_digest_sha256=_canonical_digest(graph_material),
    )


def _finding_entities(finding: _Finding) -> tuple[tuple[_EntityType, str], ...]:
    return (
        ("user", finding.user_id),
        ("source_ip", finding.source_ip),
        ("device", finding.device_id),
        ("resource", finding.resource_id),
        ("detection_rule", finding.match.rule_id),
    )


def _correlation_entities(finding: _Finding) -> tuple[tuple[_EntityType, str], ...]:
    return (
        ("user", finding.user_id),
        ("source_ip", finding.source_ip),
        ("device", finding.device_id),
        ("resource", finding.resource_id),
    )


def _entity_uid(tenant_id: str, entity_type: _EntityType, value: str) -> str:
    digest = _canonical_digest(
        {"tenant_id": tenant_id, "entity_type": entity_type, "value": value}
    )
    return f"ent-{digest[:32]}"


def _edge_uid(
    tenant_id: str,
    source_entity_uid: str,
    target_entity_uid: str,
    relationship: _Relationship,
) -> str:
    digest = _canonical_digest(
        {
            "tenant_id": tenant_id,
            "source_entity_uid": source_entity_uid,
            "target_entity_uid": target_entity_uid,
            "relationship": relationship,
        }
    )
    return f"edge-{digest[:32]}"


def _canonical_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


@lru_cache
def get_correlation_engine() -> CorrelationEngine:
    return CorrelationEngine()
