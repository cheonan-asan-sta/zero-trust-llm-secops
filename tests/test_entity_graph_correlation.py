from datetime import timedelta

import pytest
from pydantic import ValidationError

from app.models import CorrelationPolicy, DetectionPipelineResult
from app.scenarios import synthetic_events
from app.services.correlation import get_correlation_engine
from app.services.ocsf import get_ocsf_normalizer
from app.services.sigma import get_sigma_engine


def _threat_events():
    return [
        event
        for event in synthetic_events()
        if event.ground_truth.scenario_id.startswith("ZT-")
    ]


def _pipeline(event):
    normalized = get_ocsf_normalizer().normalize(event)
    return DetectionPipelineResult(
        normalized=normalized,
        detection=get_sigma_engine().evaluate(normalized),
    )


def test_default_windows_deduplicate_identical_incident_evidence() -> None:
    result = get_correlation_engine().correlate(
        [_pipeline(event) for event in _threat_events()],
        "local",
    )

    assert result.windows_evaluated == [5, 30, 1440]
    assert result.incident_count == 1
    assert result.incidents[0].window_minutes == 5
    assert [summary.incident_count for summary in result.window_summaries] == [1, 0, 0]
    assert [summary.deduplicated_count for summary in result.window_summaries] == [0, 1, 1]


def test_entity_graph_is_deterministic_and_covers_all_relationship_types() -> None:
    pipelines = [_pipeline(event) for event in _threat_events()]
    engine = get_correlation_engine()

    forward = engine.correlate(pipelines, "local")
    reversed_result = engine.correlate(list(reversed(pipelines)), "local")
    graph = forward.entity_graph

    assert graph == reversed_result.entity_graph
    assert graph.node_count == 16
    assert graph.edge_count == 17
    assert {node.entity_type for node in graph.nodes} == {
        "user",
        "source_ip",
        "device",
        "resource",
        "detection_rule",
    }
    assert {edge.relationship for edge in graph.edges} == {
        "originated_from",
        "used_device",
        "accessed_resource",
        "triggered_rule",
    }
    assert len({node.entity_uid for node in graph.nodes}) == graph.node_count
    assert len({edge.edge_uid for edge in graph.edges}) == graph.edge_count
    assert set(forward.incidents[0].entity_uids) == {
        node.entity_uid for node in graph.nodes
    }


def test_entity_identifiers_and_graph_digest_are_tenant_scoped() -> None:
    pipelines = [_pipeline(event) for event in _threat_events()]
    engine = get_correlation_engine()

    tenant_a = engine.correlate(pipelines, "tenant-a")
    tenant_b = engine.correlate(pipelines, "tenant-b")

    assert tenant_a.entity_graph.node_count == tenant_b.entity_graph.node_count
    assert tenant_a.entity_graph.edge_count == tenant_b.entity_graph.edge_count
    assert tenant_a.entity_graph.graph_digest_sha256 != tenant_b.entity_graph.graph_digest_sha256
    assert {node.entity_uid for node in tenant_a.entity_graph.nodes}.isdisjoint(
        node.entity_uid for node in tenant_b.entity_graph.nodes
    )
    assert tenant_a.incidents[0].incident_uid != tenant_b.incidents[0].incident_uid


def test_shared_device_correlates_activity_across_users_and_source_ips() -> None:
    first, second = _threat_events()[2:4]
    device = first.device.model_copy(update={"device_id": "shared-jump-host"})
    events = [
        first.model_copy(
            update={
                "event_id": "shared-device-first",
                "user": first.user.model_copy(update={"user_id": "user-first"}),
                "device": device,
                "network": first.network.model_copy(update={"ip": "198.51.100.21"}),
            }
        ),
        second.model_copy(
            update={
                "event_id": "shared-device-second",
                "user": second.user.model_copy(update={"user_id": "user-second"}),
                "device": device,
                "network": second.network.model_copy(update={"ip": "198.51.100.22"}),
            }
        ),
    ]

    result = get_correlation_engine().correlate(
        [_pipeline(event) for event in events],
        "local",
    )

    assert result.incident_count == 1
    assert result.incidents[0].user_ids == ["user-first", "user-second"]
    assert result.incidents[0].source_ips == ["198.51.100.21", "198.51.100.22"]
    assert result.incidents[0].device_ids == ["shared-jump-host"]


def test_activity_outside_five_minutes_correlates_in_thirty_minute_window() -> None:
    source = _threat_events()[1]
    events = [
        source.model_copy(
            update={
                "event_id": f"thirty-minute-{index}",
                "timestamp": source.timestamp + timedelta(minutes=index * 10),
                "resource": source.resource.model_copy(
                    update={"resource_id": f"document-{index}"}
                ),
            }
        )
        for index in range(3)
    ]

    result = get_correlation_engine().correlate(
        [_pipeline(event) for event in events],
        "local",
    )

    assert result.incident_count == 1
    assert result.incidents[0].window_minutes == 30
    assert [summary.incident_count for summary in result.window_summaries] == [0, 1, 0]
    assert result.window_summaries[2].deduplicated_count == 1


def test_single_window_policy_remains_backward_compatible() -> None:
    result = get_correlation_engine().correlate(
        [_pipeline(event) for event in _threat_events()],
        "local",
        CorrelationPolicy(window_minutes=30),
    )

    assert result.windows_evaluated == [30]
    assert len(result.window_summaries) == 1
    assert result.incidents[0].window_minutes == 30


@pytest.mark.parametrize(
    "payload",
    [
        {"windows_minutes": [30, 5]},
        {"windows_minutes": [5, 5]},
        {"window_minutes": 30, "windows_minutes": [5, 30]},
    ],
)
def test_invalid_correlation_window_policies_fail_closed(payload: dict) -> None:
    with pytest.raises(ValidationError):
        CorrelationPolicy.model_validate(payload)
