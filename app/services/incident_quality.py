import json
from functools import lru_cache
from hashlib import sha256

from app.models import (
    DetectionConfusionCounts,
    IncidentDatasetQuality,
    IncidentQualityReport,
    IncidentQualityTargets,
)
from app.services.correlation import CorrelationEngine, get_correlation_engine
from app.services.public_replay import PublicReplayService, get_public_replay_service

EVALUATION_VERSION = "0.14.0"


class IncidentQualityService:
    version = EVALUATION_VERSION

    def __init__(
        self,
        replay_service: PublicReplayService,
        correlation_engine: CorrelationEngine,
    ) -> None:
        self._replay_service = replay_service
        self._correlation_engine = correlation_engine

    def evaluate(self, tenant_id: str) -> IncidentQualityReport:
        suite = self._replay_service.run_all(tenant_id)
        targets = self._replay_service.incident_quality_targets
        expected_labels: list[bool] = []
        observed_labels: list[bool] = []
        dataset_results: list[IncidentDatasetQuality] = []

        for replay in suite.results:
            expected_incident = replay.dataset.expected_incident_count > 0
            observed_incident = bool(replay.incidents)
            observed_windows = sorted(incident.window_minutes for incident in replay.incidents)
            observed_deduplicated_count = sum(
                summary.deduplicated_count for summary in replay.window_summaries
            )
            expected_labels.append(expected_incident)
            observed_labels.append(observed_incident)
            dataset_results.append(
                IncidentDatasetQuality(
                    dataset_id=replay.dataset.dataset_id,
                    expected_incident_count=replay.dataset.expected_incident_count,
                    observed_incident_count=len(replay.incidents),
                    expected_windows_minutes=(
                        replay.dataset.expected_incident_windows_minutes
                    ),
                    observed_windows_minutes=observed_windows,
                    expected_entity_node_count=(
                        replay.dataset.expected_entity_node_count
                    ),
                    observed_entity_node_count=replay.entity_graph.node_count,
                    expected_entity_edge_count=(
                        replay.dataset.expected_entity_edge_count
                    ),
                    observed_entity_edge_count=replay.entity_graph.edge_count,
                    expected_deduplicated_count=(
                        replay.dataset.expected_deduplicated_count
                    ),
                    observed_deduplicated_count=observed_deduplicated_count,
                    incident_classification_correct=(
                        len(replay.incidents) == replay.dataset.expected_incident_count
                    ),
                    window_match=(
                        observed_windows
                        == replay.dataset.expected_incident_windows_minutes
                    ),
                    graph_structure_match=(
                        replay.entity_graph.node_count
                        == replay.dataset.expected_entity_node_count
                        and replay.entity_graph.edge_count
                        == replay.dataset.expected_entity_edge_count
                    ),
                    deduplication_match=(
                        observed_deduplicated_count
                        == replay.dataset.expected_deduplicated_count
                    ),
                )
            )

        confusion = _confusion(expected_labels, observed_labels)
        precision, recall, f1, false_positive_rate = _metrics(confusion)
        positive_support = sum(expected_labels)
        negative_support = len(expected_labels) - positive_support
        window_results = [
            result for result in dataset_results if result.expected_incident_count > 0
        ]
        window_match_count = sum(result.window_match for result in window_results)
        graph_match_count = sum(result.graph_structure_match for result in dataset_results)
        deduplication_match_count = sum(
            result.deduplication_match for result in dataset_results
        )
        window_accuracy = _ratio(window_match_count, len(window_results))
        graph_structure_accuracy = _ratio(graph_match_count, len(dataset_results))
        deduplication_accuracy = _ratio(
            deduplication_match_count,
            len(dataset_results),
        )
        targets_met = {
            "dataset_count": suite.dataset_count >= targets.minimum_dataset_count,
            "positive_dataset_support": (
                positive_support >= targets.minimum_positive_dataset_support
            ),
            "negative_dataset_support": (
                negative_support >= targets.minimum_negative_dataset_support
            ),
            "precision": precision >= targets.minimum_precision,
            "recall": recall >= targets.minimum_recall,
            "f1": f1 >= targets.minimum_f1,
            "false_positive_rate": (
                false_positive_rate <= targets.maximum_false_positive_rate
            ),
            "window_accuracy": window_accuracy >= targets.minimum_window_accuracy,
            "graph_structure_accuracy": (
                graph_structure_accuracy >= targets.minimum_graph_structure_accuracy
            ),
            "deduplication_accuracy": (
                deduplication_accuracy >= targets.minimum_deduplication_accuracy
            ),
            "dataset_expectations": all(
                result.incident_expectation_met for result in suite.results
            ),
        }
        fingerprint = _fingerprint(
            self._replay_service.manifest_digest_sha256,
            self._correlation_engine.version,
            targets,
            dataset_results,
        )
        return IncidentQualityReport(
            evaluation_version=EVALUATION_VERSION,
            manifest_digest_sha256=self._replay_service.manifest_digest_sha256,
            correlation_version=self._correlation_engine.version,
            evaluation_fingerprint_sha256=fingerprint,
            dataset_count=suite.dataset_count,
            positive_dataset_support=positive_support,
            negative_dataset_support=negative_support,
            confusion=confusion,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            false_positive_rate=round(false_positive_rate, 4),
            window_evaluated_dataset_count=len(window_results),
            window_match_count=window_match_count,
            window_accuracy=round(window_accuracy, 4),
            graph_structure_match_count=graph_match_count,
            graph_structure_accuracy=round(graph_structure_accuracy, 4),
            deduplication_match_count=deduplication_match_count,
            deduplication_accuracy=round(deduplication_accuracy, 4),
            targets=targets,
            targets_met=targets_met,
            gate_passed=all(targets_met.values()),
            datasets=dataset_results,
        )


def _confusion(expected: list[bool], observed: list[bool]) -> DetectionConfusionCounts:
    return DetectionConfusionCounts(
        true_positive=sum(truth and prediction for truth, prediction in zip(expected, observed)),
        false_positive=sum(
            not truth and prediction for truth, prediction in zip(expected, observed)
        ),
        false_negative=sum(
            truth and not prediction for truth, prediction in zip(expected, observed)
        ),
        true_negative=sum(
            not truth and not prediction for truth, prediction in zip(expected, observed)
        ),
    )


def _metrics(confusion: DetectionConfusionCounts) -> tuple[float, float, float, float]:
    precision = _ratio(
        confusion.true_positive,
        confusion.true_positive + confusion.false_positive,
    )
    recall = _ratio(
        confusion.true_positive,
        confusion.true_positive + confusion.false_negative,
    )
    f1 = _ratio(2 * precision * recall, precision + recall)
    false_positive_rate = _ratio(
        confusion.false_positive,
        confusion.false_positive + confusion.true_negative,
    )
    return precision, recall, f1, false_positive_rate


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _fingerprint(
    manifest_digest: str,
    correlation_version: str,
    targets: IncidentQualityTargets,
    datasets: list[IncidentDatasetQuality],
) -> str:
    material = {
        "manifest_digest_sha256": manifest_digest,
        "correlation_version": correlation_version,
        "targets": targets.model_dump(mode="json"),
        "datasets": [
            result.model_dump(mode="json")
            for result in sorted(datasets, key=lambda item: item.dataset_id)
        ],
    }
    return sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


@lru_cache
def get_incident_quality_service() -> IncidentQualityService:
    return IncidentQualityService(
        get_public_replay_service(),
        get_correlation_engine(),
    )
