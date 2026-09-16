import json
from functools import lru_cache
from hashlib import sha256

from app.models import (
    DetectionConfusionCounts,
    DetectionQualityReport,
    DetectionQualityTargets,
    PublicReplaySuiteResult,
    RuleDetectionQuality,
)
from app.services.public_replay import PublicReplayService, get_public_replay_service
from app.services.sigma import SigmaEngine, get_sigma_engine

EVALUATION_VERSION = "0.11.0"


class DetectionQualityService:
    version = EVALUATION_VERSION

    def __init__(self, replay_service: PublicReplayService, sigma_engine: SigmaEngine) -> None:
        self._replay_service = replay_service
        self._sigma_engine = sigma_engine

    def evaluate(self, tenant_id: str) -> DetectionQualityReport:
        suite = self._replay_service.run_all(tenant_id)
        targets = self._replay_service.quality_targets
        expected_labels: list[bool] = []
        detected_labels: list[bool] = []
        mapping_required = 0
        mapping_populated = 0
        fingerprint_records: list[dict[str, object]] = []

        for result in suite.results:
            expected_rule_ids = set(result.dataset.expected_rule_ids)
            for record in result.records:
                matched_rule_ids = sorted(match.rule_id for match in record.detection.matches)
                expected_labels.append(bool(expected_rule_ids))
                detected_labels.append(bool(matched_rule_ids))
                required, populated = _mapping_counts(record.normalized.event)
                mapping_required += required
                mapping_populated += populated
                fingerprint_records.append(
                    {
                        "dataset_id": result.dataset.dataset_id,
                        "source_record_id": record.source_record_id,
                        "raw_record_sha256": record.raw_record_sha256,
                        "expected_rule_ids": sorted(expected_rule_ids),
                        "matched_rule_ids": matched_rule_ids,
                    }
                )

        declared_records = sum(result.dataset.record_count for result in suite.results)
        parsed_records = sum(len(result.records) for result in suite.results)
        parse_failures = max(declared_records - parsed_records, 0)
        parse_rate = _ratio(parsed_records, declared_records)
        mapping_rate = _ratio(mapping_populated, mapping_required)
        confusion = _confusion(expected_labels, detected_labels)
        precision, recall, f1, false_positive_rate = _metrics(confusion)
        rule_results = self._rule_results(suite, targets)
        supported_rules = sum(rule.evaluation_status == "evaluated" for rule in rule_results)
        approved_rules = len(rule_results)
        coverage_rate = _ratio(supported_rules, approved_rules)
        targets_met = {
            "dataset_count": suite.dataset_count >= targets.minimum_dataset_count,
            "precision": precision >= targets.minimum_precision,
            "recall": recall >= targets.minimum_recall,
            "f1": f1 >= targets.minimum_f1,
            "false_positive_rate": (
                false_positive_rate <= targets.maximum_false_positive_rate
            ),
            "parse_success_rate": parse_rate >= targets.minimum_parse_success_rate,
            "mapping_completeness": (
                mapping_rate >= targets.minimum_mapping_completeness
            ),
            "rule_coverage_rate": coverage_rate >= targets.minimum_rule_coverage_rate,
            "dataset_expectations": suite.expectations_met,
        }
        fingerprint = _fingerprint(
            self._replay_service.manifest_digest_sha256,
            self._sigma_engine.ruleset_digest_sha256,
            targets,
            fingerprint_records,
        )
        return DetectionQualityReport(
            evaluation_version=EVALUATION_VERSION,
            manifest_digest_sha256=self._replay_service.manifest_digest_sha256,
            ruleset_digest_sha256=self._sigma_engine.ruleset_digest_sha256,
            evaluation_fingerprint_sha256=fingerprint,
            dataset_count=suite.dataset_count,
            declared_record_count=declared_records,
            parsed_record_count=parsed_records,
            parse_failure_count=parse_failures,
            parse_success_rate=round(parse_rate, 4),
            mapped_field_count=mapping_populated,
            required_field_count=mapping_required,
            mapping_completeness=round(mapping_rate, 4),
            confusion=confusion,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            false_positive_rate=round(false_positive_rate, 4),
            approved_rule_count=approved_rules,
            supported_rule_count=supported_rules,
            rule_coverage_rate=round(coverage_rate, 4),
            targets=targets,
            targets_met=targets_met,
            gate_passed=all(targets_met.values()),
            rules=rule_results,
        )

    def _rule_results(
        self,
        suite: PublicReplaySuiteResult,
        targets: DetectionQualityTargets,
    ) -> list[RuleDetectionQuality]:
        results: list[RuleDetectionQuality] = []
        for rule in self._sigma_engine.summaries():
            expected: list[bool] = []
            detected: list[bool] = []
            for replay in suite.results:
                is_expected = rule.rule_id in replay.dataset.expected_rule_ids
                for record in replay.records:
                    expected.append(is_expected)
                    detected.append(
                        any(match.rule_id == rule.rule_id for match in record.detection.matches)
                    )
            confusion = _confusion(expected, detected)
            precision, recall, f1, false_positive_rate = _metrics(confusion)
            positive_support = confusion.true_positive + confusion.false_negative
            evaluated = positive_support > 0
            results.append(
                RuleDetectionQuality(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    evaluation_status=(
                        "evaluated" if evaluated else "no_positive_support"
                    ),
                    positive_support=positive_support,
                    negative_support=confusion.true_negative + confusion.false_positive,
                    confusion=confusion,
                    precision=round(precision, 4) if evaluated else None,
                    recall=round(recall, 4) if evaluated else None,
                    f1=round(f1, 4) if evaluated else None,
                    false_positive_rate=round(false_positive_rate, 4),
                    targets_met=(
                        precision >= targets.minimum_precision
                        and recall >= targets.minimum_recall
                        and f1 >= targets.minimum_f1
                        and false_positive_rate <= targets.maximum_false_positive_rate
                        if evaluated
                        else None
                    ),
                )
            )
        return results


def _mapping_counts(event: object) -> tuple[int, int]:
    values = [
        event.time,
        event.category_uid,
        event.class_uid,
        event.activity_id,
        event.type_uid,
        event.status_id,
        event.metadata.uid,
        event.actor.user.uid,
        event.src_endpoint.ip,
        event.device.uid,
        event.resources[0].uid,
        event.raw_data_hash.value,
    ]
    populated = sum(value is not None and value != "" for value in values)
    return len(values), populated


def _confusion(expected: list[bool], detected: list[bool]) -> DetectionConfusionCounts:
    if len(expected) != len(detected):
        raise ValueError("expected and detected labels must have equal length")
    return DetectionConfusionCounts(
        true_positive=sum(truth and prediction for truth, prediction in zip(expected, detected)),
        false_positive=sum(
            not truth and prediction for truth, prediction in zip(expected, detected)
        ),
        false_negative=sum(
            truth and not prediction for truth, prediction in zip(expected, detected)
        ),
        true_negative=sum(
            not truth and not prediction for truth, prediction in zip(expected, detected)
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
    ruleset_digest: str,
    targets: DetectionQualityTargets,
    records: list[dict[str, object]],
) -> str:
    material = {
        "manifest_digest_sha256": manifest_digest,
        "ruleset_digest_sha256": ruleset_digest,
        "targets": targets.model_dump(mode="json"),
        "records": sorted(
            records,
            key=lambda item: (str(item["dataset_id"]), str(item["source_record_id"])),
        ),
    }
    canonical = json.dumps(
        material,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


@lru_cache
def get_detection_quality_service() -> DetectionQualityService:
    return DetectionQualityService(get_public_replay_service(), get_sigma_engine())
