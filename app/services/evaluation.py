import asyncio
import math
from collections import Counter
from time import perf_counter

from openai import APITimeoutError, OpenAIError

from app.analyzers.base import Analyzer
from app.models import (
    EvaluationCaseResult,
    EvaluationSummary,
    EvaluationTargets,
    RiskLevel,
    ScenarioCategory,
    ScenarioEvaluationSummary,
    ViolationType,
)
from app.scenarios import get_scenario, synthetic_events
from app.services.policy import enforce_assessment_safety


async def run_evaluation(
    analyzer: Analyzer,
    runs_per_scenario: int = 1,
    concurrency: int = 4,
) -> EvaluationSummary:
    evaluation_inputs = []

    for run_number in range(1, runs_per_scenario + 1):
        for source in synthetic_events():
            event = source.model_copy(
                update={"event_id": f"{source.event_id}-eval-{run_number}"}
            )
            truth = event.ground_truth
            if truth is None:  # Synthetic evaluation cases always carry a private label.
                continue
            evaluation_inputs.append((event, truth))

    semaphore = asyncio.Semaphore(concurrency)

    async def evaluate_case(event, truth) -> EvaluationCaseResult:
        scenario = get_scenario(truth.scenario_id)
        threat_expected = scenario.category == ScenarioCategory.THREAT
        error_category = None

        async with semaphore:
            started = perf_counter()
            try:
                assessment = await analyzer.analyze(event)
                safe = enforce_assessment_safety(assessment, event)
                actual_risk = safe.risk_level
                actual_action = safe.recommended_action
                threat_detected = safe.violation_type != ViolationType.NORMAL
                json_valid = True
            except (TimeoutError, APITimeoutError):
                actual_risk = None
                actual_action = None
                threat_detected = False
                json_valid = False
                error_category = "timeout"
            except OpenAIError:
                actual_risk = None
                actual_action = None
                threat_detected = False
                json_valid = False
                error_category = "provider"
            except (TypeError, ValueError):
                actual_risk = None
                actual_action = None
                threat_detected = False
                json_valid = False
                error_category = "validation"
            except RuntimeError:
                actual_risk = None
                actual_action = None
                threat_detected = False
                json_valid = False
                error_category = "runtime"

            latency_ms = round((perf_counter() - started) * 1000, 2)
        return EvaluationCaseResult(
            event_id=event.event_id,
            scenario_id=truth.scenario_id,
            expected_risk=truth.risk_level,
            actual_risk=actual_risk,
            expected_action=truth.expected_action,
            actual_action=actual_action,
            risk_correct=actual_risk == truth.risk_level,
            action_correct=actual_action == truth.expected_action,
            threat_expected=threat_expected,
            threat_detected=threat_detected,
            json_valid=json_valid,
            latency_ms=latency_ms,
            error_category=error_category,
        )

    evaluation_started = perf_counter()
    cases = await asyncio.gather(
        *(evaluate_case(event, truth) for event, truth in evaluation_inputs)
    )
    duration_ms = (perf_counter() - evaluation_started) * 1000

    total = len(cases)
    if total == 0:
        raise ValueError("evaluation requires at least one labeled case")

    risk_accuracy = sum(case.risk_correct for case in cases) / total
    action_accuracy = sum(case.action_correct for case in cases) / total
    json_valid_rate = sum(case.json_valid for case in cases) / total
    error_count = sum(case.error_category is not None for case in cases)
    error_rate = error_count / total
    error_categories = dict(
        sorted(Counter(case.error_category for case in cases if case.error_category).items())
    )

    true_positive = sum(case.threat_expected and case.threat_detected for case in cases)
    false_positive = sum(not case.threat_expected and case.threat_detected for case in cases)
    false_negative = sum(case.threat_expected and not case.threat_detected for case in cases)
    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)

    latencies = sorted(case.latency_ms for case in cases)
    average_latency = sum(latencies) / total
    p50_latency = _percentile(latencies, 0.50)
    p95_latency = _percentile(latencies, 0.95)
    p99_latency = _percentile(latencies, 0.99)
    throughput = total / (duration_ms / 1000) if duration_ms else 0

    scenario_breakdown = []
    for scenario_id in sorted({case.scenario_id for case in cases}):
        scenario_cases = [case for case in cases if case.scenario_id == scenario_id]
        scenario_latencies = sorted(case.latency_ms for case in scenario_cases)
        scenario_total = len(scenario_cases)
        scenario_breakdown.append(
            ScenarioEvaluationSummary(
                scenario_id=scenario_id,
                total_cases=scenario_total,
                risk_accuracy=round(
                    sum(case.risk_correct for case in scenario_cases) / scenario_total, 4
                ),
                action_accuracy=round(
                    sum(case.action_correct for case in scenario_cases) / scenario_total, 4
                ),
                error_count=sum(case.error_category is not None for case in scenario_cases),
                average_latency_ms=round(sum(scenario_latencies) / scenario_total, 2),
                p95_latency_ms=round(_percentile(scenario_latencies, 0.95), 2),
            )
        )

    confusion_labels = [level.value for level in RiskLevel]
    risk_confusion_matrix = {
        expected: {actual: 0 for actual in [*confusion_labels, "ERROR"]}
        for expected in confusion_labels
    }
    for case in cases:
        actual = case.actual_risk.value if case.actual_risk is not None else "ERROR"
        risk_confusion_matrix[case.expected_risk.value][actual] += 1

    targets = EvaluationTargets()
    return EvaluationSummary(
        analyzer=analyzer.name,
        total_cases=total,
        risk_accuracy=round(risk_accuracy, 4),
        action_accuracy=round(action_accuracy, 4),
        threat_precision=round(precision, 4),
        threat_recall=round(recall, 4),
        threat_f1=round(f1, 4),
        json_valid_rate=round(json_valid_rate, 4),
        error_count=error_count,
        error_rate=round(error_rate, 4),
        error_categories=error_categories,
        duration_ms=round(duration_ms, 2),
        throughput_per_second=round(throughput, 2),
        average_latency_ms=round(average_latency, 2),
        p50_latency_ms=round(p50_latency, 2),
        p95_latency_ms=round(p95_latency, 2),
        p99_latency_ms=round(p99_latency, 2),
        risk_confusion_matrix=risk_confusion_matrix,
        scenario_breakdown=scenario_breakdown,
        targets=targets,
        targets_met={
            "risk_accuracy": risk_accuracy >= targets.risk_accuracy,
            "action_accuracy": action_accuracy >= targets.action_accuracy,
            "threat_f1": f1 >= targets.threat_f1,
            "json_valid_rate": json_valid_rate >= targets.json_valid_rate,
            "error_rate": error_rate <= targets.maximum_error_rate,
            "p95_latency_ms": p95_latency <= targets.p95_latency_ms,
        },
        cases=cases,
    )


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: list[float], percentile: float) -> float:
    index = max(math.ceil(len(values) * percentile) - 1, 0)
    return values[index]
