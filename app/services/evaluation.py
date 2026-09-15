import math
from time import perf_counter

from openai import OpenAIError

from app.analyzers.base import Analyzer
from app.models import (
    EvaluationCaseResult,
    EvaluationSummary,
    EvaluationTargets,
    ScenarioCategory,
    ViolationType,
)
from app.scenarios import get_scenario, synthetic_events
from app.services.policy import enforce_assessment_safety


async def run_evaluation(
    analyzer: Analyzer,
    runs_per_scenario: int = 1,
) -> EvaluationSummary:
    cases: list[EvaluationCaseResult] = []

    for run_number in range(1, runs_per_scenario + 1):
        for source in synthetic_events():
            event = source.model_copy(
                update={"event_id": f"{source.event_id}-eval-{run_number}"}
            )
            truth = event.ground_truth
            if truth is None:  # Synthetic evaluation cases always carry a private label.
                continue

            started = perf_counter()
            try:
                assessment = await analyzer.analyze(event)
                safe = enforce_assessment_safety(assessment, event)
                actual_risk = safe.risk_level
                actual_action = safe.recommended_action
                threat_detected = safe.violation_type != ViolationType.NORMAL
                json_valid = True
            except (OpenAIError, RuntimeError, TypeError, ValueError):
                actual_risk = None
                actual_action = None
                threat_detected = False
                json_valid = False

            latency_ms = round((perf_counter() - started) * 1000, 2)
            scenario = get_scenario(truth.scenario_id)
            threat_expected = scenario.category == ScenarioCategory.THREAT
            cases.append(
                EvaluationCaseResult(
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
                )
            )

    total = len(cases)
    risk_accuracy = sum(case.risk_correct for case in cases) / total
    action_accuracy = sum(case.action_correct for case in cases) / total
    json_valid_rate = sum(case.json_valid for case in cases) / total

    true_positive = sum(case.threat_expected and case.threat_detected for case in cases)
    false_positive = sum(not case.threat_expected and case.threat_detected for case in cases)
    false_negative = sum(case.threat_expected and not case.threat_detected for case in cases)
    precision = _safe_ratio(true_positive, true_positive + false_positive)
    recall = _safe_ratio(true_positive, true_positive + false_negative)
    f1 = _safe_ratio(2 * precision * recall, precision + recall)

    latencies = sorted(case.latency_ms for case in cases)
    average_latency = sum(latencies) / total
    p95_index = max(math.ceil(total * 0.95) - 1, 0)
    p95_latency = latencies[p95_index]

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
        average_latency_ms=round(average_latency, 2),
        p95_latency_ms=round(p95_latency, 2),
        targets=targets,
        targets_met={
            "risk_accuracy": risk_accuracy >= targets.risk_accuracy,
            "json_valid_rate": json_valid_rate >= targets.json_valid_rate,
            "p95_latency_ms": p95_latency <= targets.p95_latency_ms,
        },
        cases=cases,
    )


def _safe_ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0
