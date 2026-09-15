from collections.abc import Iterable
from enum import Enum
from operator import eq, ge, gt, le, lt, ne

from app.models import (
    ConditionOperator,
    EventScenarioEvaluation,
    ScenarioCategory,
    ScenarioCondition,
    ScenarioMatch,
    ScenarioSummary,
    SecurityEvent,
)

_COMPARATORS = {
    ConditionOperator.EQUALS: eq,
    ConditionOperator.NOT_EQUALS: ne,
    ConditionOperator.GREATER_THAN: gt,
    ConditionOperator.GREATER_THAN_OR_EQUAL: ge,
    ConditionOperator.LESS_THAN: lt,
    ConditionOperator.LESS_THAN_OR_EQUAL: le,
}


def _read_field(event: SecurityEvent, path: str) -> object:
    value: object = event
    for part in path.split("."):
        if not hasattr(value, part):
            raise ValueError(f"unsupported scenario condition field: {path}")
        value = getattr(value, part)
    return value.value if isinstance(value, Enum) else value


def condition_matches(event: SecurityEvent, condition: ScenarioCondition) -> bool:
    actual = _read_field(event, condition.field)
    expected = condition.value

    if condition.operator == ConditionOperator.IN:
        return actual in _as_collection(expected)
    if condition.operator == ConditionOperator.NOT_IN:
        return actual not in _as_collection(expected)

    comparator = _COMPARATORS[condition.operator]
    try:
        return bool(comparator(actual, expected))
    except TypeError:
        return False


def _as_collection(value: object) -> Iterable[object]:
    if not isinstance(value, list):
        raise TypeError("membership conditions require a list")
    return value


def match_scenario(event: SecurityEvent, scenario: ScenarioSummary) -> ScenarioMatch:
    outcomes = [condition_matches(event, condition) for condition in scenario.detection_conditions]
    matched_descriptions = [
        condition.description
        for condition, matched in zip(scenario.detection_conditions, outcomes, strict=True)
        if matched
    ]
    unmet_descriptions = [
        condition.description
        for condition, matched in zip(scenario.detection_conditions, outcomes, strict=True)
        if not matched
    ]
    matched = all(outcomes) if scenario.detection_logic == "all" else any(outcomes)
    return ScenarioMatch(
        scenario_id=scenario.scenario_id,
        name=scenario.name,
        matched=matched,
        coverage=round(sum(outcomes) / len(outcomes), 3),
        matched_conditions=matched_descriptions,
        unmet_conditions=unmet_descriptions,
    )


def evaluate_scenarios(
    event: SecurityEvent,
    scenarios: list[ScenarioSummary],
) -> EventScenarioEvaluation:
    matches = [match_scenario(event, scenario) for scenario in scenarios]
    priorities = {
        scenario.scenario_id: (
            scenario.category == ScenarioCategory.THREAT,
            len(scenario.detection_conditions),
        )
        for scenario in scenarios
    }
    matches.sort(
        key=lambda item: (item.matched, item.coverage, *priorities[item.scenario_id]),
        reverse=True,
    )
    exact_matches = [item for item in matches if item.matched]
    best_match = exact_matches[0].scenario_id if exact_matches else None
    return EventScenarioEvaluation(
        event_id=event.event_id,
        best_match=best_match,
        matches=matches,
    )
