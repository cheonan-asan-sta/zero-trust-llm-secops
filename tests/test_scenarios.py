from app.models import ScenarioCategory
from app.scenarios import SCENARIOS, get_scenario, synthetic_events


def test_catalog_contains_five_attack_mapped_threat_scenarios() -> None:
    threats = [scenario for scenario in SCENARIOS if scenario.category == ScenarioCategory.THREAT]

    assert len(threats) == 5
    for scenario in threats:
        assert scenario.attack_techniques
        assert scenario.observable_signals
        assert scenario.normal_exceptions
        for technique in scenario.attack_techniques:
            assert technique.reference_url.endswith(f"/{technique.technique_id}/")


def test_normal_scenarios_do_not_claim_attack_techniques() -> None:
    normal_scenarios = [
        scenario for scenario in SCENARIOS if scenario.category != ScenarioCategory.THREAT
    ]

    assert normal_scenarios
    assert all(not scenario.attack_techniques for scenario in normal_scenarios)


def test_event_ground_truth_is_derived_from_scenario_catalog() -> None:
    for event in synthetic_events():
        assert event.ground_truth is not None
        scenario = get_scenario(event.ground_truth.scenario_id)
        assert event.ground_truth.risk_level == scenario.expected_risk
        assert event.ground_truth.expected_action == scenario.expected_action
