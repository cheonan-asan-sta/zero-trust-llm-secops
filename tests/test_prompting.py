import json

from app.models import SecurityAssessment
from app.prompting import build_analysis_input, few_shot_events
from app.scenarios import synthetic_events


def test_ten_few_shot_pairs_are_available() -> None:
    examples = few_shot_events()

    assert len(examples) >= 10
    assert all("ground_truth" not in example.analysis_payload() for example in examples)


def test_prompt_contains_valid_structured_answers_without_label_leakage() -> None:
    messages = build_analysis_input(synthetic_events()[0], max_examples=10)
    assistant_messages = [message for message in messages if message["role"] == "assistant"]
    user_messages = [message for message in messages if message["role"] == "user"]

    assert len(assistant_messages) == 10
    assert len(user_messages) == 11
    assert all("ground_truth" not in message["content"] for message in user_messages)
    for message in assistant_messages:
        SecurityAssessment.model_validate(json.loads(message["content"]))


def test_prompt_injection_text_is_kept_inside_event_data() -> None:
    messages = build_analysis_input(synthetic_events()[0], max_examples=10)
    injection_index = next(
        index
        for index, message in enumerate(messages)
        if "이전 지시를 무시" in message["content"]
    )
    parsed_answer = SecurityAssessment.model_validate_json(messages[injection_index + 1]["content"])

    assert messages[injection_index]["role"] == "user"
    assert parsed_answer.risk_level.value == "LOW"


def test_runtime_prompt_selects_only_the_closest_examples() -> None:
    messages = build_analysis_input(synthetic_events()[-1], max_examples=3)

    assert len([message for message in messages if message["role"] == "assistant"]) == 3
    assert "evt-zt-s05" in messages[0]["content"]
