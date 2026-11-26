import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.analyzers.openai_analyzer import (
    COMPACT_OUTPUT_INSTRUCTIONS,
    SYSTEM_INSTRUCTIONS,
    OpenAIAnalyzer,
)
from app.config import Settings
from app.models import SecurityAssessment
from app.prompting import EVENT_PROMPT
from app.scenarios import synthetic_events
from app.services.analysis_authority import bind_analysis_authority


def test_openai_mode_requires_api_key() -> None:
    settings = Settings(analyzer_mode="openai", openai_api_key=None)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAIAnalyzer(settings)


def test_openai_key_can_be_loaded_from_secrets_manager() -> None:
    settings = Settings(
        analyzer_mode="openai",
        openai_api_key=None,
        openai_api_key_secret_arn="arn:aws:secretsmanager:ap-northeast-2:172585182454:secret:test",
    )
    secrets_client = Mock()
    secrets_client.get_secret_value.return_value = {
        "SecretString": '{"OPENAI_API_KEY":"test-placeholder"}'
    }

    with patch("app.analyzers.openai_analyzer.boto3.client", return_value=secrets_client):
        analyzer = OpenAIAnalyzer(settings)

    assert analyzer.name == "openai"
    secrets_client.get_secret_value.assert_called_once()


def test_compact_legacy_output_keeps_schema_and_event_evidence() -> None:
    event = synthetic_events()[0]
    requests = []
    with (
        patch("app.analyzers.openai_analyzer.AsyncOpenAI"),
        patch(
            "app.analyzers.openai_analyzer.parse_structured_response",
            new_callable=AsyncMock,
            return_value=(SimpleNamespace(output_parsed=None), None),
        ) as full_parse,
        patch(
            "app.analyzers.openai_analyzer.parse_single_structured_response",
            new_callable=AsyncMock,
            return_value=(None, None),
        ) as single_parse,
    ):
        for compact, parse in ((False, full_parse), (True, single_parse)):
            analyzer = OpenAIAnalyzer(
                Settings(openai_api_key="test-placeholder", openai_compact_legacy_output=compact)
            )
            asyncio.run(analyzer._parse_assessment(analyzer._client, event, None, 800))
            parse.assert_awaited_once()
            requests.append(parse.await_args.kwargs)

    default, compact = requests
    assert default["input"][0]["content"] == SYSTEM_INSTRUCTIONS
    assert compact["input"][0]["content"] == SYSTEM_INSTRUCTIONS + "\n" + COMPACT_OUTPUT_INSTRUCTIONS
    assert compact["input"][2] == default["input"][2]
    for index in (1, 3):
        compressed = compact["input"][index]["content"].removeprefix(EVENT_PROMPT)
        original = default["input"][index]["content"].removeprefix(EVENT_PROMPT)
        assert len(compressed) < len(original)
        evidence = json.loads(original)
        del evidence["event_id"]
        assert json.loads(compressed) == evidence
    assert compact["text_format"] is default["text_format"] is SecurityAssessment
    assert compact["max_output_tokens"] == default["max_output_tokens"] == 800
    assert compact["store"] is default["store"] is False
    assert "service_tier" not in default
    assert "temperature" not in default


def test_openai_can_explicitly_set_processing_tier_and_temperature() -> None:
    event = synthetic_events()[0]
    with (
        patch("app.analyzers.openai_analyzer.AsyncOpenAI"),
        patch(
            "app.analyzers.openai_analyzer.parse_structured_response",
            new_callable=AsyncMock,
            return_value=(SimpleNamespace(output_parsed=None), None),
        ) as parse,
    ):
        analyzer = OpenAIAnalyzer(
            Settings(
                openai_api_key="test-placeholder", openai_service_tier="priority",
                openai_temperature=0,
            )
        )
        asyncio.run(analyzer._parse_assessment(analyzer._client, event, None, 800))
    assert parse.await_args.kwargs["service_tier"] == "priority"
    assert parse.await_args.kwargs["temperature"] == 0


def test_compact_legacy_rechecks_server_authority_after_provider_response() -> None:
    revoked = False

    async def revalidate():
        if revoked:
            raise PermissionError("caller withdrawn")

    async def parse(*args, **kwargs):
        nonlocal revoked
        revoked = True
        return Mock(spec=SecurityAssessment), None

    async def run():
        with (
            patch("app.analyzers.openai_analyzer.AsyncOpenAI") as sdk,
            patch(
                "app.analyzers.openai_analyzer.parse_single_structured_response",
                side_effect=parse,
            ) as compact_parser,
            bind_analysis_authority(revalidate),
        ):
            analyzer = OpenAIAnalyzer(
                Settings(openai_api_key="test-placeholder", openai_compact_legacy_output=True)
            )
            with pytest.raises(PermissionError, match="caller withdrawn"):
                await analyzer.analyze(synthetic_events()[0])
            sdk.return_value.with_options.assert_called_once_with(max_retries=0)
            compact_parser.assert_awaited_once()
            assert compact_parser.await_args.args[0] is sdk.return_value.with_options.return_value

    asyncio.run(run())
