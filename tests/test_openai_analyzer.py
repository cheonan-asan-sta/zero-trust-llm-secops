from unittest.mock import Mock, patch

import pytest

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings


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
