import pytest

from app.analyzers.openai_analyzer import OpenAIAnalyzer
from app.config import Settings


def test_openai_mode_requires_api_key() -> None:
    settings = Settings(analyzer_mode="openai", openai_api_key=None)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAIAnalyzer(settings)
