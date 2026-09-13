from typing import Protocol

from app.models import SecurityAssessment, SecurityEvent


class Analyzer(Protocol):
    name: str

    async def analyze(self, event: SecurityEvent) -> SecurityAssessment:
        """Analyze a normalized security event without executing a response."""
