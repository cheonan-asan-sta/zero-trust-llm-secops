import os
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

_test_runtime = TemporaryDirectory(prefix="zero-trust-secops-tests-")
os.environ["ANALYZER_MODE"] = "rule"
os.environ["APP_ENVIRONMENT"] = "test"
os.environ["AUTH_MODE"] = "disabled"
os.environ["AUDIT_LOG_PATH"] = str(Path(_test_runtime.name) / "audit.jsonl")
os.environ["CASE_LOG_PATH"] = str(Path(_test_runtime.name) / "cases.jsonl")
os.environ["OUTBOX_LOG_PATH"] = str(Path(_test_runtime.name) / "integration-outbox.jsonl")
os.environ["ZERO_TRUST_DB_PATH"] = str(Path(_test_runtime.name) / "zero-trust.sqlite3")


@pytest.fixture
def recovery_clock(monkeypatch):
    """Stable checkpoint time for integrity cases; expiry cases shift relative to it."""
    from scripts import app_state_recovery as recovery

    instant = datetime.now(UTC)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz) if tz is not None else instant.replace(tzinfo=None)

    monkeypatch.setattr(recovery, 'datetime', Clock)
    return instant
