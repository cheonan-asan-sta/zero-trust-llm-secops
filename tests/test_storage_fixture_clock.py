"""Keep infrastructure recovery fixtures deterministic across VM clock steps."""

from datetime import UTC, datetime, timedelta

from app.services import cases
from scripts import app_storage_contract as storage
from scripts import app_storage_fixture as fixture
from scripts.app_recovery_fixture import prepare


def test_recovery_seed_uses_one_case_clock_and_restores_runtime_clock(tmp_path, monkeypatch):
    instant = datetime(2026, 11, 15, tzinfo=UTC)
    calls = []

    class RegressingClock(datetime):
        @classmethod
        def now(cls, tz=None):
            calls.append(1)
            value = instant - timedelta(seconds=len(calls))
            return value.astimezone(tz) if tz is not None else value.replace(tzinfo=None)

    monkeypatch.setattr(cases, "datetime", RegressingClock)
    directory = tmp_path / "data"
    prepare(directory)
    fixture.seed_logs(directory)
    assert cases.datetime is RegressingClock and calls == []
    store = cases.CaseStore(directory / storage.FILES["cases"])
    for tenant in ("recovery-tenant", "unrelated-tenant"):
        rows = store.recent(100, tenant)
        assert rows
        changed = [row for row in rows if row.version == 4]
        assert len(changed) == 1
        row = changed[0]
        assert row.created_at == row.updated_at
        assert {entry.changed_at for entry in row.history} == {row.created_at}
    assert store.integrity()["ok"]
