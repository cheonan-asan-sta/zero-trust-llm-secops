"""Local maintenance preserves receipts and never exposes their private contents."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.services.signal_inbox import InboxUnavailable, SignalInbox
from scripts import signal_inbox as cli


@pytest.fixture
def settings(tmp_path, monkeypatch):
    value = SimpleNamespace(app_environment="test", zero_trust_db_path=tmp_path / "inbox.sqlite3",
                            signal_inbox_max_pending=1000, signal_inbox_max_records=10000,
                            signal_inbox_max_attempts=3, signal_inbox_lease_seconds=30,
                            signal_inbox_retry_seconds=1)
    monkeypatch.setattr(cli, "get_settings", lambda: value)
    return value


def test_status_prints_storage_counts_without_paths(settings, capsys):
    assert cli.main(["status"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["inbox"] == "status" and result["total_records"] == 0
    assert result["max_records"] == 10000 and result["max_archive_records"] == 100000
    assert str(settings.zero_trust_db_path) not in json.dumps(result)


def test_compact_preserves_terminal_receipt_and_processing_lease(settings, capsys):
    inbox = SignalInbox(settings.zero_trust_db_path)
    now = datetime.now(UTC)
    for event in ("finished", "working"):
        inbox.accept("tenant", event, {"private": "synthetic-sensitive-envelope"}, "a" * 64, "operator", now)
    completed = inbox.claim(now=now)
    assert completed["event_id"] == "finished"
    receipt = inbox.complete("tenant", "finished", completed["lease_token"], {"private": "synthetic-result"}, now)
    lease = inbox.claim(now=now)
    assert cli.main(["compact", "--database", str(inbox.path), "--limit", "2"]) == 0
    captured = capsys.readouterr().out
    result = json.loads(captured)
    assert result["compacted"] == 1 and result["total_records"] == 2
    assert result["active_records"] == result["archived_records"] == 1
    assert all(value not in captured for value in ("synthetic", '"operator"', '"tenant"', '"finished"', '"working"'))
    assert inbox.get("tenant", "finished") == receipt
    assert inbox.claim(now=now) is None
    assert inbox.complete("tenant", "working", lease["lease_token"], {}, now)["state"] == "completed"


def test_production_is_refused_before_creating_or_opening_storage(settings, monkeypatch, capsys):
    settings.app_environment = "production"
    monkeypatch.setattr(cli, "SignalInbox", lambda *_args, **_kw: pytest.fail("production storage opened"))
    assert cli.main(["compact"]) == 1
    assert not settings.zero_trust_db_path.exists()
    assert json.loads(capsys.readouterr().err)["error"] == "CONFIG_OR_STORAGE_UNAVAILABLE"


@pytest.mark.parametrize("limit", ["0", "-1", "10001"])
def test_invalid_limit_is_rejected_before_storage_creation(settings, limit):
    with pytest.raises(SystemExit) as error:
        cli.main(["compact", "--limit", limit])
    assert error.value.code == 2 and not settings.zero_trust_db_path.exists()


def test_errors_never_print_exception_payload_or_database_path(settings, monkeypatch, capsys):
    def unavailable(*_args, **_kw):
        raise InboxUnavailable("synthetic-private-envelope-and-credential")

    monkeypatch.setattr(cli, "SignalInbox", unavailable)
    assert cli.main(["status"]) == 1
    captured = capsys.readouterr()
    assert not captured.out and "synthetic-private" not in captured.err
    assert str(settings.zero_trust_db_path) not in captured.err
    assert json.loads(captured.err) == {"inbox": "unavailable", "error": "CONFIG_OR_STORAGE_UNAVAILABLE"}
