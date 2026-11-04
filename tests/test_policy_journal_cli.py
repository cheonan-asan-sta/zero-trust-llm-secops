"""Local maintenance commands expose only bounded storage counts and fixed errors."""

import json
from types import SimpleNamespace

import pytest

from app.services.zero_trust import JournalUnavailable, ZeroTrustOperations
from scripts import policy_journal as cli


@pytest.fixture
def settings(tmp_path, monkeypatch):
    value = SimpleNamespace(app_environment="test", zero_trust_db_path=tmp_path / "policy.sqlite3")
    monkeypatch.setattr(cli, "get_settings", lambda: value)
    return value


def test_status_initializes_an_empty_local_store_and_prints_only_counts(settings, capsys):
    assert cli.main(["status"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["journal"] == "status" and result["total_records"] == 0
    assert result["max_active_records"] == 10000
    assert str(settings.zero_trust_db_path) not in json.dumps(result)


def test_compact_cli_preserves_complete_logical_history(settings, capsys):
    service = ZeroTrustOperations(settings.zero_trust_db_path)
    with service._transaction() as transaction:
        for _ in range(4):
            service._append(transaction, {"kind": "access", "allowed": False})
    with service._transaction() as transaction:
        before = transaction[1]
    assert cli.main(["compact", "--database", str(service.path), "--limit", "2"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["compacted"] == 2 and result["total_records"] == 4
    assert result["archived_records"] == result["active_records"] == 2
    with service._transaction() as transaction:
        assert transaction[1] == before


def test_production_is_refused_before_opening_any_database(settings, monkeypatch, capsys):
    settings.app_environment = "production"
    monkeypatch.setattr(cli, "ZeroTrustOperations", lambda *_args: pytest.fail("production storage opened"))
    assert cli.main(["compact"]) == 1
    assert not settings.zero_trust_db_path.exists()
    assert json.loads(capsys.readouterr().err)["error"] == "CONFIG_OR_STORAGE_UNAVAILABLE"


@pytest.mark.parametrize("limit", ["0", "-1", "10001"])
def test_invalid_compaction_limit_is_rejected_before_creating_storage(settings, limit):
    with pytest.raises(SystemExit) as error:
        cli.main(["compact", "--limit", limit])
    assert error.value.code == 2 and not settings.zero_trust_db_path.exists()


def test_storage_errors_never_print_exception_payload_or_database_path(settings, monkeypatch, capsys):
    def unavailable(_path):
        raise JournalUnavailable("synthetic-private-payload-and-token")

    monkeypatch.setattr(cli, "ZeroTrustOperations", unavailable)
    assert cli.main(["status"]) == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "synthetic-private" not in captured.err and str(settings.zero_trust_db_path) not in captured.err
    assert json.loads(captured.err) == {"journal": "unavailable", "error": "CONFIG_OR_STORAGE_UNAVAILABLE"}
