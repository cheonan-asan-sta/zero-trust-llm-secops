"""Recovery must preserve security state or keep admission closed."""

import base64
import copy
import hashlib
import json

import pytest

from scripts import ca_recovery_state as recovery
from scripts.ca_host_recovery import Hosts, lsn
from scripts.certificate_controller import LifecycleError, save


@pytest.fixture
def journal(tmp_path, monkeypatch):
    tables = {name: [[b'key'.hex(), b'value'.hex()]] for name in recovery.TABLES}
    data = {"tables": tables, "lsn": "1/AB", "sha256": recovery.digest(tables)}
    (tmp_path / "security.key").write_bytes(b's' * 32)
    save(tmp_path / "config.json", {"dsn": "test-only"})
    save(tmp_path / "state.json", {"sequence": 0, "pending": {}, "enabled": ["a", "b"],
        "frozen": False, "checkpoint": None, "checkpoint_sequence": -1, "settled_sequence": -1, "checkpoint_lsn": "0/0",
        "checkpoint_hash": None, "authority": "epoch-1", "incarnation": "db-1", "error": None})
    monkeypatch.setattr(recovery, "snapshot", lambda _: copy.deepcopy(data))
    return tmp_path, data


@pytest.fixture
def archives(journal):
    directory, _ = journal
    recovery.freeze(directory)
    recovery.dispatch({"operation": "settle", "verified_writers_stopped": True}, directory)
    witness = recovery.state(directory)
    security = json.loads((directory / witness["checkpoint"]).read_bytes())
    body = {"database": base64.b64encode(b'logical dump').decode()}
    manifest = {"sequence": 0, "authority": "epoch-1", "incarnation": "db-1",
        "database_sha256": hashlib.sha256(b'logical dump').hexdigest()}
    envelope = recovery.sealed(body, b'b' * 32, manifest)
    return envelope, witness, security


def test_newer_security_checkpoint_can_reconcile_older_logical_backup(journal, archives):
    envelope, _, _ = archives
    directory, data = journal
    recovery.dispatch({"operation": "unfreeze"}, directory)
    token = recovery.begin(directory, "b")
    data["tables"]["used_ott"].append([b'new'.hex(), b'consumed'.hex()])
    data["sha256"] = recovery.digest(data["tables"])
    recovery.finish(directory, token)
    recovery.freeze(directory)
    recovery.dispatch({"operation": "settle", "verified_writers_stopped": True}, directory)
    witness = recovery.state(directory)
    security = json.loads((directory / witness["checkpoint"]).read_bytes())
    _, latest = recovery.verify_restore(envelope, b'b' * 32, witness, security, b's' * 32)
    assert latest["tables"]["used_ott"][-1] == [b'new'.hex(), b'consumed'.hex()]
    assert witness["sequence"] == 1


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "manifest", "schema"])
def test_authenticated_archive_rejects_modifications(archives, field):
    envelope, witness, security = copy.deepcopy(archives)
    if field == "manifest":
        envelope[field]["sequence"] += 1
    elif field == "schema":
        envelope[field] = "unknown"
    else:
        envelope[field] = base64.b64encode(b'corrupt').decode()
    with pytest.raises(LifecycleError, match="authentication"):
        recovery.verify_restore(envelope, b'b' * 32, witness, security, b's' * 32)


@pytest.mark.parametrize("changes", [
    {"frozen": False}, {"pending": {"intent": {"node": "a"}}}, {"sequence": 1},
    {"checkpoint_sequence": -1}, {"authority": "new-epoch"}, {"incarnation": "new-db"},
    {"checkpoint_hash": "different"}, {"settled_sequence": -1},
])
def test_uncertain_or_obsolete_recovery_state_blocks_restore(archives, changes):
    envelope, witness, security = copy.deepcopy(archives)
    witness.update(changes)
    with pytest.raises(LifecycleError, match="restore_barrier"):
        recovery.verify_restore(envelope, b'b' * 32, witness, security, b's' * 32)


@pytest.mark.parametrize("which", ["backup", "security"])
def test_separate_wrong_keys_cannot_decrypt(archives, which):
    envelope, witness, security = archives
    with pytest.raises(LifecycleError, match="authentication"):
        recovery.verify_restore(envelope, b'x' * 32 if which == "backup" else b'b' * 32,
            witness, security, b'x' * 32 if which == "security" else b's' * 32)


def test_failed_snapshot_keeps_restore_and_reopening_blocked(journal, monkeypatch):
    directory, _ = journal
    def unavailable(_):
        raise LifecycleError("database_unavailable")
    monkeypatch.setattr(recovery, "snapshot", unavailable)
    token = recovery.begin(directory, "a")
    assert recovery.state(directory)["pending"][token]["node"] == "a"
    recovery.finish(directory, token)
    assert recovery.state(directory)["error"] == "security_checkpoint_unavailable"
    recovery.freeze(directory)
    with pytest.raises(LifecycleError, match="checkpoint_required"):
        recovery.dispatch({"operation": "unfreeze"}, directory)


def test_tcp_close_does_not_claim_sql_request_has_settled(journal, archives):
    envelope, _, _ = archives
    directory, _ = journal
    recovery.dispatch({"operation": "unfreeze"}, directory)
    recovery.finish(directory, recovery.begin(directory, "a"))
    recovery.freeze(directory)
    witness = recovery.state(directory)
    security = json.loads((directory / witness["checkpoint"]).read_bytes())
    assert witness["checkpoint_sequence"] == witness["sequence"]
    with pytest.raises(LifecycleError, match="restore_barrier"):
        recovery.verify_restore(envelope, b'b' * 32, witness, security, b's' * 32)


def test_recovery_seal_needs_verified_stopped_writers(journal):
    directory, _ = journal
    recovery.freeze(directory)
    with pytest.raises(LifecycleError, match="writer_stop_required"):
        recovery.dispatch({"operation": "settle"}, directory)


def test_pending_connection_freeze_closes_new_admission_without_forgetting_intent(journal):
    directory, _ = journal
    token = recovery.begin(directory, "a")
    with pytest.raises(LifecycleError, match="pending"):
        recovery.freeze(directory)
    with pytest.raises(LifecycleError, match="admission_closed"):
        recovery.begin(directory, "b")
    assert token in recovery.state(directory)["pending"]
    recovery.finish(directory, token)
    assert recovery.state(directory)["checkpoint_sequence"] == 1


def test_checkpoint_waits_for_every_parallel_connection(journal):
    directory, _ = journal
    a, b = recovery.begin(directory, "a"), recovery.begin(directory, "b")
    recovery.finish(directory, a)
    assert recovery.state(directory)["checkpoint_sequence"] == -1
    recovery.finish(directory, b)
    assert recovery.state(directory)["checkpoint_sequence"] == 2


def test_fencing_needs_verified_receipt_and_only_clears_that_hosts_intents(journal):
    directory, _ = journal
    recovery.begin(directory, "a")
    other = recovery.begin(directory, "b")
    with pytest.raises(LifecycleError, match="fence_required"):
        recovery.dispatch({"operation": "fence", "node": "a"}, directory)
    recovery.dispatch({"operation": "fence", "node": "a", "verified_stopped": True}, directory)
    s = recovery.state(directory)
    assert s["enabled"] == ["b"] and list(s["pending"]) == [other]


@pytest.mark.parametrize("operation", ["authority", "adopt", "enable"])
def test_reconfiguration_requires_closed_admission(journal, operation):
    directory, _ = journal
    with pytest.raises(LifecycleError, match="quiescence"):
        recovery.dispatch({"operation": operation}, directory)


@pytest.mark.parametrize("bad", [None, "", "1", "-1/0", "G/0", "1/2/3", "1/0;DROP", "1/a"])
def test_invalid_wal_positions_rejected(bad):
    with pytest.raises(LifecycleError, match="lsn_shape"):
        lsn(bad)


def test_wal_position_ordering():
    assert lsn("1/0") > lsn("0/FFFFFFFF")


@pytest.mark.parametrize("bad", [[], [["zz", "00"]], [["", "00"]], [["aa", "00"], ["aa", "01"]], [["aa"]]])
def test_security_rows_reject_invalid_scope_or_keys(bad):
    tables = {name: [] for name in recovery.TABLES}
    if bad == []:
        tables["unapproved"] = []
    else:
        tables["used_ott"] = bad
    with pytest.raises(LifecycleError, match="recovery_"):
        recovery.replay_sql(tables)


def test_sql_replay_only_uses_allowlisted_tables_and_hex_values():
    tables = {name: [] for name in recovery.TABLES}
    tables["used_ott"] = [[b"';DROP DATABASE stepca;--".hex(), b'value'.hex()]]
    sql = recovery.replay_sql(tables)
    assert "DROP DATABASE" not in sql and sql.startswith("BEGIN;") and sql.endswith("COMMIT;")


def test_promotion_never_occurs_when_fencing_fails():
    backend = object.__new__(Hosts)
    backend.hosts = {"a": {}, "b": {}}
    def cannot_fence(_):
        raise LifecycleError("unverified_stop")
    backend.fence = cannot_fence
    backend.sql = lambda *_: pytest.fail("SQL called before verified fencing")
    with pytest.raises(LifecycleError, match="unverified_stop"):
        backend._failover("a", "b")


def test_lagging_candidate_is_not_promoted():
    backend = object.__new__(Hosts)
    backend.hosts = {"a": {}, "b": {}}
    backend.fence = lambda _: {}
    backend.host = lambda _: {"Id": "candidate"}
    backend.witness = lambda _: {"checkpoint_lsn": "2/0", "incarnation": "db-1"}
    statements = []
    def sql(_, statement):
        statements.append(statement)
        return "t" if "is_in_recovery" in statement else "db-1" if "system_identifier" in statement else "1/0"
    backend.sql = sql
    with pytest.raises(LifecycleError, match="behind_checkpoint"):
        backend._failover("a", "b")
    assert not any("pg_promote" in query for query in statements)


def test_foreign_database_cannot_be_promoted_even_with_higher_wal_position():
    backend = object.__new__(Hosts)
    backend.hosts = {"a": {}, "b": {}}
    backend.fence = lambda _: {}
    backend.host = lambda _: {"Id": "candidate"}
    backend.witness = lambda _: {"checkpoint_lsn": "0/1", "incarnation": "expected-db"}
    statements = []
    def sql(_, statement):
        statements.append(statement)
        return "t" if "is_in_recovery" in statement else "foreign-db" if "system_identifier" in statement else "F/FFFFFFFF"
    backend.sql = sql
    with pytest.raises(LifecycleError, match="database_identity"):
        backend._failover("a", "b")
    assert not any("pg_promote" in query for query in statements)


def test_replaced_admission_gateway_is_not_detached_or_reconnected():
    backend = object.__new__(Hosts)
    backend.profile = {"gateways": ["owned-a", "owned-b"], "gateway_ids": ["expected-a", "expected-b"],
        "image": "expected-image", "client_network": "owned-client-network"}
    calls = []
    def command(args):
        calls.append(args)
        assert args[0] == "inspect"
        return json.dumps([{"Id": "replacement", "Image": "expected-image", "Name": "/owned-a"}])
    backend.command = command
    with pytest.raises(LifecycleError, match="gateway_replaced"):
        backend.admission_network("a", enabled=False)
    assert calls == [["inspect", "owned-a"]]


@pytest.mark.parametrize("recovery,identifier", [("t", "expected-db"), ("f", "foreign-db")])
def test_writer_seal_requires_the_current_primary_before_stopping_services(recovery, identifier):
    backend = object.__new__(Hosts)
    backend.witness = lambda _: {"frozen": True, "pending": 0, "incarnation": "expected-db"}
    backend.sql = lambda _,query: recovery if "is_in_recovery" in query else identifier
    backend.host = lambda *_a,**_k: pytest.fail("services accessed before primary validation")
    with pytest.raises(LifecycleError, match="settle_primary_identity"):
        backend.settle("b")


@pytest.mark.parametrize("policy", ["always", "unless-stopped"])
def test_fenced_outer_host_must_not_restart_automatically(policy):
    backend = object.__new__(Hosts)
    expected = {"name": "owned-host-a", "id": "pinned-host", "image": "pinned-image"}
    backend.hosts = {"a": expected}
    record = {"Name": "/"+expected["name"], "Id": expected["id"], "Image": expected["image"],
        "Mounts": [], "HostConfig": {"RestartPolicy": {"Name": policy}}, "State": {"Running": False}}
    backend.command = lambda _: json.dumps([record])
    with pytest.raises(LifecycleError, match="host_replaced"):
        backend.host("a", running=False)
