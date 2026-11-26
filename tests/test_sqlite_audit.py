import asyncio
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest
from test_audit_cancellation import record
from test_native_analysis_http import api as api  # noqa: PLC0414
from test_service_analysis_evidence import executed as executed  # noqa: PLC0414

from app.models import ReviewStatus
from app.services.federated_audit import AuditQueryUnavailable
from app.services.sqlite_audit import AuditReviewConflict, SQLiteAuditStore
from scripts.local_process_runtime import direct_python


def initial(index):
    return record(index).model_copy(update={"review_status": ReviewStatus.PENDING})


def review(original, reviewer="reviewer"):
    return original.model_copy(
        update={
            "review_status": ReviewStatus.RESOLVED,
            "reviewer": reviewer,
            "review_note": "Reviewed locally",
            "review_updated_at": datetime.now(UTC),
        }
    )


def test_independent_instances_share_records_and_review_without_duplicate_metrics(tmp_path):
    path = tmp_path / "audit.sqlite3"
    first, second = SQLiteAuditStore(path), SQLiteAuditStore(path)
    original = initial(1)
    asyncio.run(first.save(original))
    assert second.get(original.event_id) == original
    updated = review(original)
    asyncio.run(second.save_review(updated, original))
    restored = SQLiteAuditStore(path)
    assert restored.get(original.event_id) == updated
    assert restored.metrics().total_analyses == 1
    assert restored.integrity()["verified_lines"] == 2


def test_concurrent_review_has_one_winner_and_no_lost_update(tmp_path):
    path = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(path)
    original = initial(1)
    asyncio.run(store.save(original))

    def attempt(index):
        try:
            asyncio.run(
                SQLiteAuditStore(path).save_review(review(original, f"reviewer-{index}"), original)
            )
            return True
        except AuditReviewConflict:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(attempt, range(4)))
    assert sum(results) == 1
    assert store.integrity()["verified_lines"] == 2


@pytest.mark.parametrize("change", ["payload", "head", "tail_delete", "gap", "missing_db"])
def test_corrupt_chain_or_missing_db_never_returns_partial_results(tmp_path, change):
    path = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(path)
    asyncio.run(store.save(initial(1)))
    asyncio.run(store.save(initial(2)))
    if change == "missing_db":
        path.unlink()
    else:
        with sqlite3.connect(path) as con:
            if change == "payload":
                con.execute("UPDATE audit_entries SET payload='{}' WHERE seq=1")
            if change == "head":
                con.execute("UPDATE audit_head SET seq=0")
            if change == "tail_delete":
                con.execute("DELETE FROM audit_entries WHERE seq=2")
            if change == "gap":
                con.execute("DELETE FROM audit_entries WHERE seq=1")
    assert store.integrity()["ok"] is False
    with pytest.raises(AuditQueryUnavailable):
        store.recent()
    with pytest.raises(AuditQueryUnavailable):
        asyncio.run(store.save(initial(3)))
    if change == "missing_db":
        assert not path.exists()


def test_cross_tenant_filter_and_idempotent_retries(tmp_path):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    first = initial(1)
    second = initial(2).model_copy(update={"tenant_id": "other"})
    for value in (first, first, second):
        asyncio.run(store.save(value))
    assert store.integrity()["verified_lines"] == 2
    assert store.get(second.event_id) is None
    assert store.metrics().total_analyses == 1
    assert store.get(second.event_id, "other") == second


@pytest.mark.parametrize("kind", ["immutable", "stale", "blind", "newer_analysis"])
def test_review_rejects_tampering_or_stale_preconditions(tmp_path, kind):
    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    original = initial(1)
    asyncio.run(store.save(original))
    updated = review(original)
    if kind == "immutable":
        updated = updated.model_copy(update={"actor_id": "forged"})
    if kind == "stale":
        asyncio.run(store.save_review(review(original, "first-reviewer"), original))
    if kind == "newer_analysis":
        asyncio.run(store.save(initial(2).model_copy(update={"event_id": original.event_id})))
    with pytest.raises(AuditReviewConflict):
        asyncio.run(
            store.save(updated) if kind == "blind" else store.save_review(updated, original)
        )


def test_multiple_process_writers_serialize_one_chain(tmp_path):
    path = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(path)
    code = """import asyncio,json,sys
from app.models import AnalysisResult
from app.services.sqlite_audit import SQLiteAuditStore
data=json.loads(sys.stdin.read())
store=SQLiteAuditStore(data['path'])
asyncio.run(store.save(AnalysisResult.model_validate(data['record'])))
"""
    env = dict(os.environ, AWS_EC2_METADATA_DISABLED="true")
    env.pop("OPENAI_API_KEY", None)
    children = [
        subprocess.Popen(
            [sys.executable, "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        for _ in range(4)
    ]
    for index, child in enumerate(children):
        child.stdin.write(
            json.dumps({"path": str(path), "record": initial(index).model_dump(mode="json")})
        )
        child.stdin.flush()
    for child in children:
        _, error = child.communicate(timeout=20)
        assert child.returncode == 0, error
    assert store.metrics().total_analyses == 4
    assert store.integrity()["verified_lines"] == 4


def test_foreign_database_is_not_modified(tmp_path):
    path = tmp_path / "policy.sqlite3"
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE policy (id TEXT)")
    before = path.read_bytes()
    with pytest.raises(AuditQueryUnavailable):
        SQLiteAuditStore(path)
    assert path.read_bytes() == before


def test_http_native_analysis_uses_shared_writer_and_cross_instance_review(
    api, tmp_path, monkeypatch
):
    from app import main

    path = tmp_path / "http-audit.sqlite3"
    store = SQLiteAuditStore(path)
    monkeypatch.setattr(main, "audit_store", store)
    response = api.post()
    assert response.status_code == 200, response.text
    payload = response.json()
    other = SQLiteAuditStore(path)
    assert other.get(payload["event_id"], payload["tenant_id"]).model_dump(mode="json") == payload
    monkeypatch.setattr(main, "audit_store", other)
    reviewed = api.client.patch(
        f"/results/{payload['event_id']}/review",
        headers=api.headers,
        json={"status": "RESOLVED", "note": "Verified native evidence"},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert (
        store.get(payload["event_id"], payload["tenant_id"]).reviewer == api.lab.principal.subject
    )
    assert store.metrics(payload["tenant_id"]).total_analyses == 1


def test_http_corruption_preflight_never_calls_model(api, tmp_path, monkeypatch):
    from app import main

    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    asyncio.run(store.save(initial(1)))
    with sqlite3.connect(store.path) as con:
        con.execute("UPDATE audit_head SET seq=100")
    monkeypatch.setattr(main, "audit_store", store)
    assert api.post().status_code == 502
    api.provider.analyze_with_evidence.assert_not_called()
    assert api.client.get("/results", headers=api.headers).status_code == 503


def test_http_review_race_returns_409_and_preserves_other_writer(api, tmp_path, monkeypatch):
    from app import main

    store = SQLiteAuditStore(tmp_path / "audit.sqlite3")
    original = initial(1).model_copy(update={"tenant_id": api.lab.principal.tenant_id})
    asyncio.run(store.save(original))
    save = store.save_review

    async def race(updated, expected):
        await save(review(expected, "competing-reviewer"), expected)
        await save(updated, expected)

    monkeypatch.setattr(store, "save_review", race)
    monkeypatch.setattr(main, "audit_store", store)
    response = api.client.patch(
        f"/results/{original.event_id}/review",
        headers=api.headers,
        json={"status": "RESOLVED", "note": "Review against stale read"},
    )
    assert response.status_code == 409
    assert store.get(original.event_id, original.tenant_id).reviewer == "competing-reviewer"


def test_factory_requires_explicit_backend_and_rejects_policy_path(tmp_path):
    from app.config import Settings
    from app.services.audit import AuditStore, create_audit_store

    config = Settings(
        _env_file=None,
        audit_backend="sqlite",
        audit_db_path=tmp_path / "audit.sqlite3",
        audit_log_path=tmp_path / "audit.jsonl",
        zero_trust_db_path=tmp_path / "policy.sqlite3",
    )
    assert isinstance(create_audit_store(config), SQLiteAuditStore)
    assert isinstance(
        create_audit_store(config.model_copy(update={"audit_backend": "jsonl"})), AuditStore
    )
    with pytest.raises(ValueError):
        create_audit_store(config.model_copy(update={"audit_db_path": config.zero_trust_db_path}))


@pytest.mark.parametrize("commit", [False, True])
def test_process_kill_before_or_after_commit_recovers_exact_chain(tmp_path, commit):
    path = tmp_path / "audit.sqlite3"
    store = SQLiteAuditStore(path)
    original, pending = initial(1), initial(2)
    asyncio.run(store.save(original))
    code = """import sys,json,sqlite3,hashlib,os
data=json.loads(sys.stdin.readline())
con=sqlite3.connect(data['path'])
con.execute('PRAGMA synchronous=FULL')
con.execute('BEGIN IMMEDIATE')
seq,head=con.execute('SELECT seq,digest FROM audit_head').fetchone()
payload=data['payload']
digest=hashlib.sha256((head+'.'+payload).encode()).hexdigest()
con.execute('INSERT INTO audit_entries VALUES (?,?,?,?)',(seq+1,head,digest,payload))
con.execute('UPDATE audit_head SET seq=?,digest=?',(seq+1,digest))
if data['commit']: con.commit()
print(json.dumps({'state':'ready','pid':os.getpid()}),flush=True)
sys.stdin.readline()
"""
    executable, environment = direct_python(os.environ)
    child = subprocess.Popen(
        [executable, "-c", code],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        child.stdin.write(
            json.dumps({"path": str(path), "payload": pending.model_dump_json(), "commit": commit})
            + "\n"
        )
        child.stdin.flush()
        assert json.loads(child.stdout.readline()) == {"state": "ready", "pid": child.pid}
        child.kill()
        child.wait(timeout=10)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
    recovered = SQLiteAuditStore(path)
    assert recovered.get(original.event_id) == original
    assert (recovered.get(pending.event_id) == pending) is commit
    assert recovered.integrity()["verified_lines"] == (2 if commit else 1)
    asyncio.run(recovered.save(initial(3)))
    assert recovered.integrity()["ok"]
