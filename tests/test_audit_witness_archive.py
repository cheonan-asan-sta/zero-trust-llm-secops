"""Recover a complete signed generation from independently held bytes and pins."""

import base64
import io
import json
import os
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import uuid4

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError, IncompleteReadError
from botocore.response import StreamingBody
from botocore.stub import Stubber
from test_audit_witness_observer import ready

from app.services import audit_witness_archive as archive
from app.services import audit_witness_worm as worm
from app.services.audit_backup import backup_sqlite
from app.services.audit_transfer import AuditTransferError, canonical, decode, sha
from app.services.sqlite_audit import SQLiteAuditStore
from scripts import audit_witness_archive as archive_cli
from scripts.run_witness_systemd_controls import fill_generation

BUCKET = "separate-audit-fixture"
OWNER = "123456789012"
VERSION = "pinned-test-version"


@pytest.fixture(scope="module")
def closed_generation(tmp_path_factory):
    root = tmp_path_factory.mktemp("portable-witness")
    source_host = root / "source-host"
    source_host.mkdir()
    source, signer, public_key, first, control, profile = ready(source_host)
    terminal = fill_generation(signer, control, public_key, first["receipt_sha256"])
    recovery_host = root / "recovery-host"
    recovery_host.mkdir()
    exported = recovery_host / "previous.json"
    before = (source.path.read_bytes(), (signer / "journal.sqlite3").read_bytes(),
              (control / "observer.sqlite3").read_bytes())
    result = archive.export(control, profile, terminal, exported)
    assert result["receipt_count"] == 4096
    assert before == (source.path.read_bytes(), (signer / "journal.sqlite3").read_bytes(),
                      (control / "observer.sqlite3").read_bytes())
    backup = recovery_host / "audit.aes"
    key = os.urandom(32)
    key_file = recovery_host / "recovery.key"
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    saved = backup_sqlite(source, backup, key, minimum_head=result["audit_minimum_head"])
    old_path = str(source.path)
    source_host.rename(root / "source-offline")
    assert not source_host.exists()
    pins = {"archive_pin": result["archive_sha256"], "key_pin": public_key, "terminal_pin": terminal}
    return exported, backup, saved["backup_sha256"], key_file, pins, old_path


def test_separate_cli_process_restores_without_original_paths(closed_generation, tmp_path):
    exported, backup, backup_pin, key_file, pins, old_path = closed_generation
    args = ["--archive", str(exported), "--archive-sha256", pins["archive_pin"],
            "--public-key-sha256", pins["key_pin"], "--terminal-sha256", pins["terminal_pin"]]
    command = [sys.executable, "-m", "scripts.audit_witness_archive"]
    inspected = subprocess.run(command + ["inspect", *args], check=True, capture_output=True,
                               text=True, encoding="utf-8", timeout=60)
    evidence = json.loads(inspected.stdout)
    assert evidence["receipt_count"] == 4096
    assert old_path not in exported.read_text(encoding="utf-8")
    destination = tmp_path / "recovered.sqlite3"
    restored = subprocess.run(
        command + ["restore-audit", *args, "--backup", str(backup), "--backup-sha256", backup_pin,
                   "--key-file", str(key_file), "--key-sha256", sha(key_file.read_bytes()),
                   "--destination", str(destination)],
        check=True, capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    assert json.loads(restored.stdout)["restored_audit"]["head"] == evidence["audit_minimum_head"]
    SQLiteAuditStore.open_existing(destination)
    if os.name == "posix":
        assert destination.stat().st_mode & 0o077 == 0


def test_valid_encrypted_backup_behind_witness_head_is_not_published(closed_generation, tmp_path):
    exported, _, _, _, pins, _ = closed_generation
    empty = SQLiteAuditStore(tmp_path / "empty.sqlite3")
    backup = tmp_path / "empty.aes"
    key = os.urandom(32)
    saved = backup_sqlite(empty, backup, key)
    destination = tmp_path / "recovered.sqlite3"
    with pytest.raises(AuditTransferError, match="older than required checkpoint"):
        archive.restore_audit(
            archive.read(exported), pins["archive_pin"], pins["key_pin"], pins["terminal_pin"],
            backup, saved["backup_sha256"], key, destination,
        )
    assert not destination.exists()


@pytest.mark.parametrize("change", ["middle_signature", "truncated", "terminal_pin", "key_pin"])
def test_archive_requires_independent_pins_and_every_signature(closed_generation, change):
    exported, _, _, _, pins, _ = closed_generation
    raw = archive.read(exported)
    if change in {"middle_signature", "truncated"}:
        value = decode(raw)
        if change == "truncated":
            value["receipts"].pop(2000)
        else:
            value["receipts"][2000]["signature"] = base64.b64encode(bytes(64)).decode()
        raw = canonical(value)
        pins = dict(pins, archive_pin=sha(raw))
    else:
        pins = dict(pins, **{change: "a" * 64})
    with pytest.raises(AuditTransferError):
        archive.inspect(raw, **pins)


def s3_stub(raw, pins, until):
    client = boto3.client("s3", region_name="us-east-1", aws_access_key_id="fake-access",
                          aws_secret_access_key="fake-secret")
    location = {"Bucket": BUCKET, "ExpectedBucketOwner": OWNER,
                "Key": "audit-witness/v1/sha256/" + pins["archive_pin"] + ".json"}
    request = dict(location, VersionId=VERSION)
    response = {"VersionId": VERSION, "ObjectLockMode": "COMPLIANCE",
                "ObjectLockRetainUntilDate": until, "ContentLength": len(raw),
                "Body": StreamingBody(io.BytesIO(raw), len(raw))}
    return client, location, request, response


def test_worm_conditional_upload_readback_and_pinned_recovery(closed_generation, tmp_path):
    exported, _, _, _, pins, _ = closed_generation
    raw = archive.read(exported)
    until = datetime.now(UTC).replace(microsecond=0) + timedelta(days=10)
    client, location, request, response = s3_stub(raw, pins, until)
    put = dict(location, Body=raw, IfNoneMatch="*", ContentType="application/json",
               ChecksumAlgorithm="SHA256",
               ChecksumSHA256=base64.b64encode(bytes.fromhex(pins["archive_pin"])).decode(),
               ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until)
    with Stubber(client) as stub:
        stub.add_response("put_object", {"VersionId": VERSION}, put)
        stub.add_response("get_object", response, request)
        receipt = worm.upload(client, BUCKET, OWNER, until, raw, **pins)
        assert receipt["retention_active"] and receipt["version_id"] == VERSION
        stub.add_client_error("put_object", service_error_code="PreconditionFailed",
                              http_status_code=412, expected_params=put)
        with pytest.raises(ClientError, match="PreconditionFailed"):
            worm.upload(client, BUCKET, OWNER, until, raw, **pins)
        _, _, _, response = s3_stub(raw, pins, until)
        stub.add_response("get_object", response, request)
        downloaded, evidence = worm.fetch(client, BUCKET, OWNER, VERSION, until, **pins)
        recovered = tmp_path / "from-store.json"
        archive.write(downloaded, recovered)
        assert archive.read(recovered) == raw
        assert evidence == receipt
        stub.assert_no_pending_responses()


@pytest.mark.skipif(not os.getenv("AUDIT_LOCAL_S3_ENDPOINT"), reason="local S3 simulator is opt-in")
def test_loopback_s3_worm_exact_version_restore(closed_generation, tmp_path):
    endpoint = os.environ["AUDIT_LOCAL_S3_ENDPOINT"]
    parts = urlsplit(endpoint)
    assert parts.scheme == "http" and parts.hostname == "127.0.0.1" and parts.port
    assert parts.netloc == f"127.0.0.1:{parts.port}" and not (parts.path or parts.query or parts.fragment)
    exported, backup, backup_pin, key_file, pins, _ = closed_generation
    bucket = "ephemeral-archive-" + uuid4().hex[:12]

    def client(identity):
        return boto3.client("s3", endpoint_url=endpoint, region_name="us-east-1",
                            aws_access_key_id=identity, aws_secret_access_key="fixture-secret",
                            config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 0}))

    with closing(client("placeholder-publisher")) as publisher, closing(client("placeholder-restorer")) as restorer:
        publisher.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
        retain_until = datetime.now(UTC).replace(microsecond=0) + timedelta(days=2)
        receipt = worm.upload(publisher, bucket, OWNER, retain_until, archive.read(exported), **pins)
        with pytest.raises(ClientError) as retained:
            publisher.delete_object(Bucket=bucket, Key=receipt["object_key"], VersionId=receipt["version_id"])
        assert retained.value.response["Error"]["Code"] == "AccessDenied"
        raw, copied = worm.fetch(restorer, bucket, OWNER, receipt["version_id"], retain_until, **pins)
        assert copied["retention_mode"] == "COMPLIANCE" and copied["retention_active"]
        assert copied["archive_sha256"] == pins["archive_pin"] and copied["receipt_count"] == 4096
        destination = tmp_path / "recovered-from-loopback.sqlite3"
        archive.restore_audit(raw, pins["archive_pin"], pins["key_pin"], pins["terminal_pin"],
                              backup, backup_pin, key_file.read_bytes(), destination)
        SQLiteAuditStore.open_existing(destination)


@pytest.mark.parametrize("fault", ["version", "mode", "retention", "bytes"])
def test_worm_refuses_unpinned_or_unprotected_readback(closed_generation, fault):
    exported, _, _, _, pins, _ = closed_generation
    raw = archive.read(exported)
    until = datetime.now(UTC) + timedelta(days=10)
    client, _, request, response = s3_stub(raw, pins, until)
    if fault == "version":
        response["VersionId"] = "unexpected-latest"
    elif fault == "mode":
        response["ObjectLockMode"] = "GOVERNANCE"
    elif fault == "retention":
        response["ObjectLockRetainUntilDate"] = until - timedelta(days=1)
    else:
        response["Body"] = StreamingBody(io.BytesIO(b"!" + raw[1:]), len(raw))
    with Stubber(client) as stub:
        stub.add_response("get_object", response, request)
        with pytest.raises(AuditTransferError):
            worm.fetch(client, BUCKET, OWNER, VERSION, until, **pins)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("size_mismatch", [0, -1, 1])
def test_worm_readback_handles_fragmented_response(closed_generation, size_mismatch):
    class FragmentedBody(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 65536))

    exported, _, _, _, pins, _ = closed_generation
    raw = archive.read(exported)
    until = datetime.now(UTC) + timedelta(days=10)
    client, _, request, response = s3_stub(raw, pins, until)
    body = raw[:-1] if size_mismatch < 0 else raw + b"x" * size_mismatch
    source = FragmentedBody(body)
    response["Body"] = StreamingBody(source, len(raw))
    with Stubber(client) as stub:
        stub.add_response("get_object", response, request)
        if size_mismatch < 0:
            with pytest.raises(IncompleteReadError):
                worm.fetch(client, BUCKET, OWNER, VERSION, until, **pins)
        elif size_mismatch > 0:
            with pytest.raises(AuditTransferError, match="object length mismatch"):
                worm.fetch(client, BUCKET, OWNER, VERSION, until, **pins)
        else:
            downloaded, result = worm.fetch(client, BUCKET, OWNER, VERSION, until, **pins)
            assert downloaded == raw and result["version_id"] == VERSION
        stub.assert_no_pending_responses()
    assert source.closed


def test_worm_upload_preserves_version_when_verification_could_not_finish(closed_generation):
    exported, _, _, _, pins, _ = closed_generation
    raw = archive.read(exported)
    until = datetime.now(UTC) + timedelta(days=10)
    client, location, request, response = s3_stub(raw, pins, until)
    put = dict(location, Body=raw, IfNoneMatch="*", ContentType="application/json",
               ChecksumAlgorithm="SHA256", ChecksumSHA256=base64.b64encode(bytes.fromhex(pins["archive_pin"])).decode(),
               ObjectLockMode="COMPLIANCE", ObjectLockRetainUntilDate=until)
    with Stubber(client) as stub:
        stub.add_response("put_object", {"VersionId": VERSION}, put)
        stub.add_client_error("get_object", service_error_code="ServiceUnavailable",
                              http_status_code=503, expected_params=request)
        with pytest.raises(worm.WormReadbackError) as result:
            worm.upload(client, BUCKET, OWNER, until, raw, **pins)
        assert result.value.version_id == VERSION
        assert isinstance(result.value.__cause__, ClientError)
        stub.add_response("get_object", response, request)
        assert worm.fetch(client, BUCKET, OWNER, result.value.version_id, until, **pins)[0] == raw
        stub.assert_no_pending_responses()


def test_worm_upload_cli_reports_unverified_version_without_success(closed_generation, monkeypatch, capsys):
    exported, _, _, _, pins, _ = closed_generation
    until = datetime.now(UTC) + timedelta(days=10)
    client = object()
    monkeypatch.setattr(boto3, "client", lambda *args, **kwargs: client)
    def interrupted(s3, bucket, owner, deadline, raw, **expected):
        assert (s3, bucket, owner, deadline, expected) == (client, BUCKET, OWNER, until, pins)
        raise worm.WormReadbackError(VERSION)

    monkeypatch.setattr(worm, "upload", interrupted)
    monkeypatch.setattr(sys, "argv", [
        "archive", "upload-worm", "--archive", str(exported),
        "--archive-sha256", pins["archive_pin"], "--public-key-sha256", pins["key_pin"],
        "--terminal-sha256", pins["terminal_pin"], "--bucket", BUCKET, "--bucket-owner", OWNER,
        "--region", "us-east-1", "--retain-until", until.isoformat(),
    ])
    assert archive_cli.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert json.dumps(VERSION) in output.err and "fetch-worm" in output.err
