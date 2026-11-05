"""Runtime build failures must stop before installing unverified input."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from infra.runtime import build_runtime as build
from infra.runtime import verify_security
from scripts import test_continuous_mtls_runtime as mtls_checks
from scripts import verify_runtime_upgrade as upgrade
from scripts.recheck_supply_chain import IDENTITIES, verify_prior_snapshot
from scripts.test_continuous_mtls_runtime import Checks, RuntimeFailure

ROOT = Path(__file__).resolve().parents[1]
PATCH = "--- Lib/http/client.py\n+++ Lib/http/client.py\n@@ -1,2 +1,2 @@\n first\n-old\n+new\n"


def test_exact_patch_preserves_unmodified_tail():
    assert build.apply_hunks("first\nold\ntail\n", PATCH) == "first\nnew\ntail\n"


@pytest.mark.parametrize("patch,source", [
    (PATCH.replace("+++ Lib/http/client.py", "+++ ../../outside"), "first\nold\n"),
    (PATCH, "changed\nold\n"),
    (PATCH.replace("-1,2", "-2,2"), "first\nold\n"),
    (PATCH.replace("+1,2", "+2,2"), "first\nold\n"),
    (PATCH.replace("-1,2", "-1,3"), "first\nold\n"),
    (PATCH + "@@ -1 +1 @@\n first\n", "first\nold\n"),
    (PATCH + "invalid\n", "first\nold\n"),
])
def test_patch_refuses_scope_context_offsets_and_malformed_hunks(patch, source):
    with pytest.raises(ValueError):
        build.apply_hunks(source, patch)


@pytest.mark.parametrize("tamper,reason", [
    ("source", "stdlib_before_digest"), ("patch", "stdlib_patch_digest"),
    ("result", "stdlib_after_digest"), ("version", "runtime_python_version"),
])
def test_http_patch_tamper_never_writes_target(tmp_path, monkeypatch, tamper, reason):
    source = b"first\nold\ntail\n"
    client = tmp_path / "http/client.py"
    client.parent.mkdir()
    client.write_bytes(source)
    (tmp_path / "http-client.patch").write_text(PATCH, encoding="utf-8", newline="\n")
    lock = {"python_version": "3.12.16", "http_client": {
        "before_sha256": build.sha256(source), "patch_sha256": build.sha256(PATCH.encode()),
        "after_sha256": build.sha256(b"first\nnew\ntail\n")}}
    monkeypatch.setattr(build, "HERE", tmp_path)
    monkeypatch.setattr(build.sysconfig, "get_path", lambda _: str(tmp_path))
    monkeypatch.setattr(build.platform, "python_version", lambda: "wrong" if tamper == "version" else "3.12.16")
    key = {"source": "before_sha256", "patch": "patch_sha256", "result": "after_sha256"}.get(tamper)
    if key:
        lock["http_client"][key] = "0" * 64
    with pytest.raises(ValueError, match=reason):
        build.patch_http(lock)
    assert client.read_bytes() == source


@pytest.mark.parametrize("url", ["http://www.sqlite.org/file", "https://evil.invalid/file"])
def test_source_origin_rejected_before_network(tmp_path, monkeypatch, url):
    monkeypatch.setattr(build, "urlopen", lambda *_a, **_k: pytest.fail("network must not run"))
    with pytest.raises(ValueError, match="runtime_source_origin"):
        build.download({"url": url}, tmp_path / "target")


@pytest.mark.parametrize("fault", ["redirect", "sha256", "sha3", "size"])
def test_download_refuses_untrusted_bytes_without_writing(tmp_path, monkeypatch, fault):
    class Response(io.BytesIO):
        url = "https://evil.invalid/file" if fault == "redirect" else "https://www.sqlite.org/file"
    data = b"verified-small-source"
    monkeypatch.setattr(build, "urlopen", lambda *_a, **_k: Response(data))
    spec = {"url": "https://www.sqlite.org/file", "sha256": build.sha256(data),
            "sha3_256": hashlib.sha3_256(data).hexdigest()}
    if fault in {"sha256", "sha3"}:
        spec["sha256" if fault == "sha256" else "sha3_256"] = "0" * 64
    target = tmp_path / "target"
    with pytest.raises(ValueError, match="runtime_source"):
        build.download(spec, target, limit=1 if fault == "size" else 100)
    assert not target.exists()


@pytest.mark.parametrize("kind", ["traversal", "absolute", "symlink", "hardlink", "fifo"])
def test_sqlite_archive_refuses_paths_and_links(tmp_path, kind):
    archive = tmp_path / "source.tar.gz"
    member = tarfile.TarInfo({"traversal": "../escaped", "absolute": "/escaped"}.get(kind, "source/entry"))
    member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                   "fifo": tarfile.FIFOTYPE}.get(kind, tarfile.REGTYPE)
    member.linkname = "../../escaped"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.addfile(member, io.BytesIO(b""))
    destination = tmp_path / "unpack"
    destination.mkdir()
    with pytest.raises(ValueError, match="source_archive_path"):
        build.extract_sqlite(archive, destination)
    assert list(destination.iterdir()) == []


def test_bootstrap_rejects_tampered_wheel_before_pip(tmp_path, monkeypatch):
    wheel = tmp_path / "pip.whl"
    wheel.write_bytes(b"tampered")
    monkeypatch.setattr(build.subprocess, "run", lambda *_a, **_k: pytest.fail("pip must not run"))
    with pytest.raises(ValueError, match="pip_bootstrap_digest"):
        build.bootstrap_pip({"pip": {"filename": wheel.name, "sha256": "0" * 64}}, tmp_path)


def test_install_rejects_tampered_library_before_system_change(tmp_path, monkeypatch):
    (tmp_path / "libsqlite3.so.0").write_bytes(b"tampered")
    (tmp_path / "runtime.json").write_text(json.dumps({"library_sha256": "0" * 64}))
    monkeypatch.setattr(build.subprocess, "run", lambda *_a, **_k: pytest.fail("installer must not run"))
    with pytest.raises(ValueError, match="sqlite_install_digest"):
        build.install_library(tmp_path)


def test_project_build_rejects_ambiguous_wheel_directory(tmp_path, monkeypatch):
    (tmp_path / "foreign.whl").write_bytes(b"untrusted")
    monkeypatch.setattr(build.subprocess, "run", lambda *_a, **_k: pytest.fail("build must not run"))
    with pytest.raises(ValueError, match="project_wheel_directory_not_empty"):
        build.build_project(tmp_path)


def test_runtime_locks_require_versions_hashes_and_no_source_builds():
    for path in (ROOT / "infra/runtime/requirements").glob("*.lock"):
        text = path.read_text(encoding="utf-8")
        assert "--hash=sha256:" in text and "==" in text
        assert not any(token in text for token in ["http:", "https:", "git+", "--extra-index", "--trusted-host"])


@pytest.mark.skipif(os.environ.get("SECOPS_PATCHED_RUNTIME") != "1", reason="patched Linux image only; host runtime unchanged")
def test_actual_container_runtime_security_and_provenance():
    result = verify_security.report()
    assert result["passed"], result["checks"]
    metadata = json.loads(Path("/opt/secops-runtime/runtime.json").read_text())
    build.verify(build.load_lock(), Path("/opt/secops-runtime/runtime.json"))
    assert metadata["debian_package"]["official_debian_build"] is False
    assert result["http_client_sha256"] == build.load_lock()["http_client"]["after_sha256"]


def test_parser_controls_preserve_valid_http_and_sqlite_backup():
    assert verify_security.content_length(b"5 \t") == 5
    assert verify_security.chunk_size(b"5;name=value") == 5
    assert all(verify_security.sqlite_checks().values())


def test_journal_upgrade_fixture_preserves_consumption_revocation_and_backup(tmp_path):
    assert upgrade.prepare(tmp_path)["prepared"]
    result = upgrade.verify(tmp_path)
    assert result["passed"], result["checks"]
    assert len(result["checks"]) == 18


def test_upgrade_requires_fresh_scratch(tmp_path):
    (tmp_path / "user-file").write_text("preserve")
    with pytest.raises(RuntimeError, match="fresh_scratch_directory_required"):
        upgrade.prepare(tmp_path)
    assert (tmp_path / "user-file").read_text() == "preserve"


@pytest.mark.parametrize("fault", [None, "incomplete", "tool", "identity", "missing_signature", "unverified", "db_mutated", "db_empty"])
def test_rescan_rejects_changed_tools_signature_records_or_database(fault):
    lock = {"tools": ["fixture"]}
    previous = {"completed": True, "tools": lock, "db_files": {"db": "digest"},
                "db_files_after": {"db": "digest"}, "signature_verification": {
                    name: {"checksum_verified": True, "identity": identity} for name, identity in IDENTITIES.items()}}
    if fault == "incomplete":
        previous["completed"] = False
    elif fault == "tool":
        previous["tools"] = {}
    elif fault == "identity":
        previous["signature_verification"]["syft"]["identity"] = "untrusted-workflow"
    elif fault == "missing_signature":
        previous["signature_verification"].pop("trivy")
    elif fault == "unverified":
        previous["signature_verification"]["grype"]["checksum_verified"] = False
    elif fault == "db_mutated":
        previous["db_files_after"]["db"] = "changed"
    elif fault == "db_empty":
        previous["db_files"] = previous["db_files_after"] = {}
    if fault is None:
        verify_prior_snapshot(previous, lock)
    else:
        with pytest.raises(ValueError, match="historical_"):
            verify_prior_snapshot(previous, lock)


@pytest.mark.parametrize("fault", [None, "before", "after", "new_wheel", "old_wheel", "bundle_scope", "marker"])
def test_ensurepip_refresh_validates_every_input_before_writing(tmp_path, monkeypatch, fault):
    source = b'_PIP_VERSION = "25.0.1"\n'
    target = tmp_path / "ensurepip/__init__.py"
    bundled = target.parent / "_bundled"
    bundled.mkdir(parents=True)
    target.write_bytes(source)
    old = bundled / "pip-25.0.1-py3-none-any.whl"
    old.write_bytes(b"old-wheel")
    wheel = tmp_path / "pip-26.3-py3-none-any.whl"
    wheel.write_bytes(b"verified-wheel")
    lock = {"pip": {"version": "26.3", "filename": wheel.name, "sha256": build.sha256(wheel.read_bytes())},
            "ensurepip": {"old_version": "25.0.1", "before_sha256": build.sha256(source),
                          "after_sha256": build.sha256(source.replace(b"25.0.1", b"26.3")),
                          "old_wheel_sha256": build.sha256(old.read_bytes())}}
    monkeypatch.setattr(build.sysconfig, "get_path", lambda _: str(tmp_path))
    if fault in {"before", "after"}:
        lock["ensurepip"][fault + "_sha256"] = "0" * 64
    elif fault == "new_wheel":
        wheel.write_bytes(b"tampered")
    elif fault == "old_wheel":
        old.write_bytes(b"tampered")
    elif fault == "bundle_scope":
        (bundled / "foreign.whl").write_bytes(b"unexpected")
    elif fault == "marker":
        lock["ensurepip"]["old_version"] = "wrong"
    if fault is None:
        build.refresh_ensurepip(lock, wheel)
        assert target.read_bytes() == b'_PIP_VERSION = "26.3"\n'
        assert not old.exists() and (bundled / wheel.name).read_bytes() == wheel.read_bytes()
    else:
        with pytest.raises(ValueError, match="ensurepip_"):
            build.refresh_ensurepip(lock, wheel)
        assert target.read_bytes() == source
        assert not (bundled / wheel.name).exists()


@pytest.mark.skipif(os.environ.get("SECOPS_PATCHED_RUNTIME") != "1", reason="patched Linux image only; host runtime unchanged")
def test_new_offline_venv_bootstraps_patched_pip(tmp_path):
    environment = tmp_path / "fresh-venv"
    subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True, capture_output=True, timeout=45)
    result = subprocess.check_output([str(environment / "bin/python"), "-m", "pip", "--version"], text=True, timeout=15)
    assert result.startswith("pip 26.3 ")


@pytest.mark.parametrize("status,reason,response_status,passes", [
    ("ACTIVE", "GRANT_EXPIRED", 403, True),
    ("HELD", "SESSION_NOT_AUTHORIZED", 403, True),
    ("ACTIVE", "GRANT_INVALID", 403, False),
    ("ACTIVE", "GRANT_EXPIRED", 200, False),
    ("REVOKED", "SESSION_NOT_AUTHORIZED", 403, False),
    ("BAD_HOLD", "SESSION_NOT_AUTHORIZED", 403, False),
])
def test_long_outage_control_never_hides_revocation_or_revives_expired_grant(status, reason, response_status, passes):
    first = {"version": 1, "decision": "ALLOW", "status": "ACTIVE",
             "grant_expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat()}
    history = [first]
    if status != "ACTIVE":
        history.append({"version": 2, "decision": "DENY" if status == "REVOKED" else "HOLD",
                        "status": "REVOKED" if status == "REVOKED" else "HELD",
                        "reason_codes": ["UNEXPECTED"] if status == "BAD_HOLD" else ["SIGNAL_PROOF_EXPIRED"]})
    checks = object.__new__(Checks)
    records = []
    checks.history = lambda _: history
    checks.runtime = SimpleNamespace(probe=lambda _: {"status": response_status, "body": {"reason_code": reason}})
    checks.mint = lambda name, **_: (name, "fresh-synthetic-token")
    checks.access = lambda pair, allowed, label: records.append((pair, allowed, label))
    checks.add = lambda *_a, **_kw: None
    if passes:
        checks.unrelated_after_outage(("old-session", "expired-synthetic-token"))
        assert records[0][0] == ("old-session-fresh", "fresh-synthetic-token")
        assert records[0][1] is True
    else:
        with pytest.raises(RuntimeFailure, match="outage_"):
            checks.unrelated_after_outage(("old-session", "expired-synthetic-token"))
        assert not records


@pytest.mark.parametrize("fail", [False, True])
def test_storage_snapshot_quiesces_and_always_resumes_expiry_watchdog(monkeypatch, fail):
    calls = []
    checks = object.__new__(Checks)
    checks.runtime = SimpleNamespace(container=lambda _: "owned-watchdog")
    monkeypatch.setattr(mtls_checks, "command", lambda argv: calls.append(argv))

    def mint(_):
        assert calls == [["docker", "stop", "--time", "2", "owned-watchdog"]]
        return ("normal", "synthetic")

    checks.mint = mint
    checks.access = lambda *_a: None

    def journal(_):
        if fail:
            raise RuntimeFailure("synthetic_snapshot_failure")
    checks.journal_security = journal
    if fail:
        with pytest.raises(RuntimeFailure, match="synthetic_snapshot_failure"):
            checks.journal_phase()
    else:
        checks.journal_phase()
    assert calls[-1] == ["docker", "start", "owned-watchdog"]
