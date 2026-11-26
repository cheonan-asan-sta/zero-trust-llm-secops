"""Free local shared-reader fixtures and independent-process acceptance."""

import hashlib
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from app.services.trusted_signals import SignalRejected, SignalVerifier
from app.services.zero_trust import ZeroTrustOperations
from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.service_analysis_evidence import publish_service_analysis
from scripts.f1_lab.shared_service_analysis import SharedServiceConfig, open_shared_service_registry


def configure(lab, directory, *, capacity=128):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    key = directory / "reference-key.bin"
    key.write_bytes(secrets.token_bytes(32))
    key.chmod(0o600)
    config = SharedServiceConfig(
        reference_db_path=str((directory / "references.sqlite3").resolve()),
        encryption_key_path=str(key.resolve()),
        encryption_key_sha256=hashlib.sha256(key.read_bytes()).hexdigest(),
        service_registry_path=str(lab.broker.joiner.registry.path.resolve()),
        service_registry_sha256=lab.broker.joiner.registry.expected_sha256,
        service_ledger_path=str(lab.broker.joiner.path.resolve()),
        caller_registry_path=str(lab.broker.registry.path.resolve()),
        caller_registry_sha256=lab.broker.registry.sha256,
        caller_environment="local_oidc",
        capacity=capacity,
    )
    path = directory / "shared-reader.json"
    path.write_text(config.model_dump_json(), encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest(), config


def new_operations(lab):
    return ZeroTrustOperations(
        lab.operations.path,
        signal_verifier=SignalVerifier(lab.operations.signal_verifier.registry_path),
    )


def probe(lab, config_path, config_sha256, ref):
    env = dict(os.environ)
    env.pop("OPENAI_API_KEY", None)
    env.pop("OPENAI_API_KEY_SECRET_ARN", None)
    env["AWS_EC2_METADATA_DISABLED"] = "true"
    request = {
        "operations_db": str(lab.operations.path),
        "signal_sources": str(lab.operations.signal_verifier.registry_path),
        "config_path": str(config_path),
        "config_sha256": config_sha256,
        "execution_ref": ref,
        "subject": lab.principal.subject,
        "tenant_id": lab.principal.tenant_id,
    }
    result = subprocess.run(
        [sys.executable, "-m", "scripts.probe_shared_native_analysis"],
        input=json.dumps(request),
        text=True,
        encoding="utf-8",
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    require(result.returncode == 0, "shared_native_independent_process_probe")
    return json.loads(result.stdout)


def run(lab, request, access, receipt, event, proofs, directory, passed):
    path, pin, config = configure(lab, Path(directory) / "shared-analysis")
    publisher = open_shared_service_registry(lab.operations, path, pin)
    ref = publish_service_analysis(
        publisher,
        lab.operations,
        lab.signals[access.session_id],
        lab.principal,
        lab.broker.joiner,
        lab.broker.registry,
        request,
        event,
        proofs,
        receipt,
    )
    first = probe(lab, path, pin, ref)
    second = probe(lab, path, pin, ref)
    require(
        first == second and first["available"] and first["event_sha256"] == event.sha256,
        "shared_native_cross_process_restart",
    )
    passed("shared_native_separate_process_reloads_and_revalidates_encrypted_reference")
    passed("shared_native_new_process_preserves_original_reference_and_expiry")
    reader = open_shared_service_registry(new_operations(lab), path, pin)
    _, context = reader.resolve(ref, lab.principal)
    raw = Path(config.reference_db_path).read_bytes()
    require(
        all(
            secret not in raw
            for secret in (
                request.nonce.encode(),
                receipt.signature.encode(),
                ref.encode(),
                Path(config.encryption_key_path).read_bytes(),
            )
        ),
        "shared_native_no_plaintext",
    )
    passed("shared_native_db_excludes_plaintext_nonce_signatures_reference_and_key")
    publisher.revoke(ref)
    require(probe(lab, path, pin, ref) == {"available": False}, "shared_native_durable_revocation")
    passed("shared_native_revocation_survives_process_restart")
    try:
        context.verify_current()
    except SignalRejected:
        passed("shared_native_other_reader_observes_inflight_revocation")
    else:
        raise ValueError("shared reader failed to observe withdrawal")
    return path, pin
