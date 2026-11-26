"""Fixed-schema signed bundles and pinned host bootstrap for shared HTTP readers.

Serialized evidence never selects a file path, URL, key, decoder, or Python object.
The loader is installed only by trusted server configuration, not an HTTP request.
"""

import hashlib
import sqlite3
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.models import StrictModel
from app.services.shared_native_analysis import (
    EncryptedNativeReferenceStore,
    SharedNativeAnalysisRegistry,
)
from app.services.trusted_signals import SignalRegistryUnavailable
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.native_jsonl import decode, require
from scripts.f1_lab.service_analysis_evidence import collect_service_analysis_evidence
from scripts.f1_lab.service_caller_identity import (
    CallerReceipt,
    PinnedCallerRegistry,
    ServiceRequest,
)
from scripts.f1_lab.shared_execution_evidence import (
    PinnedServiceRegistry,
    ServiceEvent,
    ServiceEvidenceJoiner,
    ServiceProof,
)
from scripts.f1_lab.web_verified_context import SHA


class NativeServiceBundle(StrictModel):
    schema_version: Literal["native-service-analysis-bundle-1"] = "native-service-analysis-bundle-1"
    signal: SignedSessionSignal
    request: ServiceRequest
    event: ServiceEvent
    proofs: list[ServiceProof] = Field(min_length=2, max_length=2)
    receipt: CallerReceipt


def shared_service_registry(operations, store, joiner, caller_registry):
    def decoder(raw):
        bundle = NativeServiceBundle.model_validate(decode(raw))

        def collect(principal):
            return collect_service_analysis_evidence(
                operations,
                bundle.signal,
                principal,
                joiner,
                caller_registry,
                bundle.request,
                bundle.event,
                bundle.proofs,
                bundle.receipt,
            )

        return bundle.signal, collect

    return SharedNativeAnalysisRegistry(operations, store, decoder)


class SharedServiceConfig(StrictModel):
    schema_version: Literal["native-shared-analysis-config-1"] = "native-shared-analysis-config-1"
    reference_db_path: str
    encryption_key_path: str
    encryption_key_sha256: SHA
    service_registry_path: str
    service_registry_sha256: SHA
    service_ledger_path: str
    caller_registry_path: str
    caller_registry_sha256: SHA
    caller_environment: Literal["local_oidc", "oidc"] = "oidc"
    capacity: int = Field(default=128, strict=True, ge=1, le=1024)

    @field_validator(
        "reference_db_path",
        "encryption_key_path",
        "service_registry_path",
        "service_ledger_path",
        "caller_registry_path",
    )
    @classmethod
    def absolute_path(cls, value):
        require(Path(value).is_absolute(), "shared_native_absolute_path")
        return value

    @model_validator(mode="after")
    def distinct_files(self):
        paths = [
            Path(value).resolve()
            for value in (
                self.reference_db_path,
                self.encryption_key_path,
                self.service_registry_path,
                self.service_ledger_path,
                self.caller_registry_path,
            )
        ]
        require(len(set(paths)) == len(paths), "shared_native_separate_files")
        return self


def open_shared_service_registry(operations, config_path, config_sha256):
    """Called at worker startup; bad/missing configuration never falls back to memory."""
    try:
        path = Path(config_path)
        require(path.is_file() and not path.is_symlink(), "shared_native_config_path")
        with path.open("rb") as stream:
            raw = stream.read(16385)
        require(
            len(raw) <= 16384 and hashlib.sha256(raw).hexdigest() == config_sha256,
            "shared_native_config_pin",
        )
        config = SharedServiceConfig.model_validate(decode(raw))
        require(
            Path(config.reference_db_path).resolve()
            not in {
                path.resolve(),
                operations.path.resolve(),
            },
            "shared_native_application_db_isolation",
        )
        joiner = ServiceEvidenceJoiner(
            PinnedServiceRegistry(config.service_registry_path, config.service_registry_sha256),
            config.service_ledger_path,
            read_only=True,
        )
        caller_registry = PinnedCallerRegistry(
            config.caller_registry_path,
            config.caller_registry_sha256,
            expected_environment=config.caller_environment,
        )
        store = EncryptedNativeReferenceStore(
            config.reference_db_path,
            config.encryption_key_path,
            config.encryption_key_sha256,
            capacity=config.capacity,
        )
        return shared_service_registry(operations, store, joiner, caller_registry)
    except (OSError, ValueError, TypeError, sqlite3.Error) as error:
        raise SignalRegistryUnavailable(
            "Shared native analysis configuration unavailable"
        ) from error
