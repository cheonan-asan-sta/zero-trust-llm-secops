"""Local acceptance probe, not an authentication endpoint or production identity source.

Reads only bounded test control settings on stdin; no credentials/nonce on argv.
Reopens the application's persisted PDP and the pinned shared-reader bootstrap.
"""

import json
import sys
from pathlib import Path

from app.config import Settings
from app.security import Principal, Role
from app.services.native_analysis_registry import (
    NativeAnalysisMissing,
    create_native_analysis_registry,
)
from app.services.trusted_signals import SignalVerifier
from app.services.zero_trust import ZeroTrustOperations


def main():
    value = json.loads(sys.stdin.buffer.read(8193))
    operations = ZeroTrustOperations(
        Path(value["operations_db"]), signal_verifier=SignalVerifier(Path(value["signal_sources"]))
    )
    settings = Settings(
        _env_file=None,
        native_analysis_shared_config_path=value["config_path"],
        native_analysis_shared_config_sha256=value["config_sha256"],
    )
    registry = create_native_analysis_registry(operations, settings)
    principal = Principal(
        value["subject"], value["tenant_id"], frozenset({Role.ANALYST}), "api_key"
    )
    try:
        signal, context = registry.resolve(value["execution_ref"], principal)
        context.verify_current()
    except NativeAnalysisMissing:
        print(json.dumps({"available": False}))
    else:
        facts = context.for_event(signal.event)["native_execution"]
        print(
            json.dumps(
                {
                    "available": True,
                    "analysis_ref_sha256": facts["analysis_ref_sha256"],
                    "event_sha256": facts["event_sha256"],
                    "app_grant_already_consumed": facts["app_grant_already_consumed"],
                }
            )
        )


if __name__ == "__main__":
    main()
