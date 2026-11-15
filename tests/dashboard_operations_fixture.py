"""Loopback-only, synthetic authenticated server for browser acceptance."""

import argparse
import json
from pathlib import Path

from pydantic import SecretStr

from scripts.serve_dashboard_demo import isolated_app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    args.directory.mkdir(mode=0o700)
    app = isolated_app(args.directory)
    from app.main import settings
    from tests.test_api_key_accounts import account, sha

    settings.auth_mode = "api_key"
    settings.api_key_sha256 = SecretStr(sha("synthetic-requester-key"))
    settings.api_key_subject = "operator"
    settings.api_key_tenant_id = "tenant-a"
    settings.api_key_roles = "admin"
    settings.api_key_accounts_path = args.directory / "accounts.json"
    settings.api_key_accounts_path.write_text(json.dumps({
        "schema": "api-key-accounts-1", "accounts": [
            account("reviewer-a", "synthetic-reviewer-a-key"),
            account("reviewer-b", "synthetic-reviewer-b-key"),
            account("viewer", "synthetic-viewer-key", roles=["viewer"]),
            account("foreign", "synthetic-foreign-key", tenant_id="tenant-b", roles=["admin"]),
        ],
    }))
    settings.dashboard_operations_directory = args.directory / "jobs"
    settings.dashboard_operations_tenant = "tenant-a"
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
