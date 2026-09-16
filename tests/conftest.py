import os
from pathlib import Path
from tempfile import TemporaryDirectory

_test_runtime = TemporaryDirectory(prefix="zero-trust-secops-tests-")
os.environ["ANALYZER_MODE"] = "rule"
os.environ["APP_ENVIRONMENT"] = "test"
os.environ["AUTH_MODE"] = "disabled"
os.environ["AUDIT_LOG_PATH"] = str(Path(_test_runtime.name) / "audit.jsonl")
os.environ["CASE_LOG_PATH"] = str(Path(_test_runtime.name) / "cases.jsonl")
