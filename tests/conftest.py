import os
from pathlib import Path
from tempfile import TemporaryDirectory

_test_runtime = TemporaryDirectory(prefix="zero-trust-secops-tests-")
os.environ["ANALYZER_MODE"] = "rule"
os.environ["AUDIT_LOG_PATH"] = str(Path(_test_runtime.name) / "audit.jsonl")
