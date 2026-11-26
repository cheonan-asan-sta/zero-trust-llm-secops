"""Run the actual owned interpreter, avoiding a Windows venv redirector PID."""

import os
import sys


def direct_python(environment):
    environment = dict(environment)
    if os.name == "nt":
        environment["PYTHONPATH"] = os.pathsep.join(str(path) for path in sys.path if path)
        return sys._base_executable, environment
    return sys.executable, environment
