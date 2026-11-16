#!/usr/bin/python3
"""One preauthorized, real sudo log-read operation per real SSH session."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

result=subprocess.run(['/usr/bin/sudo','-n','/usr/bin/tail','/var/log/syslog'],capture_output=True,timeout=30,check=False)
print(json.dumps({'uid':os.getuid(),'loginuid':Path('/proc/self/loginuid').read_text().strip(),
    'sessionid':Path('/proc/self/sessionid').read_text().strip(),'tty':os.ttyname(0),
    'command':['/usr/bin/sudo','-n','/usr/bin/tail','/var/log/syslog'],'exit_code':result.returncode,
    'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_bytes':len(result.stderr)}),flush=True)
raise SystemExit(result.returncode)
