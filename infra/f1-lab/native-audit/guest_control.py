#!/usr/bin/python3
"""Fixed control operations inside the exclusively owned training guest."""
import base64
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path


def command(argv):
    result=subprocess.run(argv,capture_output=True,timeout=30,check=False)
    if result.returncode:raise RuntimeError('guest_control_command_failed:'+argv[0])
    return result.stdout.decode('utf8')


def status():
    audit={}
    for line in command(['/usr/sbin/auditctl','-s']).splitlines():
        key,value=line.split(None,1);audit[key]=value
    return {'kernel':os.uname().release,'hostname':os.uname().nodename,
        'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'timezone':command(['/usr/bin/timedatectl','show','--property=Timezone','--value']).strip(),
        'audit':audit,'ready':Path('/var/lib/zt-native-audit/ready').exists(),
        'policy_sha256':hashlib.sha256(Path('/etc/sudoers.d/zt-normal-audit').read_bytes()).hexdigest(),
        'utc':time.time()}


def main():
    if os.geteuid()!=0:raise RuntimeError('guest_control_requires_owned_guest_root')
    action=os.environ.get('SSH_ORIGINAL_COMMAND','')
    if action=='status':print(json.dumps(status()))
    elif action=='begin':
        command(['/usr/sbin/auditctl','--signal','rotate'])
        time.sleep(1)
        print(json.dumps({'begun':True,'status':status()}))
    elif action=='capture':
        path=Path('/var/log/audit/audit.log');data=None
        for _ in range(20):
            before=path.stat()
            if before.st_size>16*1024**2:raise RuntimeError('guest_audit_size_bound')
            candidate=path.read_bytes();after=path.stat()
            if ((before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_ino,after.st_size,after.st_mtime_ns)
                    and len(candidate)==before.st_size and candidate.endswith(b'\n')):
                data=candidate;break
            time.sleep(.1)
        if data is None:raise RuntimeError('guest_audit_unstable_snapshot')
        print(json.dumps({'status':status(),'capture_utc':time.time(),'bytes':len(data),
            'sha256':hashlib.sha256(data).hexdigest(),'audit_base64':base64.b64encode(data).decode(),
            'source_inode':before.st_ino,'source_mtime_ns':before.st_mtime_ns,'complete_file_snapshot':True}))
    elif action=='poweroff':
        print(json.dumps({'shutdown_requested':True}),flush=True)
        subprocess.Popen(['/bin/systemctl','poweroff'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    else:raise RuntimeError('guest_control_action_not_allowed')


if __name__=='__main__':main()
