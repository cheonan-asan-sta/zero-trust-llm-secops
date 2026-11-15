"""Bind a Unix peer to the exact live systemd main process, not UID alone.

The administrator/system manager, cgroup-v2 ownership and kernel remain
trusted. This is local workload authentication, not a human login or remote
attestation. No cgroup membership or global host setting is changed.
"""

import re
import socket
import struct
import subprocess
from pathlib import Path

from pydantic import TypeAdapter

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.shared_execution_collector import READ_ENV
from scripts.f1_lab.shared_execution_evidence import Unit


def process_start(pid):
    path = Path('/proc')/str(pid)/'stat'
    with path.open('rb') as stream:
        raw = stream.read(8193)
    require(0 < len(raw) <= 8192, 'credential_peer_process_bound')
    closing = raw.rfind(b') ')
    require(closing > 0 and raw.split(b' ', 1)[0] == str(pid).encode(), 'credential_peer_process_identity')
    fields = raw[closing+2:].split()
    # Fields start at state (3); starttime is field22.
    require(len(fields) >= 20 and fields[19].isdigit() and int(fields[19]) > 0,
            'credential_peer_process_start')
    return int(fields[19])


def cgroup_membership(raw, expected):
    """Require one exact v2 membership; hybrid v1 controller rows may coexist."""
    require(type(raw) is bytes and 0 < len(raw) <= 8192, 'credential_peer_cgroup')
    lines = raw.decode('utf8').splitlines()
    require(0 < len(lines) <= 64, 'credential_peer_cgroup')
    seen, unified, systemd = set(), [], []
    for line in lines:
        parts = line.split(':', 2)
        require(len(parts) == 3, 'credential_peer_cgroup')
        hierarchy, controllers, path = parts
        require(hierarchy.isdigit() and len(hierarchy) <= 5 and hierarchy not in seen
                and path.startswith('/') and len(path) <= 1024 and '\x00' not in path,
                'credential_peer_cgroup')
        seen.add(hierarchy)
        if hierarchy == '0':
            require(controllers == '', 'credential_peer_cgroup')
            unified.append(path)
        else:
            require(bool(re.fullmatch('[A-Za-z0-9_=,-]{1,128}', controllers)), 'credential_peer_cgroup')
            if controllers == 'name=systemd':
                systemd.append(path)
    require(unified == [expected] and (not systemd or systemd == [expected]), 'credential_peer_cgroup')
    return True


def peer_service(connection, unit):
    unit = TypeAdapter(Unit).validate_python(unit)
    require(hasattr(socket, 'SO_PEERCRED'), 'credential_peer_kernel_identity')
    pid, uid, _gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(pid > 1 and uid >= 0, 'credential_peer_pid')
    before = process_start(pid)
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--no-pager',
            '--property=Id,MainPID,ControlGroup,InvocationID,ActiveState,SubState', '--', unit],
            env=READ_ENV, capture_output=True, timeout=0.35, check=False)
    except subprocess.SubprocessError as error:
        raise ValueError('native_source_credential_peer_manager') from error
    require(result.returncode == 0 and len(result.stdout) <= 8192 and len(result.stderr) <= 8192,
            'credential_peer_manager')
    fields = {}
    for line in result.stdout.decode('utf8').splitlines():
        key, sep, value = line.partition('=')
        require(sep and key not in fields, 'credential_peer_manager_shape')
        fields[key] = value
    require(set(fields) == {'Id', 'MainPID', 'ControlGroup', 'InvocationID', 'ActiveState', 'SubState'},
            'credential_peer_manager_shape')
    require(fields['Id'] == unit, 'credential_peer_service_identity')
    require(fields['MainPID'] == str(pid), 'credential_peer_service_pid')
    require(fields['ActiveState'] in {'active', 'activating'} and fields['SubState'] in {'running', 'start'},
            'credential_peer_service_state')
    require(re.fullmatch('[a-f0-9]{32}', fields['InvocationID']) and fields['InvocationID'] != '0'*32,
            'credential_peer_service_invocation')
    require(fields['ControlGroup'].startswith('/system.slice/') and len(fields['ControlGroup']) <= 1024,
            'credential_peer_service_group')
    with (Path('/proc')/str(pid)/'cgroup').open('rb') as stream:
        raw = stream.read(8193)
    cgroup_membership(raw, fields['ControlGroup'])
    require(process_start(pid) == before, 'credential_peer_reuse')
    return True
