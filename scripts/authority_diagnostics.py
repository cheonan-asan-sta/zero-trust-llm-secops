"""Read-only, bounded CA startup evidence; never emit journals, grants or PEM."""

import json
import math
import re
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from scripts.authority_runtime_assets import MANAGED, RELOADS, SERVERS
from scripts.certificate_controller import PUBLIC_FAILURE_REASONS
from scripts.certificate_reload_runner import watch_digest
from scripts.continuous_mtls_runtime import command

PHASES = {'prepared', 'staged', 'activated', 'retiring', 'revoking', 'cleaning'}
MOUNTS = ('certificate-state', *MANAGED, *('ack-' + name for name in RELOADS))
GROUPS = {'proxy': {'proxy.pem', 'proxy-auth.pem', 'proxy-resource.pem', 'nginx-rekey.conf'},
          'prometheus': {'prometheus.pem', 'scrape-agent.pem', 'monitor-alert.pem', 'config.yml', 'web.yml'},
          'alertmanager': {'alertmanager.pem', 'alert-manager.pem', 'config.yml', 'web.yml'}}


def limited(path, maximum=131072):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('diagnostic_asset_scope')
    return path.read_bytes()


def snapshot(state=Path('/state'), managed=Path('/managed'), acknowledgements=Path('/ack')):
    status = json.loads(limited(state / 'status.json'))
    cfg = json.loads(limited(state / 'config.json'))
    if not isinstance(status, dict) or not isinstance(cfg, dict):
        raise TypeError('diagnostic_shape')
    credentials = status['credentials']
    if not isinstance(credentials, dict) or len(credentials) > 64:
        raise ValueError('diagnostic_inventory')
    generations = Counter(str(c['generation']) for c in credentials.values() if isinstance(c, dict)
        and type(c.get('generation')) is int and 0 <= c['generation'] <= 1_000_000)
    reason = status.get('last_error_reason')
    phase = status.get('phase')
    observed = status.get('server_observations', {})
    at = status.get('at')
    result = {'available': True, 'credential_count': len(credentials), 'generations': dict(generations),
        'controller_at': at if type(at) in {int, float} and math.isfinite(at) and 0 <= at <= 1e12 else None,
        'phase': phase if isinstance(phase, str) and phase in PHASES else None,
        'paused': status.get('paused') is True, 'publication_failed': bool(status.get('last_error')),
        'reason': reason if isinstance(reason, str) and reason in PUBLIC_FAILURE_REASONS else None,
        'native_servers_observed': [name for name in SERVERS if isinstance(observed, dict) and name in observed],
        'reloads': []}
    groups = cfg.get('reload_groups', [])
    if not isinstance(groups, list):
        raise TypeError('diagnostic_groups')
    for group in groups[:3]:
        if not isinstance(group, dict):
            continue
        name = next((n for n in GROUPS if group.get('root') == '/managed/' + n + '-tls'), None)
        if name is None:
            continue
        row = {'service': name, 'available': False}
        result['reloads'].append(row)
        try:
            root = PurePosixPath('/managed/' + name + '-tls')
            files = group['files']
            if (not isinstance(files, list) or not 1 <= len(files) <= 8
                    or group['ack'] != '/ack/' + name + '/ack'
                    or any(PurePosixPath(p).parent != root or PurePosixPath(p).name not in GROUPS[name] for p in files)):
                continue
            local = [managed / root.name / PurePosixPath(p).name for p in files]
            resolved = []
            for path in local:
                body = limited(path, 65536)
                if group.get('resolve_tls'):
                    names = set(re.findall(rb'/service-tls/([A-Za-z0-9_-]+\.(?:pem|key))', body))
                    if len(names) > 32:
                        raise ValueError('diagnostic_references')
                    resolved.extend(path.parent / n.decode() for n in names)
            for path in resolved:
                limited(path, 65536)
            expected = watch_digest(local, bool(group.get('resolve_tls')))
            actual = limited(acknowledgements / name / 'ack', 256).decode().strip()
            row.update(available=True, expected_sha256=expected,
                       observed_sha256=actual if re.fullmatch('[a-f0-9]{64}', actual) else None,
                       matches=expected == actual)
        except (OSError, ValueError, TypeError, KeyError):
            pass
    return result


def collect(runtime):
    state = runtime.state or {}
    result = {'schema': 'public-authority-failure-1', 'captured_at': datetime.now(UTC).isoformat(),
              'authority_initialized': state.get('authority_initialized') is True,
              'storage_initialized': state.get('initialized') is True, 'snapshot': {'available': False}}
    # Docker may create a missing named volume even for a read-only mount.
    # Failure handling must not create storage or attach foreign volumes.
    if not result['storage_initialized']:
        return result
    try:
        project = state['project']
        if not isinstance(project, str) or not re.fullmatch('kmtls-[a-f0-9]{12}', project):
            return result
        names = [state['volumes'][name] for name in MOUNTS]
        if names != [project + '-' + name for name in MOUNTS]:
            return result
        template = '{"name":{{json .Name}},"project":{{json (index .Labels "secops.runtime")}}}'
        raw = command(['docker', 'volume', 'inspect', '--format', template, *names], timeout=3)
        rows = [json.loads(line) for line in raw.splitlines()]
        if (len(rows) != len(names) or any(not isinstance(row, dict) for row in rows)
                or {row.get('name'): row.get('project') for row in rows} != dict.fromkeys(names, project)):
            return result
        value = json.loads(runtime.helper(['-m', 'scripts.authority_diagnostics'], readonly=True, timeout=8))
        result['snapshot'] = value if isinstance(value, dict) else {'available': False}
    except (RuntimeError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        result['snapshot'] = {'available': False}
    return result


def main():
    try:
        result = snapshot()
    except (OSError, ValueError, KeyError, TypeError):
        result = {'available': False}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
