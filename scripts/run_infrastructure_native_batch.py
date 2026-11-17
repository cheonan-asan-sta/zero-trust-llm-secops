"""Reproduce fixed local systemd controls from explicitly pinned offline archives.

No arbitrary command/module, credentials, installs or production configuration
are accepted. A timed-out or unconfirmed cleanup preserves the owned source
snapshot for inspection instead of deleting files still referenced by a unit.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import uuid
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 512*1024**2
MAX_MEMBERS = 20000
SUITES = (
    ('bundle', 'scripts.run_exec_history_controls', ('--bundle-observability',),
     ('owned_unit_removed', 'owned_private_state_removed')),
    ('provider', 'scripts.run_collector_provider_controls', (),
     ('owned_units_removed', 'owned_provider_processes_stopped', 'owned_state_removed')),
    ('pam', 'scripts.run_pam_journal_controls', ('--ledger', '--checkpoint'),
     ('owned_units_removed', 'owned_provider_stopped', 'owned_state_removed', 'owned_ledger_state_removed')),
)


class BatchUnavailable(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise BatchUnavailable(code)


def extract_pinned(path, pin, destination, *, dependencies=False):
    """Hash/read the same stable file descriptor; only bounded regular entries."""
    require(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin), 'archive_pin')
    path, destination = Path(path), Path(destination)
    require(not path.is_symlink(), 'archive_link')
    require(destination.is_dir() and not destination.is_symlink()
        and not any(destination.iterdir()), 'fresh_extract_destination')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_ARCHIVE,
                'archive_file')
        sha = hashlib.sha256()
        hashed = 0
        for chunk in iter(lambda: stream.read(1024**2), b''):
            hashed += len(chunk)
            require(hashed <= MAX_ARCHIVE, 'archive_read_bound')
            sha.update(chunk)
        require(sha.hexdigest() == pin, 'archive_changed')
        stream.seek(0)
        names, total = set(), 0
        with tarfile.open(fileobj=stream, mode='r|*') as archive:
            for member in archive:
                name = member.name.rstrip('/') if member.isdir() else member.name
                pure = PurePosixPath(name)
                require(name and bool(pure.parts) and len(name.encode('utf8')) <= 4096
                    and not pure.is_absolute() and str(pure) == name
                    and '..' not in pure.parts and '.' not in pure.parts and '\\' not in name and ':' not in name
                    and not re.search(r'[\x00-\x1f\x7f]', name), 'archive_member_path')
                require(name not in names and len(names) < MAX_MEMBERS
                    and (member.isfile() or member.isdir()) and 0 <= member.size <= 64*1024**2,
                    'archive_member_type_or_bound')
                require(not dependencies or pure.parts[0] == 'site-packages', 'dependency_archive_scope')
                names.add(name)
                total += member.size
                require(total <= MAX_ARCHIVE, 'archive_total_bound')
                archive.extract(member, destination, filter='data')
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        require(all(getattr(before, field) == getattr(after, field) for field in fields), 'archive_unstable')
    require(bool(names), 'archive_empty')
    return {'sha256': pin, 'entries': len(names), 'uncompressed_bytes': total}


def cleanup_confirmed(report, flags):
    return type(report) is dict and all(report.get(flag) is True for flag in flags)


def execute(source_archive, source_pin, dependencies_archive, dependencies_pin, lock_pin, output):
    require(os.name == 'posix' and os.geteuid() == 0 and Path('/proc/1/comm').read_text().strip() == 'systemd'
        and sys.version_info[:2] == (3, 12) and platform.machine() == 'x86_64', 'owned_linux_systemd_python312_required')
    require(type(lock_pin) is str and re.fullmatch('[a-f0-9]{64}', lock_pin), 'dependency_lock_pin')
    output = Path(output)
    require(output.is_absolute() and output.parent.is_dir() and not output.exists()
        and not output.is_symlink() and not re.search(r'[\x00-\x1f\x7f]', str(output)), 'fresh_output_required')
    output.mkdir(mode=0o700)
    snapshot = Path('/run')/('zt-pam-journal-v93-'+uuid.uuid4().hex)
    snapshot.mkdir(mode=0o755)
    report = {'schema': 'infrastructure-native-batch-1', 'completed': False,
        'aws_calls': 0, 'paid_api_calls': 0, 'goal_qualified': False, 'long_soak_started': False,
        'production_configuration_changed': False, 'owned_source_snapshot': str(snapshot), 'suites': {}}
    safe_to_remove = True
    try:
        report['source'] = extract_pinned(source_archive, source_pin, snapshot)
        source_files = {path.relative_to(snapshot).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in snapshot.rglob('*') if path.is_file()}
        for _, module, _, _ in SUITES:
            require((snapshot/(module.replace('.', '/')+'.py')).is_file(), 'fixed_suite_source_required')
        lock = snapshot/'infra/runtime/requirements/test.lock'
        require(lock.is_file() and hashlib.sha256(lock.read_bytes()).hexdigest() == lock_pin,
                'dependency_lock_changed')
        deps = snapshot/'dependencies'
        deps.mkdir(exist_ok=False)
        report['dependencies'] = extract_pinned(dependencies_archive, dependencies_pin, deps, dependencies=True)
        report['dependency_lock_sha256'] = lock_pin
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
            'PYTHONPATH': str(deps/'site-packages')+':'+str(snapshot),
            'PYTHONDONTWRITEBYTECODE': '1', 'AWS_EC2_METADATA_DISABLED': 'true'}
        for name, module, args, flags in SUITES:
            safe_to_remove = False
            result = subprocess.run(['/usr/bin/python3', '-m', module, '--directory', str(output/name), *args],
                cwd=snapshot, env=env, capture_output=True, timeout=540, check=False)
            (output/(name+'.log')).write_bytes(result.stdout+b'\n'+result.stderr)
            row_path = output/name/'run.json'
            require(row_path.is_file() and 0 < row_path.stat().st_size <= 256*1024, 'suite_receipt_required')
            row = json.loads(row_path.read_bytes())
            safe_to_remove = cleanup_confirmed(row, flags)
            report['suites'][name] = {'exit_code': result.returncode, 'completed': row.get('completed') is True,
                'conditions': len(row.get('cases', [])), 'cleanup_confirmed': safe_to_remove,
                'receipt_sha256': hashlib.sha256(row_path.read_bytes()).hexdigest()}
            require(result.returncode == 0 and row.get('completed') is True and safe_to_remove, 'suite_incomplete')
        unchanged = all((snapshot/name).is_file() and not (snapshot/name).is_symlink()
            and hashlib.sha256((snapshot/name).read_bytes()).hexdigest() == pin for name, pin in source_files.items())
        report['source_files_unchanged_after'] = unchanged
        require(unchanged, 'source_changed_during_controls')
        report['completed'] = True
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        report['failure'] = str(error) if isinstance(error, BatchUnavailable) else 'native_batch_unavailable'
    finally:
        require(snapshot.parent == Path('/run') and re.fullmatch('zt-pam-journal-v93-[a-f0-9]{32}', snapshot.name),
                'owned_snapshot_scope')
        if safe_to_remove:
            shutil.rmtree(snapshot)
        report['owned_snapshot_removed'] = not snapshot.exists()
        report['snapshot_retained_for_unconfirmed_cleanup'] = snapshot.exists()
        (output/'batch.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-archive', 'source-sha256', 'dependencies-archive', 'dependencies-sha256',
                 'dependency-lock-sha256', 'output'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args(argv)
    try:
        report = execute(args.source_archive, args.source_sha256, args.dependencies_archive,
            args.dependencies_sha256, args.dependency_lock_sha256, args.output)
        print(json.dumps({key: report[key] for key in ('completed', 'owned_snapshot_removed',
            'snapshot_retained_for_unconfirmed_cleanup', 'suites')}))
        return 0 if report['completed'] else 2
    except (OSError, ValueError, TypeError):
        print(json.dumps({'completed': False, 'failure': 'native_batch_preflight_failed'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
