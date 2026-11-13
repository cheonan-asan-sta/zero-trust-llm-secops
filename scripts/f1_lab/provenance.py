"""Optional Git metadata for source snapshots running outside a Git checkout."""

import subprocess


def git_context(root, paths=()):
    try:
        head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True,
                              text=True, timeout=10, check=False)
        status = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=all', '--', *paths],
                                cwd=root, capture_output=True, text=True, timeout=10, check=False)
        value = head.stdout.strip()
        if head.returncode or status.returncode or len(value) != 40 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('git_metadata_unavailable')
        return {'source_commit': value, 'source_dirty': bool(status.stdout.strip()),
                'git_metadata': 'available_snapshot_hashes_still_required'}
    except (OSError, ValueError, subprocess.SubprocessError):
        # Missing Git must not be mistaken for a clean checkout. Snapshot hashes
        # remain the mandatory identity; stderr is not copied into public output.
        return {'source_commit': None, 'source_dirty': None,
                'git_metadata': 'unavailable_use_explicit_source_snapshot_hashes'}
