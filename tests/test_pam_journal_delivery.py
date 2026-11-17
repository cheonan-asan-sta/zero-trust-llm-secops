import hashlib
import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from scripts import collect_pam_journal as collector
from scripts import verify_pam_journal as verifier
from scripts.f1_lab import pam_journal_native as native
from tests.test_pam_journal import build, configured

__all__ = ['configured']
pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='native bounded reader and private Linux artifact files')


def test_private_fresh_publication_keyless_hash_and_no_output_overwrite(configured, tmp_path):
    f = configured
    capture = build(f)
    tmp_path.chmod(0o700)
    output = tmp_path/'capture'
    receipt = collector.publish(capture, output)
    raw = (output/'capture.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == receipt['capture_sha256']
    assert verifier.read_pinned(output/'capture.json', receipt['capture_sha256']) == capture
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE((output/name).stat().st_mode) == 0o600 for name in ('capture.json', 'receipt.json'))
    assert {p.name for p in output.iterdir()} == {'capture.json', 'receipt.json'}
    with pytest.raises(ValueError):
        collector.publish(capture, output)
    assert raw == (output/'capture.json').read_bytes()
    (output/'capture.json').write_bytes(raw+b' ')
    with pytest.raises(ValueError):
        verifier.read_pinned(output/'capture.json', receipt['capture_sha256'])


@pytest.mark.parametrize('mutation', ['symlink', 'hardlink', 'fifo', 'unsafe_parent'])
def test_unsafe_files_and_output_parents_cannot_be_used(configured, tmp_path, mutation):
    f = configured
    tmp_path.chmod(0o700)
    receipt = collector.publish(build(f), tmp_path/'capture')
    source = tmp_path/'capture/capture.json'
    alias = tmp_path/'alias'
    if mutation == 'unsafe_parent':
        tmp_path.chmod(0o755)
        with pytest.raises(ValueError):
            collector.publish(build(f), tmp_path/'other')
        assert not (tmp_path/'other').exists()
        return
    if mutation == 'symlink':
        alias.symlink_to(source)
    elif mutation == 'hardlink':
        os.link(source, alias)
    else:
        os.mkfifo(alias, 0o600)
    with pytest.raises((ValueError, OSError)):
        verifier.read_pinned(alias, receipt['capture_sha256'])


@pytest.mark.parametrize('mode', ['valid', 'oversized', 'truncated', 'partial', 'failed', 'timeout', 'cancel'])
def test_fixed_reader_bounds_real_child_output_and_always_reaps_only_its_process(mode, monkeypatch):
    original_popen = subprocess.Popen
    children = []
    code = {'valid': "print('{}');print('{}')",
        'oversized': "import sys,time;sys.stdout.write('x'*18000);sys.stdout.flush();time.sleep(30)",
        'truncated': "for _ in range(1001):print('{}')",
        'partial': "print('{}',end='')",
        'failed': "import sys;print('{}');sys.stderr.write('DO_NOT_LEAK_STDERR_CANARY');sys.exit(3)",
        'timeout': 'import time;time.sleep(30)',
        'cancel': "import time;print('{}',flush=True);time.sleep(30)"}[mode]

    def child(argv, **kwargs):
        assert argv[0] == '/usr/bin/journalctl' and '--no-pager' in argv and '--boot=0' in argv
        assert argv[argv.index('--unit')+1] == 'owned.service'
        assert kwargs['stderr'] == subprocess.DEVNULL and 'OPENAI_API_KEY' not in kwargs['env']
        fields = next(a for a in argv if a.startswith('--output-fields='))
        assert '_CMDLINE' not in fields and 'SYSLOG_RAW' not in fields and 'SYSLOG_PID' not in fields
        process = original_popen([sys.executable, '-c', code], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(native.subprocess, 'Popen', child)
    monkeypatch.setattr(native, 'Path', lambda *_: SimpleNamespace(read_text=lambda: 'systemd\n'))
    if mode == 'timeout':
        monkeypatch.setattr(native, 'JOURNAL_TIMEOUT', .05)
    stream = native.journal_rows('owned.service', 1000000, 2000000)
    if mode == 'valid':
        assert list(stream) == [b'{}', b'{}']
    elif mode == 'cancel':
        assert next(stream) == b'{}'
        stream.close()
    else:
        with pytest.raises(ValueError):
            list(stream)
    assert len(children) == 1 and children[0].poll() is not None and children[0].stdout.closed


def test_fixed_reader_rejects_unit_and_window_before_spawning(monkeypatch):
    monkeypatch.setattr(native, 'Path', lambda *_: SimpleNamespace(read_text=lambda: 'systemd\n'))
    monkeypatch.setattr(native.subprocess, 'Popen', lambda *_args, **_kwargs: pytest.fail('must not start'))
    for unit, start, end in [('x.service --since=-1', 1, 2), ('owned.service', 2, 1),
                             ('owned.service', 1, 600000002)]:
        with pytest.raises(ValueError):
            list(native.journal_rows(unit, start, end))


def test_missing_systemd_auth_credential_never_reads_stdin_or_collects(configured, tmp_path, monkeypatch, capsys):
    f = configured
    args = ['collect_pam_journal', '--tenant', f.scope.tenant_id, '--server', f.scope.server_id,
        '--unit', f.scope.unit, '--source', f.scope.source_id, '--key-id', f.scope.key_id,
        '--registry', str(f.path), '--registry-sha256', f.pinned.expected_sha256,
        '--output', str(tmp_path/'never'), '--systemd-credential']
    monkeypatch.setattr(sys, 'argv', args)
    monkeypatch.setattr(collector.ctypes, 'CDLL', lambda *_args, **_kwargs: SimpleNamespace(prctl=lambda *_: 0))

    def missing(**kwargs):
        assert kwargs == {'credential_name': 'auth-journal-key'}
        raise OSError('DO_NOT_LEAK_PRIVATE_EXCEPTION_CANARY')

    monkeypatch.setattr(collector, 'read_systemd_key', missing)
    monkeypatch.setattr(sys, 'stdin', SimpleNamespace(buffer=SimpleNamespace(read=lambda *_: pytest.fail('no fallback'))))
    monkeypatch.setattr(collector, 'collect', lambda *_args, **_kwargs: pytest.fail('no collect'))
    assert collector.main() == 2
    public = capsys.readouterr().out
    assert 'DO_NOT_LEAK' not in public and json.loads(public)['failure_stage'] == 'credential'
    assert not (tmp_path/'never').exists()
