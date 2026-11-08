import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / '.github/workflows/ci.yml').read_text(encoding='utf-8'))


def test_independent_jobs_preserve_every_prior_acceptance_and_new_combined_graph():
    value = workflow()
    assert set(value['jobs']) == {'unit', 'docker', 'runtime', 'lambda', 'test'}
    rows = value['jobs']['runtime']['strategy']['matrix']['include']
    assert {r['kind'] for r in rows} == {
        'application', 'application-mtls', 'monitored', 'authority', 'rekey', 'authority-ha',
        'database-transport', 'database-backup', 'database-recovery',
    }
    assert len({r['directory'] for r in rows}) == len(rows) == len({r['report'] for r in rows})
    assert value['jobs']['runtime']['strategy']['fail-fast'] is False
    app = next(r for r in rows if r['kind'] == 'application')
    assert '--full-state' in app['command']
    for row in rows:
        assert ('--directory ' + row['directory']) in row['command']
    assert 'pytest -q' in value['jobs']['unit']['steps'][-1]['run']
    assert 'Dockerfile.test' in value['jobs']['docker']['steps'][-1]['run']
    assert 'Dockerfile.lambda' in value['jobs']['lambda']['steps'][-1]['run']


def test_every_parallel_code_job_checks_out_same_immutable_event_commit():
    for name, job in workflow()['jobs'].items():
        if name != 'test':
            assert job['steps'][0] == {'uses': 'actions/checkout@v4', 'with': {'ref': '${{ github.sha }}'}}
    assert workflow()['permissions'] == {'contents': 'read'}


def test_python_setup_preserves_both_hash_locks_and_offline_project_install():
    value = yaml.safe_load((ROOT / '.github/actions/python-locked/action.yml').read_text())
    command = value['runs']['steps'][-1]['run']
    for name in ('build', 'test'):
        assert '--only-binary=:all: --require-hashes -r infra/runtime/requirements/' + name + '.lock' in command
    assert '--no-index --no-deps --no-build-isolation .' in command and 'pip check' in command


@pytest.mark.parametrize('outcome', ['success', 'failure', 'skipped', 'cancelled', 'timed_out', 'missing'])
def test_final_required_check_refuses_any_incomplete_dependency(outcome):
    gate = workflow()['jobs']['test']
    assert gate['if'] == 'always()' and set(gate['needs']) == {'unit', 'docker', 'runtime', 'lambda'}
    program = gate['steps'][0]['run'].split("python - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    data = {name: {'result': 'success'} for name in gate['needs']}
    if outcome == 'missing':
        data.pop('runtime')
    else:
        data['runtime']['result'] = outcome
    result = subprocess.run([sys.executable, '-c', program], env={**os.environ, 'RESULTS': json.dumps(data)},
                            capture_output=True, timeout=5, check=False)
    assert result.returncode == (0 if outcome == 'success' else 1)
