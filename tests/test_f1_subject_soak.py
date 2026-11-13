import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from scripts import run_f1_subject_soak as soak


def test_first_cycle_exercises_cross_session_jobs_failures_fanout_isolation_and_exact_journal(tmp_path):
    lab = soak.SubjectSoakLab(tmp_path)
    result = lab.cycle(0)
    assert result['accepted_unique_events'] == result['journal_seq'] == 20
    assert result['exact_retries'] == 3
    for name in ('negative_probes_rejected', 'approved_fixture_jobs', 'partial_device_approvals_rejected',
                 'unapproved_export_episodes', 'failed_login_episodes', 'fanout_episodes', 'risk_episodes', 'isolation_probes'):
        assert result[name] == 1
    assert result['expired_risk_observations'] == 0
    assert all('PRIVATE KEY' not in (tmp_path/(name+'.json')).read_text() for name in ('sources', 'policies', 'approvals', 'pins'))


@pytest.mark.parametrize('phase', soak.CRASHES.values())
def test_subject_soak_recovers_actual_worker_death_once_in_the_original_scope(tmp_path, phase):
    lab = soak.SubjectSoakLab(tmp_path)
    lab.crash(phase)
    assert lab.counts['accepted_unique_events'] == lab.counts['worker_exits_recovered'] == 1
    assert lab.counts['exact_retries'] == int(phase in {'after_db_commit', 'after_publish'})
    assert lab.store._witness(lab.store._key())['current']['seq'] == 1


@pytest.mark.parametrize('delta', [-1, 6*3600+60])
def test_subject_soak_rejects_past_or_unbounded_deadlines_without_creating_output(tmp_path, delta):
    with pytest.raises(ValueError, match='run_bounds'):
        soak.run(tmp_path/'result', datetime.now(UTC)+timedelta(seconds=delta))
    assert not (tmp_path/'result').exists()


@pytest.mark.parametrize('interval,maximum', [(0, 1), (301, 1), (1, 0), (1, 1001), (True, 1)])
def test_subject_soak_rejects_unbounded_or_coerced_loop_configuration(tmp_path, interval, maximum):
    with pytest.raises(ValueError, match='run_bounds'):
        soak.run(tmp_path/'result', datetime.now(UTC)+timedelta(minutes=1), interval=interval, maximum_cycles=maximum)
    assert not (tmp_path/'result').exists()


def test_subject_soak_cannot_run_in_production_or_overwrite_an_existing_directory(tmp_path, monkeypatch):
    existing = tmp_path/'existing'
    existing.mkdir()
    (existing/'user-file').write_bytes(b'preserve')
    with pytest.raises(ValueError, match='fresh_output'):
        soak.run(existing, datetime.now(UTC)+timedelta(minutes=1))
    assert (existing/'user-file').read_bytes() == b'preserve'
    monkeypatch.setattr(soak, 'get_settings', lambda: SimpleNamespace(app_environment='production'))
    with pytest.raises(ValueError, match='local_test_only'):
        soak.run(tmp_path/'production', datetime.now(UTC)+timedelta(minutes=1))
    assert not (tmp_path/'production').exists()


def test_short_cycle_limit_preserves_public_hashes_cleans_private_runtime_and_does_not_claim_deadline_completion(tmp_path, capsys):
    directory = tmp_path/'result'
    result = soak.run(directory, datetime.now(UTC)+timedelta(minutes=1), interval=1, maximum_cycles=1)
    assert result['cycles'] == 1 and not result['completed'] and result['stop_reason'] == 'cycle_limit'
    assert not result['private_runtime_remaining'] and result['source_snapshot_unchanged']
    assert not result['goal_qualified'] and not result['new_independent_evaluation'] and result['actual_organization_approvals'] == 0
    assert not list(directory.glob('.private-*'))
    assert set(result['public_artifact_sha256']) == {'public-sources.json', 'public-policies.json',
        'public-approvals.json', 'public-pins.json', 'heartbeats.jsonl'}
    assert all(hashlib.sha256((directory/name).read_bytes()).hexdigest() == value for name, value in result['public_artifact_sha256'].items())
    envelopes = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    artifacts = [item['public_artifact'] for item in envelopes if 'public_artifact' in item]
    assert len(artifacts) == 4
    for artifact in artifacts:
        body = base64.b64decode(artifact['data'], validate=True)
        assert artifact['encoding'] == 'base64' and len(body) == artifact['bytes']
        assert hashlib.sha256(body).hexdigest() == artifact['sha256']
    assert sum('public_heartbeat' in item for item in envelopes) == 1
    assert json.loads((directory/'status.json').read_bytes()) == result


def test_failed_functional_probe_still_removes_private_witness_and_records_failure(tmp_path, monkeypatch, capsys):
    def fail(_self, _index):
        raise ValueError('subject_soak_injected_probe_failure')
    monkeypatch.setattr(soak.SubjectSoakLab, 'cycle', fail)
    result = soak.run(tmp_path/'failed', datetime.now(UTC)+timedelta(minutes=1), interval=1, maximum_cycles=1)
    assert not result['completed'] and result['failure_code'] == 'subject_soak_injected_probe_failure'
    assert result['cycles'] == 0 and not result['private_runtime_remaining']
    assert not list((tmp_path/'failed').glob('.private-*'))
