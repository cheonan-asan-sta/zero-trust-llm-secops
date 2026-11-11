import json
from datetime import UTC, datetime, timedelta

import pytest

from scripts import run_f1_soak as soak


def test_scheduled_fixture_cycle_checks_authority_jobs_danger_and_exact_counts(tmp_path):
    lab = soak.SoakLab(tmp_path)
    result = lab.cycle(0)
    assert result['approved_fixture_jobs'] == result['unapproved_export_episodes'] == result['failed_login_episodes'] == 1
    assert result['resource_denial_episodes'] == 1 and result['negative_probes_rejected'] == 3
    assert result['accepted_unique_events'] == result['journal_seq']
    assert result['exact_retries'] == 1
    # Approved export context cannot hide risk received in a different session.
    recent = lab.detector.evaluate_signed(lab.last_event, soak.PRINCIPAL, now=datetime.now(UTC))
    assert 'RECENT_AT_RISK_DEVICE' in recent['reason_codes']


@pytest.mark.parametrize('phase', soak.CRASHES.values())
def test_soak_worker_actual_exit_resumes_one_signed_event(tmp_path, phase):
    lab = soak.SoakLab(tmp_path)
    lab.crash_worker(phase)
    assert lab.worker_exits == 1 and lab.accepted == 2
    assert lab.store._witness(lab.store._key())['current']['seq'] == 2


@pytest.mark.parametrize('delta', [-1, 6*3600+30])
def test_soak_rejects_past_or_unbounded_deadline_before_creating_runtime(tmp_path, delta):
    with pytest.raises(soak.SoakFailure, match='deadline'):
        soak.run(tmp_path/'run', datetime.now(UTC)+timedelta(seconds=delta))
    assert not (tmp_path/'run').exists()


def test_short_bounded_run_cleans_private_keys_and_does_not_report_f1_success(tmp_path, capsys):
    result = soak.run(tmp_path/'run', datetime.now(UTC)+timedelta(minutes=1), interval=1, maximum_cycles=1)
    assert not result['completed'] and result['stop_reason'] == 'cycle_bound'
    assert result['cycles'] == 1 and not result['goal_qualified']
    assert result['private_runtime_remaining'] == 0 and result['source_snapshot_unchanged']
    assert not list((tmp_path/'run').glob('.private-*'))
    saved = json.loads((tmp_path/'run/status.json').read_bytes())
    assert saved['effects']['paid_api_calls'] == saved['effects']['access_grants'] == 0
    assert 'PRIVATE KEY' not in (tmp_path/'run/public-sources.json').read_text()
    exported = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {r['public_artifact']['name'] for r in exported if 'public_artifact' in r} == {
        'public-sources.json', 'public-policies.json', 'public-approvals.json', 'public-pins.json'}
    assert sum('public_heartbeat' in r for r in exported) == 1
    assert set(saved['public_artifact_sha256']) == {
        'public-sources.json', 'public-policies.json', 'public-approvals.json', 'public-pins.json', 'heartbeats.jsonl'}
