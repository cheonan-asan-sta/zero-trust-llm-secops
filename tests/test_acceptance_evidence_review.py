"""Incomplete/failed/mixed-source evidence must never become a successful review."""

import copy
import json

import pytest

from scripts import review_acceptance_evidence as module
from scripts.runtime_release import digest

COMMIT = 'a' * 40
URL = 'https://github.com/example/project/actions/runs/123'


@pytest.fixture
def evidence():
    reports = {}
    for kind, (schema, minimum) in module.RUNTIME_REPORTS.items():
        reports[kind] = {'schema': schema, 'completed': True, 'source_commit': COMMIT,
                         'checks': [{'label': 'check_' + str(n), 'passed': True} for n in range(minimum)],
                         'cleanup': {'containers': 0, 'volumes': 0, 'networks': 0}}
    reports['application'].update(passed=True, base_git_head=COMMIT)
    reports['application']['checks'] = {row['label']: True for row in reports['application']['checks']}
    execution = reports['execution-mtls']
    execution.pop('source_commit')
    execution.update(release={'payload': {'files': {'app/main.py': 'b' * 64}},
                              'sha256': digest({'files': {'app/main.py': 'b' * 64}})},
                     cleanup={'stopped': True, 'purged': True})
    names = ['unit', 'docker', 'lambda', 'test'] + ['runtime (' + kind + ')' for kind in reports]
    ci = {'headSha': COMMIT, 'url': URL, 'status': 'completed', 'conclusion': 'success',
          'jobs': [{'name': name, 'status': 'completed', 'conclusion': 'success',
                    'url': URL + '/job/' + str(i)} for i, name in enumerate(names)]}
    return ci, reports


def log_for(reports):
    return '\n'.join('runtime (' + kind + ')\tReport verification\t2026-11-13T01:00:00Z ' + line
                     for kind, report in reports.items() for line in json.dumps(report, indent=2).splitlines())


def test_complete_run_retains_source_and_explicitly_leaves_human_approval_empty(evidence):
    ci, reports = evidence
    parsed = module.extract_reports(log_for(reports))
    reviewed = module.review(ci, parsed, COMMIT)
    assert reviewed['ci_jobs'] == 16 and reviewed['runtime_checks'] == 419
    assert reviewed['human_independent_review'] is False and reviewed['human_approval'] is None
    assert 'no embedded Git SHA' in reviewed['reports'][3]['source_binding']


@pytest.mark.parametrize('mutation', ['failed_run', 'running', 'skipped_job', 'missing_job', 'duplicate_job',
                                     'unbound_job', 'different_ci_commit', 'different_report_commit',
                                     'failed_check', 'duplicate_check', 'too_few_checks', 'bad_label',
                                     'dirty_source', 'unfinished_runtime', 'leftover_volume',
                                     'cleanup_not_purged', 'release_changed', 'missing_report'])
def test_reject_incomplete_or_mixed_evidence(evidence, mutation):
    ci, reports = copy.deepcopy(evidence)
    if mutation == 'failed_run': ci['conclusion'] = 'failure'
    elif mutation == 'running': ci['status'] = 'in_progress'
    elif mutation == 'skipped_job': ci['jobs'][0]['conclusion'] = 'skipped'
    elif mutation == 'missing_job': ci['jobs'].pop()
    elif mutation == 'duplicate_job': ci['jobs'][-1] = ci['jobs'][0]
    elif mutation == 'unbound_job': ci['jobs'][0]['url'] = URL + '99/job/1'
    elif mutation == 'different_ci_commit': ci['headSha'] = 'b' * 40
    elif mutation == 'different_report_commit': reports['monitored']['source_commit'] = 'b' * 40
    elif mutation == 'failed_check': reports['monitored']['checks'][0]['passed'] = False
    elif mutation == 'duplicate_check': reports['monitored']['checks'][1] = reports['monitored']['checks'][0]
    elif mutation == 'too_few_checks': reports['monitored']['checks'].pop()
    elif mutation == 'bad_label': reports['monitored']['checks'][0]['label'] = {'secret': 'never-output'}
    elif mutation == 'dirty_source': reports['monitored']['source_dirty'] = True
    elif mutation == 'unfinished_runtime': reports['response-mtls']['completed'] = False
    elif mutation == 'leftover_volume': reports['response-mtls']['cleanup']['volumes'] = 1
    elif mutation == 'cleanup_not_purged': reports['execution-mtls']['cleanup']['purged'] = False
    elif mutation == 'release_changed': reports['execution-mtls']['release']['payload']['files'] = {}
    elif mutation == 'missing_report': reports.pop('selection')
    with pytest.raises(ValueError):
        module.review(ci, reports, COMMIT)


def test_missing_and_ambiguous_log_reports_are_rejected(evidence):
    _, reports = evidence
    text = log_for(reports)
    with pytest.raises(ValueError, match='ambiguous'):
        module.extract_reports(text + '\n' + log_for({'selection': reports['selection']}))
    reports.pop('selection')
    with pytest.raises(ValueError, match='missing_runtime_report'):
        module.extract_reports(log_for(reports))


def test_unknown_step_export_requires_exact_job_schema_and_one_report(evidence):
    _, reports = evidence
    text = log_for(reports).replace('\tReport verification\t', '\tUNKNOWN STEP\t')
    assert module.extract_reports(text) == reports
    unrelated = 'runtime (selection)\tUNKNOWN STEP\t2026-11-13T01:00:00Z '
    assert module.extract_reports(text + '\n' + unrelated + '{"checks": {"other": true}}') == reports
    duplicate = log_for({'selection': reports['selection']}).replace(
        '\tReport verification\t', '\tUNKNOWN STEP\t')
    assert module.extract_reports(text + '\n' + duplicate) == reports
    conflicting = copy.deepcopy(reports['selection'])
    conflicting['completed'] = False
    duplicate = log_for({'selection': conflicting}).replace(
        '\tReport verification\t', '\tUNKNOWN STEP\t')
    with pytest.raises(ValueError, match='ambiguous'):
        module.extract_reports(text + '\n' + duplicate)
    with pytest.raises(ValueError):
        module.extract_reports(text.replace('runtime (selection)', 'runtime (application)'))


def test_cli_requires_fresh_output_and_never_echoes_untrusted_input(tmp_path, capsys):
    ci, log, output = tmp_path / 'ci.json', tmp_path / 'ci.log', tmp_path / 'output'
    ci.write_text('{"private_key": "secret-never-output", broken')
    log.write_text('nothing')
    args = ['--ci-json', str(ci), '--ci-log', str(log), '--expected-commit', COMMIT,
            '--directory', str(output)]
    assert module.main(args) == 1 and not output.exists()
    assert 'secret-never-output' not in capsys.readouterr().out
    output.mkdir()
    assert module.main(args) == 1
    assert json.loads(capsys.readouterr().out)['error'] == 'fresh_output_directory_required'
