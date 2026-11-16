import hashlib
import json
from dataclasses import replace

import pytest

from scripts.f1_lab.apparmor_status_notice import AppArmorStatusReview
from scripts.f1_lab.audit_intent_head import IntentHead
from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.transfer_evaluation import sha
from scripts.run_audit_intent_review import observations, predict
from scripts.stage_vpn_protocol_replay import stage
from tests.test_apparmor_noop import event
from tests.test_vpn_protocol_stage import fixture

SOURCE = 'a' * 64
START = 1700000000.123


def status(**kwargs):
    return event(**kwargs)[1]


def observe(line=None):
    return AppArmorStatusReview(SOURCE).observe(1, line or status(), START, source_sha256=SOURCE)


def head(tmp_path, normal=5, attack=0):
    model = IntentHead()
    for _ in range(normal):
        model.add(observe(), False)
    for _ in range(attack):
        model.add(observe(), True)
    pin = model.save(tmp_path / 'head.json')
    return IntentHead.load(tmp_path / 'head.json', pin)


def test_first_status_remains_caller_unverified_without_future_syscalls():
    reader = AppArmorStatusReview(SOURCE)
    first = reader.observe(1, status(), START, source_sha256=SOURCE)
    assert first.eligible and first.key[-2:] == ('uid_missing', 'caller_unverified')
    for ordinal, line in enumerate((event()[0], event()[2]), 2):
        assert not reader.observe(ordinal, line, START, source_sha256=SOURCE).eligible
    assert first.key[-2:] == ('uid_missing', 'caller_unverified')
    changed = status().replace('info="same as current profile, skipping" ', '')
    assert observe(changed).key[3] == 'changed_profile'
    assert observe().key[3] == 'unchanged_profile'


def test_raw_names_pids_are_not_learned_or_converted_to_authority():
    other = status(pid='991').replace('/usr/bin/example', '/opt/another')
    assert observe(other).key == observe().key
    reported = observe(status().replace('pid=812', 'uid=0 pid=812'))
    assert reported.key[-2:] == ('reported_root', 'caller_unverified')


@pytest.mark.parametrize('before,after', [
    ('apparmor="STATUS"', 'apparmor="DENIED"'),
    ('type=AVC', 'type=SYSCALL'),
    ('profile_replace', 'profile_remove'),
    ('profile_replace', 'profile_load'),
    ('profile="unconfined"', 'profile="another"'),
    ('comm="apparmor_parser"', 'comm="sh"'),
    ('pid=812', 'pid=0'),
    ('pid=812', 'uid=-1 pid=812'),
    ('pid=812', 'uid=4294967295 pid=812'),
    ('pid=812', 'uid=00 pid=812'),
    ('pid=812', 'error=-1 pid=812'),
    ('pid=812', 'denied_mask=w pid=812'),
    ('pid=812', 'requested_mask=w pid=812'),
    ('same as current profile, skipping', 'unrecognized information'),
    ('/usr/bin/example', 'relative'),
    ('/usr/bin/example', '/etc/shadow'),
    ('/usr/bin/example', '/bin/sh;-c'),
    ('pid=812', 'pid=812 pid=813'),
])
def test_adverse_unsupported_and_payload_fields_are_not_eligible(before, after):
    assert not observe(status().replace(before, after)).eligible


@pytest.mark.parametrize('fault', ['source', 'ordinal', 'missing', 'nan', 'negative', 'regression', 'mismatch', 'serial'])
def test_bad_bindings_and_clocks_disable_lowering(fault):
    reader = AppArmorStatusReview(SOURCE)
    assert reader.observe(1, status(), START, source_sha256=SOURCE).eligible
    ordinal, source, moment = 2, SOURCE, START + .001
    line = status(stamp=str(moment), serial='72')
    if fault == 'source': source = 'b' * 64
    if fault == 'ordinal': ordinal = 3
    if fault == 'missing': moment = None
    if fault == 'nan': moment = float('nan')
    if fault == 'negative': moment = -1
    if fault == 'regression': moment = START - 1
    if fault == 'mismatch': moment += 1
    if fault == 'serial': line = line.replace(':72)', ':70)')
    assert not reader.observe(ordinal, line, moment, source_sha256=source).eligible
    assert reader.disabled


def test_enriched_semantics_and_duplicate_rows_preserve_original_digest_and_past_decision():
    line = status().rstrip('\n') + '\x1dUID="root" injected="/etc/shadow"\n'
    reader = AppArmorStatusReview(SOURCE)
    past = reader.observe(1, line, START, source_sha256=SOURCE)
    assert past.eligible and past.key == observe().key
    assert past.line_sha256 == hashlib.sha256(line.encode()).hexdigest()
    assert not reader.observe(2, line, START, source_sha256=SOURCE).eligible
    assert past.eligible


@pytest.mark.parametrize('normal,attack,lower', [(4, 0, False), (5, 0, True), (100, 1, False)])
def test_training_support_attack_veto_and_explicit_risk_retention(tmp_path, normal, attack, lower):
    model = head(tmp_path, normal, attack)
    previous = OperationDecision(.99, .99, True, True, 'unchanged')
    result = model.refine(previous, observe(), source_sha256=SOURCE, ordinal=1, raw=status())
    assert result.alert is (not lower) and result.review and not result.automatic_enforcement_allowed
    for reason in ('signed_execution_policy_violation', 'prior_journal_service_encoded_dns_error',
                   'audit_sensitive_file', 'explicit_deny'):
        protected = replace(previous, reason=reason)
        assert model.refine(protected, observe(), source_sha256=SOURCE, ordinal=1, raw=status()) is protected


def replay_fixture(tmp_path):
    raw = tmp_path / 'raw'
    raw.mkdir()
    lines = [status(stamp=str(START + n / 1000), serial=str(71 + n)) for n in range(5)]
    source = raw / 'pair-0-raw.source'
    source.write_bytes(''.join(lines).encode())
    digest = sha(source)
    member = 'gather/share/logs/audit/audit.log'
    manifest = {'completed': True, 'timestamp_basis':
        'naive dataset bounds interpreted as UTC only after explicit per-host timezone UTC check',
        'pairs': [{'provenance': {'raw_member': member, 'raw_sha256': digest,
                                 'simulation_start': START - 1, 'simulation_end': START + 100}}]}
    (raw / 'audit.json').write_text(json.dumps(manifest), encoding='utf8')
    prep = {'completed': True, 'inputs_contain_truth': False, 'source_manifest_sha256': sha(raw / 'audit.json'),
            'pairs': [{'raw_member': member, 'raw_sha256': digest, 'rows': len(lines)}]}
    reasons = ['unchanged', 'prior_journal_service_encoded_dns_error', 'unchanged', 'unchanged', 'unchanged']
    before = []
    for n, reason in enumerate(reasons, 1):
        before.append({'case_id': hashlib.sha256((digest + ':' + str(n)).encode()).hexdigest(),
                       'source_index': 0, 'before': True, 'after': n != 3,
                       'before_score': .99, 'after_score': .05 if n == 3 else .99,
                       'reason': reason, 'error': 'preserved-error' if n == 4 else None})
    baseline = tmp_path / 'baseline.jsonl'
    baseline.write_bytes(b''.join((json.dumps(r) + '\n').encode() for r in before))
    return raw, prep, baseline, before


def test_replay_is_opt_in_preserves_every_row_errors_and_independent_risk(tmp_path):
    raw, prep, baseline, before = replay_fixture(tmp_path)
    assert observations(raw, prep) == {}
    assert len(observations(raw, prep, with_apparmor_status=True)) == 5
    result = predict(head(tmp_path), prep, raw, baseline, sha(baseline), tmp_path / 'after.jsonl',
                     with_apparmor_status=True)
    after = [json.loads(line) for line in (tmp_path / 'after.jsonl').read_bytes().splitlines()]
    assert [r['case_id'] for r in after] == [r['case_id'] for r in before]
    assert [r['after'] for r in after] == [False, True, False, None, False]
    assert result['population'] == 5 and result['inference_errors'] == 1 and result['changed_alerts'] == 2
    assert result['validation_labels_opened'] is False
    assert after[1]['reason'] == before[1]['reason'] and after[2]['after_score'] == before[2]['after_score']
    assert after[3]['error'] == before[3]['error']


def test_raw_source_drift_and_combined_profiles_are_rejected(tmp_path):
    raw, prep, _, _ = replay_fixture(tmp_path)
    with pytest.raises(ValueError, match='intent_apparmor_status_option'):
        observations(raw, prep, with_apparmor_causality=True, with_apparmor_status=True)
    (raw / 'pair-0-raw.source').write_bytes(b'tampered\n')
    with pytest.raises(ValueError):
        observations(raw, prep, with_apparmor_status=True)


def test_status_stage_carries_only_its_frozen_parameters_and_no_labels(tmp_path):
    path, _, _, _ = fixture(tmp_path)
    out = tmp_path / 'package'
    result = stage(path, sha(path), out, profile='apparmor-status')
    assert result['profile'] == 'apparmor-status' and result['frozen_training_parameters_staged'] is True
    assert result['model_sha256'] == sha(out / 'inputs/models/head.json')
    assert {p.name for p in (out / 'inputs/models').iterdir()} == {'head.json'}
    assert not list((out / 'inputs').rglob('*truth*'))
    assert not list((out / 'inputs/raw').rglob('*.source'))
