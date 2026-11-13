import base64
import hashlib
import io
import json
from dataclasses import replace
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from scripts.f1_lab.native_bayes import counts, metrics, record
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.operation_refinement import OperationDecision, OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE as VPN_PROFILE
from scripts.f1_lab.web_residual import WebResidualRefinement, build_evidence, encoded_argv_request
from scripts.run_web_residual import compare

SOURCE = 'a'*64


def access(target, method='GET', status=200, agent='client'):
    return f'192.0.2.1 - - [18/Jan/2022:10:00:00 +0000] "{method} {target} HTTP/1.1" {status} 10 "-" "{agent}"\n'


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def command(value=None, path='/media/uploads/a.php', key='payload'):
    return access(path+'?'+key+'='+quote(encoded(value or ['cat', '/tmp/example']), safe=''))


def error(path, client='192.0.2.1', module='php7', level='error'):
    return f"[Tue Jan 18 10:07:23.000000 2022] [{module}:{level}] [pid 100] [client {client}:1234] script '{path}' not found or unable to stat\n"


def model(score=.1):
    return WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _: score),
        SimpleNamespace(profile=VPN_PROFILE, probability=lambda _: .9)))


@pytest.mark.parametrize('argv', [['cat', '/tmp/example'], ['uname', '-a'], ['/bin/sh', '-c', 'id'],
                                    ['./tools/inspection.sh', '-a'], ['curl', 'https://example.test/data']])
def test_structured_command_in_uploaded_script_query_is_observation_only(argv):
    line = command(argv, key='different_parameter')
    assert encoded_argv_request(line)
    values = build_evidence([(1, None, line)], 'access', SOURCE)
    item = next(iter(values.values()))
    value = model().decide(core_features(line), item.case_id, evidence=item)
    assert value.score == .1 and not value.alert and value.review
    assert value.baseline_score == .1 and not value.automatic_enforcement_allowed


@pytest.mark.parametrize('line', [
    access('/?value='+encoded(['cat', '/tmp/example'])),
    command(path='/uploads/image.png'), command(path='/uploads/photo.php.jpg'),
    command(path='/other/run.php'), command(['ordinary_metadata', 'value']),
    command(['cat']), command({'command': ['cat', '/tmp/example']}), command(['cat', 1]),
    command(['cat', '\x00bad']), command(['cat', 'x'*1025]),
    access('/uploads/a.php?payload=not_base64!'),
    access('/uploads/a.php?payload='+base64.b64encode(b'[[[[[').decode()),
    access('/uploads/a.php?payload='+encoded(['cat', '/x'])*1000),
    command(path='https://untrusted.test/uploads/a.php'),
    access('/ordinary', agent='nmap'), access('/uploads/a.php'),
    access('/uploads/a.php?'+('&'.join('x=1' for _ in range(33)))),
    'unparsed log "GET /uploads/a.php?value='+encoded(['cat', '/x'])+' HTTP/1.1" 200',
])
def test_ordinary_encoded_data_agent_alone_invalid_or_missing_context_does_not_raise(line):
    assert not encoded_argv_request(line)
    assert build_evidence([(1, None, line)], 'access', SOURCE) == {}


def test_decode_is_bounded_and_never_executes_or_follows_a_url():
    token = encoded(['curl', 'https://example.test/never-fetched'])
    assert encoded_argv_request(access('/uploads/a.php?v='+quote(quote(token, safe=''), safe='')))
    # A third encoded layer is deliberately outside this parser's contract.
    token = encoded(['cat', '/a'])
    token = token.replace('W', '%57', 1)
    assert not encoded_argv_request(access('/uploads/a.php?v='+quote(quote(token, safe=''), safe='')))


def test_error_burst_requires_distinct_prior_paths_and_current_new_path():
    records = [(n, float(n), error('/srv/'+str(n)+'.php')) for n in range(1, 5)]
    values = build_evidence(records, 'error', SOURCE)
    assert len(values) == 1
    item = next(iter(values.values()))
    assert item.ordinal == 4
    value = model().decide(core_features(records[-1][2]), item.case_id, evidence=item)
    assert value.alert and value.review and value.score == .95
    repeated = [(n, float(n), error('/srv/same.php')) for n in range(1, 20)]
    assert not build_evidence(repeated, 'error', SOURCE)


def test_equal_time_future_missing_time_peer_source_and_expiry_do_not_leak():
    prefix = [(n, 0., error('/srv/'+str(n)+'.php')) for n in range(1, 4)]
    assert not build_evidence(prefix+[(4, 0., error('/srv/new.php'))], 'error', SOURCE)
    assert len(build_evidence(prefix+[(4, 60., error('/srv/new.php'))], 'error', SOURCE)) == 1
    assert not build_evidence(prefix+[(4, 60.001, error('/srv/new.php'))], 'error', SOURCE)
    assert not build_evidence(prefix+[(4, None, error('/srv/new.php'))], 'error', SOURCE)
    assert not build_evidence(prefix+[(4, 1., error('/srv/new.php', client='192.0.2.2'))], 'error', SOURCE)
    assert not build_evidence([(4, 1., error('/srv/new.php'))], 'error', 'b'*64)
    before = build_evidence(prefix+[(4, 1., error('/srv/new.php'))], 'error', SOURCE)
    after = build_evidence(prefix+[(4, 1., error('/srv/new.php')), (5, 2., error('/srv/future.php'))], 'error', SOURCE)
    assert all(after[k] == v for k, v in before.items())


@pytest.mark.parametrize('changes', [{'module':'other'}, {'level':'warn'}, {'client':'unknown'}])
def test_unparsed_or_different_error_messages_do_not_count_as_script_scanning(changes):
    records = [(n, float(n), error('/srv/'+str(n)+'.php', **changes)) for n in range(1, 8)]
    assert not build_evidence(records, 'error', SOURCE)


@pytest.mark.parametrize('damage', ['case', 'ordinal', 'source', 'core', 'reason'])
def test_evidence_cannot_attach_to_another_source_case_or_changed_features(damage):
    line = command()
    item = next(iter(build_evidence([(1, None, line)], 'access', SOURCE).values()))
    changed = {'case': {'case_id':'b'*64}, 'ordinal': {'ordinal':2}, 'source': {'source_sha256':'b'*64},
               'core': {'core_sha256':'b'*64}, 'reason': {'reason':'trust_me'}}[damage]
    with pytest.raises(ValueError):
        model().decide(core_features(line), item.case_id, evidence=replace(item, **changed))


@pytest.mark.parametrize('score', [0., .2, .94, .95, .99, 1.])
def test_existing_alerts_reviews_and_higher_scores_are_never_lowered(score):
    line = command()
    item = next(iter(build_evidence([(1, None, line)], 'access', SOURCE).values()))
    previous = OperationDecision(score, score, score >= .95, score >= .9, 'existing')
    candidate = model()
    assert candidate.refine(previous, core_features(line), item.case_id) is previous
    new = candidate.refine(previous, core_features(line), item.case_id, item)
    assert new.score == score and new.alert == previous.alert and new.review


def test_prepared_http_history_is_separate_from_intrinsic_raw_binding():
    line = command()
    item = next(iter(build_evidence([(1, None, line)], 'access', SOURCE).values()))
    features = {**core_features(line), 'http_window_available':True, 'http_requests_60s':6,
                'http_targets_60s':4, 'http_requests_1s':3, 'http_requests_10s':5, 'http_errors_10s':2}
    value = model().decide(features, item.case_id, evidence=item)
    assert value.review and not value.alert
    with pytest.raises(ValueError, match='feature_binding'):
        model().decide({**features, 'http_method':'POST'}, item.case_id, evidence=item)


@pytest.mark.parametrize('records', [[(1, 1., 'x'), (1, 2., 'y')], [(0, 1., 'x')], [(1, float('nan'), 'x')]])
def test_bad_source_rows_fail_explicitly(records):
    with pytest.raises(ValueError):
        build_evidence(records, 'error', SOURCE)


def test_comparison_preserves_rows_and_nonweb_and_separates_review_from_alert(tmp_path):
    lines = [command(), access('/ordinary'), 'ordinary nonweb log']
    pairs = [{'raw_sha256': SOURCE, 'raw_member': 'site-access.log', 'rows': 2},
             {'raw_sha256': 'b'*64, 'raw_member': 'other.log', 'rows': 1}]
    inputs, truth, groups = [], [], [counts(), counts()]
    for ordinal, line in enumerate(lines, 1):
        index = 0 if ordinal < 3 else 1
        within = ordinal if index == 0 else 1
        case = hashlib.sha256((pairs[index]['raw_sha256']+':'+str(within)).encode()).hexdigest()
        inputs.append({'case_id':case, 'features':core_features(line), 'observation_error':None})
        truth.append({'case_id':case, 'malicious':ordinal == 1, 'attack_labels':[]})
        record(groups[index], ordinal == 1, False)
    preparation = {'pairs':pairs, 'files':{}}
    for name, rows in [('inputs.jsonl', inputs), ('truth.jsonl', truth)]:
        payload = b''.join(canonical(r)+b'\n' for r in rows)
        (tmp_path/name).write_bytes(payload)
        preparation['files'][name] = {'bytes':len(payload), 'sha256':hashlib.sha256(payload).hexdigest()}
    total = counts()
    for gold in (True, False, False):
        record(total, gold, False)
    prior = {'metrics':{'alert':metrics(total)}, 'per_pair':[{'metrics':{'alert':metrics(g)}} for g in groups]}
    baseline = model().baseline
    base = SimpleNamespace(operation_model=baseline, web_model=baseline.web_model)
    evidence = build_evidence([(1, None, lines[0]), (2, None, lines[1])], 'access', SOURCE)
    stream = io.BytesIO()
    result = compare(tmp_path, preparation, {}, evidence, base, prior, stream)
    assert result['population'] == 3 and result['web_rows'] == 2
    assert result['changes'] == {}
    assert result['metrics']['after']['fn'] == 1 and result['metrics']['after']['fp'] == 0
    assert result['review_changes'] == {'publisher_threat_review_added':1}
    assert len(set(result['nonweb_decision_sha256'].values())) == 1
    rows = [json.loads(body) for body in stream.getvalue().splitlines()]
    assert len(rows) == 1 and rows[0]['after_alert'] is False and rows[0]['after_review'] is True
