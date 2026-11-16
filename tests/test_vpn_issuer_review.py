import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from scripts.f1_lab.operation_refinement import OperationDecision
from scripts.f1_lab.vpn_issuer_review import (
    FIELDS,
    IssuerHead,
    IssuerRelationReview,
    feature_pin,
    verified_subject,
)
from scripts.f1_lab.vpn_protocol_review import ProtocolObservation, ProtocolReview

SOURCE = 'a' * 64
DEPENDENCIES = {key: char * 64 for key, char in
                [('legacy_identity_sha256', 'a'), ('protocol_model_sha256', 'b'), ('control_model_sha256', 'c')]}
START = 1640995200


def line(body, moment=START, *, peer='192.0.2.1:12345', name=None):
    stamp = datetime.fromtimestamp(moment, UTC).strftime('%Y-%m-%d %H:%M:%S')
    return stamp + ' ' + ((name + '/') if name else '') + (peer + ' ' if peer else '') + body + '\n'


def native(body, *, ordinal=1, moment=START, source=SOURCE, peer='192.0.2.1:12345', available=True):
    raw = line(body, moment, peer=peer)
    protocol = ProtocolObservation(source, ordinal, hashlib.sha256(raw.encode()).hexdigest(), 'f' * 64, available, False)
    return raw, protocol


def apply(review, body, ordinal=1, moment=START, *, peer='192.0.2.1:12345'):
    raw, protocol = native(body, ordinal=ordinal, moment=moment, source=review.source, peer=peer)
    return review.observe(ordinal, raw, moment, protocol, source_sha256=review.source)


def issuer(subject='example-ca'):
    return 'VERIFY OK: depth=1, C=AT, O=Example, CN=' + subject + ', emailAddress=operator@example.test'


@pytest.mark.parametrize('subject,peer,source', [('one-ca', '192.0.2.1:12345', 'a' * 64),
    ('another-ca', '198.51.100.1:54321', 'b' * 64)])
def test_only_relationship_flags_enter_features_not_literal_subject_peer_or_source(subject, peer, source):
    review = IssuerRelationReview(source)
    observation = apply(review, issuer(subject), peer=peer)
    expected = dict(zip(FIELDS, (True, False, False), strict=True))
    assert observation.projection_sha256 == feature_pin(expected)
    assert observation.human_or_device_identity_verified is False and observation.authority_verified is False
    repeated = apply(review, issuer(subject), ordinal=2, moment=START + 1, peer=peer)
    assert repeated.projection_sha256 == feature_pin(dict(zip(FIELDS, (True, True, False), strict=True)))


def test_new_subject_relationship_is_distinct_from_previously_seen_subject():
    review = IssuerRelationReview(SOURCE)
    apply(review, issuer('old'))
    new = apply(review, issuer('new'), ordinal=2, moment=START + 1)
    assert new.projection_sha256 == feature_pin(dict(zip(FIELDS, (True, False, True), strict=True)))


@pytest.mark.parametrize('body', ['VERIFY OK: depth=1, CN=x, CN=y', 'VERIFY OK: depth=1, X=x, CN=y',
    'VERIFY OK: depth=1, O=Example', 'VERIFY OK: depth=1, CN=x, injected=y',
    'VERIFY OK: depth=1, CN=a,b', 'VERIFY ERROR: depth=1, CN=x', 'VERIFY OK: depth=-1, CN=x'])
def test_unsupported_or_failed_subject_cannot_create_an_issuer_observation(body):
    review = IssuerRelationReview(SOURCE)
    assert verified_subject(body) is None
    assert apply(review, body) is None
    assert apply(review, 'VERIFY KU OK', ordinal=2) is None


def test_leaf_alone_does_not_supply_missing_issuer_and_future_issuer_does_not_backfill():
    review = IssuerRelationReview(SOURCE)
    assert apply(review, 'VERIFY OK: depth=0, CN=leaf') is None
    assert apply(review, 'VERIFY KU OK', ordinal=2) is None
    assert apply(review, issuer(), ordinal=3) is not None


def test_new_initial_or_other_connection_cannot_borrow_prior_issuer():
    review = IssuerRelationReview(SOURCE)
    assert apply(review, issuer()) is not None
    assert apply(review, 'VERIFY KU OK', ordinal=2, peer='192.0.2.1:12346') is None
    assert apply(review, 'TLS: Initial packet from [AF_INET]192.0.2.1:12345, sid=01234567 89abcdef', ordinal=3) is None
    assert apply(review, 'VERIFY KU OK', ordinal=4) is None


@pytest.mark.parametrize('age,available', [(300, True), (301, False)])
def test_issuer_report_has_fixed_lifetime_and_unrelated_claims_do_not_refresh_it(age, available):
    review = IssuerRelationReview(SOURCE)
    apply(review, issuer())
    assert apply(review, 'peer info: IV_PLAT=linux', ordinal=2, moment=START + 299) is None
    assert (apply(review, 'VERIFY KU OK', ordinal=3, moment=START + age) is not None) == available


@pytest.mark.parametrize('age,seen', [(86400, True), (86401, False)])
def test_subject_join_history_has_a_bounded_lifetime(age, seen):
    review = IssuerRelationReview(SOURCE)
    apply(review, issuer())
    observation = apply(review, issuer(), ordinal=2, moment=START + age)
    assert observation.projection_sha256 == feature_pin(dict(zip(FIELDS, (True, seen, False), strict=True)))


def test_global_startup_rows_advance_sequence_and_restart_clears_old_state():
    review, protocol = IssuerRelationReview(SOURCE), ProtocolReview(SOURCE)
    bodies = [('OpenVPN 2.4.4 example startup', None), (issuer(), '192.0.2.1:12345'),
              ('OpenVPN 2.4.4 restarted', None), ('VERIFY KU OK', '192.0.2.1:12345')]
    observed = []
    for n, (body, peer) in enumerate(bodies, 1):
        raw = line(body, START + n, peer=peer)
        prior = protocol.observe(n, raw, START + n, source_sha256=SOURCE)
        observed.append(review.observe(n, raw, START + n, prior, source_sha256=SOURCE))
    assert observed[0] is None and observed[1] is not None and observed[2:] == [None, None]


@pytest.mark.parametrize('fault', ['order', 'time', 'source', 'raw_binding'])
def test_wrong_current_source_order_clock_or_line_cannot_be_used(fault):
    review = IssuerRelationReview(SOURCE)
    apply(review, issuer())
    raw, protocol = native('VERIFY KU OK', ordinal=2, moment=START + 1)
    ordinal, moment, source = 2, START + 1, SOURCE
    if fault == 'order': ordinal = 3; protocol = replace(protocol, ordinal=3)
    if fault == 'time': moment = START - 1
    if fault == 'source': source = 'b' * 64; protocol = replace(protocol, source_sha256=source)
    if fault == 'raw_binding': raw += 'changed'
    if fault == 'raw_binding':
        with pytest.raises(ValueError, match='binding'):
            review.observe(ordinal, raw, moment, protocol, source_sha256=source)
    else:
        assert review.observe(ordinal, raw, moment, protocol, source_sha256=source) is None
        assert review.disabled is True


def head(tmp_path, normal, attack=0):
    raw, _base = native(issuer())
    observation = apply(IssuerRelationReview(SOURCE), issuer())
    value = IssuerHead(DEPENDENCIES)
    for _ in range(normal): value.add(observation, False)
    for _ in range(attack): value.add(observation, True)
    pin = value.save(tmp_path / 'head.json')
    return IssuerHead.load(tmp_path / 'head.json', pin, DEPENDENCIES), observation, raw


@pytest.mark.parametrize('normal,attack,lower', [(4, 0, False), (5, 0, True), (100, 1, False)])
def test_support_boundary_and_any_attack_veto_keep_review_without_identity_or_grants(tmp_path, normal, attack, lower):
    model, observation, raw = head(tmp_path, normal, attack)
    previous = OperationDecision(.4, .98, True, True, 'vpn_history_risk_review')
    result = model.refine(previous, observation, source_sha256=SOURCE, ordinal=1, raw=raw)
    assert result.alert is not lower
    assert result.review is True and result.automatic_enforcement_allowed is False
    assert observation.human_or_device_identity_verified is False and observation.authority_verified is False


@pytest.mark.parametrize('fault', ['protected', 'high_base', 'denial', 'unseen', 'missing'])
def test_current_failures_denials_high_risk_and_unsupported_cells_are_preserved(tmp_path, fault):
    model, observation, raw = head(tmp_path, 5)
    previous = OperationDecision(.4, .98, True, True, 'vpn_history_risk_review')
    if fault == 'protected': observation = replace(observation, protected=True)
    if fault == 'high_base': previous = replace(previous, baseline_score=.95)
    if fault == 'denial': previous = replace(previous, reason='independent_current_denial')
    if fault == 'unseen': observation = replace(observation, projection_sha256='d' * 64)
    if fault == 'missing': observation = None
    assert model.refine(previous, observation, source_sha256=SOURCE, ordinal=1, raw=raw) is previous


@pytest.mark.parametrize('fault', ['authority', 'support', 'dependencies', 'unknown_feature', 'boolean_count'])
def test_resigned_model_cannot_change_profile_minimum_dependencies_or_claim_authority(tmp_path, fault):
    head(tmp_path, 5)
    path = tmp_path / 'head.json'
    value = json.loads(path.read_bytes())
    if fault == 'authority': value['identity_or_authority_verified'] = True
    if fault == 'support': value['minimum_support'] = 4
    if fault == 'dependencies': value['dependencies']['protocol_model_sha256'] = 'e' * 64
    if fault == 'unknown_feature': value['rows'] = {'e' * 64: [5, 0]}
    if fault == 'boolean_count': next(iter(value['rows'].values()))[0] = True
    path.write_text(json.dumps(value), encoding='utf8')
    with pytest.raises(ValueError):
        IssuerHead.load(path, hashlib.sha256(path.read_bytes()).hexdigest(), DEPENDENCIES)


@pytest.mark.parametrize('age,protected', [(60, True), (61, False)])
def test_native_protocol_failure_window_is_inherited_and_never_shortened(age, protected):
    review, protocol = IssuerRelationReview(SOURCE), ProtocolReview(SOURCE)
    values = [(issuer(), START), ('TLS Error: TLS handshake failed', START), ('VERIFY KU OK', START + age)]
    last = None
    for ordinal, (body, moment) in enumerate(values, 1):
        raw = line(body, moment)
        observation = protocol.observe(ordinal, raw, moment, source_sha256=SOURCE)
        last = review.observe(ordinal, raw, moment, observation, source_sha256=SOURCE)
    assert last is not None and last.protected is protected
