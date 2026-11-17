import pytest

from scripts.f1_lab.audit_auth_review import SuEvent
from scripts.f1_lab.ordered_audit_login import OrderedAuditReview

PIN = 'a'*64


def row(kind, serial, stamp=10.2, *, pid=43, account='worker', res='success', auid=1001, ses=3):
    if kind == 'LOGIN':
        return f'type=LOGIN msg=audit({stamp}:{serial}): pid={pid} uid=0 auid={auid} ses={ses} res={res}'
    executable = '/bin/su' if kind == 'USER_AUTH' else '/lib/systemd/systemd'
    return (f'type={kind} msg=audit({stamp}:{serial}): pid={pid} uid=0 auid={auid} ses={ses} '
            f'msg=\'op=PAM:accounting acct="{account}" exe="{executable}" res={res}\'')


def observe(review, text, time):
    return review.observe(text, time, source_sha256=PIN)


def primed(*, seed=9.9):
    review = OrderedAuditReview((SuEvent(seed, 42, 'worker'),), PIN)
    observe(review, row('USER_AUTH', 1, 10.1, pid=42), 10.1)
    observe(review, row('USER_ACCT', 2), 10.2)
    observe(review, row('CRED_ACQ', 3), 10.2)
    return review


def test_increasing_same_source_serial_orders_equal_timestamp_login():
    review = primed()
    assert observe(review, row('LOGIN', 4, res='1'), 10.2) == 'web_service_su_followed_by_process_login'
    assert review.ordered_login_observations == 1


@pytest.mark.parametrize('change', [{'serial': 3}, {'serial': 2}, {'serial': 0},
    {'serial': 2**64}, {'serial': 4, 'pid': 44}, {'serial': 4, 'res': '0'},
    {'serial': 4, 'auid': 4294967295}, {'serial': 4, 'ses': 4294967295}])
def test_duplicate_backwards_invalid_or_unbound_login_is_not_promoted(change):
    review = primed()
    args = {'serial': 4, 'res': '1', **change}
    assert observe(review, row('LOGIN', **args), 10.2) is None
    assert review.ordered_login_observations == 0


@pytest.mark.parametrize('line', ['malformed', row('SERVICE_START', 1, 10.3),
                                row('SERVICE_START', 3, 10.3)])
def test_invalid_or_regressed_serial_disables_extension_for_remaining_source(line):
    review = primed()
    observe(review, line, 10.3)
    assert not review.ordered_available
    # The pre-existing strictly later-time rule must remain effective.
    assert observe(review, row('LOGIN', 10, 10.3, res='1'), 10.3) == 'web_service_su_followed_by_process_login'
    assert review.ordered_login_observations == 0


def test_malformed_record_cannot_enable_a_new_equal_timestamp_observation():
    review = primed()
    observe(review, 'malformed', 10.2)
    assert observe(review, row('LOGIN', 4, res='1'), 10.2) is None


def test_source_pin_cannot_change_to_reuse_another_sources_process_state():
    review = primed()
    with pytest.raises(ValueError, match='source_changed'):
        review.observe(row('LOGIN', 4, res='1'), 10.2, source_sha256='b'*64)


def test_same_time_cross_source_auth_seed_remains_ineligible():
    review = primed(seed=10.1)
    assert observe(review, row('LOGIN', 4, res='1'), 10.2) is None


@pytest.mark.parametrize('change', [{'kind': 'USER_END'}, {'kind': 'USER_ACCT', 'account': 'other'}])
def test_process_end_and_account_change_invalidate_retained_order(change):
    review = primed()
    observe(review, row(serial=4, **change), 10.2)
    assert observe(review, row('LOGIN', 5, res='1'), 10.2) is None


def test_later_timestamp_existing_reason_is_preserved_without_new_tie_observation():
    review = primed()
    assert observe(review, row('LOGIN', 4, 10.3, res='1'), 10.3)
    assert review.ordered_login_observations == 0


def test_equal_float_time_cannot_replace_the_raw_event_timestamp():
    review = primed()
    assert observe(review, row('LOGIN', 4, 10.3, res='1'), 10.2) is None
    assert not review.ordered_available
