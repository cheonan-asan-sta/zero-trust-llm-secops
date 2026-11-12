"""CLI acceptance inventories must agree with the composed isolated graph."""

import importlib

import pytest

from tests.reviewer_credentials import assert_reviewer_isolation


@pytest.mark.parametrize('profile,checks_name', [
    ('rekey_mtls', 'RekeyChecks'), ('persistent_authority', 'Checks'),
    ('database_transport', 'Checks'), ('database_backup', 'Checks'),
    ('database_recovery', 'Checks'),
])
def test_runtime_acceptance_counts_include_unmounted_reviewer_volumes(profile, checks_name):
    runtime = importlib.import_module('scripts.' + profile + '_runtime')
    acceptance = importlib.import_module('scripts.test_' + profile + '_runtime')
    spec = runtime.definition('kmtls-' + 'a' * 12, 'app', 'nginx')
    assert getattr(acceptance, checks_name).expected_volumes == len(spec['volumes'])
    assert_reviewer_isolation(spec)
