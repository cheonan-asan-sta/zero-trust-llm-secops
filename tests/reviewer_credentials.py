"""Credential isolation invariant shared by infrastructure compatibility tests."""

REVIEWER_VOLUMES = {'reviewer-a-tls', 'reviewer-a-auth', 'reviewer-b-tls', 'reviewer-b-auth'}


def assert_reviewer_isolation(spec):
    assert REVIEWER_VOLUMES <= set(spec['volumes'])
    for service in spec['services'].values():
        sources = {mount.split(':')[0] for mount in service.get('volumes', [])}
        assert not REVIEWER_VOLUMES & sources, 'An online service mounts private reviewer credentials'
