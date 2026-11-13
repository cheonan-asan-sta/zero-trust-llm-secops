import hashlib
from datetime import timedelta
from types import SimpleNamespace

import pytest

from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.f1_lab.vpn_signal_controls import NOW


@pytest.fixture
def enrollment(tmp_path):
    data = {'schema_version': 'zt-vpn-enrollments-1', 'version': 2,
        'issued_at': (NOW-timedelta(seconds=1)).isoformat(), 'expires_at': (NOW+timedelta(minutes=5)).isoformat(),
        'bindings': [{'tenant_id': 'tenant', 'gateway_id': 'gateway', 'user_id': 'user',
                      'device_id': 'device', 'client_certificate_sha256': 'a'*64, 'enabled': True}]}
    path = tmp_path/'enrollment.json'
    path.write_bytes(canonical(data))
    request = SimpleNamespace(tenant_id='tenant', gateway_id='gateway', user_id='user',
                              device_id='device', client_certificate_sha256='a'*64)
    verifier = PinnedVPNEnrollments(path, hashlib.sha256(path.read_bytes()).hexdigest(), minimum_version=2)
    return data, path, request, verifier


def repin(data, path, verifier):
    path.write_bytes(canonical(data))
    verifier.expected_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()


def test_exact_certificate_device_subject_mapping(enrollment):
    _, _, request, verifier = enrollment
    assert verifier.verify(request, now=NOW) == verifier.expected_sha256


@pytest.mark.parametrize('field,value', [
    ('tenant_id','other'),('gateway_id','other'),('user_id','other'),
    ('device_id','other'),('client_certificate_sha256','b'*64),
])
def test_other_certificate_or_subject_does_not_inherit_healthy_device(enrollment, field, value):
    _, _, request, verifier = enrollment
    setattr(request, field, value)
    with pytest.raises(ValueError, match='enrollment_identity'):
        verifier.verify(request, now=NOW)


@pytest.mark.parametrize('change', ['disabled','expired','rollback','duplicate','changed-unpinned'])
def test_revocation_expiry_rollback_and_conflicting_mapping_fail(enrollment, change):
    data, path, request, verifier = enrollment
    if change=='disabled':
        data['bindings'][0]['enabled']=False
    elif change=='expired':
        data['expires_at']=NOW.isoformat()
    elif change=='rollback':
        data['version']=1
    elif change=='duplicate':
        data['bindings'].append({**data['bindings'][0], 'device_id':'other'})
    else:
        path.write_bytes(b'{}')
    if change!='changed-unpinned':
        repin(data,path,verifier)
    with pytest.raises(ValueError):
        verifier.verify(request,now=NOW)


def test_missing_or_naive_clock_is_not_a_valid_registration(enrollment):
    _, path, request, verifier = enrollment
    with pytest.raises(ValueError, match='clock'):
        verifier.verify(request,now=NOW.replace(tzinfo=None))
    path.unlink()
    with pytest.raises(ValueError, match='file'):
        verifier.verify(request,now=NOW)
