import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts.continuous_mtls_runtime import RuntimeFailure
from scripts.test_persistent_authority_runtime import Checks
from scripts.test_transport_process_recovery import public_failure


@pytest.mark.parametrize('probe',['sql','health'])
def test_one_readonly_timeout_still_requires_real_ready_with_original_deadline(probe):
    checks=object.__new__(Checks)
    checks.report={}
    calls={'sql':0,'health':0,'save':0}
    def sql(query):
        assert query=='SELECT 1;'
        calls['sql']+=1
        if probe=='sql' and calls['sql']==1:
            raise subprocess.TimeoutExpired(['docker','exec','secret-canary'],8)
        return '1'
    def health():
        calls['health']+=1
        if probe=='health' and calls['health']==1:
            raise subprocess.TimeoutExpired(['docker','exec','secret-canary'],8)
        return {'healthy':True,'server_time':123}
    checks.runtime=SimpleNamespace(sql=sql,authority_health=health)
    def save():calls['save']+=1
    checks.save=save
    def wait(predicate,label,timeout):
        assert label=='persistent_authority_replicas_not_ready' and timeout==45
        assert predicate() is False
        assert predicate() is True
    checks.wait=wait
    checks.ready()
    assert checks._ca_floor==123 and calls['save']==1
    assert checks.report['transient_readiness_probe_timeouts']==1
    assert 'secret-canary' not in json.dumps(checks.report)


def test_ownership_or_trust_failure_is_never_retried_as_a_readiness_timeout():
    checks=object.__new__(Checks)
    checks.report={}
    def sql(_):raise RuntimeFailure('runtime_volume_ownership_changed')
    checks.runtime=SimpleNamespace(sql=sql,authority_health=lambda:pytest.fail('health after ownership failure'))
    checks.save=lambda:pytest.fail('ownership failure masked')
    checks.wait=lambda predicate,*a,**kw:predicate()
    with pytest.raises(RuntimeFailure,match='ownership_changed'):checks.ready()
    assert not checks.report


def test_repeated_timeouts_cannot_turn_not_ready_into_success():
    checks=object.__new__(Checks)
    checks.report={}
    checks._ca_floor=0
    def sql(_):raise subprocess.TimeoutExpired(['docker','exec'],8)
    checks.runtime=SimpleNamespace(sql=sql,authority_health=lambda:pytest.fail('health after failed sql'))
    checks.save=lambda:None
    def wait(predicate,label,timeout):
        assert timeout==45
        for _ in range(3):assert predicate() is False
        raise RuntimeFailure(label)
    checks.wait=wait
    with pytest.raises(RuntimeFailure,match='replicas_not_ready'):checks.ready()
    assert checks._ca_floor==0 and checks.report['transient_readiness_probe_timeouts']==3


@pytest.mark.parametrize('timeout',[8,8.5,True,'8',float('nan'),float('inf'),901])
def test_timeout_receipt_does_not_echo_command_output_or_environment(timeout):
    error=subprocess.TimeoutExpired(['docker','exec','private-token-canary'],timeout,
        output='private-key-canary',stderr='private-path-canary')
    receipt=public_failure(error)
    assert receipt['reason']=='runtime_command_timeout'
    assert 'canary' not in json.dumps(receipt)
    assert receipt['command_timeout_seconds']==(timeout if type(timeout) in {int,float} and 0<timeout<=900 else None)


@pytest.mark.parametrize('code',[1,125,137,-9])
def test_nonzero_fixed_runtime_exit_is_retained_without_raw_docker_text(code):
    receipt=public_failure(RuntimeFailure('runtime_command_failed_'+str(code)))
    assert receipt['reason']=='runtime_command_failed' and receipt['cli_exit_code']==code


def test_non_allowlisted_exception_text_is_not_reflected():
    receipt=public_failure(RuntimeFailure('runtime_command_failed_1 private-key-canary'))
    assert 'cli_exit_code' not in receipt and 'canary' not in json.dumps(receipt)
