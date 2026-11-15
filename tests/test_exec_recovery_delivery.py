import http.client
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from scripts import signal_metrics_exporter as exporter
from scripts.f1_lab import exec_recovery_status as status
from scripts.f1_lab.exec_recovery_inventory import inspect_recovery
from tests.test_managed_exec_retention import fixture

pytestmark=pytest.mark.skipif(sys.platform!='linux',reason='POSIX native recovery reporting')


@pytest.mark.parametrize('enabled',[False,True])
def test_authenticated_exporter_adds_recovery_only_when_explicitly_configured(enabled,tmp_path,monkeypatch):
    f=fixture(tmp_path)
    f.execute()
    values=inspect_recovery(f.intents,f.root,f.archive_scope,f.lab.broker.joiner.registry,f.lab.broker.registry)
    path=tmp_path/'status.json'
    status.publish(path,status.report(f.archive_scope,values))
    profile={'schema':'zt-exec-recovery-metrics-profile-1','scope_sha256':status.scope_hash(f.archive_scope),
             'status_file':str(path),'max_indeterminate_age_seconds':5,'max_unpublished_age_seconds':5,'max_intents':10000}
    monkeypatch.setattr(exporter,'metrics',lambda *_:'secops_signal_collection_success 1\n')
    token='x'*32
    server=ThreadingHTTPServer(('127.0.0.1',0),exporter.handler('http://127.0.0.1:1/zero-trust/signals/inbox',
                                                           'fixture',token,recovery_profile=profile if enabled else None))
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        for headers,expected in [({},401),({'Authorization':'Bearer '+token},200)]:
            client=http.client.HTTPConnection(*server.server_address,timeout=5)
            client.request('GET','/metrics',headers=headers)
            reply=client.getresponse()
            body=reply.read().decode()
            assert reply.status==expected
            if expected==200:assert ('secops_exec_recovery_bridge_enabled' in body) is enabled
            client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_cli_requires_real_environment_unless_local_fixture_is_explicit_and_does_not_launch(tmp_path):
    f=fixture(tmp_path)
    f.execute()
    public=tmp_path/'public'
    public.mkdir(mode=0o755)
    output=public/'status.json'
    args=[sys.executable,'-m','scripts.exec_recovery_status','--tenant',f.archive_scope.tenant_id,
          '--server',f.archive_scope.server_id,'--unit',f.archive_scope.unit,'--source',f.archive_scope.source_id,
          '--intents',str(f.intents),'--root',str(f.root),'--registry',str(f.lab.broker.joiner.registry.path),
          '--registry-sha256',f.lab.broker.joiner.registry.expected_sha256,
          '--caller-registry',str(f.lab.broker.registry.path),'--caller-registry-sha256',f.lab.broker.registry.sha256,
          '--status-output',str(output)]
    before={p:p.read_bytes() for p in (f.root/'latest.json',f.lab.broker.path,f.lab.operations.path)}
    for local,expected,state in [(False,2,'unavailable'),(True,0,'ready')]:
        extra=['--caller-environment','local_oidc'] if local else []
        result=subprocess.run([*args,*extra],cwd=Path(__file__).resolve().parents[1],
                              env={**os.environ,'AWS_EC2_METADATA_DISABLED':'true'},capture_output=True,timeout=20,check=False)
        assert result.returncode==expected
        assert json.loads(result.stdout)['state']==state
        value=json.loads(output.read_bytes())
        assert value['state']==state and value['authorization_asserted'] is False
    assert all(p.read_bytes()==raw for p,raw in before.items()) and len(f.launches)==1


def test_enabled_profile_does_not_refresh_an_expired_signed_artifact_report(tmp_path):
    f=fixture(tmp_path)
    values={'intents':0,'sealed':0,'indeterminate':0,'published':0,'unpublished':0,'raw_bytes':0,
            'oldest_indeterminate_at':None,'oldest_unpublished_at':None}
    p=tmp_path/'status.json'
    status.publish(p,status.report(f.archive_scope,values,now=datetime(2025,1,1,tzinfo=UTC)))
    config={'schema':'zt-exec-recovery-metrics-profile-1','scope_sha256':status.scope_hash(f.archive_scope),
            'status_file':str(p),'max_indeterminate_age_seconds':5,'max_unpublished_age_seconds':5,'max_intents':10000}
    old=p.read_bytes()
    assert 'secops_exec_recovery_status_success 0' in status.metrics(config)
    assert p.read_bytes()==old
