import asyncio
import base64
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest

from app.security import Principal, Role
from scripts.f1_lab.operation_refinement import OperationRefinement
from scripts.f1_lab.vpn_context import PROFILE
from scripts.f1_lab.web_capture_lab import ALLOW_PATH, DENY_PATH, LocalWebCaptureLab
from scripts.f1_lab.web_capture_transport import loopback_http
from scripts.f1_lab.web_evidence_ledger import LedgerUnavailable
from scripts.f1_lab.web_request_capture import RequestCaptureMiddleware
from scripts.f1_lab.web_residual import WebResidualRefinement


def baseline(score=.02):
    return WebResidualRefinement(OperationRefinement(SimpleNamespace(probability=lambda _:score),
        SimpleNamespace(profile=PROFILE,probability=lambda _:.98)))


def target(path=ALLOW_PATH,argv=None):
    value = base64.b64encode(json.dumps(argv or ['cat','/tmp/example']).encode()).decode()
    return path+'?parameters='+quote(value,safe='')


def receipts(lab):
    return [json.loads(p.read_bytes()) for p in (lab.directory/'captures').glob('*.json')]


def request(lab,method='POST',url=None,body=b'example',headers=None):
    async def call():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lab.app,client=('127.0.0.1',12345)),base_url='http://local.test',trust_env=False) as client:
            return await client.request(method,url or target(),content=body,
                headers=headers if headers is not None else {'X-API-Key':lab.api_key})
    return asyncio.run(call())


@pytest.mark.parametrize('body',[b'',b'hello',b'\x00\xff\xfe\x10',b'private-body-value-987'])
def test_actual_request_bytes_and_server_auth_are_bound_without_invented_mfa(tmp_path,body):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    result = request(lab,body=body)
    assert result.status_code == 200 and result.json()['body_sha256'] == hashlib.sha256(body).hexdigest()
    row = receipts(lab)[0]
    assert row['body_complete'] and row['body_bytes'] == len(body) and row['body_sha256'] == hashlib.sha256(body).hexdigest()
    assert row['context_state'] == 'review'  # API-key authentication did not perform MFA.
    assert row['decision']['review'] and not row['decision']['verified_adverse']
    assert row['request_id'] == result.headers['x-capture-id']
    text = ''.join(p.read_text() for p in (lab.directory/'captures').glob('*.json'))
    assert lab.api_key not in text and 'private-body-value-987' not in text


@pytest.mark.parametrize('headers',[{}, {'X-API-Key':'incorrect','X-User':'web-user','X-Session':'forged'},
    [('X-API-Key','incorrect'),('X-API-Key','another')]])
def test_failed_authentication_does_not_fabricate_identity_or_execution(tmp_path,headers):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    result = request(lab,headers=headers)
    assert result.status_code == 401 and lab.executions == 0
    row = receipts(lab)[0]
    assert row['body_complete'] and row['context_state'] == 'unavailable' and row['decision'] is None
    assert 'identity_sha256' not in row


def test_client_request_session_identity_and_forwarded_headers_cannot_replace_server_context(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    headers = {'X-API-Key':lab.api_key,'X-Request-ID':'attacker-chosen-id','X-User':'admin',
        'X-Tenant':'other','X-Session':'forged','X-Session-Version':'999','X-Forwarded-For':'203.0.113.9'}
    first,second = request(lab,headers=headers),request(lab,headers=headers)
    rows = receipts(lab)
    assert first.status_code == second.status_code == 200
    assert len({r['request_id'] for r in rows}) == 2
    assert all(r['request_id'] != headers['X-Request-ID'] and r['context_state'] == 'review' for r in rows)
    assert len({r['identity_sha256'] for r in rows}) == 1


def test_real_policy_denial_prevents_child_and_denial_bypass_is_detected_only_in_fault_lab(tmp_path):
    normal = LocalWebCaptureLab(tmp_path/'normal',baseline())
    assert request(normal,url=target(DENY_PATH)).status_code == 403 and normal.executions == 0
    assert not receipts(normal)[0]['decision']['verified_adverse']
    faulty = LocalWebCaptureLab(tmp_path/'fault',baseline(),fault_denied_execution=True)
    assert request(faulty,url=target(DENY_PATH)).status_code == 200 and faulty.executions == 1
    row = receipts(faulty)[0]
    assert row['decision']['verified_adverse'] and row['decision']['alert'] and row['context_state'] == 'adverse'


def test_client_encoded_command_is_not_used_as_a_subprocess_command(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    marker = tmp_path/'must-not-exist'
    assert request(lab,url=target(argv=['touch',str(marker)])).status_code == 200
    assert lab.executions == 1 and not marker.exists()


def test_empty_body_is_hashed_only_when_actually_complete_and_overlimit_never_executes(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline(),max_body_bytes=4)
    assert request(lab,body=b'12345').status_code == 413 and lab.executions == 0
    row = receipts(lab)[0]
    assert not row['body_complete'] and row['body_sha256'] is None and row['capture_state'] == 'body_limit'


def test_revoked_local_service_session_cannot_be_replaced_with_client_headers(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    lab.revoke_session()
    result = request(lab,headers={'X-API-Key':lab.api_key,'X-Session':'new-session'})
    assert result.status_code == 401 and lab.executions == 0
    assert receipts(lab)[0]['decision'] is None


def test_later_normal_context_does_not_lower_existing_model_alarm(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline(.99))
    assert request(lab).status_code == 200
    decision = receipts(lab)[0]['decision']
    assert decision['alert'] and decision['score'] == .99


def test_spool_failure_changes_http_ack_to_503_without_claiming_action_rollback(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline(),max_records=1)
    assert request(lab).status_code == 200
    assert request(lab).status_code == 503
    assert len(receipts(lab)) == 1  # No fabricated receipt for an unacknowledged capture.


async def raw_asgi(messages, *, target_bytes=b'/a?b=1', max_chunks=10, wait=False):
    captures,sent,seen = [],[],[]
    async def application(scope,receive,send):
        while True:
            item = await receive()
            seen.append(item['body'])
            if not item.get('more_body',False): break
        await send({'type':'http.response.start','status':200,'headers':[]})
        await send({'type':'http.response.body','body':b'ok'})
    values = iter(messages)
    async def receive():
        if wait: await asyncio.sleep(.05)
        return next(values)
    async def send(message): sent.append(message)
    path,_,query = target_bytes.partition(b'?')
    app = RequestCaptureMiddleware(application,captures.append,max_chunks=max_chunks,receive_seconds=.01 if wait else 5.)
    await app({'type':'http','method':'POST','raw_path':path,'query_string':query,'client':('127.0.0.1',20),'headers':[]},receive,send)
    return captures,sent,seen


def test_chunked_body_is_forwarded_unchanged_and_hashed_as_one_request():
    captures,sent,seen = asyncio.run(raw_asgi([{'type':'http.request','body':b'ab','more_body':True},
        {'type':'http.request','body':b'\x00cd','more_body':False}]))
    assert seen == [b'ab',b'\x00cd'] and sent[0]['status'] == 200
    assert captures[0].body_complete and captures[0].body_sha256 == hashlib.sha256(b'ab\x00cd').hexdigest()


@pytest.mark.parametrize('messages,kwargs,state,status', [
    ([{'type':'http.request','body':b'partial','more_body':True},{'type':'http.disconnect'}],{},'disconnected',400),
    ([{'type':'http.request','body':b'','more_body':True}]*2,{'max_chunks':2},'chunk_limit',413),
    ([{'type':'http.request','body':'not-bytes'}],{},'invalid_body_stream',400),
    ([{'type':'http.request','body':b'','more_body':'false'}],{},'invalid_body_stream',400),
    ([{'type':'http.request','body':b'','more_body':False}],{'wait':True},'body_timeout',408),
])
def test_missing_truncated_or_invalid_stream_never_creates_a_complete_empty_body(messages,kwargs,state,status):
    captures,sent,seen = asyncio.run(raw_asgi(messages,**kwargs))
    assert not seen and sent[0]['status'] == status
    assert captures[0].capture_state == state and captures[0].body_sha256 is None and not captures[0].body_complete


@pytest.mark.parametrize('path',[b'/a"x',b'/a\r\nx',b'/\xff',b'/'+b'x'*16385])
def test_raw_target_ambiguity_is_not_silently_rewritten(path):
    captures,sent,seen = asyncio.run(raw_asgi([{'type':'http.request','body':b'','more_body':False}],target_bytes=path))
    assert not seen and sent[0]['status'] == 400 and captures[0].raw_target is None


def test_actual_loopback_http_transport_captures_bytes_and_leaves_no_listener(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    with loopback_http(lab.app) as url:
        with httpx.Client(base_url=url,timeout=5,trust_env=False) as client:
            result = client.post(target(),content=b'actual-loopback-bytes',headers={'X-API-Key':lab.api_key})
        assert result.status_code == 200 and lab.executions == 1
    assert receipts(lab)[0]['body_sha256'] == hashlib.sha256(b'actual-loopback-bytes').hexdigest()


def test_local_only_capture_rejects_production_configuration(tmp_path,monkeypatch):
    monkeypatch.setattr('scripts.f1_lab.web_capture_lab.get_settings',lambda:SimpleNamespace(app_environment='production'))
    with pytest.raises(LedgerUnavailable,match='local_only'):
        LocalWebCaptureLab(tmp_path/'no-app',baseline())


def test_only_scoped_collector_can_read_detached_request_for_review(tmp_path):
    lab = LocalWebCaptureLab(tmp_path/'lab',baseline())
    result = request(lab)
    request_id = result.headers['x-capture-id']
    captured = lab.pipeline.request_for(request_id,lab.operator)
    captured.body_sha256 = 'b'*64
    assert lab.pipeline.request_for(request_id,lab.operator).body_sha256 != captured.body_sha256
    wrong = Principal('other-operator','capture-lab',frozenset({Role.ADMIN}),'api_key')
    with pytest.raises(ValueError,match='operator'):
        lab.pipeline.request_for(request_id,wrong)


def test_handler_failure_before_response_is_recorded_without_exposing_exception_text():
    captures,sent = [],[]
    async def application(_scope,_receive,_send):
        raise RuntimeError('private-exception-value')
    async def receive(): return {'type':'http.request','body':b'body','more_body':False}
    async def send(message): sent.append(message)
    app = RequestCaptureMiddleware(application,captures.append)
    asyncio.run(app({'type':'http','method':'POST','raw_path':b'/a','query_string':b'',
        'client':('127.0.0.1',1),'headers':[]},receive,send))
    assert sent[0]['status'] == 500 and b'private-exception-value' not in sent[-1]['body']
    assert captures[0].body_complete and captures[0].capture_state == 'application_error'
