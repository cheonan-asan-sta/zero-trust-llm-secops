"""Local-only HTTP collection lab with real API-key checks and a fixed child."""

import asyncio
import base64
import hashlib
import os
import secrets
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from starlette.responses import JSONResponse

from app.config import Settings, get_settings
from app.security import Principal, Role, _api_key_principal
from scripts.f1_lab.operation_context import canonical
from scripts.f1_lab.web_durable_risk import DurableWebRisk
from scripts.f1_lab.web_evidence_ledger import WebEvidenceLedger, require
from scripts.f1_lab.web_ledger_backup import CheckpointedWebLedger, WebLedgerBackup
from scripts.f1_lab.web_request_capture import (
    STATE_KEY,
    RequestCaptureMiddleware,
    ServerObservation,
    WebCapturePipeline,
)
from scripts.f1_lab.web_verified_context import (
    Authentication,
    Authorization,
    PinnedWebRegistry,
    Runtime,
    VerifiedWebRisk,
    WebTrustBridge,
    digest,
)

SCRIPT = 'import hashlib,sys; data=sys.stdin.buffer.read(); print(hashlib.sha256(data).hexdigest())'
RESOURCE = 'local-fixture-script'
ALLOW_PATH, DENY_PATH = '/media/uploads/allowed.php', '/media/uploads/denied.php'


class LocalWebCaptureLab:
    def __init__(self, directory, baseline, *, fault_denied_execution=False, max_body_bytes=1048576,
                 max_records=1000):
        require(get_settings().app_environment in {'local','test'} and type(fault_denied_execution) is bool,
                'web_capture_lab_local_only')
        self.directory = Path(directory)
        require(not self.directory.exists(),'web_capture_lab_fresh_output')
        self.directory.mkdir(parents=True,mode=0o700)
        self.api_key = secrets.token_urlsafe(32)
        self.settings = Settings(_env_file=None,app_environment='local',auth_mode='api_key',
            api_key_sha256=hashlib.sha256(self.api_key.encode()).hexdigest(),api_key_subject='web-user',
            api_key_tenant_id='capture-lab',api_key_roles='viewer',analyzer_mode='rule',openai_api_key=None)
        self.operator = Principal('capture-operator','capture-lab',frozenset({Role.ANALYST}),'api_key')
        self.policy = {'action':'execute_uploaded_script','resource':RESOURCE,'version':1,'method':['GET','POST'],
            'allowed_path':ALLOW_PATH,'denied_path':DENY_PATH,'required_role':'viewer',
            'execution_scope':'local_fixed_fixture_only'}
        self.policy_sha = digest(self.policy)
        self.session_id,self.version,self.enabled = 'service-'+secrets.token_hex(16),0,True
        self.session_lock = RLock()
        self.fault,self.executions = fault_denied_execution,0
        self.executable = Path(sys.executable).resolve()
        require(self.executable.is_file() and self.executable.stat().st_size <= 64*1024**2,'web_capture_executable_bound')
        self.executable_sha = hashlib.sha256(self.executable.read_bytes()).hexdigest()
        keys = {kind:Ed25519PrivateKey.generate() for kind in ('authentication','authorization','runtime')}
        now = datetime.now(UTC)
        registry = {'schema_version':'zt-web-context-registry-1','version':1,
            'issued_at':(now-timedelta(seconds=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat(),
            'authorities':[{'tenant_id':'capture-lab','source_id':kind,'key_id':'key-1','kind':kind,
                'public_key':base64.urlsafe_b64encode(key.public_key().public_bytes(
                    serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode().rstrip('='),
                'enabled':True,'server_ids':['local-http'],'subject_ids':['web-user'],'resource_ids':[RESOURCE],
                'issued_at':(now-timedelta(seconds=1)).isoformat(),'expires_at':(now+timedelta(hours=1)).isoformat()}
                for kind,key in keys.items()],
            'resources':[{'tenant_id':'capture-lab','server_id':'local-http','resource_id':RESOURCE,
                'authorization_policy_sha256':self.policy_sha,'minimum_policy_version':1}]}
        registry_path = self.directory/'public-registry.json'
        registry_path.write_bytes(canonical(registry)+b'\n')
        self.bridge = WebTrustBridge(PinnedWebRegistry(registry_path,hashlib.sha256(registry_path.read_bytes()).hexdigest(),minimum_version=1))
        source = WebEvidenceLedger(self.directory/'ledger/events.sqlite',self.directory/'ledger/witness')
        source.initialize()
        admin = Principal('capture-maintainer','capture-lab',frozenset({Role.ADMIN}),'api_key')
        manager = WebLedgerBackup(source,secrets.token_bytes(32),'bootstrap-only',
            maintainers=frozenset({('capture-lab','capture-maintainer')}))
        checkpoint_path = self.directory/'external-checkpoints/bootstrap.json'
        self.checkpoint = manager.checkpoint(checkpoint_path,admin,now=now)
        self.ledger = CheckpointedWebLedger(source.database,source.control,checkpoint_path,self.checkpoint['sha256'])
        model = DurableWebRisk(VerifiedWebRisk(baseline,self.bridge),self.ledger)
        self.pipeline = WebCapturePipeline(model,self.operator,self.directory/'captures',server_id='local-http',
            keys=keys,source_ids={kind:(kind,'key-1') for kind in keys},max_records=max_records)
        self.app = RequestCaptureMiddleware(self._application,self.pipeline,max_body_bytes=max_body_bytes)

    def revoke_session(self):
        with self.session_lock:
            self.enabled = False
            self.version += 1

    def _run(self, body, request_id):
        require(hashlib.sha256(self.executable.read_bytes()).hexdigest() == self.executable_sha,'web_capture_executable_changed')
        environment = {'PYTHONDONTWRITEBYTECODE':'1'}
        if 'SYSTEMROOT' in os.environ:
            environment['SYSTEMROOT'] = os.environ['SYSTEMROOT']
        process = subprocess.Popen([str(self.executable),'-I','-S','-c',SCRIPT],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=environment)
        with self.session_lock:
            self.executions += 1
        reference = digest({'pid':process.pid,'request_id':request_id,'observed_at':datetime.now(UTC).isoformat(),
                            'fixed_script_sha256':hashlib.sha256(SCRIPT.encode()).hexdigest()})
        runtime = Runtime(kind='runtime',executed=True,executable_sha256=self.executable_sha,process_ref_sha256=reference)
        try:
            stdout,_ = process.communicate(body,timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return runtime,None,504
        return runtime,stdout.decode('ascii').strip() if process.returncode == 0 else None,200 if process.returncode == 0 else 500

    async def _application(self, scope, receive, send):
        if scope['type'] != 'http':
            if scope['type'] == 'lifespan':
                while True:
                    message = await receive()
                    if message['type'] == 'lifespan.startup': await send({'type':'lifespan.startup.complete'})
                    else:
                        await send({'type':'lifespan.shutdown.complete'})
                        return
            return
        principal = None
        authentication = Authentication(kind='authentication',result='failure',mfa='not_used')
        session,version,resource,permission = None,None,None,None
        runtime = Runtime(kind='runtime',executed=False,executable_sha256=None,process_ref_sha256=None)
        try:
            credentials = [v for k,v in scope.get('headers',[]) if k.lower() == b'x-api-key']
            require(len(credentials) == 1,'web_capture_single_credential')
            principal = _api_key_principal(credentials[0].decode('utf8'),self.settings)
            with self.session_lock:
                require(self.enabled,'web_capture_service_session_revoked')
                session,version = self.session_id,self.version
            authentication = Authentication(kind='authentication',result='success',mfa='not_used')
        except (HTTPException,ValueError,UnicodeError):
            scope['state'][STATE_KEY] = ServerObservation(principal,None,None,None,authentication,None,runtime)
            await JSONResponse({'detail':'Authentication required'},status_code=401)(scope,receive,send)
            return
        raw_path = scope['raw_path']
        path = raw_path.decode('ascii')
        status = 404
        if path in {ALLOW_PATH,DENY_PATH} and scope['method'] in {'GET','POST'}:
            resource = RESOURCE
            allowed = path == ALLOW_PATH and Role.VIEWER in principal.effective_roles
            permission = Authorization(kind='authorization',decision='allow' if allowed else 'deny',
                action='execute_uploaded_script',policy_sha256=self.policy_sha,policy_version=1)
            status = 200 if allowed else 403
            body = bytearray()
            while True:
                message = await receive()
                body.extend(message.get('body',b''))
                if not message.get('more_body',False): break
            result = None
            if allowed or self.fault:
                runtime,result,status = await asyncio.to_thread(self._run,bytes(body),scope['state']['secops_capture_id'])
            with self.session_lock:
                if not self.enabled or self.version != version:
                    authentication = Authentication(kind='authentication',result='unknown',mfa='not_used')
            response = {'body_sha256':result,'execution_scope':'local_fixed_fixture_only'}
        else:
            response = {'detail':'Unsupported route'}
        scope['state'][STATE_KEY] = ServerObservation(principal,session,version,resource,authentication,permission,runtime)
        await JSONResponse(response,status_code=status)(scope,receive,send)
