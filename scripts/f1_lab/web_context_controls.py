"""Authored functional controls, not real server observations or attack labels."""

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.security import Principal, Role
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.web_residual import ACCESS, build_evidence
from scripts.f1_lab.web_verified_context import (
    KINDS,
    PinnedWebRegistry,
    ServerProof,
    WebBundle,
    WebRequest,
    WebTrustBridge,
    digest,
    digest_raw,
    proof_bytes,
)

NOW = datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
OPERATOR = Principal('web-control-operator', 'web-lab', frozenset({Role.ANALYST}), 'api_key')


def sign(proof, key):
    return proof.model_copy(update={'signature':base64.urlsafe_b64encode(key.sign(proof_bytes(proof))).decode().rstrip('=')})


class WebControls:
    def __init__(self, directory, *, capacity=1000):
        directory.mkdir(parents=True, exist_ok=False)
        self.directory = directory
        self.keys = {kind:Ed25519PrivateKey.generate() for kind in KINDS}
        self.registry = {'schema_version':'zt-web-context-registry-1', 'version':1,
            'issued_at':(NOW-timedelta(minutes=1)).isoformat(), 'expires_at':(NOW+timedelta(hours=1)).isoformat(),
            'authorities':[{'tenant_id':'web-lab','source_id':kind,'key_id':'key-1','kind':kind,
                'public_key':self.public(kind),'enabled':True,'server_ids':['web-server'],
                'subject_ids':['web-user'],'resource_ids':['uploaded-script'],
                'issued_at':(NOW-timedelta(minutes=1)).isoformat(),'expires_at':(NOW+timedelta(hours=1)).isoformat()}
                for kind in KINDS],
            'resources':[{'tenant_id':'web-lab','server_id':'web-server','resource_id':'uploaded-script',
                'authorization_policy_sha256':digest({'fixture_policy':'execute_uploaded_script'}),'minimum_policy_version':1}]}
        self.write()
        self.pinned = PinnedWebRegistry(directory/'web-registry.json', digest_file(directory/'web-registry.json'), minimum_version=1)
        self.bridge = WebTrustBridge(self.pinned, capacity=capacity)

    def public(self, kind):
        raw = self.keys[kind].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.urlsafe_b64encode(raw).decode().rstrip('=')

    def write(self):
        (self.directory/'web-registry.json').write_bytes(canonical(self.registry)+b'\n')

    def repin(self):
        self.write()
        self.pinned.expected_sha256 = digest_file(self.directory/'web-registry.json')

    def build(self, *, index=1, now=NOW, authentication='success', mfa='success', permission='allow', executed=True):
        token = quote(base64.b64encode(canonical(['cat','/tmp/example.txt'])).decode(), safe='')
        target = '/media/uploads/example.php?parameters='+token
        raw = '192.0.2.1 - - ['+now.strftime('%d/%b/%Y:%H:%M:%S +0000')+'] "GET '+target+' HTTP/1.1" 200 10 "-" "local-test"\n'
        source = digest_raw(raw)
        item = next(iter(build_evidence([(1,None,raw)], 'access', source).values()))
        request = WebRequest(tenant_id='web-lab', server_id='web-server', request_id='request-'+str(index),
            case_id=item.case_id, subject_id='web-user', session_id='web-session', session_version=0,
            resource_id='uploaded-script', method='GET', target_sha256=digest_raw(ACCESS.fullmatch(raw.rstrip())['target']),
            body_sha256=digest_raw(''), raw_line_sha256=digest_raw(raw), observed_at=now)
        challenge = self.bridge.issue(request, OPERATOR, now=now)
        observations = [
            {'kind':'authentication','result':authentication,'mfa':mfa},
            {'kind':'authorization','decision':permission,'action':'execute_uploaded_script',
             'policy_sha256':self.registry['resources'][0]['authorization_policy_sha256'],'policy_version':1},
            {'kind':'runtime','executed':executed,'executable_sha256':digest_raw('fixture executable') if executed else None,
             'process_ref_sha256':digest_raw('fixture process') if executed else None}]
        proofs = []
        for observation in observations:
            proof = ServerProof(schema_version='zt-web-server-proof-1', tenant_id='web-lab',
                source_id=observation['kind'], key_id='key-1', request_sha256=challenge.sha256,
                observed_at=now, issued_at=now, expires_at=now+timedelta(seconds=30),
                observation=observation, signature='A'*86)
            proofs.append(sign(proof,self.keys[observation['kind']]))
        return {'features':{**core_features(raw),**semantic_observations(raw)}, 'case_id':item.case_id,
            'evidence':item, 'nonce':challenge.nonce, 'bundle':WebBundle(proofs=proofs), 'raw_line':raw,
            'principal':OPERATOR, 'now':now, 'challenge':challenge}

    def resign(self, row, kind, **changes):
        proofs = []
        for proof in row['bundle'].proofs:
            if proof.observation.kind == kind:
                proof = proof.model_copy(update=changes)
                proof = sign(proof,self.keys[kind])
            proofs.append(proof)
        row['bundle'] = WebBundle(proofs=proofs)


def digest_file(path):
    import hashlib
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arguments(row):
    return {k:v for k,v in row.items() if k != 'challenge'}
