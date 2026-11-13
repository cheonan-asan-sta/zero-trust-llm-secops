"""Authored prospective VPN controls with ephemeral keys; never historical labels."""

import base64
import hashlib
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.continuous_signal_models import SignedContinuousSignal
from app.models import EventAction, SecurityEvent
from app.security import Principal, Role
from app.services.trusted_signals import canonical_observation, canonical_signal
from app.zero_trust_models import SignedSessionSignal
from scripts.f1_lab.approvals import ApprovalContext, sign
from scripts.f1_lab.operation_context import canonical, core_features
from scripts.f1_lab.raw_semantics import semantic_observations
from scripts.f1_lab.registry import PinnedApprovalVerifier
from scripts.f1_lab.resource_policy import PinnedResourcePolicies
from scripts.f1_lab.source_registry import FrozenSignalVerifier
from scripts.f1_lab.vpn_enrollment import PinnedVPNEnrollments
from scripts.f1_lab.vpn_risk_retention import retained_contexts
from scripts.f1_lab.vpn_verified_signals import (
    VPNBinding,
    VPNConnection,
    VPNEvidence,
    VPNTrustBridge,
    binding_bytes,
    payload_sha,
)

NOW = datetime(2026, 11, 13, 0, 0, tzinfo=UTC)
OPERATOR = Principal('vpn-controls-operator', 'vpn-lab', frozenset({Role.ANALYST}), 'api_key')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature(key, payload):
    return base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip('=')


class VPNControls:
    def __init__(self, directory, baseline, *, now=NOW, capacity=1000):
        directory.mkdir(parents=True, exist_ok=False)
        self.directory, self.baseline, self.now = directory, baseline, now
        self.keys = {name: Ed25519PrivateKey.generate() for name in ('gateway', 'identity', 'device', 'approval')}
        self.registry = {'sources': []}
        for name in ('gateway', 'identity', 'device'):
            self.registry['sources'].append({
                'tenant_id': 'vpn-lab', 'source_id': name, 'enabled': True,
                'user_ids': ['vpn-user'], 'device_ids': ['vpn-device'], 'roles': ['employee'],
                'observation_kinds': ['device'] if name == 'device' else [],
                'keys': [{'key_id': 'key-1', 'public_key_pem': self.public(name), 'enabled': True,
                          'not_before': (now-timedelta(hours=1)).isoformat(),
                          'not_after': (now+timedelta(hours=1)).isoformat()}]})
        self.approvals = {'schema_version': 'zt-business-authorities-1', 'version': 1,
            'revoked_approval_ids': [], 'authorities': [{
                'tenant_id': 'vpn-lab', 'issuer_id': 'permission-owner', 'key_id': 'approval-1',
                'public_key_pem': self.public('approval'), 'allowed_deviations': ['remote_access'],
                'user_ids': ['vpn-user'], 'device_ids': ['vpn-device'], 'resource_ids': ['vpn-resource'],
                'actions': ['REMOTE_ACCESS'], 'key_not_before': (now-timedelta(hours=1)).isoformat(),
                'key_not_after': (now+timedelta(hours=1)).isoformat(), 'active': True}]}
        self.policy = {'schema_version': 'f1-resource-policies-1', 'version': 1,
            'issued_at': (now-timedelta(minutes=1)).isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat(),
            'resources': [{'tenant_id': 'vpn-lab', 'resource_id': 'vpn-resource', 'sensitivity': 'internal',
                           'permissions': [{'action': 'REMOTE_ACCESS', 'roles': ['employee']}]}]}
        self.enrollment_registry = {'schema_version': 'zt-vpn-enrollments-1', 'version': 1,
            'issued_at': (now-timedelta(minutes=1)).isoformat(), 'expires_at': (now+timedelta(hours=1)).isoformat(),
            'bindings': [{'tenant_id': 'vpn-lab', 'gateway_id': 'gateway-local', 'user_id': 'vpn-user',
                          'device_id': 'vpn-device', 'client_certificate_sha256': 'c'*64, 'enabled': True}]}
        self.write()
        self.signals = FrozenSignalVerifier(directory/'sources.json', sha(directory/'sources.json'))
        self.permissions = PinnedApprovalVerifier(directory/'approvals.json', sha(directory/'approvals.json'), minimum_version=1)
        self.policies = PinnedResourcePolicies(directory/'policies.json', sha(directory/'policies.json'), minimum_version=1)
        self.enrollments = PinnedVPNEnrollments(directory/'enrollments.json', sha(directory/'enrollments.json'))
        self.bridge = VPNTrustBridge(self.signals, self.permissions, self.policies, self.enrollments,
            gateways={('vpn-lab', 'gateway', 'key-1'): {'gateway-local'}},
            identity_sources={('vpn-lab', 'identity', 'key-1')},
            device_sources={('vpn-lab', 'device', 'key-1')}, capacity=capacity)

    def public(self, name):
        return self.keys[name].public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def write(self):
        for name, value in [('sources', self.registry), ('approvals', self.approvals), ('policies', self.policy),
                            ('enrollments', self.enrollment_registry)]:
            (self.directory/(name+'.json')).write_bytes(canonical(value)+b'\n')
        # No private key is persisted.

    def build(self, *, now=None, index=1, session='vpn-session', raw_message=None,
              device='healthy', managed=True, active=True, role='employee', mfa='success',
              authentication='success', approval=True, event_changes=None):
        now = self.now if now is None else now
        message = raw_message or 'TLS: Initial packet from client'
        raw = now.strftime('%Y-%m-%d %H:%M:%S')+' 192.0.2.10:1194 '+message+'\n'
        source_sha = hashlib.sha256(raw.encode()).hexdigest()
        context = next(iter(retained_contexts([(1, now.timestamp(), raw)], source_sha, self.baseline.vpn_model).values()))
        features = {**core_features(raw), **semantic_observations(raw)}
        event = SecurityEvent.model_validate({
            'event_id': 'vpn-event-'+str(index), 'timestamp': now,
            'user': {'user_id': 'vpn-user', 'role': role, 'active': active},
            'device': {'device_id': 'vpn-device', 'managed': managed, 'security_posture': device},
            'network': {'ip': '192.0.2.10', 'location': 'local-lab', 'access_method': 'vpn'},
            'resource': {'resource_id': 'vpn-resource', 'resource_type': 'vpn', 'sensitivity': 'internal'},
            'action': 'REMOTE_ACCESS', 'auth_context': {'authentication_result': authentication, 'mfa': mfa,
                'failed_attempts': 1 if mfa == 'failed' or authentication == 'failure' else 0}, 'behavior': {}})
        if event_changes:
            data = event.model_dump()
            for key, values in event_changes.items():
                data[key] = {**data[key], **values} if isinstance(values, dict) else values
            event = SecurityEvent.model_validate(data)
        connection = VPNConnection(tenant_id='vpn-lab', gateway_id='gateway-local', session_id=session,
            session_version=0, user_id='vpn-user', device_id='vpn-device', resource_id='vpn-resource',
            peer_ip='192.0.2.10', peer_port=1194, client_certificate_sha256='c'*64,
            tls_channel_sha256='d'*64, raw_line_sha256=hashlib.sha256(raw.encode()).hexdigest(), observed_at=now)
        challenge = self.bridge.issue(connection, OPERATOR, now=now)
        identity = SignedSessionSignal(tenant_id='vpn-lab', source_id='identity', key_id='key-1',
            session_id=session, expected_version=0, event=event, issued_at=now,
            expires_at=now+timedelta(seconds=30), signature='A'*86)
        identity = identity.model_copy(update={'signature': signature(self.keys['identity'], canonical_signal(identity))})
        posture = SignedContinuousSignal(tenant_id='vpn-lab', event_id='device-event-'+str(index),
            source_id='device', key_id='key-1', issued_at=now, expires_at=now+timedelta(seconds=30),
            observed_at=now, observation={'kind': 'device', 'subject_id': 'vpn-device',
                                        'managed': managed, 'security_posture': device}, signature='A'*86)
        posture = posture.model_copy(update={'signature': signature(self.keys['device'], canonical_observation(posture))})
        permission = None
        if approval:
            from scripts.f1_lab.approvals import event_digest
            permission = sign(ApprovalContext(approval_id='approval-'+format(index, '032x'),
                tenant_id='vpn-lab', issuer_id='permission-owner', key_id='approval-1',
                event_sha256=event_digest(event), user_id='vpn-user', device_id='vpn-device',
                resource_id='vpn-resource', action=EventAction.REMOTE_ACCESS,
                permitted_deviations=['remote_access'], maximum_download_mb=0.,
                issued_at=now, expires_at=now+timedelta(seconds=30),
                window_evidence_sha256=challenge.evidence_sha256), self.keys['approval'])
        binding = VPNBinding(source_id='gateway', key_id='key-1', request_nonce=challenge.nonce,
            request_sha256=challenge.evidence_sha256, session_sha256=payload_sha(identity),
            posture_sha256=payload_sha(posture), approval_sha256=payload_sha(permission),
            issued_at=now, expires_at=now+timedelta(seconds=30), signature='A'*86)
        binding = binding.model_copy(update={'signature': signature(self.keys['gateway'], binding_bytes(binding))})
        return {'features': features, 'case_id': context.base.case_id, 'context': context,
                'nonce': challenge.nonce, 'evidence': VPNEvidence(binding=binding, identity=identity,
                    posture=posture, approval=permission), 'raw_line': raw, 'principal': OPERATOR,
                'now': now, 'challenge': challenge}

    def resign_binding(self, bundle):
        binding = bundle.binding.model_copy(update={'session_sha256': payload_sha(bundle.identity),
            'posture_sha256': payload_sha(bundle.posture), 'approval_sha256': payload_sha(bundle.approval)})
        binding = binding.model_copy(update={'signature': signature(self.keys['gateway'], binding_bytes(binding))})
        return bundle.model_copy(update={'binding': binding})


def arguments(control):
    return {key: value for key, value in control.items() if key != 'challenge'}
