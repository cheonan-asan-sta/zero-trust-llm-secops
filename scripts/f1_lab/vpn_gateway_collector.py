"""Read actual local gateway TLS facts for the existing signed VPN bridge.

This is a trusted ingress adapter, not an OpenVPN plugin. It does not infer user
identity, device health, MFA or business permission from a certificate or IP.
The bridge still requires independent signed identity/posture/approval and the
operator-pinned certificate enrollment on every request.
"""

import hashlib
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime

from scripts.f1_lab.native_jsonl import require
from scripts.f1_lab.vpn_verified_signals import VPNConnection


@dataclass(frozen=True)
class GatewayObservation:
    connection: VPNConnection
    raw_line: str


def collect_connection(channel, *, tenant_id, gateway_id, session_id, session_version,
                       user_id, device_id, resource_id, now=None):
    require(isinstance(channel, ssl.SSLSocket) and channel.server_side
            and channel.context.verify_mode == ssl.CERT_REQUIRED
            and channel.version() in {'TLSv1.2', 'TLSv1.3'}, 'vpn_verified_tls_server')
    peer = channel.getpeername()
    certificate = channel.getpeercert(binary_form=True)
    binding = channel.get_channel_binding('tls-unique')
    require(len(peer) == 2 and isinstance(certificate, bytes) and 0 < len(certificate) <= 65536
            and isinstance(binding, bytes) and 12 <= len(binding) <= 256, 'vpn_tls_peer_facts')
    observed = datetime.now(UTC) if now is None else now
    require(observed.tzinfo is not None and observed.utcoffset() is not None, 'vpn_gateway_time')
    observed = observed.astimezone(UTC)
    # A new metadata-only observation, never a replacement for an error/auth log.
    raw = observed.strftime('%Y-%m-%d %H:%M:%S')+f' {peer[0]}:{peer[1]} TLS: Initial packet from client\n'
    connection = VPNConnection(tenant_id=tenant_id, gateway_id=gateway_id, session_id=session_id,
        session_version=session_version, user_id=user_id, device_id=device_id, resource_id=resource_id,
        peer_ip=peer[0], peer_port=peer[1], client_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        tls_channel_sha256=hashlib.sha256(binding).hexdigest(),
        raw_line_sha256=hashlib.sha256(raw.encode()).hexdigest(), observed_at=observed)
    require(channel.getpeername() == peer and channel.getpeercert(binary_form=True) == certificate
            and channel.get_channel_binding('tls-unique') == binding
            and channel.context.verify_mode == ssl.CERT_REQUIRED, 'vpn_tls_channel_changed')
    return GatewayObservation(connection, raw)
