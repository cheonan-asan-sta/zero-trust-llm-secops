"""Publish the managed NGINX route after a fenced standby proves readiness."""

import argparse
import json
import os
import re
import secrets
import ssl
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from tempfile import NamedTemporaryFile

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field, field_validator, model_validator
from starlette.responses import JSONResponse, Response

from app.models import StrictModel
from app.services.audit_transfer import canonical
from scripts import login_queue_activation as activation
from scripts import login_queue_disaster_recovery as recovery
from scripts.f1_lab.capture_backup import (
    fresh_file,
    pinned,
    private_directory,
    private_file,
    sha,
    sync,
)

READY_PATH = "/internal/login-queue-ready/"
READY_PREFIX = b"zt-login-ready-1\x00"
PROFILE = "route-profile.json"
ROUTE = "route.conf"
PRIVATE_NETWORKS = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
DIGEST = r"^[a-f0-9]{64}$"
IDENTIFIER = r"^[a-f0-9]{32}$"


class Upstream(StrictModel):
    address: str
    port: int = Field(strict=True, ge=1, le=65535)
    tls_name: str = Field(pattern=r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$")

    @field_validator("address")
    @classmethod
    def private_ipv4(cls, value):
        ip = IPv4Address(value)
        if not ip.is_loopback and not any(ip in network for network in PRIVATE_NETWORKS):
            raise ValueError("Route requires a private IPv4 upstream")
        return str(ip)


class RouteProfile(StrictModel):
    recovery: recovery.RecoveryProfile
    standby_id: str = Field(pattern=IDENTIFIER)
    readiness_public_key_sha256: str = Field(pattern=DIGEST)
    ca_sha256: str = Field(pattern=DIGEST)
    ca_file: str = Field(pattern=r"^/[a-zA-Z0-9_/.-]+$")
    client_cert: str = Field(pattern=r"^/[a-zA-Z0-9_/.-]+$")
    client_key: str = Field(pattern=r"^/[a-zA-Z0-9_/.-]+$")
    primary: Upstream
    standby: Upstream

    @model_validator(mode="after")
    def distinct_upstreams(self):
        if (
            (self.primary.address, self.primary.port) == (self.standby.address, self.standby.port)
            or self.primary.tls_name.lower() == self.standby.tls_name.lower()
        ):
            raise ValueError("Each upstream requires a distinct address and certificate name")
        return self


class Readiness(StrictModel):
    nonce: str = Field(pattern=DIGEST)
    generation: int = Field(strict=True, ge=2, lt=2**63)
    standby_id: str = Field(pattern=IDENTIFIER)
    receipt_sha256: str = Field(pattern=DIGEST)


class SignedReadiness(StrictModel):
    readiness: Readiness
    signature: str = Field(pattern=r"^[a-f0-9]{128}$")


class RecoveryReadiness:
    """Only the running managed API can answer for its held recovery selection."""

    def __init__(self, app, status, key_path):
        self.app = app
        self.key = Ed25519PrivateKey.from_private_bytes(private_file(key_path, 32))
        self.selection = status["generations"][-1]
        self.receipt = status.get("host_handoff", {}).get("receipt")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith(READY_PATH):
            await self.app(scope, receive, send)
            return
        nonce = scope["path"].removeprefix(READY_PATH)
        if (
            scope["method"] != "GET" or not re.fullmatch(DIGEST, nonce) or self.receipt is None
            or self.selection["predecessor_state"] != "externally_fenced_host"
        ):
            await Response(status_code=404)(scope, receive, send)
            return
        claim = Readiness(
            nonce=nonce, generation=self.selection["number"], standby_id=self.receipt["standby_id"],
            receipt_sha256=self.receipt["receipt_sha256"],
        )
        proof = SignedReadiness(
            readiness=claim, signature=self.key.sign(READY_PREFIX + canonical(claim.model_dump())).hex(),
        )
        await JSONResponse(proof.model_dump(), headers={"Cache-Control": "no-store"})(scope, receive, send)


def _route(profile, state, receipt_hash=None):
    suffix = f" {receipt_hash}" if receipt_hash else ""
    head = f"# zt-login-route {state}{suffix}\n"
    if state == "paused":
        return (head + "return 503;\n").encode()
    node = profile.primary if state == "primary" else profile.standby
    return (head + f"""proxy_pass https://{node.address}:{node.port};
proxy_ssl_server_name on;
proxy_ssl_name {node.tls_name};
proxy_ssl_protocols TLSv1.2 TLSv1.3;
proxy_ssl_verify on;
proxy_ssl_verify_depth 2;
proxy_ssl_trusted_certificate {profile.ca_file};
proxy_ssl_certificate {profile.client_cert};
proxy_ssl_certificate_key {profile.client_key};
proxy_set_header Host {node.tls_name};
proxy_next_upstream off;
proxy_connect_timeout 3s;
proxy_read_timeout 15s;
""").encode()


def _selection(profile, raw):
    if raw == _route(profile, "primary"):
        return "primary", None
    if raw == _route(profile, "paused"):
        return "paused", None
    match = re.fullmatch(rb"# zt-login-route standby ([a-f0-9]{64})", raw.split(b"\n", 1)[0])
    if match and raw == _route(profile, "standby", match[1].decode()):
        return "standby", match[1].decode()
    raise activation.ActivationConflict("Generated login route does not match its pinned profile")


def _profile(root):
    return RouteProfile.model_validate_json(private_file(root / PROFILE, 8192))


def _replace_route(root, raw):
    with NamedTemporaryFile(dir=root, prefix=".route-", delete=False) as stream:
        scratch = Path(stream.name)
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            stream.close()
            os.replace(scratch, root / ROUTE)
            sync(root)
        finally:
            scratch.unlink(missing_ok=True)


def enroll(root, profile):
    root = private_directory(root)
    pinned(Path(profile.ca_file), profile.ca_sha256, 32768)
    with activation._private_fd(root / "route.lock", create=True):
        pass
    with activation._lock(root, "route.lock"):
        if not (root / PROFILE).exists():
            fresh_file(root / PROFILE, canonical(profile.model_dump()))
        if _profile(root) != profile:
            raise activation.ActivationConflict("Route profile is already enrolled")
        if not (root / ROUTE).exists():
            fresh_file(root / ROUTE, _route(profile, "primary"))


def pause(root):
    root = private_directory(root)
    with activation._lock(root, "route.lock"):
        profile = _profile(root)
        state, _ = _selection(profile, private_file(root / ROUTE, 8192))
        if state == "standby":
            raise activation.ActivationConflict("Route already cut over to standby")
        if state == "primary":
            _replace_route(root, _route(profile, "paused"))


def _readiness(profile, public_key_path, expected_hash):
    public_key = pinned(public_key_path, profile.readiness_public_key_sha256, 32)
    ca = pinned(Path(profile.ca_file), profile.ca_sha256, 32768)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca.decode("ascii"))
    context.load_cert_chain(profile.client_cert, profile.client_key)
    node = profile.standby
    nonce = secrets.token_hex(32)
    url = f"https://{node.address}:{node.port}{READY_PATH}{nonce}"
    with (
        httpx.Client(verify=context, follow_redirects=False, trust_env=False, timeout=5) as client,
        client.stream("GET", url, extensions={"sni_hostname": node.tls_name}) as response,
    ):
        response.raise_for_status()
        payload = next(response.iter_raw(chunk_size=4097), b"")
        if not 0 < len(payload) <= 4096:
            raise ValueError("Standby readiness response exceeds its permitted size")
    proof = SignedReadiness.model_validate_json(payload)
    expected = Readiness(
        nonce=nonce, generation=profile.recovery.checkpoint.generation + 1,
        standby_id=profile.standby_id, receipt_sha256=expected_hash,
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(proof.signature), READY_PREFIX + canonical(proof.readiness.model_dump()),
        )
    except InvalidSignature as error:
        raise activation.ActivationConflict("Standby readiness signature is invalid") from error
    if proof.readiness != expected:
        raise activation.ActivationConflict("Standby readiness differs from the approved generation")


def promote(root, receipt, authority_public_key, readiness_public_key):
    root = private_directory(root)
    with activation._lock(root, "route.lock"):
        profile = _profile(root)
        state, previous_hash = _selection(profile, private_file(root / ROUTE, 8192))
        if state == "primary":
            raise activation.ActivationConflict("Pause primary ingress before promotion")
        _, receipt_hash = recovery.verify_receipt(receipt, authority_public_key, profile.recovery, profile.standby_id)
        if state == "standby" and receipt_hash != previous_hash:
            raise activation.ActivationConflict("Route already enabled by a different recovery receipt")
        _readiness(profile, readiness_public_key, receipt_hash)
        if state == "paused":
            _replace_route(root, _route(profile, "standby", receipt_hash))


def status(root):
    root = private_directory(root)
    with activation._lock(root, "route.lock", shared=True):
        raw = private_file(root / ROUTE, 8192)
        state, receipt_hash = _selection(_profile(root), raw)
        return {"state": state, "receipt_sha256": receipt_hash, "configuration_sha256": sha(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    commands = parser.add_subparsers(dest="action", required=True)
    enrollment = commands.add_parser("enroll")
    enrollment.add_argument("profile", type=Path)
    enrollment.add_argument("profile_sha256")
    commands.add_parser("pause")
    commands.add_parser("status")
    promote_command = commands.add_parser("promote")
    for name in ("receipt", "authority_public_key", "readiness_public_key"):
        promote_command.add_argument(name, type=Path)
    args = parser.parse_args()
    root = args.directory
    if args.action == "enroll":
        enroll(root, RouteProfile.model_validate_json(pinned(args.profile, args.profile_sha256, 8192)))
    elif args.action == "pause":
        pause(root)
    elif args.action == "promote":
        promote(root, args.receipt, args.authority_public_key, args.readiness_public_key)
    print(json.dumps(status(root)))


if __name__ == "__main__":
    main()
