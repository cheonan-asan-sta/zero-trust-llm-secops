"""NGINX mTLS and client fixtures for the local login recovery exercise."""

import json
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.services.audit_transfer import canonical
from scripts import login_queue_activation as activation
from scripts import login_queue_ingress as ingress
from scripts.f1_lab.capture_backup import fresh_file, sha
from scripts.f1_lab.native_jsonl import require
from scripts.run_login_queue_disaster import COLLECTOR, PORT, docker, rejected, until

EDGE = Path("/edge")
CONTROL = EDGE / "control"
TLS_PORT = 9443
WORKER_PORT = 8800
NGINX = "nginx:stable-alpine"
HEADER = """worker_processes 1;
pid /tmp/fixture-nginx.pid;
error_log /dev/stderr warn;
events { worker_connections 128; }
"""


def certificate(name, *, issuer=None, issuer_key=None, usage=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=issuer is None, path_length=0 if issuer is None else None), critical=True)
    )
    if usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256()), key


def configure(payload):
    EDGE.chmod(0o700)
    CONTROL.mkdir(mode=0o700)
    ca, ca_key = certificate("login-lab-ca")
    ca_raw = ca.public_bytes(serialization.Encoding.PEM)
    fresh_file(EDGE / "ca.pem", ca_raw)
    for role, identity, usage in (
        ("primary", "primary.login.lab", ExtendedKeyUsageOID.SERVER_AUTH),
        ("standby", "standby.login.lab", ExtendedKeyUsageOID.SERVER_AUTH),
        ("edge", "edge.login.lab", ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        cert, key = certificate(identity, issuer=ca, issuer_key=ca_key, usage=usage)
        fresh_file(EDGE / f"{role}.pem", cert.public_bytes(serialization.Encoding.PEM))
        fresh_file(EDGE / f"{role}.key", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
    for backend in ("primary", "standby"):
        conf = HEADER + f"""http {{
    access_log off;
    server {{
        listen {TLS_PORT} ssl;
        ssl_certificate /edge/{backend}.pem;
        ssl_certificate_key /edge/{backend}.key;
        ssl_client_certificate /edge/ca.pem;
        ssl_verify_client on;
        ssl_protocols TLSv1.2 TLSv1.3;
        location / {{
            proxy_set_header Host 127.0.0.1;
            proxy_next_upstream off;
            proxy_pass http://127.0.0.1:{PORT};
        }}
    }}
}}
"""
        fresh_file(EDGE / f"{backend}.conf", conf.encode())
    conf = HEADER + f"""http {{
    access_log off;
    server {{
        listen {WORKER_PORT};
        location ^~ {ingress.READY_PATH} {{ return 404; }}
        location / {{ include /edge/control/route.conf; }}
    }}
}}
"""
    fresh_file(EDGE / "edge.conf", conf.encode())
    authority = bytes.fromhex(payload["authority"])
    readiness = bytes.fromhex(payload["readiness"])
    fresh_file(EDGE / "authority.pub", authority)
    fresh_file(EDGE / "readiness.pub", readiness)
    ingress.enroll(CONTROL, ingress.RouteProfile.model_validate({
        "recovery": {"checkpoint": payload["checkpoint"], "authority_public_key_sha256": sha(authority)},
        "standby_id": payload["standby_id"], "readiness_public_key_sha256": sha(readiness),
        "ca_sha256": sha(ca_raw), "ca_file": "/edge/ca.pem", "client_cert": "/edge/edge.pem",
        "client_key": "/edge/edge.key",
        "primary": {"address": payload["primary"], "port": TLS_PORT, "tls_name": "primary.login.lab"},
        "standby": {"address": payload["standby"], "port": TLS_PORT, "tls_name": "standby.login.lab"},
    }))
    return ingress.status(CONTROL)


def parse_grant(payload):
    raw = payload["receipt"].encode()
    assert sha(raw) == payload["pin"]
    return raw


def unready(payload):
    receipt = EDGE / "fence.json"
    fresh_file(receipt, parse_grant(payload))
    before = ingress.status(CONTROL)
    assert before["state"] == "paused"
    with rejected(httpx.HTTPStatusError, "502"):
        ingress.promote(CONTROL, receipt, EDGE / "authority.pub", EDGE / "readiness.pub")
    assert ingress.status(CONTROL) == before
    return before


def promote():
    receipt = EDGE / "fence.json"
    raw = receipt.read_bytes()
    changed = json.loads(raw)
    changed["decision"]["confirmation"]["record_id"] += "-changed"
    tampered = EDGE / "tampered.json"
    fresh_file(tampered, canonical(changed))
    with rejected(activation.ActivationConflict, "signature is invalid"):
        ingress.promote(CONTROL, tampered, EDGE / "authority.pub", EDGE / "readiness.pub")
    assert ingress.status(CONTROL)["state"] == "paused"
    ingress.promote(CONTROL, receipt, EDGE / "authority.pub", EDGE / "readiness.pub")
    selected = ingress.status(CONTROL)
    assert selected["state"] == "standby" and selected["receipt_sha256"] == sha(raw)
    ingress.promote(CONTROL, receipt, EDGE / "authority.pub", EDGE / "readiness.pub")
    assert ingress.status(CONTROL) == selected
    with rejected(activation.ActivationConflict, "already cut over"):
        ingress.pause(CONTROL)
    return selected


def request(payload):
    with httpx.Client(base_url=payload["edge"], timeout=7, trust_env=False, follow_redirects=False) as client:
        response = client.request(
            payload.get("method", "GET"), payload["path"], json=payload.get("body"),
            headers={"X-API-Key": payload["key"]},
        )
    return {"status": response.status_code, "body": response.json() if response.is_success else None}


def public_probe():
    profile = ingress._profile(CONTROL)
    node = profile.primary
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(profile.ca_file)
    with httpx.Client(verify=context, trust_env=False, timeout=5) as client:
        response = client.get(
            f"https://{node.address}:{node.port}/auth/me", extensions={"sni_hostname": node.tls_name},
        )
    assert response.status_code == 400
    return {"without_mtls_rejected": True}


class RouteLab:
    def __init__(self, source_code, marker, label, image):
        self.source_code, self.marker, self.label, self.image = source_code, marker, label, image
        self.network = marker + "-network"
        self.volume = marker + "-edge"
        self.proxies = []
        self.controller = None
        self.volume_created = self.network_created = False

    def start(self):
        docker("network", "create", "--internal", "--label", self.label, self.network)
        self.network_created = True
        docker("volume", "create", "--label", self.label, self.volume)
        self.volume_created = True
        self.controller = docker(
            "run", "-d", "--pull=never", "--network", self.network, "--label", self.label,
            "--mount", f"type=volume,source={self.source_code},target=/src,readonly",
            "--mount", f"type=volume,source={self.volume},target=/edge",
            "-e", "PYTHONDONTWRITEBYTECODE=1", "--workdir", "/src", "--entrypoint", "python", self.image,
            "-c", "from threading import Event; Event().wait()",
        ).stdout.decode().strip()

    def call(self, command, payload=None):
        result = docker("exec", "-i", self.controller, "python", "-m", "scripts.run_login_queue_ingress", command,
                        stdin=canonical(payload) if payload is not None else b"", check=False, timeout=45)
        if result.returncode:
            raise RuntimeError(f"{command}: {result.stderr.decode(errors='replace')[-2800:]}")
        return json.loads(result.stdout)

    def address(self, node):
        snapshot = json.loads(docker("inspect", node).stdout)[0]
        return snapshot["NetworkSettings"]["Networks"][self.network]["IPAddress"]

    def launch_proxy(self, role, network):
        identifier = docker(
            "run", "-d", "--pull=never", "--network", network, "--label", self.label,
            "--name", self.marker + "-" + role + "-proxy",
            "--mount", f"type=volume,source={self.volume},target=/edge,readonly",
            "--entrypoint", "nginx", NGINX, "-c", f"/edge/{role}.conf", "-g", "daemon off;",
        ).stdout.decode().strip()
        self.proxies.append(identifier)
        docker("exec", identifier, "nginx", "-t", "-c", f"/edge/{role}.conf")
        return identifier

    def traffic(self, path, *, method="GET", body=None):
        return self.call("request", {"edge": self.edge_url, "key": self.key, "method": method, "path": path, "body": body})

    def prepare(self, source, standby, key, checkpoint, prepared, authority):
        self.key = key
        pinned = self.call("configure", {
            "primary": self.address(source), "standby": self.address(standby), "checkpoint": checkpoint,
            "standby_id": prepared["standby"], "readiness": prepared["readiness_pub"], "authority": authority,
        })
        assert pinned["state"] == "primary"
        self.primary_proxy = self.launch_proxy("primary", f"container:{source}")
        self.launch_proxy("standby", f"container:{standby}")
        self.edge = self.launch_proxy("edge", self.network)
        self.edge_url = f"http://{self.address(self.edge)}:{WORKER_PORT}"
        primary = self.traffic("/auth/me")
        assert primary["status"] == 200 and primary["body"]["subject"] == COLLECTOR
        assert self.traffic(ingress.READY_PATH + "0" * 64)["status"] == 404
        assert self.call("public-probe")["without_mtls_rejected"]

    def reload_edge(self):
        for flag in ("-t", "-s"):
            operation = [flag, "reload"] if flag == "-s" else [flag]
            docker("exec", self.edge, "nginx", *operation, "-c", "/edge/edge.conf")

    def pause(self):
        assert self.call("pause")["state"] == "paused"
        self.reload_edge()
        until(lambda: self.traffic("/auth/me")["status"] == 503)

    def fence_source_proxy(self):
        docker("rm", "-f", self.primary_proxy)
        self.proxies.remove(self.primary_proxy)

    def verify_unready(self, grant):
        assert self.call("unready", grant)["state"] == "paused"
        assert self.traffic("/auth/me")["status"] == 503

    def promote(self, grant, event, new_event):
        route = self.call("promote")
        assert route["receipt_sha256"] == grant["pin"]
        self.reload_edge()
        until(lambda: self.traffic("/auth/me")["status"] == 200)
        delivery = self.traffic("/analysis/login-delivery", method="POST", body=event)
        assert delivery["status"] == 200 and delivery["body"]["duplicate"]
        first = self.traffic("/analysis/login-delivery", method="POST", body=new_event)
        second = self.traffic("/analysis/login-delivery", method="POST", body=new_event)
        assert first["status"] == second["status"] == 200
        assert not first["body"]["duplicate"] and second["body"]["duplicate"]
        assert first["body"]["result"]["analysis_id"] == second["body"]["result"]["analysis_id"]
        assert self.traffic(ingress.READY_PATH + "0" * 64)["status"] == 404
        return {
            "primary_before_outage_http_status": 200, "paused_http_status": 503,
            "unready_standby_kept_maintenance_route": True, "tampered_fence_receipt_refused": True,
            "standby_behind_same_ingress_http_status": 200, "readiness_path_hidden_behind_ingress": True,
            "upstream_mtls_name_and_client_certificate_verified": True, "duplicate_delivery_reused": True,
            "backend_without_client_certificate_rejected": True, "new_login_delivery_recorded_once": True,
            "route_bound_to_fence_receipt_sha256": grant["pin"], "final_route": route["state"],
        }

    def stop(self):
        for identifier in reversed(self.proxies):
            docker("rm", "-f", identifier, check=False)
        if self.controller:
            docker("rm", "-f", self.controller, check=False)

    def finish(self):
        if self.volume_created:
            docker("volume", "rm", self.volume)
        if self.network_created:
            docker("network", "rm", self.network)


if __name__ == "__main__":
    actions = {
        "configure": configure, "pause": lambda: (ingress.pause(CONTROL), ingress.status(CONTROL))[1],
        "unready": unready, "promote": promote, "request": request, "public-probe": public_probe,
    }
    require(len(sys.argv) == 2 and sys.argv[1] in actions, "login_ingress_fixture_command")
    payload = sys.stdin.buffer.read()
    action = actions[sys.argv[1]]
    print(json.dumps(action(json.loads(payload)) if payload else action()))
