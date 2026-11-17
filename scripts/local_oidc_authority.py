"""Ephemeral loopback OIDC signing/JWKS fixture; never a production IdP.

This serves real public JWKS over loopback HTTP so the production JWT verification
path can be tested without replacing the principal or the JWKS fetch operation.
Private keys and bearer tokens remain in memory. MFA claims are not fabricated.
"""

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


class LocalOIDCAuthority:
    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.key_id = "ephemeral-local-oidc-key"
        self.audience = "local-verified-session-analysis"
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self._key.public_key(), as_dict=True)
        jwk.update(kid=self.key_id, alg="RS256", use="sig")
        document = json.dumps({"keys": [jwk]}).encode()
        self.fetches = 0
        authority = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != "/.well-known/jwks.json":
                    self.send_error(404)
                    return
                authority.fetches += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(document)))
                self.end_headers()
                self.wfile.write(document)

            def log_message(self, *_):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.issuer = f"http://127.0.0.1:{self._server.server_port}"
        self.jwks_url = self.issuer + "/.well-known/jwks.json"
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def issue(self, **overrides):
        now = datetime.now(UTC)
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "local-operator",
            "tenant_id": "local-lab",
            "roles": ["analyst"],
            "iat": now,
            "exp": now + timedelta(minutes=5),
            **overrides,
        }
        return jwt.encode(claims, self._key, algorithm="RS256", headers={"kid": self.key_id})
