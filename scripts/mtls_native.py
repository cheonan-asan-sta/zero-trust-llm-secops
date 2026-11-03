"""Native, fail-closed mTLS listeners for local ASGI and stdlib services.

No HTTP sidecar backend: Uvicorn itself speaks TLS and supplies the real TLS peer
to its per-connection ASGI guard. No forwarded identity header is trusted.
"""

import argparse
import hashlib
import re
import ssl
import threading
from collections import Counter
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from scripts import mtls_transport as tls


def identity(path, der, method, target):
    valid_client(der)
    peer = tls.server_policy(path)["peers"].get(hashlib.sha256(der).hexdigest()) if der else None
    if peer is None or not any(method == verb and re.fullmatch(pattern, target)
                               for verb, pattern in tls.ROUTES[peer]):
        raise ValueError("service_scope_denied")
    return peer


def valid_client(der):
    certificate = x509.load_der_x509_certificate(der)
    now = datetime.now(UTC)
    if hasattr(certificate, "not_valid_before_utc"):
        start, end = certificate.not_valid_before_utc, certificate.not_valid_after_utc
    else:  # Preserve the project's existing cryptography dependency compatibility.
        start, end = certificate.not_valid_before.replace(tzinfo=UTC), certificate.not_valid_after.replace(tzinfo=UTC)
    try:
        purposes = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        raise ValueError("client_purpose_missing") from None
    if (not start <= now < end
            or ExtendedKeyUsageOID.CLIENT_AUTH not in purposes):
        raise ValueError("client_certificate_expired_or_wrong_purpose")


def forwarded_client(headers, path):
    values = headers.get_all("X-Verified-Client-Cert", [])
    if len(values) != 1 or len(values[0]) > 16384:
        raise ValueError("frontend_identity_missing")
    der = ssl.PEM_cert_to_DER_cert(unquote(values[0]))
    valid_client(der)
    if hashlib.sha256(der).hexdigest() not in tls.pins(tls.profile(path)["forwarded_peers"]):
        raise ValueError("frontend_identity_revoked")


def guarded_handler(handler, path):
    class Guarded(handler):
        def parse_request(self):
            if not super().parse_request():
                return False
            try:
                self.service_identity = identity(path, self.connection.getpeercert(binary_form=True),
                                                 self.command, self.requestline.split()[1])
            except (OSError, ValueError, TypeError, KeyError):
                self.send_response(403)
                self.send_header("X-Secops-Transport-Denied", "1")
                self.send_header("Content-Length", "0")
                self.end_headers()
                self.close_connection = True
                return False
            return True
    return Guarded


class NativeServer(tls.Gateway):
    def __init__(self, address, path, handler):
        self.path, self.counts, self.count_lock = path, Counter(), threading.Lock()
        tls.server_context(path)
        ThreadingHTTPServer.__init__(self, address, guarded_handler(handler, path))


def reloadable_context(path):
    context = tls.server_context(path)
    def refresh(connection, server_name, initial_context):
        try:
            connection.context = tls.server_context(path)
        except (OSError, ValueError, KeyError, TypeError):
            return ssl.ALERT_DESCRIPTION_ACCESS_DENIED
        return None
    context.sni_callback = refresh
    return context


async def guard_asgi(app, path, der, scope, receive, send):
    try:
        target = scope["raw_path"].decode("ascii")
        if scope.get("query_string"):
            target += "?" + scope["query_string"].decode("ascii")
        identity(path, der, scope["method"], target)
    except (OSError, ValueError, KeyError, TypeError):
        await send({"type": "http.response.start", "status": 403, "headers": [(b"content-length", b"0"), (b"x-secops-transport-denied", b"1")]})
        await send({"type": "http.response.body", "body": b""})
        return
    await app(scope, receive, send)


def run_api(path, port):
    import uvicorn
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class CertificateProtocol(H11Protocol):
        def connection_made(self, transport):
            super().connection_made(transport)
            application = self.app
            peer = transport.get_extra_info("ssl_object")
            der = peer.getpeercert(binary_form=True) if peer else None
            async def authenticated(scope, receive, send):
                await guard_asgi(application, path, der, scope, receive, send)
            self.app = authenticated

    data = tls.server_policy(path)
    config = uvicorn.Config("app.main:app", host="0.0.0.0", port=port, http=CertificateProtocol,
        ws="none", proxy_headers=False, access_log=False, ssl_certfile=tls.asset(path, data["cert"]),
        ssl_keyfile=tls.asset(path, data["key"]))
    config.load()
    config.ssl = reloadable_context(path)
    uvicorn.Server(config).run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["api", "receiver"])
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if args.mode == "api":
        run_api(args.profile, args.port)
    else:
        from scripts.observability_lab import receiver
        NativeServer(("0.0.0.0", args.port), args.profile,
                     receiver(args.token_file.read_text().strip())).serve_forever()


if __name__ == "__main__":
    main()
