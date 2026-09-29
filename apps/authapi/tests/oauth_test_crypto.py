"""Runtime RSA keys, RS256 JWT signing, and JWKS over HTTPS for OAuth e2e tests."""

from __future__ import annotations

import datetime
import json
import socket
import ssl
import tempfile
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import base64

import jwt


@dataclass(frozen=True)
class OAuthTestSigningKey:
    kid: str
    private_pem: bytes
    public_jwk: dict[str, Any]
    cert_pem: bytes

    def sign_rs256(self, payload: dict[str, Any]) -> str:
        return jwt.encode(
            payload,
            self.private_pem,
            algorithm='RS256',
            headers={'kid': self.kid, 'typ': 'JWT'},
        )

    def google_certs_document(self) -> dict[str, str]:
        return {self.kid: self.cert_pem.decode('ascii')}

    def jwks_document(self) -> dict[str, Any]:
        return {'keys': [dict(self.public_jwk)]}


@dataclass(frozen=True)
class AppleTestSigningKey:
    kid: str
    private_pem: bytes
    public_jwk: dict[str, Any]

    def sign_es256(self, payload: dict[str, Any]) -> str:
        return jwt.encode(
            payload,
            self.private_pem,
            algorithm='ES256',
            headers={'kid': self.kid, 'typ': 'JWT'},
        )

    def jwks_document(self) -> dict[str, Any]:
        return {'keys': [dict(self.public_jwk)]}


def generate_apple_test_signing_key(*, kid: str = 'apple-e2e-kid') -> AppleTestSigningKey:
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public = key.public_key().public_numbers()
    public_jwk = {
        'kty': 'EC',
        'kid': kid,
        'use': 'sig',
        'alg': 'ES256',
        'crv': 'P-256',
        'x': _b64url_int(public.x),
        'y': _b64url_int(public.y),
    }
    return AppleTestSigningKey(kid=kid, private_pem=private_pem, public_jwk=public_jwk)


def _b64url_int(value: int) -> str:
    width = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(width, 'big')).decode('ascii').rstrip('=')


def generate_oauth_test_signing_key(*, kid: str = 'oauth-e2e-kid') -> OAuthTestSigningKey:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_numbers = key.public_key().public_numbers()

    public_jwk = {
        'kty': 'RSA',
        'kid': kid,
        'use': 'sig',
        'alg': 'RS256',
        'n': _b64url_int(public_numbers.n),
        'e': _b64url_int(public_numbers.e),
    }
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'oauth-e2e')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return OAuthTestSigningKey(
        kid=kid,
        private_pem=private_pem,
        public_jwk=public_jwk,
        cert_pem=cert.public_bytes(serialization.Encoding.PEM),
    )


def _self_signed_cert_for_hosts(hostnames: list[str]) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = sorted({h.lower() for h in hostnames if h})
    primary = names[0] if names else 'localhost'
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, primary)])
    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in names])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=1))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _pem_temp_file(pem: bytes) -> str:
    handle = tempfile.NamedTemporaryFile(delete=False, suffix='.pem')
    handle.write(pem)
    handle.flush()
    handle.close()
    return handle.name


def free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(('127.0.0.1', 0))
        return int(sock.getsockname()[1])


RouteHandler = Callable[[BaseHTTPRequestHandler], None]


@dataclass
class OAuthMockHttpsServer:
    """Threaded TLS HTTP server keyed by (host, method, path)."""

    port: int
    cert_pem: bytes
    _httpd: HTTPServer
    _thread: threading.Thread
    _routes: dict[tuple[str, str, str], RouteHandler]
    hostnames: list[str]

    @classmethod
    def start(
        cls,
        *,
        hostnames: list[str],
        routes: dict[tuple[str, str, str], RouteHandler],
    ) -> OAuthMockHttpsServer:
        port = free_local_port()
        cert_pem, key_pem = _self_signed_cert_for_hosts(hostnames)
        route_map = dict(routes)

        class Handler(BaseHTTPRequestHandler):
            def _dispatch(self) -> None:
                host = (self.headers.get('Host') or '').split(':')[0].lower()
                path = urlparse(self.path).path
                key = (host, self.command.upper(), path)
                handler = route_map.get(key)
                if handler is None:
                    best: tuple[int, RouteHandler] | None = None
                    for (h, method, route_path), candidate in route_map.items():
                        if h != host or method != self.command.upper():
                            continue
                        if path == route_path or path.startswith(route_path):
                            score = len(route_path)
                            if best is None or score > best[0]:
                                best = (score, candidate)
                    if best is not None:
                        handler = best[1]
                if handler is None:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'not found')
                    return
                handler(self)

            def do_GET(self) -> None:
                self._dispatch()

            def do_POST(self) -> None:
                self._dispatch()

            def log_message(self, format: str, *args: object) -> None:
                return

        httpd = HTTPServer(('127.0.0.1', port), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            certfile=_pem_temp_file(cert_pem),
            keyfile=_pem_temp_file(key_pem),
        )
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        return cls(
            port=port,
            cert_pem=cert_pem,
            _httpd=httpd,
            _thread=thread,
            _routes=route_map,
            hostnames=sorted({h.lower() for h in hostnames}),
        )

    def ssl_client_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(cadata=self.cert_pem.decode('ascii'))
        return ctx

    def shutdown(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


def json_response_handler(payload: dict | list) -> RouteHandler:
    body = json.dumps(payload).encode('utf-8')

    def _handler(http: BaseHTTPRequestHandler) -> None:
        http.send_response(200)
        http.send_header('Content-Type', 'application/json')
        http.send_header('Content-Length', str(len(body)))
        http.end_headers()
        http.wfile.write(body)

    return _handler
