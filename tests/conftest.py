from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from secscan.checks.base import ScanConfig, ScanContext
from secscan.target import Target

# ---------------------------------------------------------------- HTTP test server

DEFAULT_HEADERS = [("X-Content-Type-Options", "nosniff")]


class _Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.1"
    sys_version = ""

    def do_GET(self) -> None:
        cfg = self.server.config  # type: ignore[attr-defined]
        if cfg.get("redirect"):
            self.send_response(301)
            self.send_header("Location", cfg["redirect"])
            self.end_headers()
            return
        self.send_response(200)
        for name, value in cfg.get("headers", DEFAULT_HEADERS):
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


@contextmanager
def serve_http(**config: object) -> Iterator[int]:
    """A local HTTP server; yields its port. config: headers=[(name, value)], redirect=url."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.config = config  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def http_server() -> Iterator[int]:
    with serve_http() as port:
        yield port


@pytest.fixture
def http_server_factory() -> Callable[..., object]:
    return serve_http


# ---------------------------------------------------------------- TCP ports


@pytest.fixture
def listening_port() -> Iterator[int]:
    """A local TCP port that accepts connections."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        yield sock.getsockname()[1]


@pytest.fixture
def closed_port() -> int:
    """A local TCP port that is (almost certainly) closed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ---------------------------------------------------------------- TLS test server


def make_cert(
    directory: Path,
    *,
    common_name: str = "localhost",
    key_size: int = 2048,
    days_valid: int = 365,
    expired: bool = False,
    hash_alg: hashes.HashAlgorithm | None = None,
) -> tuple[Path, Path]:
    """Write a self-signed certificate and key; returns (certfile, keyfile)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=400 if expired else 1)
    end = now - dt.timedelta(days=5) if expired else now + dt.timedelta(days=days_valid)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hash_alg or hashes.SHA256())
    )
    certfile, keyfile = directory / f"{common_name}-{key_size}.crt", directory / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return certfile, keyfile


@contextmanager
def serve_tls(
    certfile: Path,
    keyfile: Path,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    legacy: bool = False,
) -> Iterator[int]:
    """A local TLS server that completes handshakes and closes; yields its port.
    legacy=True allows every cipher, weak keys and old protocols (a badly configured server)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if legacy:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    if minimum:
        ctx.minimum_version = minimum
    if maximum:
        ctx.maximum_version = maximum
    ctx.load_cert_chain(certfile, keyfile)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(32)
    listener.settimeout(0.2)
    stop = threading.Event()

    def handle(conn: socket.socket) -> None:
        conn.settimeout(3)
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError):
            pass
        finally:
            conn.close()

    def loop() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(2)
        listener.close()


# ---------------------------------------------------------------- helpers


def make_ctx(
    port: int | None = None, scheme: str | None = None, host: str = "127.0.0.1", **config: object
) -> ScanContext:
    target = Target(host=host, address="127.0.0.1", scheme=scheme, port=port)
    return ScanContext(target=target, config=ScanConfig(**config))  # type: ignore[arg-type]
