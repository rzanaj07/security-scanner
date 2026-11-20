from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from secscan.checks.base import ScanConfig, ScanContext
from secscan.target import Target


class _Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.1"
    sys_version = ""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def http_server() -> Iterator[int]:
    """A local HTTP server; yields its port."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


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


def make_ctx(port: int | None = None, scheme: str | None = None, **config: object) -> ScanContext:
    target = Target(host="127.0.0.1", address="127.0.0.1", scheme=scheme, port=port)
    return ScanContext(target=target, config=ScanConfig(**config))  # type: ignore[arg-type]
