"""Parsing and resolving the scan target (hostname, IP address or URL)."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class TargetError(ValueError):
    """The target is malformed or cannot be resolved."""


@dataclass(frozen=True)
class Target:
    host: str
    address: str
    scheme: str | None = None  # "http"/"https" when the user passed a URL
    port: int | None = None  # explicit port from the user's input, if any


def parse_target(raw: str) -> tuple[str, str | None, int | None]:
    """Split user input into (host, scheme, port) without touching the network."""
    raw = raw.strip()
    if not raw:
        raise TargetError("target is empty")

    has_scheme = "://" in raw
    parts = urlsplit(raw if has_scheme else "//" + raw)
    scheme = parts.scheme.lower() if has_scheme else None
    if scheme is not None and scheme not in ("http", "https"):
        raise TargetError(f"unsupported scheme {scheme!r} (use http or https)")

    host = parts.hostname
    if not host:
        raise TargetError(f"no hostname in {raw!r}")

    try:
        port = parts.port
    except ValueError as e:
        raise TargetError(f"invalid port in {raw!r}") from e

    return host, scheme, port


def resolve_target(raw: str) -> Target:
    """Parse user input and resolve it to an IPv4 address once, up front."""
    host, scheme, port = parse_target(raw)
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise TargetError(f"cannot resolve {host!r}: {e.strerror}") from e
    if not infos:
        raise TargetError(f"cannot resolve {host!r}")
    address = str(infos[0][4][0])
    return Target(host=host, address=address, scheme=scheme, port=port)
