import socket

import pytest

from secscan.target import TargetError, parse_target, resolve_target


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", ("example.com", None, None)),
        ("  Example.COM  ", ("example.com", None, None)),
        ("192.168.1.10", ("192.168.1.10", None, None)),
        ("example.com:8080", ("example.com", None, 8080)),
        ("https://example.com/some/path", ("example.com", "https", None)),
        ("HTTP://example.com:8000", ("example.com", "http", 8000)),
    ],
)
def test_parse_target(raw, expected):
    assert parse_target(raw) == expected


@pytest.mark.parametrize("raw", ["", "   ", "ftp://example.com", "https://", "example.com:99999"])
def test_parse_target_rejects_bad_input(raw):
    with pytest.raises(TargetError):
        parse_target(raw)


def test_resolve_target_localhost():
    target = resolve_target("127.0.0.1")
    assert target.address == "127.0.0.1"


def test_resolve_target_unresolvable(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(TargetError, match="cannot resolve"):
        resolve_target("does-not-exist.invalid")
