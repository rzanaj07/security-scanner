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
        ("::1", ("::1", None, None)),
        ("[::1]:8080", ("::1", None, 8080)),
        ("https://[2001:db8::1]/x", ("2001:db8::1", "https", None)),
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


def test_netloc_brackets_ipv6():
    from secscan.target import Target

    assert Target(host="::1", address="::1").netloc(8080) == "[::1]:8080"
    assert Target(host="example.com", address="1.2.3.4").netloc() == "example.com"
    assert Target(host="10.0.0.1", address="10.0.0.1").host_is_ip
    assert not Target(host="example.com", address="1.2.3.4").host_is_ip


def test_resolve_prefers_ipv4(monkeypatch):
    def fake(host, port, family, socktype):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    assert resolve_target("dual.example").address == "192.0.2.1"
