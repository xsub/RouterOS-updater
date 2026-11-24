import socket
import struct

from routeros_updater.config import HealthCheck
from routeros_updater.health import check_one, dns_check


def test_tcp_failure_is_reported_as_health_failure(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise OSError("unreachable")

    monkeypatch.setattr(socket, "create_connection", unavailable)
    assert check_one(HealthCheck(name="office", kind="tcp", host="10.42.0.10", port=445)) == (
        "office",
        False,
    )


class DNS:
    def __init__(self, *, wrong_id=False, truncated=False, address="10.42.0.10"):
        self.query = None
        self.wrong_id, self.truncated, self.address = wrong_id, truncated, address

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def settimeout(self, _value):
        pass

    def connect(self, _endpoint):
        pass

    def send(self, query):
        self.query = query

    def recv(self, _size):
        identity = struct.unpack_from("!H", self.query)[0]
        flags = 0x8380 if self.truncated else 0x8180
        return (
            struct.pack("!6H", identity ^ int(self.wrong_id), flags, 1, 1, 0, 0)
            + self.query[12:]
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 30, 4)
            + socket.inet_aton(self.address)
        )


def test_dns_checks_transaction_id_address_and_truncation(monkeypatch):
    check = HealthCheck(
        name="dns",
        kind="dns",
        host="10.42.0.53",
        dns_name="service.example.test",
        expected_ip="10.42.0.10",
    )
    for simulated, expected in [
        (DNS(), True),
        (DNS(wrong_id=True), False),
        (DNS(truncated=True), False),
        (DNS(address="10.42.0.99"), False),
    ]:
        monkeypatch.setattr(socket, "socket", lambda *_args, result=simulated, **_kwargs: result)
        assert dns_check(check) == expected


def test_https_always_verifies_tls_and_does_not_follow_redirect(monkeypatch):
    from routeros_updater import health

    calls = {}

    def tls(**kwargs):
        calls["ca"] = kwargs
        return "verified-context"

    class HTTPS:
        def __init__(self, *_args, **kwargs):
            calls.update(kwargs)

        def request(self, *_args, **_kwargs):
            calls["requests"] = calls.get("requests", 0) + 1

        def getresponse(self):
            return type("Response", (), {"status": 302})()

        def close(self):
            pass

    monkeypatch.setattr(health.ssl, "create_default_context", tls)
    monkeypatch.setattr(health.http.client, "HTTPSConnection", HTTPS)
    assert check_one(HealthCheck(name="web", kind="https", url="https://example.org/")) == (
        "web",
        False,
    )
    assert calls["context"] == "verified-context"
    assert calls["requests"] == 1
