import http.client
import secrets
import socket
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from .config import HealthCheck


def _skip_name(packet: bytes, offset: int) -> int:
    for _ in range(128):
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length & 0xC0 or length > 63:
            raise ValueError("Invalid DNS name")
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("DNS name too long")


def dns_check(check: HealthCheck) -> bool:
    name = check.dns_name.rstrip(".").encode("idna")
    labels = name.split(b".")
    if any(not label or len(label) > 63 for label in labels) or len(name) > 253:
        return False
    identity = secrets.randbits(16)
    query = struct.pack("!6H", identity, 0x0100, 1, 0, 0, 0)
    query += (
        b"".join(bytes([len(label)]) + label for label in labels) + b"\0" + struct.pack("!HH", 1, 1)
    )
    family = socket.AF_INET6 if ":" in check.host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(check.timeout)
        client.connect((check.host, check.port or 53))
        client.send(query)
        packet = client.recv(65535)
    response_id, flags, questions, answers, _, _ = struct.unpack_from("!6H", packet)
    if response_id != identity or flags & 0x8000 == 0 or flags & 0x020F or questions != 1:
        return False
    offset = _skip_name(packet, 12) + 4
    for _ in range(answers):
        offset = _skip_name(packet, offset)
        kind, klass, _, length = struct.unpack_from("!HHIH", packet, offset)
        offset += 10
        if (
            kind == 1
            and klass == 1
            and length == 4
            and socket.inet_ntoa(packet[offset : offset + 4]) == check.expected_ip
        ):
            return True
        offset += length
    return False


def check_one(check: HealthCheck) -> tuple[str, bool]:
    try:
        if check.kind == "tcp":
            with socket.create_connection((check.host, check.port), check.timeout):
                return check.name, True
        if check.kind == "dns":
            return check.name, dns_check(check)
        url = urlsplit(check.url)
        context = ssl.create_default_context(cafile=check.ca_file or None)
        connection = http.client.HTTPSConnection(
            url.hostname, url.port or 443, timeout=check.timeout, context=context
        )
        try:
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            connection.request("GET", path, headers={"User-Agent": "RouterOS-updater/0.1"})
            response = connection.getresponse()
            # No redirect following and no unbounded response body download.
            return check.name, response.status == check.expected_status
        finally:
            connection.close()
    except (OSError, ValueError, IndexError, struct.error, http.client.HTTPException, UnicodeError):
        return check.name, False


def check_all(checks: list[HealthCheck]) -> dict[str, bool]:
    if not checks:
        return {}
    with ThreadPoolExecutor(max_workers=min(8, len(checks))) as pool:
        return dict(pool.map(check_one, checks))
