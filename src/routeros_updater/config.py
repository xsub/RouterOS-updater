import hashlib
import ipaddress
import json
import os
import re
import stat
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import PolicyError


def credential_path(path: Path | str) -> Path:
    value = str(path)
    if value.startswith("credential:"):
        name = value.removeprefix("credential:")
        root = os.environ.get("CREDENTIALS_DIRECTORY", "")
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name) or not Path(root).is_absolute():
            raise PolicyError("systemd credential directory is unavailable")
        return Path(root) / name
    return Path(path)


def private_file(path: Path, *, secret: bool = True) -> None:
    """Reject symlinks, non-regular files and writable credentials/configuration."""
    path = credential_path(path)
    try:
        info = path.lstat()
    except OSError:
        raise PolicyError(f"Missing or unreadable protected file: {path.name}") from None
    forbidden = 0o077 if secret else 0o022
    if not stat.S_ISREG(info.st_mode) or info.st_mode & forbidden:
        raise PolicyError(f"Unsafe file permissions or type: {path.name}")
    if info.st_uid not in (0, os.getuid()):
        raise PolicyError(f"Untrusted file owner: {path.name}")


def backup_key_id(value: str) -> str:
    return hashlib.sha256(b"routeros-updater-backup-v1\0" + value.encode()).hexdigest()


def secret(path: Path) -> str:
    path = credential_path(path)
    private_file(path)
    value = path.read_text().rstrip("\r\n")
    if not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise PolicyError("Invalid credential content")
    return value


@dataclass(frozen=True)
class SSHConfig:
    host: str
    user: str
    key_file: str
    known_hosts: str
    expected_serial: str = ""
    expected_model: str = ""
    port: int = 22
    timeout: int = 15


@dataclass(frozen=True)
class Policy:
    channel: str = "long-term"
    auto_apply: bool = False
    allow_minor: bool = True
    minimum_observation_hours: int = 72
    min_free_bytes: int = 32 * 1024 * 1024
    min_free_memory: int = 32 * 1024 * 1024
    min_uptime_seconds: int = 300
    download_timeout: int = 900
    reboot_timeout: int = 600
    health_timeout: int = 180
    poll_seconds: int = 5
    plan_ttl_seconds: int = 3600
    window_timezone: str = "UTC"
    window_days: list[int] = field(default_factory=lambda: [6])
    window_start: str = "03:00"
    window_end: str = "05:00"
    allowed_versions: list[str] = field(default_factory=list)
    denied_versions: list[str] = field(default_factory=list)
    backup_keep: int = 20

    def in_window(self, now: datetime) -> bool:
        local = now.astimezone(ZoneInfo(self.window_timezone))
        start, end = time.fromisoformat(self.window_start), time.fromisoformat(self.window_end)
        at = local.time().replace(tzinfo=None)
        if start < end:
            return local.weekday() in self.window_days and start <= at < end
        # For an overnight window, the part after midnight belongs to the previous day.
        day = local.weekday() if at >= start else (local.weekday() - 1) % 7
        return day in self.window_days and (at >= start or at < end)

    def remaining(self, now: datetime) -> float:
        if not self.in_window(now):
            return 0
        local = now.astimezone(ZoneInfo(self.window_timezone))
        end = time.fromisoformat(self.window_end)
        end_date = local.date()
        if time.fromisoformat(self.window_start) > end and local.time().replace(
            tzinfo=None
        ) >= time.fromisoformat(self.window_start):
            end_date += timedelta(days=1)
        deadline = datetime.combine(end_date, end, tzinfo=local.tzinfo)
        return max(0, (deadline.astimezone(UTC) - now.astimezone(UTC)).total_seconds())


@dataclass(frozen=True)
class HealthCheck:
    name: str
    kind: str
    host: str = ""
    port: int = 0
    url: str = ""
    dns_name: str = ""
    expected_ip: str = ""
    expected_status: int = 200
    ca_file: str = ""
    timeout: int = 5


@dataclass(frozen=True)
class Config:
    name: str
    ssh: SSHConfig
    data_dir: str
    backup_password_file: str
    policy: Policy = field(default_factory=Policy)
    checks: list[HealthCheck] = field(default_factory=list)
    webhook_url: str = ""
    webhook_token_file: str = ""

    def fingerprint(self) -> str:
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()


def _construct(cls, values):
    try:
        return cls(**values)
    except (TypeError, ValueError):
        raise PolicyError(f"Invalid or unknown {cls.__name__} configuration field") from None


def load(path: Path) -> Config:
    private_file(path, secret=False)
    try:
        raw = tomllib.loads(path.read_text())
        raw["ssh"] = _construct(SSHConfig, raw["ssh"])
        raw["policy"] = _construct(Policy, raw.get("policy", {}))
        raw["checks"] = [_construct(HealthCheck, check) for check in raw.get("checks", [])]
        config = _construct(Config, raw)
        validate(config)
        return config
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        raise PolicyError("Invalid TOML configuration") from None


def validate(config: Config) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}", config.name):
        raise PolicyError("Invalid router name")
    try:
        address = ipaddress.ip_address(config.ssh.host)
        allowed = (
            address in ipaddress.ip_network("10.0.0.0/8")
            or address in ipaddress.ip_network("172.16.0.0/12")
            or address in ipaddress.ip_network("192.168.0.0/16")
            or address in ipaddress.ip_network("fc00::/7")
        )
    except ValueError:
        allowed = False
    if not allowed:
        raise PolicyError("SSH requires a literal RFC1918 or IPv6 ULA management address")
    if (
        not config.ssh.user
        or not 1 <= config.ssh.port <= 65535
        or not 1 <= config.ssh.timeout <= 120
    ):
        raise PolicyError("Invalid SSH settings")
    for value in [
        config.ssh.known_hosts,
        config.data_dir,
    ]:
        if not Path(value).is_absolute():
            raise PolicyError("Configuration paths must be absolute")
    for value in [config.ssh.key_file, config.backup_password_file, config.webhook_token_file]:
        if (
            value
            and not Path(value).is_absolute()
            and not re.fullmatch(r"credential:[a-zA-Z0-9_-]+", value)
        ):
            raise PolicyError("Credentials require an absolute path or credential:name")
    policy = config.policy
    if policy.channel not in ("stable", "long-term"):
        raise PolicyError("Only stable and long-term channels are supported")
    if type(policy.auto_apply) is not bool or type(policy.allow_minor) is not bool:
        raise PolicyError("Boolean policy settings must be true or false")
    for name in (
        "minimum_observation_hours",
        "min_free_bytes",
        "min_free_memory",
        "min_uptime_seconds",
        "download_timeout",
        "reboot_timeout",
        "health_timeout",
        "poll_seconds",
        "plan_ttl_seconds",
        "backup_keep",
    ):
        value = getattr(policy, name)
        if type(value) is not int or value < (0 if name == "minimum_observation_hours" else 1):
            raise PolicyError(f"Invalid policy setting: {name}")
    if policy.reboot_timeout > 3600 or policy.poll_seconds > 60:
        raise PolicyError("Reboot or polling deadline exceeds safe limit")
    ZoneInfo(policy.window_timezone)
    start, end = time.fromisoformat(policy.window_start), time.fromisoformat(policy.window_end)
    if (
        start == end
        or start.tzinfo
        or end.tzinfo
        or not policy.window_days
        or any(type(day) is not int or day not in range(7) for day in policy.window_days)
    ):
        raise PolicyError("Invalid maintenance window")
    for collection in [policy.allowed_versions, policy.denied_versions]:
        if not isinstance(collection, list) or any(
            not isinstance(item, str) for item in collection
        ):
            raise PolicyError("Version policy must be a list of strings")
    names = set()
    for check in config.checks:
        if check.kind not in ("tcp", "https", "dns") or not check.name or check.name in names:
            raise PolicyError("Invalid or duplicate health check")
        names.add(check.name)
        if not 1 <= check.timeout <= 30:
            raise PolicyError("Invalid health check timeout")
        if check.kind == "tcp" and (not check.host or not 1 <= check.port <= 65535):
            raise PolicyError("TCP health check requires host and port")
        if check.kind == "dns":
            ipaddress.ip_address(check.host)
            if ipaddress.ip_address(check.expected_ip).version != 4 or not check.dns_name:
                raise PolicyError("DNS check requires name and expected IPv4 address")
        if check.kind == "https":
            from urllib.parse import urlsplit

            url = urlsplit(check.url)
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise PolicyError("HTTPS check requires a URL without embedded credentials")
    if config.webhook_url:
        from urllib.parse import urlsplit

        url = urlsplit(config.webhook_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise PolicyError("Webhook must use verified HTTPS without embedded credentials")
