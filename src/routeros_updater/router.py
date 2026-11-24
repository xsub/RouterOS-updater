import re
import time
import uuid
from dataclasses import asdict, dataclass
from dataclasses import field as dataclass_field
from pathlib import Path

from .config import Config, backup_key_id, secret
from .errors import IdentityError, PolicyError, TransportError
from .storage import atomic_json, digest, private_dir, timestamp
from .transport import SSH, quote
from .versions import Version, uptime_seconds


@dataclass(frozen=True)
class Snapshot:
    serial: str
    model: str
    version: str
    architecture: str
    uptime: float
    free_disk: int
    free_memory: int
    firmware: str
    upgrade_firmware: str
    auto_upgrade: bool
    channel: str
    packages: dict[str, str]
    scheduled: bool
    npk_files: list[str]
    disabled_packages: list[str] = dataclass_field(default_factory=list)
    update_mode: str = "unknown"
    update_certificate: str = "unknown"

    def identity(self) -> tuple:
        return self.serial, self.model, self.architecture


def parse_fields(output: str) -> dict:
    result = {}
    for line in output.splitlines():
        if line.startswith("ROSUP|"):
            parts = line.split("|", 2)
            if len(parts) != 3 or parts[1] in result:
                raise TransportError("Ambiguous RouterOS field response")
            result[parts[1]] = parts[2]
    return result


def field(name: str, expression: str) -> str:
    return f':put ("ROSUP|{name}|" . ({expression}))'


class Router:
    def __init__(self, config: Config):
        self.config = config
        self.ssh = SSH(config.ssh)

    def close(self):
        self.ssh.close()

    def snapshot(self) -> Snapshot:
        fields = {
            "serial": "[/system routerboard get serial-number]",
            "model": "[/system routerboard get model]",
            "version": "[/system resource get version]",
            "architecture": "[/system resource get architecture-name]",
            "uptime": "[/system resource get uptime]",
            "free_disk": "[/system resource get free-hdd-space]",
            "free_memory": "[/system resource get free-memory]",
            "firmware": "[/system routerboard get current-firmware]",
            "upgrade_firmware": "[/system routerboard get upgrade-firmware]",
            "auto_upgrade": "[/system routerboard settings get auto-upgrade]",
            "channel": "[/system package update get channel]",
            "update_mode": "[/system package update get mode]",
            "update_certificate": "[/system package update get check-certificate]",
        }
        body = "; ".join(
            f':do {{ {field(key, value)} }} on-error={{ :put "ROSUP|{key}|unknown" }}'
            if key in ("update_mode", "update_certificate")
            else field(key, value)
            for key, value in fields.items()
        )
        body += '; :local availablePackages [/system package find where available=yes]; :foreach p in=[/system package find] do={ :put ("ROSUP_PKG|" . [/system package get $p name] . "|" . [/system package get $p version] . "|" . [/system package get $p scheduled] . "|" . [/system package get $p disabled] . "|" . ([:typeof [:find $availablePackages $p]] != "nil")) }'
        body += (
            "; :foreach f in=[/file find where name~"
            + quote(r"\.npk$")
            + '] do={ :put ("ROSUP_NPK|" . [/file get $f name]) }'
        )
        output = self.ssh.execute(body, "snapshot")
        values = parse_fields(output)
        if set(values) != set(fields):
            raise TransportError("Router snapshot is incomplete")
        packages, files, disabled, scheduled = {}, [], [], False
        for line in output.splitlines():
            if line.startswith("ROSUP_PKG|"):
                parts = line.split("|")
                if (
                    len(parts) != 6
                    or not re.fullmatch(r"[a-z0-9-]+", parts[1])
                    or parts[1] in packages
                ):
                    raise TransportError("Invalid package inventory")
                scheduled |= bool(parts[3])
                if parts[5] not in ("true", "false", "yes", "no"):
                    raise TransportError("Invalid package availability state")
                if parts[5] in ("true", "yes"):
                    continue
                packages[parts[1]] = parts[2]
                if parts[4] not in ("true", "false", "yes", "no"):
                    raise TransportError("Invalid package enabled/disabled state")
                if parts[4] in ("true", "yes"):
                    disabled.append(parts[1])
            if line.startswith("ROSUP_NPK|"):
                files.append(line.split("|", 1)[1])
        try:
            snapshot = Snapshot(
                serial=values["serial"],
                model=values["model"],
                version=values["version"].split()[0],
                architecture=values["architecture"],
                uptime=uptime_seconds(values["uptime"]),
                free_disk=int(values["free_disk"]),
                free_memory=int(values["free_memory"]),
                firmware=values["firmware"],
                upgrade_firmware=values["upgrade_firmware"],
                auto_upgrade=values["auto_upgrade"] in ("true", "yes"),
                channel=values["channel"],
                packages=packages,
                scheduled=scheduled,
                npk_files=files,
                disabled_packages=disabled,
                update_mode=values["update_mode"],
                update_certificate=values["update_certificate"],
            )
        except (ValueError, KeyError):
            raise TransportError("Invalid router resource values") from None
        if (
            values["auto_upgrade"] not in ("true", "false", "yes", "no")
            or not packages
            or not snapshot.serial
        ):
            raise TransportError("Unsupported RouterBOARD snapshot")
        self.verify_identity(snapshot)
        return snapshot

    def verify_identity(self, snapshot: Snapshot):
        expected = self.config.ssh
        if expected.expected_serial and snapshot.serial != expected.expected_serial:
            raise IdentityError("Router serial number does not match configuration")
        if expected.expected_model and snapshot.model != expected.expected_model:
            raise IdentityError("Router model does not match configuration")

    def update_status(self) -> dict:
        output = self.ssh.execute(
            "; ".join(
                field(name, f"[/system package update get {name}]")
                for name in ["installed-version", "latest-version", "status"]
            ),
            "update-status",
        )
        result = parse_fields(output)
        if set(result) != {"installed-version", "latest-version", "status"}:
            raise TransportError("Incomplete update status")
        return result

    def latest(self) -> str:
        self.ssh.execute(
            self.download_guard() + "; /system package update check-for-updates once",
            "check-updates",
        )
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            status = self.update_status()
            if status["status"] in ("New version is available", "System is already up to date"):
                Version.parse(status["latest-version"])
                return status["latest-version"]
            if "error" in status["status"].lower():
                raise TransportError("Router could not check update server")
            time.sleep(self.config.policy.poll_seconds)
        raise TransportError("Update check did not reach a known final status")

    def download(self):
        self.ssh.execute(
            self.download_guard() + "; /system package update download", "download", timeout=120
        )

    @staticmethod
    def download_guard() -> str:
        return ':if (([/system package update get mode] != "https") || ([/system package update get check-certificate] != "yes")) do={ :error "verified HTTPS required" }'

    def reboot(self):
        try:
            self.ssh.execute("/system reboot", "reboot", timeout=20)
        finally:
            self.close()

    def flash(self):
        message = quote("Firmware upgraded successfully, please reboot for changes to take effect!")
        # Require a NEW success entry; an old log entry must not acknowledge a new flash.
        body = f':local prior [/log find where message={message}]; /system routerboard upgrade; :local confirmed false; :local attempts 0; :while ((!$confirmed) && ($attempts < 30)) do={{ :foreach entry in=[/log find where message={message}] do={{ :if ([:typeof [:find $prior $entry]] = "nil") do={{ :set confirmed true }} }}; :set attempts ($attempts + 1); :if (!$confirmed) do={{ :delay 1s }} }}; :if (!$confirmed) do={{ :error "flash not confirmed" }}'
        self.ssh.execute(body, "routerboot-flash", timeout=150)

    def backup(self, destination: Path, snapshot: Snapshot) -> dict:
        password = secret(Path(self.config.backup_password_file))
        if len(password) < 24:
            raise PolicyError("Backup encryption password must contain at least 24 characters")
        private_dir(destination)
        prefix = "rosup-" + str(uuid.uuid4())
        # Source/scripts/comments in an export may contain administrator-entered secrets.
        self.ssh.execute(
            f"/system backup save name={quote(prefix)} password={quote(password)} dont-encrypt=no encryption=aes-sha256; /export compact file={quote(prefix)}",
            "encrypted-backup",
            timeout=120,
        )
        manifest = {
            "at": timestamp(),
            "router": asdict(snapshot),
            "backup_key_id": backup_key_id(password),
            "remote_prefix": prefix,
            "files": {},
        }
        for suffix in ("backup", "rsc"):
            filename = prefix + "." + suffix
            target = destination / ("router." + suffix)
            self.ssh.fetch(filename, target)
            manifest["files"][target.name] = {
                "bytes": target.stat().st_size,
                "sha256": digest(target),
            }
        atomic_json(destination / "manifest.json", manifest)
        # Both copies are durable locally before deleting remote originals.
        self.cleanup_backup(manifest)
        return manifest

    def cleanup_backup(self, manifest: dict):
        prefix = manifest.get("remote_prefix", "")
        if not re.fullmatch(r"rosup-[a-f0-9-]{36}", prefix):
            raise PolicyError("Invalid remote backup cleanup identifier")
        commands = []
        for suffix in (".backup", ".rsc"):
            selector = f"[/file find where name={quote(prefix + suffix)}]"
            commands.append(f":if ([:len {selector}] > 0) do={{ /file remove {selector} }}")
        self.ssh.execute("; ".join(commands), "backup-cleanup")
