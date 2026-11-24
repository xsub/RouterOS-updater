import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from routeros_updater.config import Config, HealthCheck, Policy, SSHConfig, backup_key_id
from routeros_updater.engine import Engine
from routeros_updater.errors import TransportError
from routeros_updater.router import Snapshot
from routeros_updater.storage import Store, atomic_bytes, atomic_json, digest, private_dir


class Clock:
    def __init__(self):
        self.start = datetime(2026, 11, 29, 3, 0, tzinfo=UTC)
        self.elapsed = 0.0
        self.boot = "linux-boot-one"

    def now(self):
        return self.start + timedelta(seconds=self.elapsed)

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds

    def boot_id(self):
        return self.boot


class SimulatedRouter:
    def __init__(self, clock):
        self.clock = clock
        self.current = Snapshot(
            serial="FIXTURE-SERIAL-001",
            model="TEST-BOARD",
            version="7.24.6",
            architecture="arm",
            uptime=3600,
            free_disk=128 * 1024**2,
            free_memory=512 * 1024**2,
            firmware="7.24.6",
            upgrade_firmware="7.24.6",
            auto_upgrade=False,
            channel="long-term",
            packages={"routeros": "7.24.6", "container": "7.24.6"},
            scheduled=False,
            npk_files=[],
            update_mode="https",
            update_certificate="yes",
        )
        self.target = "7.24.7"
        self.calls = []
        self.boot_at = -3600
        self.flashed = False
        self.reboot_effect = True
        self.fail_backup = False
        self.disconnect_download = False
        self.disconnect_reboot = False
        self.crash_at = None

    def _call(self, name):
        self.calls.append(name)
        if name == self.crash_at:
            self.crash_at = None
            raise KeyboardInterrupt("Simulated controller power loss")

    def snapshot(self):
        self._call("snapshot")
        return replace(self.current, uptime=self.clock.elapsed - self.boot_at)

    def latest(self):
        self._call("check")
        return self.target

    def download(self):
        self._call("download")
        self.current = replace(
            self.current,
            npk_files=[f"{name}-{self.target}-arm.npk" for name in self.current.packages],
        )
        if self.disconnect_download:
            raise TransportError("Download command connection lost")

    def update_status(self):
        self._call("download-status")
        return {
            "status": "Downloaded, please reboot router to upgrade it",
            "latest-version": self.target,
            "installed-version": self.current.version,
        }

    def reboot(self):
        self._call("reboot")
        if self.reboot_effect:
            if self.current.npk_files:
                self.current = replace(
                    self.current,
                    version=self.target,
                    packages={name: self.target for name in self.current.packages},
                    upgrade_firmware=self.target,
                    npk_files=[],
                )
            if self.flashed:
                self.current = replace(self.current, firmware=self.current.upgrade_firmware)
            self.boot_at = self.clock.elapsed
            self.clock.sleep(5)
        if self.disconnect_reboot:
            raise TransportError("Expected reboot disconnect")

    def flash(self):
        self._call("flash")
        self.clock.sleep(10)
        self.flashed = True

    def backup(self, destination: Path, snapshot):
        self._call("backup-" + destination.name)
        if self.fail_backup:
            raise TransportError("SFTP backup failed")
        private_dir(destination)
        result = {
            "files": {},
            "backup_key_id": backup_key_id("test-encryption-password-at-least-24"),
        }
        for name in ("router.backup", "router.rsc"):
            atomic_bytes(destination / name, b"test-recovery-content")
            result["files"][name] = {
                "bytes": (destination / name).stat().st_size,
                "sha256": digest(destination / name),
            }
        atomic_json(destination / "manifest.json", result)
        return result

    def close(self):
        pass

    def cleanup_backup(self, _manifest):
        self._call("backup-cleanup")


@pytest.fixture
def setup(tmp_path):
    password = tmp_path / "password"
    password.write_text("test-encryption-password-at-least-24")
    password.chmod(0o600)
    config = Config(
        name="router1",
        data_dir=str(tmp_path / "data"),
        backup_password_file=str(password),
        ssh=SSHConfig(
            host="10.42.0.1",
            user="updater",
            key_file=str(tmp_path / "key"),
            known_hosts=str(tmp_path / "known_hosts"),
            expected_serial="FIXTURE-SERIAL-001",
        ),
        policy=Policy(
            minimum_observation_hours=0,
            reboot_timeout=30,
            download_timeout=60,
            health_timeout=10,
            poll_seconds=1,
        ),
        checks=[HealthCheck(name="office", kind="tcp", host="10.42.0.10", port=445)],
    )
    clock = Clock()
    router = SimulatedRouter(clock)
    store = Store(tmp_path / "data" / config.name)
    engine = Engine(config, store, router, clock=clock, checks=lambda: {"office": True})
    return config, clock, router, store, engine


def clone_state(store):
    return copy.deepcopy(store.read())
