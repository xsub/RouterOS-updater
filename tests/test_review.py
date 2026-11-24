import copy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta

import pytest

from routeros_updater.config import Config, HealthCheck, Policy, SSHConfig
from routeros_updater.engine import Engine
from routeros_updater.errors import PolicyError
from routeros_updater.router import Snapshot
from routeros_updater.storage import Store, atomic_bytes, atomic_json, private_dir


class FakeClock:
    def __init__(self):
        self.started = datetime(2026, 11, 24, 2, 30, tzinfo=UTC)
        self.elapsed = 0.0
        self.controller_boot = "controller-boot-a"

    def now(self):
        return self.started + timedelta(seconds=self.elapsed)

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds

    def boot_id(self):
        return self.controller_boot


class MemoryStore:
    def __init__(self, root, state):
        self.root = root
        self.state = copy.deepcopy(state)

    def read(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)

    def event(self, *_args, **_kwargs):
        pass


def snapshot(**changes):
    values = dict(
        serial="TESTSERIAL",
        model="TEST-BOARD",
        version="7.24.6",
        architecture="arm",
        uptime=1000.0,
        free_disk=128 * 1024 * 1024,
        free_memory=128 * 1024 * 1024,
        firmware="7.24.6",
        upgrade_firmware="7.24.6",
        auto_upgrade=False,
        channel="long-term",
        packages={"routeros": "7.24.6"},
        scheduled=False,
        npk_files=[],
        update_mode="https",
        update_certificate="yes",
    )
    values.update(changes)
    return Snapshot(**values)


@pytest.fixture
def config(tmp_path):
    return Config(
        name="review-test",
        ssh=SSHConfig(
            host="10.42.0.1",
            user="updater",
            key_file=str(tmp_path / "key"),
            known_hosts=str(tmp_path / "known_hosts"),
            expected_serial="TESTSERIAL",
        ),
        data_dir=str(tmp_path / "state"),
        backup_password_file=str(tmp_path / "password"),
        policy=Policy(
            window_days=list(range(7)),
            window_start="00:00",
            window_end="23:59",
            reboot_timeout=30,
            health_timeout=5,
            poll_seconds=1,
        ),
        checks=[HealthCheck(name="office", kind="tcp", host="10.42.0.10", port=445)],
    )


def transaction(config, before, phase, **changes):
    result = {
        "schema": 1,
        "phase": phase,
        "run_id": "a" * 32,
        "observations": {},
        "blocked": [],
        "before": asdict(before),
        "plan": {
            "target": "7.24.7",
            "action": "routeros",
            "config_fingerprint": config.fingerprint(),
        },
    }
    result.update(changes)
    return result


class MutationGuardRouter:
    def __init__(self, current):
        self.current = current

    def snapshot(self):
        return self.current

    def reboot(self):
        raise AssertionError("The controller must reject this state before reboot")

    def flash(self):
        raise AssertionError("The controller must reject this state before flash")

    def close(self):
        pass


def test_snapshot_latency_does_not_prove_a_reboot(config, tmp_path):
    clock = FakeClock()
    before = snapshot()

    class SlowRouter(MutationGuardRouter):
        def snapshot(self):
            sampled_uptime = before.uptime + clock.elapsed
            clock.elapsed += 6
            return replace(before, uptime=sampled_uptime)

    state = transaction(config, before, "ros_reboot_intent")
    state["reboot"] = {
        "before_uptime": before.uptime,
        "monotonic": clock.monotonic(),
        "controller_boot_id": clock.boot_id(),
        "deadline": (clock.now() + timedelta(seconds=20)).isoformat(),
    }
    store = MemoryStore(tmp_path, state)
    engine = Engine(config, store, SlowRouter(before), clock=clock)
    with pytest.raises(PolicyError, match="restart could not be verified"):
        engine._observe_reboot(state)


def test_controller_reboot_does_not_reuse_old_monotonic_clock(config, tmp_path):
    clock = FakeClock()
    clock.controller_boot = "controller-boot-b"
    clock.elapsed = 5000
    before = snapshot()
    state = transaction(config, before, "ros_reboot_intent")
    state["reboot"] = {
        "before_uptime": before.uptime,
        "monotonic": 1.0,
        "controller_boot_id": "controller-boot-a",
        "deadline": (clock.now() + timedelta(seconds=5)).isoformat(),
    }
    store = MemoryStore(tmp_path, state)
    router = MutationGuardRouter(replace(before, uptime=before.uptime + 10))
    engine = Engine(config, store, router, clock=clock)
    with pytest.raises(PolicyError, match="restart could not be verified"):
        engine._observe_reboot(state)


@pytest.mark.parametrize(
    "files",
    [[], ["routeros-7.24.7-arm.npk", "container-7.24.7-arm.npk"], ["routeros-7.24.6-arm.npk"]],
)
def test_resuming_downloaded_phase_rechecks_pinned_packages(config, tmp_path, files):
    before = snapshot()
    state = transaction(config, before, "downloaded")
    store = MemoryStore(tmp_path, state)
    router = MutationGuardRouter(replace(before, npk_files=files))
    engine = Engine(config, store, router, clock=FakeClock(), checks=lambda: {"office": True})
    engine._verify_backup = lambda _directory: None
    with pytest.raises(PolicyError):
        engine._resume(state)


def test_routerboot_reboot_cannot_install_unexpected_npk(config, tmp_path):
    before = snapshot()
    current = snapshot(
        version="7.24.7",
        packages={"routeros": "7.24.7"},
        upgrade_firmware="7.24.7",
        npk_files=["container-7.24.7-arm.npk"],
    )
    state = transaction(config, before, "boot_flashed", firmware_target="7.24.7")
    store = MemoryStore(tmp_path, state)
    engine = Engine(config, store, MutationGuardRouter(current), clock=FakeClock())
    engine._verify_backup = lambda _directory: None
    with pytest.raises(PolicyError):
        engine._resume(state)


def test_recovery_backup_is_required_before_routerboot_flash(config, tmp_path):
    before = snapshot()
    current = snapshot(
        version="7.24.7",
        packages={"routeros": "7.24.7"},
        upgrade_firmware="7.24.7",
    )
    state = transaction(config, before, "ros_verified")
    store = MemoryStore(tmp_path, state)
    engine = Engine(
        config,
        store,
        MutationGuardRouter(current),
        clock=FakeClock(),
        checks=lambda: {"office": True},
    )

    def missing_backup(_directory):
        raise PolicyError("Recovery backup is missing")

    engine._verify_backup = missing_backup
    with pytest.raises(PolicyError, match="backup"):
        engine._resume(state)


def test_unknown_durable_phase_fails_closed(tmp_path):
    root = tmp_path / "state"
    store = Store(root)
    atomic_json(
        root / "state.json",
        {"schema": 1, "phase": "unknown-reboot-phase", "blocked": [], "observations": {}},
    )
    with pytest.raises(PolicyError):
        store.read()


def test_new_post_backup_is_verified_before_marking_complete(config, tmp_path):
    before = snapshot()
    current = snapshot(
        version="7.24.7",
        packages={"routeros": "7.24.7"},
        firmware="7.24.7",
        upgrade_firmware="7.24.7",
    )
    state = transaction(config, before, "verifying", firmware_target="7.24.7")
    store = MemoryStore(tmp_path, state)

    class CorruptPostBackupRouter(MutationGuardRouter):
        def backup(self, destination, _snapshot):
            private_dir(destination)
            files = {}
            for name in ("router.backup", "router.rsc"):
                atomic_bytes(destination / name, b"changed-backup")
                files[name] = {"bytes": len(b"changed-backup"), "sha256": "0" * 64}
            atomic_json(destination / "manifest.json", {"files": files})
            return {"files": files}

    router = CorruptPostBackupRouter(current)
    engine = Engine(config, store, router, clock=FakeClock(), checks=lambda: {"office": True})
    with pytest.raises(PolicyError, match="backup"):
        engine._resume(state)
    assert store.read()["phase"] != "complete"
