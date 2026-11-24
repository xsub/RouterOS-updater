"""A durable state machine. Reboots/flash are never blindly retried."""

import os
import shutil
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import health
from .config import Config, backup_key_id, secret
from .errors import IdentityError, PolicyError, TransportError, UpdaterError, WindowError
from .router import Router, Snapshot
from .storage import Store, atomic_json, digest, read_json
from .versions import Version

ACTIVE = {
    "prepared",
    "downloading",
    "downloaded",
    "ros_reboot_intent",
    "ros_verified",
    "boot_flash_intent",
    "boot_flashed",
    "boot_reboot_intent",
    "verifying",
}


class Clock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float):
        time.sleep(seconds)

    def boot_id(self) -> str:
        path = Path("/proc/sys/kernel/random/boot_id")
        # Production is Linux; stable across processes, changes across OS reboots.
        return path.read_text().strip() if path.exists() else "non-linux-" + str(os.getpid())


class Engine:
    def __init__(self, config: Config, store: Store, router: Router, *, clock=None, checks=None):
        self.config, self.store, self.router = config, store, router
        self.clock = clock or Clock()
        self.checks = checks or (lambda: health.check_all(config.checks))

    def event(self, event: str, **fields):
        self.store.event(event, router=self.config.name, **fields)

    def _at(self) -> str:
        return self.clock.now().isoformat()

    def _save_phase(self, state: dict, phase: str, **fields):
        state.update(phase=phase, **fields)
        self.store.save(state)
        self.event("phase", phase=phase, run_id=state.get("run_id"))

    def _window(self, budget: int):
        if self.config.policy.remaining(self.clock.now()) < budget:
            raise WindowError("Maintenance window has insufficient time for the next operation")

    def _baseline(self):
        result = self.checks()
        if not result or not all(result.values()):
            raise PolicyError("Required network/service health checks are failing")
        return result

    def _identity(self, current: Snapshot, before: dict):
        if current.identity() != (before["serial"], before["model"], before["architecture"]):
            raise IdentityError("Router identity changed during the update")
        if current.update_mode != "https" or current.update_certificate != "yes":
            raise PolicyError("Router updater must use mode=https and check-certificate=yes")

    def plan(self) -> dict:
        state = self.store.read()
        if state["phase"] in ACTIVE:
            raise PolicyError("An update is in progress; use run to resume observation")
        if state["phase"] == "attention":
            raise PolicyError("Previous update requires operator reconciliation")
        before = self.router.snapshot()
        secure_download = before.update_mode == "https" and before.update_certificate == "yes"
        latest = self.router.latest() if secure_download else before.version
        installed, target = Version.parse(before.version), Version.parse(latest)
        reasons = []
        if not secure_download:
            reasons.append(
                "Set RouterOS updater mode=https and check-certificate=yes before checking/downloading updates"
            )
        if installed < Version(7, 23):
            reasons.append("Automatic apply requires RouterOS 7.23+ with HTTPS update downloads")
        if installed.major != 7 or target.major != installed.major:
            reasons.append("Major upgrades are excluded from unattended updates")
        if target < installed:
            reasons.append("Selected channel offers a downgrade")
        if (
            target > installed
            and not self.config.policy.allow_minor
            and target.minor != installed.minor
        ):
            reasons.append("Minor version changes are disabled")
        if not self.config.ssh.expected_serial:
            reasons.append("Pin expected_serial before applying any change")
        if before.channel != self.config.policy.channel:
            reasons.append(
                "Set the requested update channel on the router explicitly before planning"
            )
        if before.auto_upgrade:
            reasons.append(
                "Disable RouterBOARD auto-upgrade to preserve controlled flash/reboot phases"
            )
        if before.scheduled or before.npk_files:
            reasons.append("Router has pending package changes or existing NPK files")
        if before.disabled_packages:
            reasons.append("Disabled packages require a separately reviewed upgrade procedure")
        if any(Version.parse(version) != installed for version in before.packages.values()):
            reasons.append("Installed packages have inconsistent versions")
        if (
            before.free_disk < self.config.policy.min_free_bytes
            or before.free_memory < self.config.policy.min_free_memory
        ):
            reasons.append("Router lacks required free storage or memory")
        if before.uptime < self.config.policy.min_uptime_seconds:
            reasons.append("Router has rebooted too recently")
        policy = self.config.policy
        if latest in policy.denied_versions or latest in state["blocked"]:
            reasons.append("Target version is denied or blocked after a previous failure")
        if policy.allowed_versions and latest not in policy.allowed_versions:
            reasons.append("Target version is outside the configured allowlist")
        firmware_pending = Version.parse(before.upgrade_firmware) > Version.parse(before.firmware)
        action = "routeros" if target > installed else "routerboot" if firmware_pending else "none"
        # Observation age measures when THIS controller first saw the release, not its publication date.
        key = policy.channel + ":" + latest
        first_seen = state["observations"].setdefault(key, self._at())
        age = (self.clock.now() - datetime.fromisoformat(first_seen)).total_seconds()
        if action == "routeros" and age < policy.minimum_observation_hours * 3600:
            reasons.append("Target has not completed the configured local observation period")
        if not self.config.checks:
            reasons.append("Configure at least one independent network/service health check")
        checks = self.checks()
        if not checks or not all(checks.values()):
            reasons.append("Preflight network/service health checks failed")
        plan = {
            "schema": 1,
            "id": uuid.uuid4().hex,
            "created_at": self._at(),
            "config_fingerprint": self.config.fingerprint(),
            "router": self.config.name,
            "before": asdict(before),
            "target": latest,
            "action": action,
            "first_seen": first_seen,
            "checks": checks,
            "reasons": reasons,
            "ready": bool(action != "none" and not reasons),
            "in_window": policy.in_window(self.clock.now()),
        }
        self.store.save(state)
        atomic_json(self.store.root / "plan.json", plan)
        self.event("plan", target=latest, action=action, ready=plan["ready"], reasons=reasons)
        return plan

    def apply(self, plan_id: str) -> dict:
        state = self.store.read()
        if state["phase"] in ACTIVE or state["phase"] == "attention":
            raise PolicyError("Cannot start another update while a run is active or unresolved")
        plan = read_json(self.store.root / "plan.json")
        if plan.get("id") != plan_id or plan.get("config_fingerprint") != self.config.fingerprint():
            raise PolicyError("Plan ID/configuration does not match")
        if not plan.get("ready"):
            raise PolicyError("Plan is not eligible for apply")
        age = (self.clock.now() - datetime.fromisoformat(plan["created_at"])).total_seconds()
        if age < 0 or age > self.config.policy.plan_ttl_seconds:
            raise PolicyError("Plan has expired or controller clock moved backwards")
        policy = self.config.policy
        self._window(
            policy.download_timeout + 2 * policy.reboot_timeout + 2 * policy.health_timeout + 240
        )
        current = self.router.snapshot()
        self._identity(current, plan["before"])
        for name in (
            "version",
            "firmware",
            "upgrade_firmware",
            "channel",
            "packages",
            "auto_upgrade",
            "npk_files",
            "scheduled",
            "disabled_packages",
            "update_mode",
            "update_certificate",
        ):
            if getattr(current, name) != plan["before"][name]:
                raise PolicyError("Router configuration changed since planning")
        if (
            current.free_disk < policy.min_free_bytes
            or current.free_memory < policy.min_free_memory
            or current.uptime < policy.min_uptime_seconds
        ):
            raise PolicyError("Router no longer satisfies resource/uptime preflight")
        if self.router.latest() != plan["target"]:
            raise PolicyError("Update server target changed since planning")
        password = secret(Path(self.config.backup_password_file))
        if len(password) < 24:
            raise PolicyError("Backup encryption password must contain at least 24 characters")
        self._baseline()
        state.update(
            plan=plan,
            run_id=uuid.uuid4().hex,
            started_at=self._at(),
            before=asdict(current),
            backup_key_id=backup_key_id(password),
        )
        self._save_phase(state, "prepared")
        return self._resume_safe(state)

    def run(self) -> dict:
        state = self.store.read()
        if state["phase"] == "attention":
            raise PolicyError("Operator reconciliation is required; refusing another update")
        if state["phase"] in ACTIVE:
            return self._resume_safe(state)
        plan = self.plan()
        if plan["ready"] and self.config.policy.auto_apply and plan["in_window"]:
            policy = self.config.policy
            if (
                policy.remaining(self.clock.now())
                < policy.download_timeout
                + 2 * policy.reboot_timeout
                + 2 * policy.health_timeout
                + 240
            ):
                return {
                    "phase": "planned",
                    "plan": plan,
                    "waiting": "Insufficient maintenance time remaining",
                }
            return self.apply(plan["id"])
        return {"phase": "planned", "plan": plan}

    def _resume_safe(self, state: dict) -> dict:
        try:
            if state["plan"]["config_fingerprint"] != self.config.fingerprint():
                raise PolicyError("Configuration changed while an update was in progress")
            return self._resume(state)
        except WindowError:
            self.event("waiting-window", phase=state["phase"], run_id=state["run_id"])
            return {"phase": "deferred", "waiting_phase": state["phase"], "run_id": state["run_id"]}
        except UpdaterError as error:
            # A failed candidate is never retried by the timer until an operator reconciles it.
            if state["plan"]["target"] not in state["blocked"]:
                state["blocked"].append(state["plan"]["target"])
            self._save_phase(state, "attention", failed_phase=state["phase"], error=str(error))
            self.event("attention", reason=str(error), run_id=state["run_id"])
            raise
        except Exception:
            if state["plan"]["target"] not in state["blocked"]:
                state["blocked"].append(state["plan"]["target"])
            self._save_phase(
                state,
                "attention",
                failed_phase=state["phase"],
                error="Unexpected controller error; inspect privately",
            )
            raise UpdaterError(
                "Unexpected controller error; update stopped without retry"
            ) from None

    def _verify_backup(self, directory: Path):
        from .config import private_file

        try:
            manifest = read_json(directory / "manifest.json")
            expected_key = self.store.read()["backup_key_id"]
            if (
                manifest["backup_key_id"] != expected_key
                or backup_key_id(secret(Path(self.config.backup_password_file))) != expected_key
            ):
                raise PolicyError("Backup encryption credential changed during this transaction")
            for name in ("router.backup", "router.rsc"):
                item = directory / name
                private_file(item)
                if (
                    item.stat().st_size != manifest["files"][name]["bytes"]
                    or digest(item) != manifest["files"][name]["sha256"]
                ):
                    raise PolicyError("Local recovery backup is incomplete or changed")
        except (OSError, KeyError, TypeError):
            raise PolicyError("Local recovery backup is missing or incomplete") from None

    def _resume(self, state: dict) -> dict:
        policy, plan = self.config.policy, state["plan"]
        root = self.store.root / "backups" / state["run_id"]
        if state["phase"] == "prepared":
            self._window(
                policy.download_timeout
                + 2 * policy.reboot_timeout
                + 2 * policy.health_timeout
                + 240
            )
            current = self.router.snapshot()
            self._identity(current, state["before"])
            if (
                current.version != state["before"]["version"]
                or current.npk_files
                or current.scheduled
                or current.auto_upgrade
                or current.packages != state["before"]["packages"]
                or current.channel != state["before"]["channel"]
                or current.disabled_packages
            ):
                raise PolicyError("Router changed while preparing recovery backup")
            self._baseline()
            if (root / "pre").exists():
                # Resume only a complete, verified backup; partial artifacts still fail closed.
                self._verify_backup(root / "pre")
                self.router.cleanup_backup(read_json(root / "pre" / "manifest.json"))
            else:
                self.router.backup(root / "pre", current)
            self._verify_backup(root / "pre")
            current = self.router.snapshot()
            self._identity(current, state["before"])
            if (
                current.version != state["before"]["version"]
                or current.packages != state["before"]["packages"]
                or current.channel != state["before"]["channel"]
                or current.npk_files
                or current.scheduled
                or current.auto_upgrade
                or current.disabled_packages
            ):
                raise PolicyError("Router changed before downloading approved packages")
            if self.router.latest() != plan["target"]:
                raise PolicyError("Update server target changed before package download")
            self._window(
                policy.download_timeout
                + 2 * policy.reboot_timeout
                + 2 * policy.health_timeout
                + 180
            )
            self._save_phase(
                state,
                "downloaded" if plan["action"] == "routerboot" else "downloading",
                download_started_at=self._at(),
            )
            if plan["action"] == "routeros":
                try:
                    self.router.download()
                except TransportError:
                    # Outcome may be ambiguous. Observe, never send download a second time.
                    self.router.close()
        if state["phase"] == "downloading":
            self._verify_backup(root / "pre")
            deadline = datetime.fromisoformat(state["download_started_at"]) + timedelta(
                seconds=policy.download_timeout
            )
            while self.clock.now() < deadline:
                try:
                    status = self.router.update_status()
                except TransportError:
                    self.router.close()
                    self.clock.sleep(policy.poll_seconds)
                    continue
                if status["latest-version"] != plan["target"]:
                    raise PolicyError("Download target changed; pending packages need inspection")
                if status["status"].startswith("Downloaded"):
                    current = self.router.snapshot()
                    self._identity(current, state["before"])
                    if current.version != state["before"]["version"]:
                        raise PolicyError("Router rebooted independently during download")
                    expected = sorted(
                        f"{name}-{plan['target']}-{current.architecture}.npk"
                        for name in state["before"]["packages"]
                    )
                    if sorted(current.npk_files) != expected:
                        raise PolicyError(
                            "Downloaded NPK inventory does not match pinned package names/version/architecture"
                        )
                    self._save_phase(state, "downloaded")
                    break
                if "error" in status["status"].lower():
                    raise PolicyError("Router package download failed")
                self.clock.sleep(policy.poll_seconds)
            else:
                raise PolicyError("Package download timed out; inspect pending NPK files")
        if state["phase"] == "downloaded":
            self._verify_backup(root / "pre")
            self._baseline()
            current = self.router.snapshot()
            self._identity(current, state["before"])
            if (
                current.auto_upgrade
                or current.scheduled
                or current.version != state["before"]["version"]
                or current.packages != state["before"]["packages"]
                or current.channel != state["before"]["channel"]
                or current.disabled_packages
            ):
                raise PolicyError("Router changed before software restart")
            expected = (
                sorted(
                    f"{name}-{plan['target']}-{current.architecture}.npk"
                    for name in state["before"]["packages"]
                )
                if plan["action"] == "routeros"
                else []
            )
            if sorted(current.npk_files) != expected:
                raise PolicyError("NPK inventory changed before reboot")
            if plan["action"] == "routeros":
                self._issue_reboot(state, current, "ros_reboot_intent")
            else:
                self._save_phase(state, "ros_verified")
        if state["phase"] == "ros_reboot_intent":
            current = self._observe_reboot(state)
            self._verify_versions(current, plan["target"])
            self._wait_health()
            self._save_phase(state, "ros_verified")
        if state["phase"] == "ros_verified":
            self._verify_backup(root / "pre")
            self._baseline()
            current = self.router.snapshot()
            self._identity(current, state["before"])
            self._verify_versions(current, plan["target"])
            self._clean_for_firmware(current, state)
            firmware, offered = (
                Version.parse(current.firmware),
                Version.parse(current.upgrade_firmware),
            )
            if offered < firmware:
                raise PolicyError("RouterBOOT downgrade is forbidden")
            if offered > firmware:
                if current.auto_upgrade:
                    raise PolicyError("RouterBOARD auto-upgrade was enabled during this run")
                self._window(policy.reboot_timeout + policy.health_timeout + 180)
                self._save_phase(
                    state, "boot_flash_intent", firmware_target=current.upgrade_firmware
                )
                self.router.flash()
                self._save_phase(state, "boot_flashed")
            else:
                self._save_phase(state, "verifying", firmware_target=current.firmware)
        if state["phase"] == "boot_flash_intent":
            raise PolicyError(
                "Interrupted RouterBOOT flash has an ambiguous outcome; never retry automatically"
            )
        if state["phase"] == "boot_flashed":
            self._verify_backup(root / "pre")
            current = self.router.snapshot()
            self._identity(current, state["before"])
            self._verify_versions(current, plan["target"])
            self._clean_for_firmware(current, state)
            if current.upgrade_firmware != state["firmware_target"] or current.auto_upgrade:
                raise PolicyError("RouterBOOT target/settings changed before restart")
            if current.firmware == state["firmware_target"]:
                self._save_phase(state, "verifying")
            elif current.firmware != state["before"]["firmware"]:
                raise PolicyError("RouterBOOT changed unexpectedly while waiting for reboot")
            else:
                self._issue_reboot(state, current, "boot_reboot_intent")
        if state["phase"] == "boot_reboot_intent":
            self._observe_reboot(state)
            self._save_phase(state, "verifying")
        if state["phase"] == "verifying":
            current = self.router.snapshot()
            self._identity(current, state["before"])
            self._verify_versions(current, plan["target"])
            if (
                current.firmware != state["firmware_target"]
                or current.upgrade_firmware != state["firmware_target"]
            ):
                raise PolicyError(
                    "Final RouterBOOT version does not match the pinned firmware target"
                )
            if current.npk_files or current.scheduled or current.auto_upgrade:
                raise PolicyError("Unexpected package/firmware work remains after update")
            self._wait_health()
            if (root / "post").exists():
                self._verify_backup(root / "post")
            else:
                self.router.backup(root / "post", current)
            self._verify_backup(root / "post")
            self._save_phase(state, "complete", result=asdict(current), completed_at=self._at())
            try:
                self._retention(state["run_id"])
            except OSError:
                self.event("retention-warning", reason="Could not prune old completed backups")
            self.event("complete", target=plan["target"], firmware=current.firmware)
        return state

    def _clean_for_firmware(self, current: Snapshot, state: dict):
        if (
            current.npk_files
            or current.scheduled
            or current.auto_upgrade
            or current.disabled_packages
            or current.channel != state["before"]["channel"]
        ):
            raise PolicyError("Unexpected package or firmware work before RouterBOOT operation")

    def _verify_versions(self, current: Snapshot, target: str):
        if current.version != target or current.packages != {
            name: target for name in self.store.read()["before"]["packages"]
        }:
            raise PolicyError("RouterOS/package versions do not match the pinned target")

    def _issue_reboot(self, state: dict, snapshot: Snapshot, phase: str):
        self._verify_backup(self.store.root / "backups" / state["run_id"] / "pre")
        budget = self.config.policy.reboot_timeout + self.config.policy.health_timeout + 60
        if phase == "ros_reboot_intent":
            budget = 2 * budget + 120
        self._window(budget)
        self._save_phase(
            state,
            phase,
            reboot={
                "before_uptime": snapshot.uptime,
                "issued_at": self._at(),
                "monotonic": self.clock.monotonic(),
                "controller_boot_id": self.clock.boot_id(),
                "deadline": (
                    self.clock.now() + timedelta(seconds=self.config.policy.reboot_timeout)
                ).isoformat(),
            },
        )
        try:
            self.router.reboot()
        except TransportError:
            # Disconnect is expected, but success is determined exclusively by observation.
            pass

    def _observe_reboot(self, state: dict) -> Snapshot:
        intent = state["reboot"]
        deadline = datetime.fromisoformat(intent["deadline"])
        local_deadline = self.clock.monotonic() + min(
            self.config.policy.reboot_timeout, max(0, (deadline - self.clock.now()).total_seconds())
        )
        while self.clock.now() < deadline and self.clock.monotonic() < local_deadline:
            try:
                request_started = self.clock.monotonic()
                current = self.router.snapshot()
                self._identity(current, state["before"])
                elapsed = (
                    request_started - intent["monotonic"]
                    if self.clock.boot_id() == intent["controller_boot_id"]
                    else 0
                )
                # Across a Linux reboot only a strict reduction against the saved uptime is proof.
                if elapsed < 0:
                    raise PolicyError("Controller monotonic clock is inconsistent")
                if current.uptime + 2 < intent["before_uptime"] + elapsed:
                    return current
            except TransportError:
                self.router.close()
            self.clock.sleep(self.config.policy.poll_seconds)
        raise PolicyError(
            "Router restart could not be verified before deadline; refusing to send another reboot"
        )

    def _wait_health(self):
        deadline = self.clock.monotonic() + self.config.policy.health_timeout
        while self.clock.monotonic() < deadline:
            result = self.checks()
            if result and all(result.values()):
                return
            self.clock.sleep(self.config.policy.poll_seconds)
        raise PolicyError("Network/service health did not recover before deadline")

    def _retention(self, current_id: str):
        root = self.store.root / "backups"
        candidates = sorted(
            (
                item
                for item in root.iterdir()
                if item.is_dir()
                and not item.is_symlink()
                and len(item.name) == 32
                and all(char in "0123456789abcdef" for char in item.name)
                and (item / "post" / "manifest.json").is_file()
            ),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for item in candidates[self.config.policy.backup_keep :]:
            if item.name != current_id:
                shutil.rmtree(item)

    def acknowledge(self, run_id: str, note: str, *, unblock: bool = False) -> dict:
        state = self.store.read()
        if state["phase"] != "attention" or state.get("run_id") != run_id or not note.strip():
            raise PolicyError("Reconciliation requires matching failed run ID and an operator note")
        current = self.router.snapshot()
        if current.npk_files or current.scheduled or current.auto_upgrade:
            raise PolicyError(
                "Resolve pending NPK/package/auto-upgrade state on the router before acknowledging"
            )
        self._baseline()
        archived = self.store.root / "history" / f"{run_id}.json"
        atomic_json(archived, state)
        if unblock and state["plan"]["target"] in state["blocked"]:
            state["blocked"].remove(state["plan"]["target"])
        clean = {key: state[key] for key in ("schema", "observations", "blocked")}
        clean.update(phase="idle", last_acknowledged=run_id)
        self.store.save(clean)
        # Do not log free-text notes, which might inadvertently contain credentials.
        self.event("acknowledged", run_id=run_id, unblock=unblock, note_recorded=True)
        atomic_json(
            self.store.root / "history" / f"{run_id}-ack.json", {"at": self._at(), "note": note}
        )
        return clean
