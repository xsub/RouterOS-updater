import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .errors import BusyError, PolicyError

VALID_PHASES = {
    "idle",
    "prepared",
    "downloading",
    "downloaded",
    "ros_reboot_intent",
    "ros_verified",
    "boot_flash_intent",
    "boot_flashed",
    "boot_reboot_intent",
    "verifying",
    "complete",
    "attention",
}


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


def private_dir(path: Path) -> None:
    # Persist every new ancestor entry, so a durable manifest really means durable backups.
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for item in reversed(missing):
        item.mkdir(mode=0o700, exist_ok=True)
        for directory in (item, item.parent):
            fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PolicyError(
            "State/backup directory must be owned by service user, mode 0700, and not a symlink"
        )


def atomic_bytes(path: Path, content: bytes) -> None:
    private_dir(path.parent)
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path: Path, value: dict) -> None:
    atomic_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def read_json(path: Path) -> dict:
    from .config import private_file

    private_file(path)
    try:
        result = json.loads(path.read_text())
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, UnicodeError):
        raise PolicyError("Corrupt state file; refusing to reset update history") from None


class Store:
    def __init__(self, root: Path):
        self.root = root
        private_dir(root)

    @contextmanager
    def lock(self, name: str = "lock"):
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
            raise PolicyError("Invalid lock identifier")
        fd = os.open(self.root / name, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BusyError("An updater already holds this router's lock") from None
            yield
        finally:
            os.close(fd)

    def read(self) -> dict:
        path = self.root / "state.json"
        if not path.exists():
            return {"schema": 1, "phase": "idle", "observations": {}, "blocked": []}
        state = read_json(path)
        if (
            state.get("schema") != 1
            or state.get("phase") not in VALID_PHASES
            or not isinstance(state.get("blocked"), list)
            or not isinstance(state.get("observations"), dict)
        ):
            raise PolicyError("Unknown or incomplete state schema")
        if state["phase"] != "idle":
            if (
                not isinstance(state.get("plan"), dict)
                or not isinstance(state.get("before"), dict)
                or not isinstance(state.get("run_id"), str)
                or not re.fullmatch(r"[a-f0-9]{32}", state["run_id"])
            ):
                raise PolicyError("Incomplete transaction state; refusing a new update")
            if not all(key in state["plan"] for key in ("target", "config_fingerprint", "action")):
                raise PolicyError("Incomplete transaction plan")
        if state["phase"] in ("ros_reboot_intent", "boot_reboot_intent"):
            if not isinstance(state.get("reboot"), dict) or not all(
                key in state["reboot"]
                for key in (
                    "before_uptime",
                    "issued_at",
                    "monotonic",
                    "controller_boot_id",
                    "deadline",
                )
            ):
                raise PolicyError("Incomplete reboot observation state")
        return state

    def save(self, state: dict) -> None:
        state["updated_at"] = timestamp()
        atomic_json(self.root / "state.json", state)

    def event(self, event: str, **fields) -> None:
        payload = {"at": timestamp(), "event": event, **fields}
        fd = os.open(
            self.root / "events.jsonl",
            os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
        )
        try:
            with os.fdopen(fd, "a") as stream:
                stream.write(json.dumps(payload, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            raise


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()
