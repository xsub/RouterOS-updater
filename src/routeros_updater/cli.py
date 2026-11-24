import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .config import load, private_file, secret
from .engine import ACTIVE, Engine
from .errors import BusyError, UpdaterError
from .notifications import notify
from .router import Router
from .storage import Store, atomic_bytes, read_json


def metrics(store: Store, name: str) -> None:
    state = store.read()
    phase = state["phase"]
    last_success = (
        datetime.fromisoformat(state["completed_at"]).timestamp()
        if state.get("completed_at")
        else 0
    )
    text = "# HELP routeros_updater_attention 1 if operator reconciliation is required\n# TYPE routeros_updater_attention gauge\n"
    text += f'routeros_updater_attention{{router="{name}"}} {int(phase == "attention")}\n'
    text += "# TYPE routeros_updater_in_progress gauge\n"
    text += f'routeros_updater_in_progress{{router="{name}"}} {int(phase in ACTIVE)}\n'
    text += "# TYPE routeros_updater_last_success_timestamp_seconds gauge\n"
    text += f'routeros_updater_last_success_timestamp_seconds{{router="{name}"}} {last_success}\n'
    atomic_bytes(store.root / "metrics.prom", text.encode())


def parser():
    result = argparse.ArgumentParser(
        description="RouterOS updater over pinned SSH. Changes require apply or auto_apply=true."
    )
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--config", type=Path, default=Path("/etc/routeros-updater/router1.toml"))
    sub = result.add_subparsers(dest="command", required=True)
    for name in ["check", "plan", "run", "status", "doctor", "inspect"]:
        sub.add_parser(name)
    apply = sub.add_parser(
        "apply", help="Apply the stored reviewed plan inside the maintenance window"
    )
    apply.add_argument("--plan-id", required=True)
    reconcile = sub.add_parser(
        "reconcile", help="Acknowledge a failed run after manually resolving the cause"
    )
    reconcile.add_argument("--run-id", required=True)
    reconcile.add_argument("--note-file", required=True, type=Path)
    reconcile.add_argument("--unblock-target", action="store_true")
    return result


def main(argv=None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    router, store, config = None, None, None
    try:
        config = load(args.config)
        store = Store(Path(config.data_dir) / config.name)
        identity = config.ssh.expected_serial or f"{config.ssh.host}:{config.ssh.port}"
        device_lock = "device-" + hashlib.sha256(identity.encode()).hexdigest()
        with Store(Path(config.data_dir)).lock(device_lock), store.lock():
            if args.command == "status":
                result = {"state": store.read()}
                if (store.root / "plan.json").exists():
                    result["plan"] = read_json(store.root / "plan.json")
            elif args.command == "doctor":
                private_file(Path(config.ssh.key_file))
                private_file(Path(config.ssh.known_hosts), secret=False)
                value = secret(Path(config.backup_password_file))
                result = {
                    "configuration": "valid",
                    "backup_password_long_enough": len(value) >= 24,
                    "auto_apply": config.policy.auto_apply,
                    "python": sys.version.split()[0],
                    "platform": sys.platform,
                    "note": "Static check only; does not authenticate to the router",
                }
                if len(value) < 24:
                    raise UpdaterError("Backup password is shorter than 24 characters")
            else:
                router = Router(config)
                engine = Engine(config, store, router)
                if args.command in ("plan", "check"):
                    result = engine.plan()
                elif args.command == "inspect":
                    from dataclasses import asdict

                    result = asdict(router.snapshot())
                elif args.command == "apply":
                    result = engine.apply(args.plan_id)
                elif args.command == "reconcile":
                    private_file(args.note_file)
                    result = engine.acknowledge(
                        args.run_id, args.note_file.read_text(), unblock=args.unblock_target
                    )
                else:
                    result = engine.run()
                if args.command in ("run", "apply", "reconcile"):
                    current = store.read()
                    phase = current["phase"]
                    key = current.get("run_id", "") + ":" + phase
                    previous = current.get("notified_key")
                    if key != previous and phase in ("complete", "attention"):
                        sent = notify(config, phase)
                        result["notification_sent"] = sent
                        if sent:
                            current["notified_key"] = key
                            store.save(current)
            metrics(store, config.name)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
    except BusyError as error:
        print(json.dumps({"error": str(error), "kind": "busy"}), file=sys.stderr)
        return 75
    except UpdaterError as error:
        if store and config:
            try:
                state = store.read()
                if state["phase"] == "attention":
                    notify(config, "attention", str(error))
                metrics(store, config.name)
            except Exception:
                print(
                    '{"warning":"Could not publish failure metrics/notification"}', file=sys.stderr
                )
        print(json.dumps({"error": str(error), "kind": "stopped"}), file=sys.stderr)
        return 2
    except Exception:
        # Third-party exceptions may contain raw credentials or remote command text.
        print(
            json.dumps(
                {
                    "error": "Unexpected error; operation stopped. Inspect configuration and private state.",
                    "kind": "internal",
                }
            ),
            file=sys.stderr,
        )
        return 3
    finally:
        if router:
            router.close()


if __name__ == "__main__":
    raise SystemExit(main())
