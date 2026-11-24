# RouterOS-updater

A Linux service for controlled RouterOS and RouterBOOT updates over pinned SSH.
Licensed under Apache-2.0.

**Development status:** tested with simulated devices and a local SSH/SFTP server.
The RouterOS CLI contract, physical RouterBOARD update cycle and Linux systemd
deployment still require validation on test equipment.

## Features

- Device identity, architecture, firmware, package and resource inventory.
- Pinned SSH host keys and serial number; explicit user key authentication.
- Stable/long-term channels, allowlists/denylists and release observation periods.
- Separate check/plan and apply commands, with optional unattended scheduling.
- Verified HTTPS checked immediately before update checks and downloads.
- Encrypted native backups and configuration exports retrieved over SFTP before
  changes, with local checksums, manifests and fsync of files/directories.
- Controlled RouterOS restart, package/version verification and health checks.
- Separate RouterBOOT flash, fresh success confirmation, restart and verification.
- Firmware-only updates and verified post-update backups.
- Durable transaction state, device/process locks, conservative crash recovery,
  retention, JSON events, Prometheus text metrics and optional HTTPS webhooks.
- systemd timer, protected credentials and a manual command helper.

## Requirements

Python 3.11+, Linux with systemd 247+ and LoadCredential support, and a RouterBOARD
running RouterOS 7.23+ with modern SSH/SFTP. Management targets must be literal
RFC1918 IPv4 addresses or IPv6 ULA.

Require updater mode=https, check-certificate=yes and RouterBOARD auto-upgrade=no.
The service validates these settings without changing them. Major upgrades,
prereleases, downgrades, pending package changes, existing NPK files and disabled
installed packages are excluded from unattended updates.

Verify the host key independently, pin the device serial number, restrict the
service account to the controller's private management address, and validate its
backup/SFTP/update/reboot/firmware capabilities on the actual RouterOS version.
Other update schedulers/controllers must not compete with this service.

## Development

```sh
git clone https://github.com/xsub/RouterOS-updater.git
cd RouterOS-updater
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock -r build-requirements.lock
.venv/bin/pip install --no-build-isolation --no-deps -e .
.venv/bin/pip install pytest pytest-cov ruff build pip-audit
.venv/bin/python -m pytest -q -W error
.venv/bin/ruff check src tests tools
.venv/bin/python tools/check_public_tree.py
```

Tests use synthetic devices and ephemeral SSH keys on loopback. They never
contact a real router. All example names, addresses and identifiers are fictional.

## Linux installation

The installer does not enable a timer or contact a router. For reinstallation,
stop updater timers and wait for active runs to finish; installation is refused
while updater services/timers are active.

```sh
sudo sh deploy/install.sh
sudo ssh-keygen -t ed25519 -N '' -f /etc/routeros-updater/router1.ssh-key
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/routeros-updater/router1.backup-password'
```

Keep a recovery copy of the backup password. Preserve old passwords while their
backups are needed. Manifests record a key identifier, not the secret.

Import only the public user key on the router. Provision a dedicated account
with appropriate SSH/read/write/backup/update/SFTP/reboot/RouterBOOT permissions;
validate the required permissions on your software version.

Obtain the SSH host key through a trusted channel and compare its fingerprint
independently. A bare ssh-keyscan result is not authentication. Save the verified
entry to /etc/routeros-updater/router1.known_hosts. Nonstandard SSH ports require
[address]:port notation.

Edit /etc/routeros-updater/router1.toml: use your own addresses, expected_serial,
optional model, schedule and independent health checks. Set config and
known_hosts to root:routeros-updater, mode 0640. Keep the private key and password
root:root, mode 0600. LoadCredential passes them to the service. Development configs may
instead use absolute paths to protected files and a private data directory with mode 0700.

```sh
sudo routeros-updaterctl router1 doctor
sudo routeros-updaterctl router1 inspect
sudo routeros-updaterctl router1 check
sudo routeros-updaterctl router1 status
```

doctor checks local files, inspect reads the router, check/plan queries update
metadata without downloading or restarting, and status is offline. Output is JSON.
Apply a ready plan by its id within the maintenance window:

```sh
sudo routeros-updaterctl router1 apply --plan-id PLAN_ID
```

Apply rechecks identity, packages, versions, channel, update offer, plan expiry,
credentials, available time and baseline health. There is no force flag.

After validating a full cycle on test equipment, set auto_apply=true if wanted
and enable the timer:

```sh
sudo systemctl enable --now routeros-updater@router1.timer
sudo systemctl list-timers 'routeros-updater@*'
sudo journalctl -u routeros-updater@router1.service
```

The timer runs every 30 minutes. The example window is Sunday 03:00–05:00 UTC;
replace it with your timezone and schedule. The default observation
period is 72 hours and starts when this controller first sees a release, not on publication.
Each mutation needs enough remaining time. Restart observation can continue
outside the window.

With auto_apply=false, the timer only plans new updates, but can still resume a
started transaction. Stop the timer and running service to stop all work.

## Health and recovery

TCP checks validate connection establishment. DNS validates an expected A record;
HTTPS validates TLS and an expected status without redirects. Same-LAN tests do
not prove router forwarding, Internet access or inbound VPN health. Configure
checks that traverse the router and an independent external VPN monitor.

State, backups and events live under /var/lib/routeros-updater/router1/.
Ambiguous flashes/restarts, missing backups, wrong versions and failed health
checks require operator reconciliation. Further automatic attempts are blocked.

Do not delete state.json to bypass a failure. Resolve pending packages, verify
service health and write a private note readable by the service account:

```sh
sudo routeros-updaterctl router1 reconcile --run-id RUN_ID --note-file /var/lib/routeros-updater/operator-note.txt
```

The target remains blocked unless --unblock-target is supplied. Reconciliation
does not delete NPK files or restore firmware/configuration.

Native backups are encrypted by RouterOS. Exports use default sensitive-field
hiding and files with mode 0600 in directories with mode 0700. Secrets in comments or script source
can still appear. Use encrypted storage and a separate recovery copy.

Local SHA256 detects changes to downloaded files; it is not an independent
router-side checksum or proof of restoreability. Test restoration. Additional
databases can require separate backups. Firmware recovery may need physical
access or Netinstall. Automatic firmware rollback is not implemented.

## Monitoring

- events.jsonl: sanitized stage transitions and reasons.
- state.json and history/: active and reconciled transactions.
- metrics.prom: attention/in-progress flags and last success time.
- webhook_url: optional verified-HTTPS JSON POST without redirects.
  Tokens can use a protected file or a separately configured systemd credential.
- backup_keep: prune older completed sets; keep failed runs for inspection.

Restrict access to monitoring files. Do not enable protocol debugging or core
dumps with real credentials. Backup secrets travel inside SSH without local
subprocess arguments, but exist in process and device memory.

See [design and integration checklist](docs/DESIGN.md),
[upstream references](docs/SOURCES.md), [contributing](CONTRIBUTING.md) and
[security reporting](SECURITY.md).
