#!/bin/sh
# Installs the service files. Does not enable a timer or contact a router.
set -eu
if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root on the destination Linux host." >&2
    exit 1
fi
command -v systemctl >/dev/null
systemd_version=$(systemctl --version | awk 'NR==1 {print $2}')
if [ "$systemd_version" -lt 247 ]; then
    echo "systemd 247+ with LoadCredential support is required." >&2
    exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
active_units=$(systemctl list-units --state=active,activating --plain --no-legend 'routeros-updater*.timer' 'routeros-updater*.service')
if [ -n "$active_units" ]; then
    echo "Stop updater timers and wait for running updater services to finish before reinstalling." >&2
    exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! id routeros-updater >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin routeros-updater
fi
install -d -m 0755 /opt/routeros-updater
install -d -m 0750 -o root -g routeros-updater /etc/routeros-updater
install -d -m 0700 -o routeros-updater -g routeros-updater /var/lib/routeros-updater
python3 -m venv /opt/routeros-updater/venv
/opt/routeros-updater/venv/bin/pip install --require-hashes -r "$project_dir/requirements.lock"
/opt/routeros-updater/venv/bin/pip install --require-hashes -r "$project_dir/build-requirements.lock"
/opt/routeros-updater/venv/bin/pip install --no-build-isolation --no-deps "$project_dir"
install -m 0755 "$project_dir/deploy/routeros-updaterctl" /usr/local/sbin/routeros-updaterctl
install -m 0644 "$project_dir/deploy/routeros-updater@.service" /etc/systemd/system/
install -m 0644 "$project_dir/deploy/routeros-updater@.timer" /etc/systemd/system/
if [ ! -e /etc/routeros-updater/router1.toml ]; then
    install -m 0640 -o root -g routeros-updater "$project_dir/examples/router1.toml" /etc/routeros-updater/router1.toml
fi
systemctl daemon-reload
echo "Installed. Configure SSH identity, credentials and network health checks before enabling the timer."
