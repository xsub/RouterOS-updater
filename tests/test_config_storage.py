from dataclasses import replace
from datetime import UTC, datetime

import pytest

from routeros_updater.config import HealthCheck, load, private_file, secret, validate
from routeros_updater.errors import BusyError, PolicyError
from routeros_updater.storage import Store, atomic_bytes, atomic_json, private_dir
from routeros_updater.transport import quote
from routeros_updater.versions import Version, uptime_seconds


@pytest.mark.parametrize(
    "host",
    [
        "8.8.8.8",
        "router.example.test",
        "127.0.0.1",
        "::1",
        "169.254.1.1",
        "0.0.0.0",
        "192.0.2.1",
        "100.64.0.1",
    ],
)
def test_wan_loopback_and_hostname_targets_are_rejected(setup, host):
    config, *_ = setup
    with pytest.raises(PolicyError, match="management"):
        validate(replace(config, ssh=replace(config.ssh, host=host)))


@pytest.mark.parametrize("host", ["10.0.0.1", "172.16.0.1", "192.168.0.1", "fd01::1"])
def test_private_management_addresses(setup, host):
    config, *_ = setup
    validate(replace(config, ssh=replace(config.ssh, host=host)))


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1w2d3h4m5s", 788645),
        ("2d01:02:03", 176523),
        ("01:02:03", 3723),
        ("500ms", None),
        ("", None),
        ("8d4h", 705600),
        ("1.5s", 1.5),
    ],
)
def test_uptime_values_are_unambiguous(value, expected):
    if expected is None:
        with pytest.raises(PolicyError):
            uptime_seconds(value)
    else:
        assert uptime_seconds(value) == expected


@pytest.mark.parametrize(
    "value", ["7.24beta1", "7.24rc1", "7.24.7 extra", "7.24; /system reboot", ""]
)
def test_release_parser_rejects_nonproduction_or_injected_versions(value):
    with pytest.raises(PolicyError):
        Version.parse(value)


def test_versions_compare_numerically():
    assert Version.parse("7.24.10") > Version.parse("7.24.9")
    assert Version.parse("7.24 (long-term)") == Version.parse("7.24.0")


def test_quote_prevents_routeros_interpolation_and_command_injection():
    value = 'x"; /system reboot; :put "$secret\\\nż'
    result = quote(value)
    assert result.startswith('"') and result.endswith('"')
    assert '"' not in result[1:-1]
    assert "$" not in result
    assert "\n" not in result
    assert "\\22" in result and "\\24" in result and "\\5C" in result


def test_secrets_require_private_regular_file(tmp_path):
    path = tmp_path / "secret"
    path.write_text("long-enough-password")
    path.chmod(0o644)
    with pytest.raises(PolicyError):
        secret(path)
    path.chmod(0o600)
    assert secret(path) == "long-enough-password"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(PolicyError):
        private_file(link)


def test_corrupt_state_is_not_reset(tmp_path):
    store = Store(tmp_path / "state")
    atomic_bytes(store.root / "state.json", b"broken")
    with pytest.raises(PolicyError, match="Corrupt"):
        store.read()


def test_state_and_backups_have_private_permissions_and_durable_ancestors(tmp_path):
    root = tmp_path / "one" / "two" / "three"
    private_dir(root)
    for path in [root, root.parent, root.parent.parent]:
        assert path.stat().st_mode & 0o777 == 0o700
    atomic_json(root / "state.json", {"a": 1})
    assert (root / "state.json").stat().st_mode & 0o777 == 0o600


def test_parallel_runs_are_excluded(tmp_path):
    first, second = Store(tmp_path / "state"), Store(tmp_path / "state")
    with first.lock():
        with pytest.raises(BusyError):
            with second.lock():
                raise AssertionError


def test_symlinked_data_directory_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(PolicyError):
        Store(link)


def test_maintenance_window_is_timezone_aware_and_supports_overnight(setup):
    config, *_ = setup
    config = replace(config, policy=replace(config.policy, window_timezone="Europe/Berlin"))
    sunday = datetime(2026, 11, 29, 2, 30, tzinfo=UTC)
    assert config.policy.in_window(sunday)
    assert config.policy.remaining(sunday) == 5400
    overnight = replace(config.policy, window_start="23:00", window_end="02:00")
    assert overnight.in_window(datetime(2026, 11, 29, 23, 30, tzinfo=UTC))
    assert not overnight.in_window(datetime(2026, 11, 30, 1, 0, tzinfo=UTC))


def test_configuration_rejects_unknown_fields(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('name = "router1"\nunknown = true\n')
    path.chmod(0o600)
    with pytest.raises(PolicyError):
        load(path)


@pytest.mark.parametrize(
    "check",
    [
        HealthCheck(name="http", kind="https", url="http://example.org"),
        HealthCheck(name="password", kind="https", url="https://user:secret@example.org"),
        HealthCheck(name="shell", kind="command", host="rm -rf /"),
        HealthCheck(name="port", kind="tcp", host="localhost", port=0),
    ],
)
def test_unsafe_health_check_configuration_is_rejected(setup, check):
    config, *_ = setup
    with pytest.raises(PolicyError):
        validate(replace(config, checks=[check]))


def test_config_rejects_string_boolean(setup):
    config, *_ = setup
    with pytest.raises(PolicyError):
        validate(replace(config, policy=replace(config.policy, auto_apply="false")))


def test_systemd_credentials_are_resolved_only_from_explicit_directory(tmp_path, monkeypatch):
    path = tmp_path / "backup-password"
    path.write_text("actual-systemd-password")
    path.chmod(0o400)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    from pathlib import Path

    assert secret(Path("credential:backup-password")) == "actual-systemd-password"
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(PolicyError):
        secret(Path("credential:backup-password"))
