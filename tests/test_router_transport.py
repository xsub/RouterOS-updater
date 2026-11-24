import re
from dataclasses import replace
from types import SimpleNamespace

import pytest

from routeros_updater.errors import IdentityError, TransportError
from routeros_updater.router import Router, parse_fields
from routeros_updater.transport import SSH


class Channel:
    def __init__(self, output):
        self.output = output

    def recv_ready(self):
        return bool(self.output)

    def recv(self, _size):
        value, self.output = self.output, b""
        return value

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return not self.output

    def recv_exit_status(self):
        return 0

    def close(self):
        pass


class ExecClient:
    def __init__(self, error=False, echo_secret=False):
        self.command = ""
        self.error, self.echo_secret = error, echo_secret

    def exec_command(self, command, **kwargs):
        self.command = command
        nonce = re.search(r"ROSUP_([a-f0-9]+)_OK", command).group(1)
        if self.error:
            output = f"ROSUP_{nonce}_ERROR\n"
        else:
            output = f"hello\nROSUP_{nonce}_OK\n"
        if self.echo_secret:
            output = "password-do-not-log\nsyntax error\n"
        return None, SimpleNamespace(channel=Channel(output.encode())), None

    def get_transport(self):
        return SimpleNamespace(is_active=lambda: True)

    def close(self):
        pass


def test_success_requires_positive_nonce_not_ssh_exit_zero(setup):
    config, *_ = setup
    transport = SSH(config.ssh)
    transport.client = ExecClient(error=True)
    with pytest.raises(TransportError, match="failed"):
        transport.execute("/bad-command", "operation")


def test_remote_error_cannot_leak_credentials(setup):
    config, *_ = setup
    transport = SSH(config.ssh)
    transport.client = ExecClient(echo_secret=True)
    with pytest.raises(TransportError) as result:
        transport.execute('/backup password="password-do-not-log"', "backup")
    assert "password-do-not-log" not in str(result.value)
    assert "password-do-not-log" not in repr(result.value)


def test_successful_wrapper_is_one_line(setup):
    config, *_ = setup
    transport = SSH(config.ssh)
    transport.client = ExecClient()
    assert transport.execute(':put "hello"', "echo") == "hello"
    assert "\n" not in transport.client.command


def test_duplicate_fields_are_rejected():
    with pytest.raises(TransportError):
        parse_fields("ROSUP|version|7.24.7\nROSUP|version|7.24.6")


def test_router_identity_is_pinned_separately_from_ssh_key(setup):
    config, _, fake, _, _ = setup
    router = Router(config)
    with pytest.raises(IdentityError):
        router.verify_identity(replace(fake.current, serial="HOME-MIKROTIK"))


def snapshot_output(snapshot):
    values = {
        "serial": snapshot.serial,
        "model": snapshot.model,
        "version": snapshot.version,
        "architecture": snapshot.architecture,
        "uptime": "1h",
        "free_disk": str(snapshot.free_disk),
        "free_memory": str(snapshot.free_memory),
        "firmware": snapshot.firmware,
        "upgrade_firmware": snapshot.upgrade_firmware,
        "auto_upgrade": "false",
        "channel": snapshot.channel,
        "update_mode": snapshot.update_mode,
        "update_certificate": snapshot.update_certificate,
    }
    return (
        "\n".join(f"ROSUP|{name}|{value}" for name, value in values.items())
        + "\nROSUP_PKG|routeros|7.24.6||false|false"
    )


def test_snapshot_parser_collects_and_checks_packages(setup):
    config, _, fake, _, _ = setup
    router = Router(config)
    output = snapshot_output(fake.current) + "\nROSUP_NPK|routeros-7.24.7-arm.npk"
    router.ssh = SimpleNamespace(execute=lambda *_args, **_kwargs: output)
    snapshot = router.snapshot()
    assert snapshot.packages == {"routeros": "7.24.6"}
    assert snapshot.npk_files == ["routeros-7.24.7-arm.npk"]


def test_snapshot_parser_rejects_missing_resource_fields(setup):
    config, *_ = setup
    router = Router(config)
    router.ssh = SimpleNamespace(
        execute=lambda *_args, **_kwargs: "ROSUP|serial|FIXTURE-SERIAL-001"
    )
    with pytest.raises(TransportError):
        router.snapshot()


@pytest.mark.parametrize("scheduled,expected", [("", False), ("scheduled for enable", True)])
def test_available_packages_do_not_become_installed_but_pending_changes_are_detected(
    setup, scheduled, expected
):
    config, _, fake, _, _ = setup
    router = Router(config)
    output = snapshot_output(fake.current) + f"\nROSUP_PKG|wireless||{scheduled}|true|true"
    router.ssh = SimpleNamespace(execute=lambda *_args, **_kwargs: output)
    result = router.snapshot()
    assert result.packages == {"routeros": "7.24.6"}
    assert result.disabled_packages == []
    assert result.scheduled is expected


def test_download_checks_tls_in_same_routeros_script_as_download(setup):
    config, *_ = setup
    router = Router(config)
    captured = []
    router.ssh = SimpleNamespace(execute=lambda body, *_args, **_kwargs: captured.append(body))
    router.download()
    command = captured[0]
    assert command.index('mode] != "https"') < command.index("/system package update download")
    assert command.index('check-certificate] != "yes"') < command.index(
        "/system package update download"
    )
