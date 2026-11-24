"""Exercise real Paramiko negotiation/authentication/SFTP against a local SSH fixture."""

import os
import re
import socket
import threading
import time
from pathlib import Path

import paramiko
import pytest

from routeros_updater.config import SSHConfig
from routeros_updater.errors import IdentityError
from routeros_updater.transport import SSH


class Server(paramiko.ServerInterface):
    def __init__(self, user_key):
        self.user_key = user_key

    def check_auth_publickey(self, username, key):
        return (
            paramiko.AUTH_SUCCESSFUL
            if username == "updater" and key == self.user_key
            else paramiko.AUTH_FAILED
        )

    def get_allowed_auths(self, _username):
        return "publickey"

    def check_channel_request(self, kind, _channel_id):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_exec_request(self, channel, command):
        def answer():
            time.sleep(0.03)
            nonce = re.search(rb"ROSUP_([a-f0-9]+)_OK", command).group(1)
            channel.sendall(b"real-SSH\nROSUP_" + nonce + b"_OK\n")
            channel.send_exit_status(0)
            channel.shutdown_write()

        threading.Thread(target=answer, daemon=True).start()
        return True


class SFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *args, root, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.root = root

    def _path(self, name):
        if not re.fullmatch(r"rosup-[a-f0-9-]+\.(backup|rsc)", name):
            raise OSError("forbidden")
        return self.root / name

    def stat(self, name):
        try:
            return paramiko.SFTPAttributes.from_stat(self._path(name).stat())
        except OSError:
            return paramiko.SFTP_NO_SUCH_FILE

    def open(self, name, flags, _attributes):
        if flags != os.O_RDONLY:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            result = paramiko.SFTPHandle(flags)
            result.readfile = self._path(name).open("rb")
            return result
        except OSError:
            return paramiko.SFTP_NO_SUCH_FILE


@pytest.fixture
def ssh_server(tmp_path):
    server_key = paramiko.RSAKey.generate(2048)
    user_key = paramiko.RSAKey.generate(2048)
    key_file = tmp_path / "key"
    user_key.write_private_key_file(str(key_file))
    key_file.chmod(0o600)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"[127.0.0.1]:{port} {server_key.get_name()} {server_key.get_base64()}\n"
    )
    known_hosts.chmod(0o600)
    stopped = threading.Event()
    connections, channels = [], []

    def serve():
        while not stopped.is_set():
            try:
                connection, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            transport = paramiko.Transport(connection)
            connections.append(transport)
            transport.add_server_key(server_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTP, root=tmp_path)
            try:
                transport.start_server(server=Server(user_key))
                while transport.is_active() and not stopped.is_set():
                    channel = transport.accept(0.1)
                    if channel:
                        channels.append(channel)
            except (paramiko.SSHException, EOFError, OSError):
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    config = SSHConfig(
        host="127.0.0.1",
        user="updater",
        port=port,
        key_file=str(key_file),
        known_hosts=str(known_hosts),
        timeout=3,
    )
    yield config, tmp_path
    stopped.set()
    listener.close()
    for connection in connections:
        connection.close()
    thread.join(timeout=3)


def test_real_ssh_validates_host_and_authenticates_with_only_specified_key(ssh_server):
    config, _ = ssh_server
    ssh = SSH(config)
    try:
        assert ssh.execute(':put "real-SSH"', "test", timeout=3) == "real-SSH"
    finally:
        ssh.close()


def test_real_sftp_backup_download_is_complete_and_private(ssh_server):
    config, root = ssh_server
    content = b"encrypted-test-content" * 10000
    (root / "rosup-deadbeef.backup").write_bytes(content)
    ssh = SSH(config)
    target = root / "downloaded.backup"
    try:
        ssh.fetch("rosup-deadbeef.backup", target)
        assert target.read_bytes() == content
        assert target.stat().st_mode & 0o777 == 0o600
        assert not target.with_suffix(".backup.part").exists()
    finally:
        ssh.close()


def test_real_ssh_rejects_changed_host_key(ssh_server):
    config, _ = ssh_server
    different = paramiko.RSAKey.generate(2048)
    Path(config.known_hosts).write_text(
        f"[127.0.0.1]:{config.port} {different.get_name()} {different.get_base64()}\n"
    )
    ssh = SSH(config)
    try:
        with pytest.raises(IdentityError, match="changed"):
            ssh.connect()
    finally:
        ssh.close()
