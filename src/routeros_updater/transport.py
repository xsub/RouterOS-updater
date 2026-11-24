"""SSH commands travel inside SSH, never through a local subprocess argv."""

import logging
import os
import re
import time
import uuid
from pathlib import Path

import paramiko

from .config import SSHConfig, credential_path, private_file
from .errors import IdentityError, TransportError

# Paramiko DEBUG may expose the SSH exec payload, including a backup password.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def quote(value: str) -> str:
    """Quote a RouterOS string, including dollar interpolation and all UTF-8 bytes."""
    return (
        '"'
        + "".join(
            chr(byte) if 32 <= byte < 127 and chr(byte) not in '\\"$' else f"\\{byte:02X}"
            for byte in value.encode("utf-8")
        )
        + '"'
    )


class SSH:
    def __init__(self, config: SSHConfig):
        self.config = config
        self.client = None

    def close(self):
        if self.client:
            self.client.close()
            self.client = None

    def connect(self):
        if self.client and self.client.get_transport() and self.client.get_transport().is_active():
            return
        self.close()
        private_file(Path(self.config.key_file))
        private_file(Path(self.config.known_hosts), secret=False)
        client = paramiko.SSHClient()
        client.load_host_keys(self.config.known_hosts)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        host = (
            self.config.host
            if self.config.port == 22
            else f"[{self.config.host}]:{self.config.port}"
        )
        if not client.get_host_keys().lookup(host):
            raise IdentityError("Router SSH host key is not pinned")
        try:
            client.connect(
                self.config.host,
                port=self.config.port,
                username=self.config.user,
                key_filename=str(credential_path(self.config.key_file)),
                allow_agent=False,
                look_for_keys=False,
                timeout=self.config.timeout,
                banner_timeout=self.config.timeout,
                auth_timeout=self.config.timeout,
                channel_timeout=self.config.timeout,
                disabled_algorithms={
                    "ciphers": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"],
                    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96"],
                },
            )
            client.get_transport().set_keepalive(10)
            self.client = client
        except paramiko.BadHostKeyException:
            client.close()
            raise IdentityError("Router SSH host key changed") from None
        except paramiko.AuthenticationException:
            client.close()
            raise IdentityError("Router SSH key authentication failed") from None
        except Exception:
            client.close()
            raise TransportError("Router SSH connection failed") from None

    def execute(self, body: str, operation: str, *, timeout: int = 30) -> str:
        self.connect()
        nonce = uuid.uuid4().hex
        ok, error = f"ROSUP_{nonce}_OK", f"ROSUP_{nonce}_ERROR"
        command = f':do {{ {body}; :put "{ok}" }} on-error={{ :put "{error}" }}'
        channel = None
        try:
            _, stdout, _ = self.client.exec_command(command, timeout=timeout, get_pty=False)
            channel = stdout.channel
            deadline = time.monotonic() + timeout
            chunks, total = [], 0
            while True:
                while channel.recv_ready():
                    block = channel.recv(65536)
                    total += len(block)
                    if total > 1024 * 1024:
                        raise TransportError(f"Response too large: {operation}")
                    chunks.append(block)
                while channel.recv_stderr_ready():
                    # Never include raw stderr in logs or exceptions.
                    total += len(channel.recv_stderr(65536))
                    if total > 1024 * 1024 or time.monotonic() > deadline:
                        raise TransportError(f"SSH error response exceeded limits: {operation}")
                if channel.exit_status_ready() and not channel.recv_ready():
                    break
                if time.monotonic() > deadline:
                    raise TransportError(f"SSH operation timed out: {operation}")
                time.sleep(0.01)
            output = b"".join(chunks).decode("utf-8", errors="replace").replace("\r", "")
            lines = output.splitlines()
            if channel.recv_exit_status() != 0 or error in lines or ok not in lines:
                raise TransportError(f"Router command failed or is ambiguous: {operation}")
            return "\n".join(line for line in lines if line != ok)
        except TransportError:
            raise
        except Exception:
            self.close()
            raise TransportError(f"SSH operation disconnected: {operation}") from None
        finally:
            if channel is not None:
                channel.close()

    def fetch(self, remote: str, local: Path) -> None:
        if not re.fullmatch(r"rosup-[a-f0-9-]+\.(backup|rsc)", remote):
            raise TransportError("Refusing unexpected backup filename")
        self.connect()
        temporary = local.with_suffix(local.suffix + ".part")
        try:
            with self.client.open_sftp() as sftp:
                sftp.get_channel().settimeout(self.config.timeout)
                size = sftp.stat(remote).st_size
                if not size or size > 128 * 1024 * 1024:
                    raise TransportError("Backup size is outside permitted limits")
                deadline = time.monotonic() + 180
                fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as target, sftp.open(remote, "rb") as source:
                    copied = 0
                    while block := source.read(256 * 1024):
                        if time.monotonic() > deadline or copied + len(block) > size:
                            raise TransportError("Backup transfer timed out or changed size")
                        target.write(block)
                        copied += len(block)
                    target.flush()
                    os.fsync(target.fileno())
                if copied != size or sftp.stat(remote).st_size != size:
                    raise TransportError("Incomplete backup transfer")
            os.replace(temporary, local)
            directory = os.open(local.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except TransportError:
            raise
        except Exception:
            raise TransportError("SFTP backup transfer failed") from None
        finally:
            temporary.unlink(missing_ok=True)
