import http.client
import json
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from .config import Config, secret


def notify(config: Config, phase: str, reason: str = "") -> bool:
    """Optional generic JSON webhook. No redirects, raw command output or credentials."""
    if not config.webhook_url:
        return True
    url = urlsplit(config.webhook_url)
    connection = http.client.HTTPSConnection(
        url.hostname, url.port or 443, timeout=10, context=ssl.create_default_context()
    )
    try:
        headers = {"Content-Type": "application/json", "User-Agent": "RouterOS-updater/0.1"}
        if config.webhook_token_file:
            headers["Authorization"] = "Bearer " + secret(Path(config.webhook_token_file))
        body = json.dumps({"router": config.name, "phase": phase, "reason": reason})
        path = url.path or "/"
        if url.query:
            path += "?" + url.query
        connection.request("POST", path, body=body, headers=headers)
        return 200 <= connection.getresponse().status < 300
    except Exception:
        return False
    finally:
        connection.close()
