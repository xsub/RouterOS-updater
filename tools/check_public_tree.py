"""Check tracked source files for common accidental publication hazards."""

import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT_FILES = {
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "pyproject.toml",
    ".gitignore",
    "MANIFEST.in",
    "requirements.in",
    "requirements.lock",
    "build-requirements.in",
    "build-requirements.lock",
}
ROOT_DIRS = {"src", "tests", "tools", "deploy", "examples", "docs", ".github"}
PRIVATE_PARTS = {
    "local",
    "private",
    "local-config",
    "__pycache__",
    "dist",
    "build",
    "htmlcov",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
}
PRIVATE_SUFFIXES = {
    ".backup",
    ".rsc",
    ".key",
    ".ssh-key",
    ".backup-password",
    ".known_hosts",
    ".pem",
    ".p12",
    ".pfx",
    ".pcap",
    ".pcapng",
    ".pyc",
    ".whl",
    ".xml",
}
PATTERNS = [
    ("private key", re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("access token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("fine-grained token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("cloud access key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("personal home path", re.compile(rb"/(?:Users|home)/[^/\s\"']+/")),
    ("machine-local temporary path", re.compile(rb"/private/(?:tmp|var)/")),
]


def violations(path: PurePosixPath, data: bytes) -> list[str]:
    reasons = []
    if len(path.parts) == 1 and path.name not in ROOT_FILES:
        reasons.append("unexpected root file")
    if len(path.parts) > 1 and path.parts[0] not in ROOT_DIRS:
        reasons.append("unexpected source directory")
    if any(part in PRIVATE_PARTS or part.startswith(".venv") for part in path.parts):
        reasons.append("private/generated directory")
    if path.suffix in PRIVATE_SUFFIXES or path.name.startswith(".env"):
        reasons.append("credential, capture or generated artifact")
    if path.name in {"state.json", "events.jsonl", "metrics.prom", "dev-environment.txt"}:
        reasons.append("runtime data")
    if path.parts[0] == "docs" and path.suffix != ".md":
        reasons.append("raw documentation report")
    for label, pattern in PATTERNS:
        if pattern.search(data):
            reasons.append(label)
    try:
        data.decode("utf-8")
    except UnicodeError:
        reasons.append("binary file")
    return reasons


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    git = shutil.which("git")
    if not git:
        print("Git is required to inspect the publication boundary.", file=sys.stderr)
        return 2
    try:
        result = subprocess.run(  # noqa: S603 -- fixed read-only command, no shell
            [git, "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        names = [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        print("Cannot read tracked source paths.", file=sys.stderr)
        return 2
    if not names:
        print("No tracked files to inspect.", file=sys.stderr)
        return 2
    failed = False
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file():
            print(f"{name}: unexpected file type", file=sys.stderr)
            failed = True
            continue
        for reason in violations(PurePosixPath(name), path.read_bytes()):
            print(f"{name}: {reason}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"Publication check passed for {len(names)} tracked source files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
