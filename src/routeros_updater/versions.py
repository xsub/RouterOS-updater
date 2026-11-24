import re
from dataclasses import dataclass

from .errors import PolicyError


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int = 0

    @classmethod
    def parse(cls, text: str) -> "Version":
        match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?: \([^\n()]+\))?", text.strip())
        if not match:
            raise PolicyError("Unsupported or prerelease RouterOS version")
        return cls(*(int(part or 0) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}" + (f".{self.patch}" if self.patch else "")


def uptime_seconds(text: str) -> float:
    """RouterOS get uptime uses 1w2d3h4m5s; accept print's HH:MM:SS too."""
    value = text.strip()
    if re.fullmatch(r"(?:\d+w)?(?:\d+d)?\d{1,2}:\d{2}:\d{2}", value):
        prefix, hours, minutes, seconds = re.fullmatch(
            r"((?:\d+w)?(?:\d+d)?)(\d{1,2}):(\d{2}):(\d{2})", value
        ).groups()
        return uptime_seconds(prefix or "0s") + int(hours) * 3600 + int(minutes) * 60 + int(seconds)
    if (
        not re.fullmatch(r"(?:\d+w)?(?:\d+d)?(?:\d+h)?(?:\d+m)?(?:\d+(?:\.\d+)?s)?", value)
        or not value
    ):
        raise PolicyError("Unrecognized RouterOS uptime")
    factors = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    return sum(
        float(number) * factors[unit]
        for number, unit in re.findall(r"(\d+(?:\.\d+)?)([wdhms])", value)
    )
