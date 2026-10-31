"""Fixed, inspectable collection profiles; they are coverage policies, not risk scores."""
from __future__ import annotations

from typing import TypedDict

COLLECTOR_ORDER = (
    "environment", "processes", "network", "persistence",
    "browsers", "auth", "packages", "kernel",
)


class Profile(TypedDict):
    checks: tuple[str, ...]
    duration_seconds: int
    journal_lines: int
    max_file_visits: int
    max_processes: int


# Quick deliberately omits slower historical/package assessment. It is not a full audit.
PROFILES: dict[str, Profile] = {
    "quick": {
        "checks": ("environment", "processes", "network", "persistence", "browsers"),
        "duration_seconds": 35,
        "journal_lines": 0,
        "max_file_visits": 1100,
        "max_processes": 2500,
    },
    "standard": {
        "checks": COLLECTOR_ORDER,
        "duration_seconds": 120,
        "journal_lines": 20000,
        "max_file_visits": 5000,
        "max_processes": 6000,
    },
    "deep": {
        "checks": COLLECTOR_ORDER,
        "duration_seconds": 240,
        "journal_lines": 50000,
        "max_file_visits": 12000,
        "max_processes": 12000,
    },
}


def config_for(name: str) -> Profile:
    if name not in PROFILES:
        raise ValueError("Unknown audit profile")
    return PROFILES[name].copy()
