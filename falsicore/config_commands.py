"""Literal command extraction for cron and desktop files; no evaluation."""
from __future__ import annotations

import re


def cron_commands(text: str, *, system: bool = False) -> str:
    """Strip cron schedule fields, retaining only command text for triage.

    Non-schedule lines (including shell scripts) are retained. This is not
    crontab validation and never expands cron '%' input or environment values.
    """
    output = []
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        fields = value.split(None, 7)
        offset = None
        if fields[0] in {"@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly"}:
            offset = 2 if system else 1
        elif len(fields) >= 6 and all(re.fullmatch(r"[0-9*,/\-A-Za-z]+", f) for f in fields[:5]):
            # Require a scheduling shape rather than treating any shell words
            # as a schedule. Named days/months remain accepted in fields 4/5.
            if all(re.fullmatch(r"[0-9*,/\-]+", f) for f in fields[:3]):
                offset = 6 if system else 5
        if offset is None:
            output.append(line)
        else:
            parts = value.split(None, offset)
            if len(parts) > offset:
                output.append(parts[offset])
    return "\n".join(output)


def desktop_commands(text: str) -> str:
    """Return Exec/TryExec values only; comments and display labels are data."""
    result = []
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() in {"Exec", "TryExec"}:
            result.append(value.strip())
    return "\n".join(result)
