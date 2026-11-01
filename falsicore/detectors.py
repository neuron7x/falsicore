"""Pure, testable detection helpers. Never execute or evaluate input content."""
from __future__ import annotations

import hashlib
import fnmatch
import ipaddress
import json
import re
from typing import Any, Iterable

MAX_JSON_BYTES = 1_048_576

SUSPICIOUS_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/")
BAD_BROWSER_FLAGS = (
    "--no-sandbox", "--disable-web-security", "--ignore-certificate-errors",
    "--allow-running-insecure-content", "--disable-site-isolation-trials",
)
REVIEW_BROWSER_FLAGS = ("--remote-debugging-port", "--remote-debugging-pipe", "--load-extension")
SENSITIVE_EXTENSION_PERMS = {
    "cookies", "debugger", "nativeMessaging", "proxy", "webRequest",
    "webRequestBlocking", "management", "history", "tabs", "scripting",
    "declarativeNetRequestWithHostAccess",
}
INJECTION_PHRASES = (
    "ignore previous instructions", "system prompt:", "developer instructions:",
    "you are now", "assistant: execute", "instruction override",
)


def digest(value: bytes | str, length: int = 16) -> str:
    value = value.encode("utf-8", "replace") if isinstance(value, str) else value
    return hashlib.sha256(value).hexdigest()[:length]


def is_temp_executable(path: str) -> bool:
    p = path.removesuffix(" (deleted)")
    return any(p.startswith(prefix) for prefix in SUSPICIOUS_PATHS)


def classify_executable(path: str, uid: int, deleted: bool = False) -> list[tuple[str, str]]:
    """(rule, severity); indicators never mean confirmed compromise."""
    found: list[tuple[str, str]] = []
    if is_temp_executable(path):
        found.append(("EXECUTABLE_IN_VOLATILE_PATH", "high" if uid == 0 else "medium"))
    if deleted or path.endswith(" (deleted)"):
        found.append(("DELETED_RUNNING_EXECUTABLE", "medium"))
    if uid == 0 and path.startswith(("/home/", "/run/user/")):
        found.append(("ROOT_RUNNING_USER_PATH", "medium"))
    return found


def suspect_command(text: str) -> list[str]:
    """Literal command-context heuristics; see shell_syntax.analyze for gaps."""
    from .shell_syntax import analyze
    return analyze(text)["patterns"]


def systemd_execs(content: object) -> list[str]:
    if not isinstance(content, str):
        return []
    lines = []
    for line in content.splitlines():
        s = line.strip()
        if s.startswith(("#", ";")):
            continue
        if re.match(r"^(ExecStart|ExecStartPre|ExecStartPost|ExecReload)\s*=", s, re.I):
            lines.append(s.split("=", 1)[1].strip())
    return lines


def suspicious_systemd(content: str) -> list[str]:
    # A temp path used as a cache/log argument is not a temp executable.
    return sorted({rule for command in systemd_execs(content)
                   for rule in suspect_command(command)})


def safe_json_parse(raw: bytes, limit: int = MAX_JSON_BYTES) -> Any:
    if len(raw) > limit:
        raise ValueError("JSON exceeds size limit")
    return json.loads(raw.decode("utf-8-sig", "replace"))


BROAD_HOST_PATTERNS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "ws://*/*", "wss://*/*")


def match_pattern_host(pattern: str) -> str | None:
    """Host part of a WebExtension match pattern, or None when the grammar is not met.

    Deliberately bounded static model: no DNS, no JavaScript evaluation, no
    runtime grant inspection. `<all_urls>` is returned as "*".
    """
    if pattern == "<all_urls>":
        return "*"
    if not isinstance(pattern, str) or "://" not in pattern:
        return None
    scheme, rest = pattern.split("://", 1)
    if scheme not in ("*", "https", "http", "file", "ftp", "ws", "wss"):
        return None
    host = rest.split("/", 1)[0].lower()   # no mutate: element 0 is the same for any maxsplit >= 1
    if not host or not all(ch.isalnum() or ch in "*.-" for ch in host):
        return None
    return host


def grants_host_access(pattern: str, hosts: Iterable[str]) -> bool:
    """Whether a match pattern reaches ANY of `hosts` (exact grammar, no substrings).

    A substring test would accept fakeexample.com or example.com.evil.invalid
    for example.com; the match-pattern host grammar does not.
    """
    host = match_pattern_host(pattern)
    if host is None:
        return False
    return any(fnmatch.fnmatchcase(candidate.lower(), host) for candidate in hosts)


def host_scope(patterns: Iterable[str]) -> str:
    """all_urls > wildcard_domains > specific > none, over valid match patterns only."""
    scope = "none"
    for pattern in patterns:
        host = match_pattern_host(pattern)
        if host is None:
            continue
        if host == "*":
            return "all_urls"
        if "*" in host:
            scope = "wildcard_domains"
        elif scope == "none":
            scope = "specific"
    return scope


def extension_assessment(manifest: dict) -> dict:
    """Works with MV2/MV3. Static permission review only; no site is special-cased.

    Capability is declared, not observed behaviour. `risk_flag` marks an
    extension that can read or alter web content or browser state: a
    sensitive API together with any host access, a content script on broad
    hosts, the debugger API or native messaging.
    """
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    permissions = manifest.get("permissions", [])
    hosts = manifest.get("host_permissions", [])
    optional = manifest.get("optional_permissions", [])
    if not isinstance(permissions, list):
        permissions = []
    if not isinstance(hosts, list):
        hosts = []
    if not isinstance(optional, list):
        optional = []
    entries = [x for x in permissions if isinstance(x, str)]
    host_entries = [x for x in (hosts + entries) if isinstance(x, str) and ("://" in x or x == "<all_urls>")]
    sensitive = sorted(set(entries) & SENSITIVE_EXTENSION_PERMS)
    wide = any(x in BROAD_HOST_PATTERNS for x in host_entries)
    content_matches: list[str] = []
    content_scripts = manifest.get("content_scripts", [])
    if isinstance(content_scripts, list):
        for cs in content_scripts:
            if isinstance(cs, dict):
                matches = cs.get("matches", [])
                content_matches.extend(m for m in (matches if isinstance(matches, list) else []) if isinstance(m, str))
    scripts_scope = host_scope(content_matches)
    declared_scope = host_scope(host_entries)
    any_host = declared_scope != "none" or scripts_scope != "none"
    return {
        "manifest_version": manifest.get("manifest_version"),
        "sensitive_permissions": sensitive,
        "broad_host_access": wide or declared_scope == "all_urls",
        "host_scope": declared_scope,
        "declared_host_count": len(host_entries),
        "content_script_scope": scripts_scope,
        "content_script_count": len(content_matches),
        "optional_sensitive_permissions": sorted({x for x in optional if isinstance(x, str)} & SENSITIVE_EXTENSION_PERMS),
        "has_native_host_access": "nativeMessaging" in sensitive,
        "risk_flag": bool(sensitive and any_host) or scripts_scope in ("all_urls", "wildcard_domains")
                     or "debugger" in sensitive or "nativeMessaging" in sensitive,
    }


def analyze_browser_flags(argv: list[str]) -> list[str]:
    out = []
    for a in argv:
        for flag in BAD_BROWSER_FLAGS:
            if a == flag or a.startswith(flag + "="):
                out.append(flag)
        for flag in REVIEW_BROWSER_FLAGS:
            if a == flag or a.startswith(flag + "="):
                out.append(flag)
    return sorted(set(out))


SANDBOX_REDUCING_FLAGS = ("--no-sandbox", "--disable-web-security", "--disable-site-isolation-trials")
TRUST_REDUCING_FLAGS = ("--ignore-certificate-errors", "--allow-running-insecure-content")


def browser_flag_review(argv: list[str]) -> dict:
    """Separate what each flag actually changes.

    --remote-debugging-pipe exposes DevTools over inherited file descriptors to
    the launching process only: it opens no network port. Only
    --remote-debugging-port can create a listener, which is correlated with the
    observed socket table separately, never assumed.
    """
    flags = analyze_browser_flags(argv)
    port = None
    for a in argv:
        if a.startswith("--remote-debugging-port="):
            value = a.split("=", 1)[1]
            port = value if value.isdigit() and 0 <= int(value) <= 65535 else "INVALID"
    channel = ("port" if "--remote-debugging-port" in flags
               else "pipe" if "--remote-debugging-pipe" in flags else None)
    sandbox = any(f in flags for f in SANDBOX_REDUCING_FLAGS)
    parts = []
    if sandbox:
        parts.append("browser renderer sandbox or site isolation reduced")
    if any(f in flags for f in TRUST_REDUCING_FLAGS):
        parts.append("TLS/content trust checks relaxed")
    if channel == "pipe":
        parts.append("DevTools control over a local pipe held by the launching process (no network port)")
    elif channel == "port":
        parts.append("DevTools control over a TCP port; reachability depends on the observed listener")
    if "--load-extension" in flags:
        parts.append("unpacked extension loaded from the command line")
    return {"flags": flags, "sandbox_reduced": sandbox, "debug_channel": channel, "debug_port": port,
            "hypothesis": "; ".join(parts) or "browser launched with review-worthy flags"}


def dpkg_verify_review(output: str) -> dict:
    """Classify `dpkg --verify` lines: '??5??????' (md5 differs), 'missing',
    or '?' in the md5 column (could not be checked, e.g. unreadable as user).

    Only the third column carries a result in current dpkg; a 'c' marks a
    conffile. Paths are reduced to their first three components.
    """
    review: dict[str, Any] = {"content_changed_conffiles": 0, "content_changed_other_files": 0,
                              "missing_files": 0, "unverifiable": 0, "unparsed_lines": 0}
    prefixes: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        conf = len(parts) >= 3 and parts[1] == "c"
        path = parts[-1]
        if line.rstrip().endswith("(Permission denied)"):
            # "missing <path> (Permission denied)": not absent, just unreadable here.
            review["unverifiable"] += 1
        elif parts[0] == "missing":
            review["missing_files"] += 1
            prefix = "/" + "/".join(path.strip("/").split("/")[:3])
            prefixes[prefix] = prefixes.get(prefix, 0) + 1
        elif len(parts[0]) == 9 and parts[0][2] == "5":
            review["content_changed_conffiles" if conf else "content_changed_other_files"] += 1
        elif len(parts[0]) == 9 and parts[0][2] == "?":
            review["unverifiable"] += 1
        else:
            review["unparsed_lines"] += 1
    review["missing_by_prefix"] = dict(sorted(prefixes.items(), key=lambda kv: (-kv[1], kv[0]))[:10])
    return review


def endpoint_class(endpoint: str) -> str:
    """Address classification without DNS resolution or contacting endpoint."""
    ep = endpoint.strip()
    if ep in ("*", "*:*", "0.0.0.0:*", "[::]:*"):
        return "wildcard"
    if ep.startswith("["):
        host = ep.split("]", 1)[0][1:]
    else:
        host = ep.rsplit(":", 1)[0] if ":" in ep else ep
    if host.startswith("%"):
        return "unknown"
    if host in ("0.0.0.0", "::", "*"):
        return "wildcard"
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_global:
        return "public"
    return "other"


def parse_ss(text: str) -> list[dict]:
    """ss -H -tuna[p] output. No remote IP addresses are returned."""
    out = []
    for line in text.splitlines():
        bits = line.split()
        if len(bits) < 5:
            continue
        proto, state = bits[0], bits[1]
        local, remote = bits[4], bits[5] if len(bits) > 5 else ""
        if proto not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        port = local.rsplit(":", 1)[-1]   # no mutate: the last element is the same for any maxsplit >= 1
        if not port.isdigit():
            port = "?"
        out.append({
            "proto": proto, "state": state, "local_class": endpoint_class(local),
            "local_port": port, "remote_class": endpoint_class(remote),
            "remote_id": digest(remote) if remote and endpoint_class(remote) != "wildcard" else None,
            "has_process_info": "pid=" in line,
            "pids": sorted({int(v) for v in re.findall(r"\bpid=(\d+)", line)}),
        })
    return out


def detect_journal_message(message: str) -> list[str]:
    """Extract only rule IDs; no raw message in artifacts."""
    m = message.lower()
    patterns = {
        "SSH_ACCEPTED": r"\baccepted (?:publickey|password|keyboard-interactive)\b",
        "SSH_FAILED": r"\bfailed (?:password|publickey)\b",
        "SUDO_SESSION": r"\bsudo(?:\[\d+\])?:|\bcommand=",
        "SEGFAULT": r"\bsegfault\b|\bsegmentation fault\b",
        "APPARMOR_DENIED": r"apparmor=\"?denied|apparmor.*denied",
        "NEW_USER": r"\bnew user\b|\buseradd\b",
        "CRON_EVENT": r"\bcron\[|\bcrond\[",
        "OOM_EVENT": r"out of memory|\boom-killer\b",
    }
    return [name for name, pat in patterns.items() if re.search(pat, m)]


def normalized_finding_summary(findings: Iterable[dict]) -> dict:
    groups: dict[str, int] = {}
    for f in findings:
        groups[f.get("rule", "UNKNOWN")] = groups.get(f.get("rule", "UNKNOWN"), 0) + 1
    return dict(sorted(groups.items()))


def interpret_verdict(findings: list[dict], coverage: list[dict]) -> str:
    """No automated rule is sufficient to declare confirmed compromise."""
    strong = [f for f in findings if f.get("kind", "INDICATOR") == "INDICATOR" and f.get("severity") in ("high", "critical")]
    medium = [f for f in findings if f.get("kind", "INDICATOR") == "INDICATOR" and f.get("severity") == "medium"]
    if strong or medium:
        return "SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION"
    essential = {"processes", "network", "persistence", "browsers", "auth", "packages", "crossview"}
    # On an offline image the live-only checks are declared, not missing: the
    # verdict then speaks about the disk, and the coverage rows say so.
    offline = {x.get("check") for x in coverage
               if x.get("status") == "SKIPPED" and x.get("check") in
               {"processes", "network", "crossview"} and (
                   "LIVE_ONLY_NOT_IN_OFFLINE_IMAGE" in (x.get("reason_codes") or {}) or
                   "LIVE_ONLY_NOT_IN_OFFLINE_IMAGE" in (x.get("scope_limits") or {}))}
    essential -= offline
    incomplete = [x for x in coverage if x.get("check") in essential and x.get("status") != "COMPLETED"]
    observed = {x.get("check") for x in coverage}
    if incomplete or (essential - observed):
        return "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS"
    return "NO_COMPROMISE_INDICATORS_OBSERVED"


def baseline_diff(old: dict, new: dict) -> dict:
    """Compare selected stable fingerprints; baseline is untrusted unless independently preserved."""
    keys = ("process_exe_hashes", "listeners", "systemd_units", "cron_entry_hashes", "ssh_key_fingerprints", "browser_extensions", "native_hosts")
    result = {}
    for key in keys:
        prior = set(str(x) for x in old.get(key, []) if isinstance(x, (str, int)))
        present = set(str(x) for x in new.get(key, []) if isinstance(x, (str, int)))
        result[key] = {"added": sorted(present - prior)[:200], "removed": sorted(prior - present)[:200]}
    return result


def redact_untrusted_text(text: str) -> str:
    """No raw untrusted text used in exported findings. Output an identifier only."""
    return f"UNTRUSTED_TEXT[sha256={digest(text, 32)},length={len(text)}]"


def is_instruction_contaminated(s: str) -> bool:
    return any(p in s.casefold() for p in INJECTION_PHRASES)
