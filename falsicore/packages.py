"""Package-database parsers and manager detection: dpkg, rpm, pacman, apk.

Pure, total, bounded functions over bytes or text the caller has already read
(safety.safe_read) or captured (the allowlisted executor). Nothing here runs a
package manager, follows a symlink, touches the network or writes a file; the
collector wires these helpers in.

What a recorded digest can and cannot prove
-------------------------------------------
A file whose digest equals the one in the package database matches what the
database SAYS was installed. That is a consistency check between two
root-owned artefacts on the same disk, not an attestation: an adversary with
root can rewrite the file AND its record (dpkg ``*.md5sums``, the rpm
``Packages``/``rpmdb.sqlite`` database, a pacman ``mtree``, apk's
``installed`` index) so that both agree. md5 (dpkg, pacman) and sha1 (apk)
are not collision resistant. A match therefore says "unchanged since recorded
unless deliberately forged"; a mismatch says "differs from the record" and
nothing about who changed it or why (local patch, interrupted upgrade,
prelink, administrator edit). Signed package files fetched from an
independent mirror are the only stronger reference and are out of scope.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Manager detection (file presence only)
# ---------------------------------------------------------------------------

MANAGERS: tuple[str, ...] = ("apk", "dpkg", "pacman", "rpm")
# (manager, path below root, kind). ``rpm`` needs a database file inside the
# directory: Debian's optional ``rpm`` tool ships an empty /var/lib/rpm.
MANAGER_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("dpkg", "var/lib/dpkg/status", "file"),
    ("rpm", "var/lib/rpm", "rpmdb"),
    ("rpm", "usr/lib/sysimage/rpm", "rpmdb"),
    ("pacman", "var/lib/pacman/local", "dir"),
    ("apk", "lib/apk/db/installed", "file"),
)
RPMDB_FILES: tuple[str, ...] = ("Packages", "Packages.db", "rpmdb.sqlite")


def _lstat_chain(root: Path, relative: str) -> os.stat_result | None:
    """lstat of ``root/relative`` provided no component below root is a symlink.

    The root itself is the caller's trust decision and is not inspected.
    Any OSError (absent, unreadable, too deep) reads as "not present".
    """
    current = root
    info: os.stat_result | None = None
    try:
        for part in relative.split("/")[:16]:
            current = current / part
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                return None
    except OSError:
        return None
    return info


def _marker_present(root: Path, relative: str, kind: str) -> bool:
    info = _lstat_chain(root, relative)
    if info is None:
        return False
    if kind == "file":
        return stat.S_ISREG(info.st_mode)
    if not stat.S_ISDIR(info.st_mode):
        return False
    if kind == "dir":
        return True
    # kind == "rpmdb": a regular, non-symlink database file inside the directory.
    return any(_marker_present(root, relative + "/" + name, "file") for name in RPMDB_FILES)


def detect_managers(root: Path | None = None) -> list[str]:
    """Package databases present below ``root`` (default ``/``), sorted.

    Presence of files only: no command is run, no database is opened, no
    symlink is followed (a symlinked component makes its marker "absent";
    Fedora's ``/var/lib/rpm -> ../../usr/lib/sysimage/rpm`` is still found
    through the real directory). Presence of a database is not presence of a
    working package manager, and absence of all markers (``[]``) is not proof
    that nothing is installed: a chroot or container may be unmanaged.
    Checked between lstat and the caller's later read, a path can change;
    the caller re-validates with safety.safe_read.
    """
    base = Path("/") if root is None else root
    found: set[str] = set()
    for manager, relative, kind in MANAGER_MARKERS:
        if manager not in found and _marker_present(base, relative, kind):
            found.add(manager)
    return sorted(found)


# ---------------------------------------------------------------------------
# pacman: BSD mtree as written by libarchive into /var/lib/pacman/local/*/mtree
# ---------------------------------------------------------------------------

MTREE_MAX_LINES = 200_000
MTREE_KEYS = frozenset({"type", "mode", "uid", "gid", "size", "md5", "sha256", "link"})
MTREE_TYPES = frozenset({"file", "dir", "link", "block", "char", "fifo", "socket"})
# Package metadata libarchive lists in the mtree but pacman never installs on disk.
PACMAN_METADATA_ENTRIES = frozenset({"/.BUILDINFO", "/.PKGINFO", "/.INSTALL", "/.CHANGELOG", "/.MTREE"})
_MTREE_KEY_ALIAS = {"md5digest": "md5", "md5": "md5", "sha256digest": "sha256", "sha256": "sha256",
                    "type": "type", "mode": "mode", "uid": "uid", "gid": "gid", "size": "size", "link": "link"}
# Known mtree keywords whose values are not retained (time stamps, other digests,
# device numbers, flags). Unknown keywords are ignored for forward compatibility.
_MTREE_IGNORED = frozenset({
    "time", "uname", "gname", "nlink", "flags", "cksum", "sha1digest", "sha1", "rmd160digest", "rmd160",
    "sha384digest", "sha384", "sha512digest", "sha512", "device", "resdevice", "inode", "contents", "tags",
    "optional", "nochange", "ignore",
})
_MTREE_TOKEN = re.compile(rb"\A[A-Za-z_][A-Za-z0-9_]*(?:=|\Z)")
_MTREE_OCTAL = re.compile(rb"[0-7]{1,3}")
_MTREE_MODE = re.compile(rb"\A[0-7]{1,5}\Z")
_MTREE_DECIMAL = re.compile(rb"\A[0-9]{1,20}\Z")
_MTREE_HEX = re.compile(rb"\A[0-9A-Fa-f]+\Z")
# vis(3) C-style escapes libarchive/mtree may emit for the path and link fields.
_VIS_SIMPLE = {b"s": b" ", b"t": b"\t", b"n": b"\n", b"r": b"\r", b"a": b"\a",
               b"b": b"\b", b"f": b"\f", b"v": b"\v", b"\\": b"\\", b"#": b"#"}


def _unvis(token: bytes) -> bytes | None:
    """Decode vis(3) escapes: ``\\ooo`` octal (1-3 digits), ``\\s`` space and the
    C-style set in _VIS_SIMPLE. Any other or dangling escape is malformed (None);
    ``\\^X``/``\\M-X`` meta forms are not decoded (libarchive never writes them)."""
    if b"\\" not in token:
        return token
    out = bytearray()
    i, n = 0, len(token)
    while i < n:
        ch = token[i:i + 1]
        if ch != b"\\":
            out += ch
            i += 1
            continue
        nxt = token[i + 1:i + 2]
        if not nxt:
            return None
        if nxt in b"01234567":
            m = _MTREE_OCTAL.match(token, i + 1)
            if m is None:
                return None
            value = int(m.group(), 8)
            if value > 255:
                return None
            out.append(value)
            i = m.end()
            continue
        simple = _VIS_SIMPLE.get(nxt)
        if simple is None:
            return None
        out += simple
        i += 2
    return bytes(out)


def _mtree_path(token: bytes) -> str | None:
    """``./usr/bin/x`` -> ``/usr/bin/x``; ``.`` -> ``/``.

    The classic relative form (bare names with ``..`` to pop a directory) is
    not supported: libarchive and pacman always write full ``./`` paths. A
    token starting with ``/`` is an mtree special command, never a path.
    Empty, ``.`` and ``..`` components are malformed, never normalised away.
    Bytes that are not UTF-8 are replaced (U+FFFD); two distinct byte paths
    can therefore map to one key.
    """
    raw = _unvis(token)
    if raw is None:
        return None
    if raw == b".":
        return "/"
    if not raw.startswith(b"./"):
        return None
    raw = raw[1:]
    if any(part in (b"", b".", b"..") for part in raw.split(b"/")[1:]):
        return None
    return raw.decode("utf-8", "replace")


def _mtree_attr(key: str, value: bytes) -> tuple[str, Any] | None:
    """Normalise one ``key=value``; None when the value is malformed for a retained key."""
    name = _MTREE_KEY_ALIAS[key]
    if name == "type":
        text = value.decode("ascii", "replace")
        return (name, text) if text in MTREE_TYPES else None
    if name == "mode":
        if not _MTREE_MODE.match(value):
            return None
        mode = int(value, 8)
        return (name, mode) if mode <= 0o7777 else None
    if name in ("uid", "gid", "size"):
        return (name, int(value)) if _MTREE_DECIMAL.match(value) else None
    if name in ("md5", "sha256"):
        expected = 32 if name == "md5" else 64
        if len(value) != expected or not _MTREE_HEX.match(value):
            return None
        return name, value.decode("ascii").lower()
    target = _unvis(value)  # link
    return (name, target.decode("utf-8", "replace")) if target is not None else None


def _mtree_attrs(tokens: list[bytes]) -> dict[str, Any] | None:
    """Keyword list of one mtree line -> retained attributes; None if any token is malformed."""
    attrs: dict[str, Any] = {}
    for token in tokens[:64]:
        if not _MTREE_TOKEN.match(token):
            return None
        key_raw, has_value, value = token.partition(b"=")
        key = key_raw.decode("ascii")
        if key in _MTREE_KEY_ALIAS:
            if not has_value:
                return None
            parsed = _mtree_attr(key, value)
            if parsed is None:
                return None
            attrs[parsed[0]] = parsed[1]
        # Keywords in _MTREE_IGNORED and unknown keywords carry nothing we retain.
    if len(tokens) > 64:
        return None
    return attrs


def parse_pacman_mtree(raw: bytes) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Parse an already-decompressed pacman ``mtree`` file.

    Returns ``(entries, stats)``. ``entries`` maps the absolute path (leading
    ``.`` stripped) to the attributes known for it, keys a subset of
    MTREE_KEYS: ``type`` (file/dir/link/...), ``mode`` (int, octal in the
    file), ``uid``, ``gid``, ``size`` (int), ``md5``/``sha256`` (lower-case
    hex) and ``link`` (decoded target). ``/set`` defaults are inherited by the
    following entries until ``/unset``; an entry's own keywords win.
    Directories and links are recorded with their ``type`` so the caller can
    skip them; PACMAN_METADATA_ENTRIES are listed but never on disk.

    ``stats`` is ``{"lines", "malformed", "truncated"}``: physical lines
    consumed, lines dropped as malformed (a line is dropped whole: an entry
    with one bad keyword is NOT recorded), and whether MTREE_MAX_LINES
    stopped the parse early. Never raises on content; later duplicates of a
    path replace earlier ones. Line continuations (trailing backslash) are
    not joined because libarchive never writes them.
    """
    entries: dict[str, dict[str, Any]] = {}
    defaults: dict[str, Any] = {}
    lines = malformed = 0
    truncated = False
    for line in raw.splitlines():
        if lines >= MTREE_MAX_LINES:
            truncated = True
            break
        lines += 1
        tokens = line.split()
        if not tokens or tokens[0].startswith(b"#"):
            continue
        head = tokens[0]
        if head == b"/set":
            attrs = _mtree_attrs(tokens[1:])
            if attrs is None:
                malformed += 1
            else:
                defaults.update(attrs)
        elif head == b"/unset":
            names = tokens[1:]
            if names == [b"all"]:
                defaults.clear()
            elif not names or not all(_MTREE_TOKEN.match(n) and b"=" not in n for n in names):
                malformed += 1
            else:
                for n in names:
                    defaults.pop(_MTREE_KEY_ALIAS.get(n.decode("ascii"), ""), None)
        elif head.startswith(b"/"):
            # Only /set and /unset are special commands; libarchive paths start with "./".
            malformed += 1
        else:
            path = _mtree_path(head)
            attrs = _mtree_attrs(tokens[1:])
            if path is None or attrs is None:
                malformed += 1
                continue
            entries[path] = {**defaults, **attrs}
    return entries, {"lines": lines, "malformed": malformed, "truncated": truncated}


# ---------------------------------------------------------------------------
# apk: /lib/apk/db/installed (apk-tools v2 text index)
# ---------------------------------------------------------------------------

APK_MAX_LINES = 1_000_000
APK_FILE_KEYS = frozenset({"package", "sha1_b64", "sha256_b64", "mode", "uid", "gid"})
# Q1 = sha1 (20 bytes -> 28 base64 chars), Q2 = sha256 (32 bytes -> 44 chars).
_APK_Q1 = re.compile(r"\AQ1[A-Za-z0-9+/]{27}=\Z")
_APK_Q2 = re.compile(r"\AQ2[A-Za-z0-9+/]{43}=\Z")
_APK_PERMS = re.compile(r"\A([0-9]{1,10}):([0-9]{1,10}):([0-7]{1,5})(?::.*)?\Z")


def _apk_dir(value: str) -> str | None:
    """``F:`` value -> ``/dir`` (``""`` -> ``/``); relative only, no ``.``/``..``/empty components."""
    if value == "":
        return "/"
    parts = value.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return "/" + value


def parse_apk_installed(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse Alpine's ``/lib/apk/db/installed`` (apk-tools 2.x text format).

    Returns ``(db, stats)``. ``db["packages"]`` lists ``{"name", "version",
    "files"}`` per record in file order; ``db["files"]`` maps the absolute
    path of every ``R:`` entry to ``{"package", "sha1_b64" | "sha256_b64",
    "uid", "gid", "mode"}`` (keys a subset of APK_FILE_KEYS, present when the
    record carried them). ``sha1_b64`` is the base64 after the ``Q1`` prefix
    of the ``Z:`` line; ``mode``/``uid``/``gid`` come from ``a:uid:gid:mode``
    and are absent when apk used its defaults (root:root 0644 for files).

    Records are blank-line separated; a record without ``P:`` is dropped and
    counted malformed once. ``R:`` before any ``F:``, ``a:``/``Z:`` before
    any ``R:``, a name containing ``/`` or an unknown checksum prefix are
    malformed lines. Unknown one-letter keys are ignored. The record in
    progress when APK_MAX_LINES is reached is dropped and ``truncated`` set.

    Not claimed: apk hashes a symlink's TARGET STRING, not a file; the
    caller must lstat before comparing. apk-tools 3 (ADB binary database)
    is not parsed. Directory permissions (``M:``) are not retained.
    """
    packages: list[dict[str, Any]] = []
    files: dict[str, dict[str, Any]] = {}
    lines = malformed = 0
    truncated = False
    name: str | None = None
    version = ""
    pending: list[tuple[str, dict[str, Any]]] = []
    current_dir: str | None = None
    current_file: dict[str, Any] | None = None
    seen_content = False

    def commit() -> None:
        nonlocal malformed, name, version, pending, current_dir, current_file, seen_content
        if seen_content:
            if name is None:
                malformed += 1
            else:
                packages.append({"name": name, "version": version, "files": len(pending)})
                for path, info in pending:
                    files[path] = {"package": name, **info}
        name, version, pending = None, "", []
        current_dir, current_file, seen_content = None, None, False

    for line_bytes in raw.splitlines():
        if lines >= APK_MAX_LINES:
            truncated = True
            break
        lines += 1
        line = line_bytes.decode("utf-8", "replace")
        if not line.strip():
            commit()
            continue
        seen_content = True
        if len(line) < 2 or line[1] != ":":
            malformed += 1
            continue
        key, value = line[0], line[2:]
        if key == "P":
            if not value or value.split() != [value]:
                malformed += 1
            else:
                name = value
        elif key == "V":
            version = value
        elif key == "F":
            current_dir = _apk_dir(value)
            current_file = None
            if current_dir is None:
                malformed += 1
        elif key == "R":
            if current_dir is None or not value or "/" in value or value in (".", ".."):
                malformed += 1
                current_file = None
            else:
                current_file = {}
                pending.append((current_dir.rstrip("/") + "/" + value, current_file))
        elif key == "a":
            perms = _APK_PERMS.match(value)
            if current_file is None or perms is None:
                malformed += 1
            else:
                current_file.update({"uid": int(perms.group(1)), "gid": int(perms.group(2)),
                                     "mode": int(perms.group(3), 8)})
        elif key == "Z":
            if current_file is None:
                malformed += 1
            elif _APK_Q1.match(value):
                current_file["sha1_b64"] = value[2:]
            elif _APK_Q2.match(value):
                current_file["sha256_b64"] = value[2:]
            else:
                malformed += 1
        # C (record checksum), A, S, I, T, U, L, o, m, t, c, D, p, r, i, M: not retained.
    if not truncated:
        commit()
    return {"packages": packages, "files": files}, {"lines": lines, "malformed": malformed, "truncated": truncated}


# ---------------------------------------------------------------------------
# rpm: classification of `rpm -Va` output
# ---------------------------------------------------------------------------

RPM_REVIEW_COUNTERS: tuple[str, ...] = (
    "content_changed_conffiles", "content_changed_other_files", "missing_files", "unverifiable",
    "metadata_changed_only", "dependency_problems", "unparsed_lines",
)
# Attribute column: S M 5 D L U G T P (rpm >= 4.6; older rpm has 8 columns
# without P). "." passed, "?" could not be tested, a letter differs. Then an
# optional type marker (c d g l r a P ...) and an absolute path.
_RPM_LINE = re.compile(r"\A(missing|[SM5DLUGTP.?]{8,9})\s+(?:([A-Za-z])\s+)?(/.*)\Z")
_RPM_DEPENDENCY = re.compile(r"\AUnsatisfied dependencies\b|\b(?:is needed by|conflicts with|is obsoleted by)\b")


def rpm_verify_review(output: str) -> dict:
    """Classify ``rpm -Va`` lines; mirrors detectors.dpkg_verify_review.

    Every non-blank line increments exactly one of RPM_REVIEW_COUNTERS:
    ``(Permission denied)`` suffix -> ``unverifiable`` (not absent, just
    unreadable here); ``missing`` -> ``missing_files`` (first three path
    components tallied in ``missing_by_prefix``, top 10); an attribute
    column with ``5`` in position 3 -> ``content_changed_conffiles`` (type
    marker ``c``) or ``content_changed_other_files``, even when other columns
    are ``?``, because the digest WAS computed and differs; otherwise any
    ``?`` -> ``unverifiable``; otherwise a differing attribute (mode, owner,
    mtime, link target, size, caps) -> ``metadata_changed_only``;
    ``Unsatisfied dependencies`` headers and their ``is needed by`` /
    ``conflicts with`` / ``is obsoleted by`` lines -> ``dependency_problems``;
    anything else (``error:`` lines, an all-dot column) -> ``unparsed_lines``.

    Not claimed: a differing digest is drift from the rpm record, not malware
    attribution; prelink, local patches and interrupted upgrades produce it.
    """
    review: dict[str, Any] = {key: 0 for key in RPM_REVIEW_COUNTERS}
    prefixes: dict[str, int] = {}
    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        m = _RPM_LINE.match(s)
        if s.endswith("(Permission denied)"):
            review["unverifiable"] += 1
        elif m is None:
            review["dependency_problems" if _RPM_DEPENDENCY.search(s) else "unparsed_lines"] += 1
        elif m.group(1) == "missing":
            review["missing_files"] += 1
            prefix = "/" + "/".join(m.group(3).strip().strip("/").split("/")[:3])
            prefixes[prefix] = prefixes.get(prefix, 0) + 1
        else:
            column = m.group(1)
            if column[2] == "5":
                conf = m.group(2) == "c"
                review["content_changed_conffiles" if conf else "content_changed_other_files"] += 1
            elif "?" in column:
                review["unverifiable"] += 1
            elif column.strip("."):
                review["metadata_changed_only"] += 1
            else:
                review["unparsed_lines"] += 1
    review["missing_by_prefix"] = dict(sorted(prefixes.items(), key=lambda kv: (-kv[1], kv[0]))[:10])
    return review


# ---------------------------------------------------------------------------
# Repository trust settings (apt, dnf/yum, pacman, apk)
# ---------------------------------------------------------------------------

REPO_SETTING_CODES = frozenset({
    "APT_TRUSTED_YES", "APT_ALLOW_INSECURE", "APT_ALLOW_WEAK", "APT_ALLOW_DOWNGRADE_TO_INSECURE",
    "APT_ALLOW_UNAUTHENTICATED",
    "DNF_GPGCHECK_OFF", "DNF_REPO_GPGCHECK_OFF", "DNF_LOCALPKG_GPGCHECK_OFF", "DNF_SSLVERIFY_OFF",
    "PACMAN_SIGLEVEL_NEVER", "PACMAN_TRUSTALL", "PACMAN_SIGLEVEL_OPTIONAL",
    "APK_ALLOW_UNTRUSTED",
})
REPO_MAX_LINES = 20_000
# apt's StringToBool: yes/true/on/with/enable/1. dnf: 0/false/no/off.
_APT_TRUE = r"(?:yes|true|on|with|enable|1)"
_DNF_FALSE = r"(?:0|false|no|off)"
# Source options: one-line "deb [key=value ...] URI ..." blocks and deb822 fields.
_APT_OPTION_CODES = {"trusted": "APT_TRUSTED_YES", "allow-insecure": "APT_ALLOW_INSECURE",
                     "allow-weak": "APT_ALLOW_WEAK", "allow-downgrade-to-insecure": "APT_ALLOW_DOWNGRADE_TO_INSECURE"}
_APT_ONE_LINE = re.compile(r"\A\s*deb(?:-src)?\s+\[([^\]]*)\]")
_APT_OPTION = re.compile(r"\A([a-z-]+)=(" + _APT_TRUE + r")\Z", re.I)
_APT_DEB822 = re.compile(r"\A\s*([A-Za-z-]+)\s*:\s*(" + _APT_TRUE + r")\s*\Z", re.I)
_APT_CONF_CODES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("APT_ALLOW_INSECURE", re.compile(r"Acquire::AllowInsecureRepositories\s*\"?" + _APT_TRUE + r"\b", re.I)),
    ("APT_ALLOW_WEAK", re.compile(r"Acquire::AllowWeakRepositories\s*\"?" + _APT_TRUE + r"\b", re.I)),
    ("APT_ALLOW_DOWNGRADE_TO_INSECURE",
     re.compile(r"Acquire::AllowDowngradeToInsecureRepositories\s*\"?" + _APT_TRUE + r"\b", re.I)),
    ("APT_ALLOW_UNAUTHENTICATED",
     re.compile(r"APT::Get::AllowUnauthenticated\s*\"?" + _APT_TRUE + r"\b|(?<![\w-])--allow-unauthenticated(?![\w-])",
                re.I)),
)


def _apt_codes(line: str) -> set[str]:
    codes: set[str] = set()
    block = _APT_ONE_LINE.match(line)
    if block:
        for token in block.group(1).split()[:32]:
            option = _APT_OPTION.match(token)
            if option and option.group(1).lower() in _APT_OPTION_CODES:
                codes.add(_APT_OPTION_CODES[option.group(1).lower()])
    field = _APT_DEB822.match(line)
    if field and field.group(1).lower() in _APT_OPTION_CODES:
        codes.add(_APT_OPTION_CODES[field.group(1).lower()])
    for code, pattern in _APT_CONF_CODES:
        if pattern.search(line):
            codes.add(code)
    return codes
_DNF_KEY = re.compile(r"\A(gpgcheck|repo_gpgcheck|localpkg_gpgcheck|sslverify)\s*=\s*" + _DNF_FALSE + r"\Z", re.I)
_DNF_CODES = {"gpgcheck": "DNF_GPGCHECK_OFF", "repo_gpgcheck": "DNF_REPO_GPGCHECK_OFF",
              "localpkg_gpgcheck": "DNF_LOCALPKG_GPGCHECK_OFF", "sslverify": "DNF_SSLVERIFY_OFF"}
_PACMAN_SIGLEVEL = re.compile(r"\ASigLevel\s*=\s*(.*)\Z")  # pacman keys are case-sensitive


def _apt_live_lines(content: str) -> list[str]:
    """Drop ``#`` comments (sources.list, deb822) and apt.conf ``//`` / ``/* */`` comments."""
    live: list[str] = []
    in_block = False
    for line in content.splitlines()[:REPO_MAX_LINES]:
        text = line
        if in_block:
            end = text.find("*/")
            if end < 0:
                continue
            text, in_block = text[end + 2:], False
        text = text.split("#", 1)[0]
        stripped = text.lstrip()
        if stripped.startswith("//"):
            continue
        if stripped.startswith("/*"):
            end = stripped.find("*/", 2)
            if end < 0:
                in_block = True
                continue
            text = stripped[end + 2:]
        if text.strip():
            live.append(text)
    return live


def detect_insecure_repo_settings(name: str, content: str) -> list[str]:
    """Codes from REPO_SETTING_CODES for trust-reducing settings in repository
    configuration text of manager ``name`` (``apt``, ``dnf``, ``pacman``,
    ``apk``); sorted, duplicates removed, ``[]`` for an unknown manager or
    for text that is entirely comments.

    apt: ``[trusted=yes]`` / ``Trusted: yes`` (APT_TRUSTED_YES), ``Allow-Insecure``,
    ``Allow-Weak``, ``Allow-Downgrade-To-Insecure`` as deb822 fields (whole
    line) or as tokens of the ``deb [...]`` option block of a one-line source
    (the same words inside a URI are data), and the apt.conf equivalents
    ``Acquire::Allow*Repositories "true"`` and
    ``APT::Get::AllowUnauthenticated "true"``. Comments: ``#`` anywhere,
    ``//`` and ``/* */`` at line start. Field names are case-insensitive.
    dnf/yum (``.repo``, ``dnf.conf``): ``gpgcheck``, ``repo_gpgcheck``
    (off is dnf's default; reported only when written explicitly),
    ``localpkg_gpgcheck`` and ``sslverify`` set to 0/false/no/off as the whole
    value; ``#`` and ``;`` comment lines. Case-insensitive.
    pacman.conf: a ``SigLevel`` line (case-sensitive key, global or per
    repository section) whose tokens end in ``Never`` (PACMAN_SIGLEVEL_NEVER,
    ``DatabaseNever`` included), ``TrustAll`` (PACMAN_TRUSTALL) or are
    ``Optional``/``PackageOptional`` (PACMAN_SIGLEVEL_OPTIONAL: unsigned
    packages accepted). ``DatabaseOptional`` is Arch's default and is not
    reported. ``LocalFileSigLevel``/``RemoteFileSigLevel`` are not inspected.
    apk: ``/etc/apk/repositories`` carries no trust flags; only the literal
    ``--allow-untrusted`` in a non-comment line is reported.

    Not claimed: an insecure setting is a hardening fact, not an intrusion;
    a setting apt/dnf would reject as a syntax error may still be reported.
    """
    codes: set[str] = set()
    if name == "apt":
        for line in _apt_live_lines(content):
            codes |= _apt_codes(line)
        return sorted(codes)
    for line in content.splitlines()[:REPO_MAX_LINES]:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if name == "dnf":
            if s.startswith(";"):
                continue
            m = _DNF_KEY.match(s)
            if m:
                codes.add(_DNF_CODES[m.group(1).lower()])
        elif name == "pacman":
            m = _PACMAN_SIGLEVEL.match(s)
            if m is None:
                continue
            for token in m.group(1).split("#", 1)[0].split()[:16]:
                if token.endswith("Never"):
                    codes.add("PACMAN_SIGLEVEL_NEVER")
                elif token.endswith("TrustAll"):
                    codes.add("PACMAN_TRUSTALL")
                elif token in ("Optional", "PackageOptional"):
                    codes.add("PACMAN_SIGLEVEL_OPTIONAL")
        elif name == "apk":
            if "--allow-untrusted" in s.split("#", 1)[0]:
                codes.add("APK_ALLOW_UNTRUSTED")
    return sorted(codes)
