"""Bounded shell-like lexical triage; never a Bash interpreter or full AST.

The supported subset is literal executable/script operands and connected
pipelines. Strings printed as data are not commands. Unsupported expansions,
heredocs and incomplete quoting are reported as analysis limitations. No input
is executed, expanded, sourced, decoded or sent to a subprocess.
"""
from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
MAX_INPUT = 131_072
MAX_DEPTH = 4
MAX_TOKENS = 8192


def _temporary(value: str) -> bool:
    # Normalize dot segments lexically, without following any filesystem link.
    parts: list[str] = []
    if not value.startswith("/"):
        return False
    for part in value.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part not in ("", "."):
            parts.append(part)
    return ("/" + "/".join(parts)).startswith(TEMP_PREFIXES)


def _head(words: list[str]) -> list[str]:
    """Remove a small, documented set of transparent literal wrappers."""
    words = list(words)
    for _ in range(12):
        if not words:
            return []
        first = PurePosixPath(words[0]).name
        if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", words[0], re.S):
            words = words[1:]
        elif first in {"then", "do", "if", "elif", "!", "command", "builtin", "nohup", "setsid", "exec"}:
            words = words[1:]
        elif first in {"sudo", "env"}:
            words = words[1:]
            while words and words[0].startswith("-"):
                option = words.pop(0)
                if option in {"-u", "-g", "-h", "-C", "--user", "--group", "--unset"} and words:
                    words.pop(0)
        else:
            break
    return words


def _command(words: list[str], depth: int, gaps: set[str]) -> tuple[set[str], str, bool]:
    """Return rules, pipeline source class, and whether stdin is shell input."""
    words = _head(words)
    found: set[str] = set()
    if not words:
        return found, "", False
    executable, args = words[0], words[1:]
    name = executable if executable == "." else PurePosixPath(executable).name
    if _temporary(executable):
        found.add("TEMP_PATH_IN_EXECUTION")
    if name in {"echo", "printf"}:
        return found, "", False
    if name in {".", "source"}:
        if args and _temporary(args[0]):
            found.add("TEMP_PATH_IN_EXECUTION")
        return found, "", False
    if name == "eval":
        if args:
            nested = analyze(" ".join(args), depth + 1)
            found.update(nested["patterns"])
            gaps.update(nested["limitations"])
        return found, "", False
    if name in SHELLS:
        if "-c" in args:
            index = args.index("-c") + 1
            if index < len(args):
                nested = analyze(args[index], depth + 1)
                found.update(nested["patterns"])
                gaps.update(nested["limitations"])
            else:
                gaps.add("MISSING_SHELL_COMMAND_OPERAND")
            return found, "", False
        # Bundled -lc/-ic forms are not guessed as script filenames.
        if any(a.startswith("-") and "c" in a[1:] for a in args):
            gaps.add("COMBINED_SHELL_COMMAND_OPTION_NOT_ANALYZED")
            return found, "", False
        if "-s" in args:
            return found, "", True
        operands = [a for a in args if not a.startswith("-")]
        if operands and _temporary(operands[0]):
            found.add("TEMP_PATH_IN_EXECUTION")
        return found, "", not operands
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", name):
        if "-c" in args:
            gaps.add("INLINE_INTERPRETER_CODE_NOT_ANALYZED")
            return found, "", False
        if "-m" not in args:
            operands = [a for a in args if not a.startswith("-")]
            if operands and _temporary(operands[0]):
                found.add("TEMP_PATH_IN_EXECUTION")
    if name.lower() in {"powershell", "pwsh"} and any(a.lower() == "-encodedcommand" for a in args):
        found.add("RISKY_EXECUTION_FLAG")
    if "--disable-web-security" in args:
        found.add("RISKY_EXECUTION_FLAG")
    source = "remote" if name in {"curl", "wget"} else ""
    if name == "base64" and any(a in {"-d", "--decode"} for a in args):
        source = "decoded"
    return found, source, False


def _scan_statement(statement: str, depth: int, gaps: set[str]) -> tuple[set[str], list[str]]:
    try:
        lexer = shlex.shlex(statement, posix=True, punctuation_chars=";&|()<>")
        lexer.whitespace_split = True
        tokens = []
        for token in lexer:
            tokens.append(token)
            if len(tokens) > MAX_TOKENS:
                gaps.add("TOKEN_LIMIT")
                return set(), []
    except ValueError:
        gaps.add("UNPARSED_QUOTING")
        return set(), []
    heredocs = [tokens[i+1] for i, t in enumerate(tokens[:-1]) if t in {"<<", "<<-"}]
    if heredocs:
        gaps.add("HEREDOC_BODY_NOT_ANALYZED")
    if "$" in statement or "`" in statement:
        gaps.add("EXPANSION_NOT_RESOLVED")
    # Lexical parsing does not preserve whether punctuation was quoted. Such
    # edge cases must not be represented as a complete Bash syntax analysis.
    if re.search(r"['\"][;&|()<>]+['\"]", statement):
        gaps.add("QUOTED_OPERATOR_AMBIGUITY")
        return set(), heredocs
    found: set[str] = set()
    word_group: list[str] = []
    pipeline_sources: set[str] = set()
    for token in [*tokens, ";"]:
        if token and set(token) <= set(";&|()"):
            flags, source, shell_input = _command(word_group, depth, gaps)
            found.update(flags)
            if shell_input:
                if "remote" in pipeline_sources:
                    found.add("REMOTE_SCRIPT_PIPELINE")
                if "decoded" in pipeline_sources:
                    found.add("BASE64_DECODE_EXECUTION_CONTEXT")
            if token == "|":
                if source:
                    pipeline_sources.add(source)
            else:
                pipeline_sources.clear()
            word_group = []
        else:
            word_group.append(token)
    return found, heredocs


def analyze(text: str, depth: int = 0) -> dict:
    """Deterministic private-content-free findings with exact start-line hints.

    A match means visible syntax, not actual execution or malicious intent.
    Lines are hints for local inspection; no source content is emitted.
    """
    gaps: set[str] = set()
    if depth > MAX_DEPTH:
        return {"patterns": [], "matches": [], "limitations": ["NESTING_LIMIT"]}
    if len(text) > MAX_INPUT:
        text = text[:MAX_INPUT]
        gaps.add("INPUT_LIMIT")
    patterns: set[str] = set()
    matches: list[dict] = []
    pending, start = "", 1
    heredocs: list[str] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if heredocs:
            if raw.lstrip("\t") == heredocs[0]:
                heredocs.pop(0)
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not pending:
            start = number
        continued = line.endswith(("\\", "|", "&&", "||"))
        pending += (" " if pending else "") + (line[:-1] if line.endswith("\\") else line)
        if continued:
            continue
        found, heredocs = _scan_statement(pending, depth, gaps)
        if found:
            patterns.update(found)
            matches.append({"line": start, "patterns": sorted(found)})
        pending = ""
    if pending:
        gaps.add("INCOMPLETE_CONTINUATION")
        found, _ = _scan_statement(pending, depth, gaps)
        patterns.update(found)
        if found:
            matches.append({"line": start, "patterns": sorted(found)})
    if heredocs:
        gaps.add("UNTERMINATED_HEREDOC")
    return {"patterns": sorted(patterns), "matches": matches, "limitations": sorted(gaps)}
