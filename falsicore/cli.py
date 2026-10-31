"""One-command local security inspection with offline, verified interpretation."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import shlex
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .collectors import Audit
from .profiles import COLLECTOR_ORDER, PROFILES
from . import monitor
from . import guide
from .report import LEGACY_SCHEMAS, SCHEMA, load_verified_summary, write_reports, verify_reports
from .safety import create_run_directory, safe_read


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="falsicore", description="Offline passive Linux compromise triage, not a clean-system certificate.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="Collect, analyze, write and verify a complete private report")
    scan.add_argument("--scope", choices=("user", "system"), default="user")
    scan.add_argument("--profile", choices=tuple(PROFILES), default="standard")
    scan.add_argument("--max-seconds", type=int, help="Bound collection to 5..600 seconds; overruns become coverage gaps")
    scan.add_argument("--target-user", help="Required for explicit root/system scan and for --root")
    scan.add_argument("--root", type=Path, help="Scan an offline image mounted at this directory instead of the live host; "
                      "live-only checks are declared, never inferred")
    scan.add_argument("--incident-at", help="ISO 8601 timestamp with offset; time context, not causal attribution")
    scan.add_argument("--output-base", type=Path, help="Private output parent; default ~/falsicore-runs")
    comparison = scan.add_mutually_exclusive_group()
    comparison.add_argument("--compare", type=Path, help="Previous verified and compatible summary.json")
    comparison.add_argument("--auto-compare", action="store_true", help="Compare with most recent compatible, verified, local report")
    scan.add_argument("--strict-exit", action="store_true", help="Exit 10 for suspicious and 11 for inconclusive; report is still written")
    sub.add_parser("doctor", help="Show constraints and profile budgets")
    verify = sub.add_parser("verify", help="Verify complete report manifest, files and privacy")
    verify.add_argument("folder", type=Path)
    explain = sub.add_parser("explain", help="Display readable Ukrainian conclusion from a VERIFIED report only")
    explain.add_argument("folder", type=Path)
    explain.add_argument("--share-safe", action="store_true",
                         help="Omit private attribution (paths, extension IDs, PIDs) for sharing with a helper")
    mon = sub.add_parser("monitor", help="Opt-in local systemd user schedule; no remote notifications")
    mon.add_argument("mode", choices=("plan", "enable", "disable", "status"))
    return p


class Progress:
    """Operator progress on stderr; stdout stays reserved for the result.

    Prints phase transitions and, while a phase runs, an elapsed-time line every
    `interval` seconds. No percentages or ETAs: collector cost is not predictable.
    """

    def __init__(self, audit: Audit | None = None, interval: float = 10.0, stream=None):
        self.audit = audit
        self.interval = interval
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = self.stream is not None
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __call__(self, line: str) -> None:
        # A closed or broken stderr must never abort or redirect a scan:
        # print(file=None) would fall back to stdout, so None disables output.
        if not self.enabled:
            return
        elapsed = time.monotonic() - self.started
        try:
            print(f"[{elapsed:6.1f}s] {line}", file=self.stream, flush=True)
        except (OSError, ValueError):
            self.enabled = False

    def _beat(self) -> None:
        while not self._stop.wait(self.interval):
            phase = getattr(self.audit, "current_phase", None)
            if phase:
                self(f"{phase}: still running")

    def __enter__(self) -> "Progress":
        if self.interval > 0:
            self._thread = threading.Thread(target=self._beat, name="falsicore-progress", daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)


def _report_list(run_dir: Path, name: str, key: str) -> list[dict]:
    """Read back what the verified report says, not in-memory state."""
    raw, _ = safe_read(run_dir / name, 8 * 1024 * 1024)
    return json.loads(raw)[key] if raw else []


def _stderr(line: str) -> None:
    try:
        if sys.stderr is not None:
            print(line, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def legacy_summary(folder: Path, verification: dict) -> str:
    """Read-only view of a report written by an older FALSICORE schema.

    Its file hashes verified, but its semantics differ from this version, so
    counts are shown as recorded and nothing is re-interpreted or compared.
    """
    raw, _ = safe_read(folder / "summary.json", 8 * 1024 * 1024)
    info = json.loads(raw) if raw else {}
    lines = [f"LEGACY REPORT ({verification['schema']}, FALSICORE {info.get('tool_version', '?')}): "
             "хеші файлів збігаються; семантику не перераховано, порівняння з новими звітами некоректне.",
             f"Записаний висновок: {info.get('outcome', '?')}",
             f"Записані знахідки за правилами: {info.get('finding_counts_by_rule', {})}",
             "Записані прогалини: " + ", ".join(f"{g.get('check')}={g.get('status')}" for g in info.get("material_coverage_gaps", [])),
             "Атрибуцію процесів/розширень ця стара схема не зберігала; її не можна відновити заднім числом.",
             "Новий звіт з атрибуцією: ./run.sh"]
    return "\n".join(guide.terminal_safe(x, 800) for x in lines)


def _load_verified(folder: Path) -> tuple[dict, list[dict], list[dict]]:
    verification = verify_reports(folder)
    if not verification["verified"]:
        if verification.get("hashes_verified") and verification.get("schema") != SCHEMA:
            raise ValueError(f"Unsupported report schema {verification.get('schema')!r}; this version reads {SCHEMA}")
        raise ValueError("Report integrity verification failed")
    docs = {}
    for name in ("summary.json", "findings.json", "coverage_matrix.json"):
        raw, status = safe_read(folder / name, 8 * 1024 * 1024)
        if raw is None:
            raise ValueError(f"Summary unavailable: {name} {status}")
        docs[name] = json.loads(raw)
    info = docs["summary.json"]
    if info.get("schema") != SCHEMA:
        raise ValueError(f"Unsupported report schema {info.get('schema')!r}; this version reads {SCHEMA}")
    return info, docs["findings.json"]["findings"], docs["coverage_matrix.json"]["checks"]


def interpretation(info: dict, findings: list[dict], coverage: list[dict], share_safe: bool = False,
                   finding_limit: int = 25) -> list[str]:
    """Ukrainian reading of a report: what ran, what was found, what is unknown, what next.

    share_safe drops private attribution (extension IDs/names, PIDs, paths,
    source refs, digests) so the text can be shown to a helper.
    """
    counts = info["finding_counts_by_kind"]
    out = [f"ВИСНОВОК: {info['outcome']}", info["outcome_explanation_ua"],
           f"Профіль: {info['profile']}; scope: {info['scope']}; правила: {info.get('rule_set_version')}",
           f"Індикатори (не докази): {counts.get('INDICATOR', 0)} · експозиції: {counts.get('EXPOSURE', 0)} · "
           f"налаштування: {counts.get('HARDENING', 0)} · контекст: {counts.get('CONTEXT', 0)}",
           "", "ЩО ПЕРЕВІРЕНО:"]
    for c in coverage:
        line = f"  {c['check']:<12} {c['status']:<9}"
        if c.get("reason_codes"):
            line += " неповнота: " + guide.codes_ua(c["reason_codes"])
        if c.get("scope_limits"):
            line += " | межі scope: " + guide.codes_ua(c["scope_limits"])
        out.append(line)
    if findings:
        out += ["", "ЩО ЗНАЙДЕНО (впорядковано за пріоритетом перевірки):"]
        ordered = sorted(findings, key=lambda f: (guide.rule(f["rule"])["priority"], f["rule"], f["id"]))
        for f in ordered[:finding_limit]:
            g = guide.rule(f["rule"])
            out.append(f"  [{g['priority']}] {f['rule']} ({f['kind']})" + ("" if share_safe else f" {f['id']}"))
            if not share_safe:
                ident = guide.identity_line(f)
                if ident:
                    out.append(f"      про що: {ident}")
            out.append(f"      можливі доброякісні пояснення: {g['benign']}")
            out.append(f"      крок: {g['action']}")
        if len(findings) > finding_limit:
            out.append(f"  … ще {len(findings) - finding_limit}; повний перелік — report.md")
    out += ["", "ЧОГО НЕ ВСТАНОВЛЕНО: " + "; ".join(info.get("cannot_exclude", [])[:6])]
    if not share_safe:
        out.append(f"ХЕШ СПОСТЕРЕЖЕНЬ: {info['analysis_digest_sha256']}")
    else:
        out.append("SHARE-SAFE: без шляхів, ID розширень, PID і посилань на джерела.")
    return [guide.terminal_safe(x, 600) for x in out]


def explain_report(folder: Path, share_safe: bool = False) -> str:
    info, findings, coverage = _load_verified(folder)
    return "\n".join(interpretation(info, findings, coverage, share_safe, finding_limit=350))


def _baseline_preflight(path: Path, scope: str, profile: str, uid: int) -> None:
    """Refuse an incompatible --compare BEFORE collecting, naming the fields."""
    old = load_verified_summary(path)
    expected = {"schema": SCHEMA, "tool_version": __version__, "rule_set_version": __version__,
                "scope": scope, "profile": profile, "target_uid": uid}
    differing = [k for k, v in expected.items() if old.get(k) != v]
    if differing:
        raise ValueError("Базовий звіт несумісний, поля відрізняються: " + ", ".join(differing)
                         + ". Порівнювати різні версії правил, профілі чи scope некоректно.")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.action == "doctor":
        print(f"FALSICORE {__version__} | Python {sys.version_info.major}.{sys.version_info.minor} | UID={os.geteuid()}")
        print("NO automatic sudo | NO socket connections | NO installs | NO uploads | NO suspicious-code execution")
        print("Private reports 0700/0600; raw endpoint/path mapping stays in private_index.json.")
        for key, profile in PROFILES.items():
            print(f"{key}: {profile['duration_seconds']}s budget, {len(profile['checks'])}/{len(COLLECTOR_ORDER)} collectors, journal limit={profile['journal_lines']}")
        print("System/root scope opt-in, with --target-user. Advanced/remote compromise cannot be excluded.")
        return 0
    if args.action == "monitor":
        bundle = Path(__file__).resolve().parent.parent
        try:
            if args.mode == "plan":
                service, timer = monitor.unit_contents(bundle)
                print("READ-ONLY PLAN: daily user-level timer at 03:00 UTC.")
                print(service + "\n" + timer)
                return 0
            if args.mode == "status":
                print(monitor.status())
                return 0
            home = Path(pwd.getpwuid(os.getuid()).pw_dir)
            print(monitor.enable(bundle, home) if args.mode == "enable" else monitor.disable(bundle, home))
        except (ValueError, PermissionError, OSError, RuntimeError) as exc:
            print(f"MONITOR ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.action in ("verify", "explain"):
        try:
            if args.action == "explain":
                legacy = verify_reports(args.folder)
                if not legacy["verified"] and legacy.get("hashes_verified") and legacy.get("schema") in LEGACY_SCHEMAS:
                    print(legacy_summary(args.folder, legacy))
                    return 0
                print(explain_report(args.folder, share_safe=args.share_safe))
            else:
                result = verify_reports(args.folder)
                if not result["verified"] and result.get("hashes_verified") and result.get("schema") in LEGACY_SCHEMAS:
                    print(f"LEGACY {result['schema']}: file hashes PASS; semantics of an older version are not re-verified")
                    return 0
                print("VERIFIED" if result["verified"] else "INVALID")
                for row in result["entries"]:
                    print(f"{'PASS' if row['verified'] else 'FAIL'} {row['entry']}")
                return 0 if result["verified"] else 2
        except (ValueError, PermissionError, OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"REPORT ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.action == "scan":
        run_dir = None
        try:
            if sys.version_info < (3, 10):
                raise RuntimeError("Python >=3.10 required")
            if args.root is not None:
                if args.root.is_symlink() or not args.root.is_dir():
                    raise ValueError("--root must be an existing directory (a mounted image)")
                if args.root.absolute() == Path("/"):
                    raise ValueError("--root / is the live host; omit --root for a live scan")
            elif args.scope == "user" and args.target_user and args.target_user != pwd.getpwuid(os.getuid()).pw_name:
                raise PermissionError("Unprivileged scan cannot select another user")
            audit = Audit(scope=args.scope, target_user=args.target_user, incident_at=args.incident_at,
                          profile=args.profile, max_seconds=args.max_seconds,
                          root=args.root if args.root is not None else "/", offline=args.root is not None)
            if args.compare is not None:
                _baseline_preflight(args.compare, args.scope, args.profile, audit.uid)
            if args.output_base is not None:
                parent = args.output_base
            elif getattr(audit, "offline", False) or os.geteuid() == 0:
                parent = Path(pwd.getpwuid(os.geteuid()).pw_dir) / "falsicore-runs"
            else:
                parent = audit.home / "falsicore-runs"
            run_dir = create_run_directory(parent)
            progress = Progress(audit)
            budget = args.max_seconds or PROFILES[args.profile]["duration_seconds"]
            progress(f"FALSICORE {__version__} | profile={args.profile} | scope={args.scope} | "
                     f"mode={'offline:' + str(args.root) if getattr(audit, 'offline', False) else 'live'} | uid={os.geteuid()} | "
                     f"whole-scan budget={budget}s | collectors={len(PROFILES[args.profile]['checks'])}/{len(COLLECTOR_ORDER)}")
            progress(f"private run directory: {run_dir}")
            with progress:
                audit.scan(progress=progress)
            progress("analysis and report writing")
            summary = write_reports(run_dir, audit, compare_report=args.compare,
                                    auto_baseline_parent=parent if args.auto_compare else None)
            progress("verifying own report manifest")
            if not verify_reports(run_dir)["verified"]:
                raise RuntimeError("Own report manifest did not verify; results MUST NOT be accepted")
            progress("done")
        except (ValueError, KeyError, PermissionError, RuntimeError, OSError) as exc:
            _stderr(f"SCAN ERROR: {type(exc).__name__}: {exc}")
            if run_dir is not None:
                _stderr(f"INCOMPLETE PRIVATE RUN: {run_dir} (do not rely on contents)")
            return 2
        except KeyboardInterrupt:
            # Owned probe groups were already killed by the executor.
            _stderr("SCAN CANCELLED: скасовано оператором; звіт не сформовано.")
            if run_dir is not None:
                _stderr(f"INCOMPLETE PRIVATE RUN: {run_dir} (do not rely on contents)")
            return 130
        findings = _report_list(run_dir, "findings.json", "findings")
        coverage = _report_list(run_dir, "coverage_matrix.json", "checks")
        print(f"⊛ FALSICORE {__version__} | {args.profile} | {args.scope}")
        for line in interpretation(summary, findings, coverage, finding_limit=12):
            print(line)
        print("PARTIAL = ціль перевірки оглянуто не повністю; межі scope = чого цей режим не бачить за задумом. Жоден статус не підтверджує злам.")
        print(f"ЧАС СКАНУВАННЯ: {summary['stats'].get('runtime',{}).get('elapsed_ms','unknown')} мс")
        comparison = summary["baseline_comparison"]
        print(f"ПОПЕРЕДНЄ ПОРІВНЯННЯ: {comparison['status']}"
              + (f" (пропущено: {comparison['skipped_candidates']})" if comparison.get("skipped_candidates") else ""))
        print(f"VERIFIED PRIVATE REPORT: {run_dir}")
        print(f"OPEN OFFLINE REPORT: {run_dir / 'dashboard.html'}")
        print("SHARE-SAFE TEXT: python3 -I " + shlex.quote(str(Path(sys.argv[0]).absolute()))
              + " explain --share-safe " + shlex.quote(str(run_dir)))
        print("PRIVATE: не надсилати private_index.json, токени або сирі журнали в LLM.")
        if args.strict_exit:
            return {"SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION":10,
                    "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS":11}.get(summary["outcome"],0)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
