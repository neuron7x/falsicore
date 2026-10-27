"""One-command local security inspection with offline, verified interpretation."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import sys
from pathlib import Path

from . import __version__
from .collectors import Audit
from .profiles import PROFILES
from . import monitor
from .report import write_reports, verify_reports
from .safety import create_run_directory, safe_read


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="falsicore", description="Offline passive Ubuntu compromise triage, not a clean-system certificate.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="Collect, analyze, write and verify a complete private report")
    scan.add_argument("--scope", choices=("user", "system"), default="user")
    scan.add_argument("--profile", choices=tuple(PROFILES), default="standard")
    scan.add_argument("--max-seconds", type=int, help="Bound collection to 5..600 seconds; overruns become coverage gaps")
    scan.add_argument("--target-user", help="Required for explicit root/system scan")
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
    mon = sub.add_parser("monitor", help="Opt-in local systemd user schedule; no remote notifications")
    mon.add_argument("mode", choices=("plan", "enable", "disable", "status"))
    return p


def explain_report(folder: Path) -> str:
    verification = verify_reports(folder)
    if not verification["verified"]:
        raise ValueError("Report integrity verification failed")
    raw, status = safe_read(folder / "summary.json", 4 * 1024 * 1024)
    if raw is None:
        raise ValueError(f"Summary unavailable: {status}")
    info = json.loads(raw)
    if info.get("schema") != "falsicore.summary.v3":
        raise ValueError("Unsupported report schema")
    pieces = [
        f"ВИСНОВОК: {info['outcome']}",
        info["outcome_explanation_ua"],
        f"Профіль: {info['profile']}; scope: {info['scope']}",
        f"Кількість індикаторів (НЕ доказів): {info['finding_counts_by_kind'].get('INDICATOR', 0)}",
        f"Кількість експозицій: {info['finding_counts_by_kind'].get('EXPOSURE', 0)}",
        f"Прогалин перевірки: {len(info['material_coverage_gaps'])}",
    ]
    for gap in info["material_coverage_gaps"][:12]:
        pieces.append(f"  - {gap['check']}: {gap['status']} — {gap['reason']}")
    pieces.extend(["ДЕТАЛІ: report.md або dashboard.html (локальний HTML без JavaScript)",
                   "МЕЖА: live-scan не може виключити всі приховані атаки чи злам Instagram-акаунта.",
                   f"ХЕШ СПОСТЕРЕЖЕНЬ: {info['analysis_digest_sha256']}"])
    return "\n".join(pieces)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.action == "doctor":
        print(f"FALSICORE {__version__} | Python {sys.version_info.major}.{sys.version_info.minor} | UID={os.geteuid()}")
        print("NO automatic sudo | NO socket connections | NO installs | NO uploads | NO suspicious-code execution")
        print("Private reports 0700/0600; raw endpoint/path mapping stays in private_index.json.")
        for key, profile in PROFILES.items():
            print(f"{key}: {profile['duration_seconds']}s budget, {len(profile['checks'])}/8 collectors, journal limit={profile['journal_lines']}")
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
                print(explain_report(args.folder))
            else:
                result = verify_reports(args.folder)
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
            if args.scope == "user" and args.target_user and args.target_user != pwd.getpwuid(os.getuid()).pw_name:
                raise PermissionError("Unprivileged scan cannot select another user")
            audit = Audit(scope=args.scope, target_user=args.target_user, incident_at=args.incident_at,
                          profile=args.profile, max_seconds=args.max_seconds)
            parent = args.output_base or (Path("/root/falsicore-runs") if args.scope == "system" else audit.home / "falsicore-runs")
            run_dir = create_run_directory(parent)
            audit.scan()
            summary = write_reports(run_dir, audit, compare_report=args.compare,
                                    auto_baseline_parent=parent if args.auto_compare else None)
            if not verify_reports(run_dir)["verified"]:
                raise RuntimeError("Own report manifest did not verify; results MUST NOT be accepted")
        except (ValueError, KeyError, PermissionError, RuntimeError, OSError) as exc:
            print(f"SCAN ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
            if run_dir is not None:
                print(f"INCOMPLETE PRIVATE RUN: {run_dir} (do not rely on contents)", file=sys.stderr)
            return 2
        print(f"⊛ FALSICORE {__version__} | {args.profile} | {args.scope}")
        print(f"ВИСНОВОК: {summary['outcome']}")
        print(summary["outcome_explanation_ua"])
        print(f"ІНДИКАТОРІВ: {summary['finding_counts_by_kind'].get('INDICATOR',0)} (не доказів злому)")
        print(f"ПОМИЛОК КОЛЕКТОРІВ: {summary.get('coverage_status_counts', {}).get('FAILED', 0)}")
        print(f"ПЕРЕВІРОК З ОБМЕЖЕННЯМИ: {len(summary['material_coverage_gaps'])} (не кількість загроз)")
        for finding in getattr(audit, "findings", []):
            if finding["kind"] == "INDICATOR":
                print("  ІНДИКАТОР:", finding["rule"], "|", finding["severity"])
                if finding.get("evidence", {}).get("file_name"):
                    print("    Файл:", finding["evidence"]["file_name"])
                for location in finding.get("evidence", {}).get("locations", []):
                    print("    Рядок:", location["line"], "|", ", ".join(location["patterns"]))
        print("PARTIAL = межа доступних даних; FAILED = збій перевірки. Жоден статус не підтверджує злам.")
        print(f"ЧАС СКАНУВАННЯ: {summary['stats'].get('runtime',{}).get('elapsed_ms','unknown')} мс")
        print(f"ПОПЕРЕДНЄ ПОРІВНЯННЯ: {summary['baseline_comparison']['status']}")
        print(f"VERIFIED PRIVATE REPORT: {run_dir}")
        print(f"OPEN OFFLINE REPORT: {run_dir / 'dashboard.html'}")
        print("PRIVATE: не надсилати private_index.json, токени або сирі журнали в LLM.")
        if args.strict_exit:
            return {"SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION":10,
                    "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS":11}.get(summary["outcome"],0)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
