"""Fail-closed, offline, interpretable reporting with explicit provenance limitations."""
from __future__ import annotations

import hashlib
import html
import json
import os
import stat
from collections import Counter
from pathlib import Path

from . import __version__, detectors as d
from .safety import exclusive_write, write_json, utc_now, safe_read

SCHEMA = "falsicore.summary.v3"
OUTCOME_UA = {
    "NO_COMPROMISE_INDICATORS_OBSERVED": "У ДОСТУПНИХ перевірених даних ознак компрометації не виявлено; це НЕ доказ повної безпеки.",
    "SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION": "Є індикатори, які потребують незалежної перевірки. Факт злому НЕ встановлено.",
    "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS": "Недостатньо доступних даних для висновку. Прогалини не означають відсутності атаки.",
}
KIND_UA = {"INDICATOR":"Індикатор (НЕ доказ)", "EXPOSURE":"Потенційна експозиція", "HARDENING":"Налаштування захисту", "CONTEXT":"Контекст"}
SEVERITY_ORDER = {"critical":0, "high":1, "medium":2, "low":3, "info":4}
REQUIRED = {"summary.json", "findings.json", "coverage_matrix.json", "command_audit.json",
            "private_index.json", "report.md", "dashboard.html", "next_actions.md"}
OPTIONAL = {"baseline_diff.json"}


def host_ref() -> str:
    raw, status = safe_read(Path("/etc/machine-id"), 4096)
    if raw and raw.strip():
        return d.digest(raw.strip(), 32)
    return "UNAVAILABLE"


def stable_findings(findings: list[dict]) -> list[dict]:
    """Same set of observations => same IDs and order regardless of enumeration order."""
    keyed = []
    seen_fingerprints: set[str] = set()
    for finding in findings:
        item = dict(finding)
        item.pop("id", None)
        payload = json.dumps(item, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        full = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if full in seen_fingerprints:
            continue  # identical observations are one finding, not duplicate notifications
        seen_fingerprints.add(full)
        item["id"] = "F-" + full[:20]
        keyed.append((SEVERITY_ORDER.get(item.get("severity"), 5), item.get("rule", ""), full, item))
    return [item for _, _, _, item in sorted(keyed)]


def _analysis_digest(findings: list[dict], coverage: list[dict]) -> str:
    """Digest of normalized observations only; excludes clock, duration and run location."""
    payload = {
        "findings": [{k: v for k, v in f.items() if k != "id"} for f in stable_findings(findings)],
        "coverage": sorted(
            ({"check": c["check"], "status": c["status"], "details": c.get("details", "")}
             for c in coverage), key=lambda c: (c["check"], c["status"])),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def report_data(audit) -> dict:
    coverage = sorted(audit.coverage, key=lambda c: c["check"])
    findings = stable_findings(audit.findings)
    verdict = d.interpret_verdict(findings, coverage)
    if audit.dropped_findings and verdict == "NO_COMPROMISE_INDICATORS_OBSERVED":
        verdict = "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS"
    statuses = Counter(c["status"] for c in coverage)
    gaps = [{"check": c["check"], "status": c["status"], "reason": c.get("details", "")}
            for c in coverage if c["status"] != "COMPLETED"]
    return {
        "schema": SCHEMA,
        "tool_version": __version__, "created_utc": utc_now(),
        "scope": audit.scope, "profile": getattr(audit, "profile", "standard"),
        "target_uid": getattr(audit, "uid", None), "host_ref": host_ref(),
        "outcome": verdict, "outcome_explanation_ua": OUTCOME_UA[verdict],
        "confirmed_compromise": False, "confirmed_attacker_attribution": False,
        "analysis_digest_sha256": _analysis_digest(findings, coverage),
        "cannot_exclude": [
            "zero-day exploitation", "past attacks with no retained artifacts",
            "adversary with root/kernel control", "firmware or hardware compromise",
            "server-side Instagram or other account compromise", "tampering with local telemetry",
        ],
        "coverage_status_counts": dict(sorted(statuses.items())),
        "material_coverage_gaps": gaps,
        "finding_counts_by_kind": dict(sorted(Counter(f["kind"] for f in findings).items())),
        "finding_counts_by_rule": d.normalized_finding_summary(findings),
        "findings_limited": bool(audit.dropped_findings),
        "stats": audit.stats,
        "baseline": {k: sorted(set(v)) for k, v in audit.baseline.items()},
    }


def recommendations(audit) -> list[str]:
    present = {x["rule"] for x in audit.findings}
    items = []
    if "SUSPICIOUS_SHELL_INIT" in present:
        items.append("SHELL: Є збіг синтаксису команди, а не доказ злому. Перевірити локально позначений файл і номери рядків; не виконувати команду й не надсилати конфігурацію в чат.")
    if present & {"SUSPICIOUS_SYSTEMD_EXECUTION", "SUSPICIOUS_CRON_EXECUTION", "SUSPICIOUS_USER_CRONTAB"}:
        items.append("PRIORITY 1: Перевірити позначені systemd/cron-конфігурації, походження файлів і відповідні події. НЕ запускати підозрілий код.")
    if present & {"EXECUTABLE_IN_VOLATILE_PATH", "DELETED_RUNNING_EXECUTABLE", "TEMP_PROCESS_PUBLIC_EGRESS"}:
        items.append("PRIORITY 1: Зіставити процес, виконуваний файл, мережеве з'єднання та контекст оновлення. Спочатку зберегти докази.")
    if present & {"POWERFUL_BROWSER_EXTENSION", "POWERFUL_FIREFOX_EXTENSION"}:
        items.append("PRIORITY 2: Звірити розширення й дозволи в інтерфейсі браузера. Дозвіл сам собою НЕ означає шкідливість.")
    if "UNSAFE_BROWSER_LAUNCH_FLAG" in present:
        items.append("PRIORITY 2: З'ясувати, хто та навіщо запустив браузер зі зниженими обмеженнями безпеки.")
    if "REMOTE_ACCESS_PORT_EXPOSED" in present:
        items.append("PRIORITY 2: Перевірити власника порту, очікуваність сервісу та реальну мережеву доступність.")
    if "INSECURE_APT_REPOSITORY_SETTING" in present:
        items.append("PRIORITY 2: Перевірити налаштування довіри APT; не редагувати під час збирання доказів.")
    if any(x["status"] != "COMPLETED" for x in audit.coverage):
        items.append("COVERAGE: PARTIAL означає обмежене спостереження, FAILED — помилку колектора. Root/deep може розширити доступ, але не усуває відсутню історію чи недовіру до скомпрометованого ядра.")
    items.extend([
        "INSTAGRAM: Перевірити активні сесії та безпеку акаунта в офіційному Accounts Center з довіреного пристрою.",
        "UPDATES: Після збереження доказів оновити ОС і браузери з офіційних джерел.",
        "IF ROOT COMPROMISE SUSPECTED: Не покладатися лише на цю живу систему; потрібен незалежний офлайн-аналіз.",
    ])
    return items


def _safe_markdown(s: object) -> str:
    return str(s).replace("|", "∣").replace("\r", " ").replace("\n", " ").replace("`", "′")


def build_markdown(summary: dict, findings: list[dict], coverage: list[dict], advice: list[str]) -> str:
    v = summary["outcome"]
    counts = summary["finding_counts_by_kind"]
    gaps = summary["material_coverage_gaps"]
    elapsed = summary.get("stats", {}).get("runtime", {}).get("elapsed_ms", "not measured")
    rows = [
        "# ⊛ FALSICORE — Звіт перевірки безпеки", "",
        f"**Висновок:** `{v}`", "", f"**Інтерпретація:** {OUTCOME_UA[v]}", "",
        f"- Режим: `{summary['profile']}`; повноваження: `{summary['scope']}`",
        f"- Дата UTC: `{summary['created_utc']}`",
        f"- Тривалість сканування (мс): `{elapsed}`",
        f"- Індикаторів: **{counts.get('INDICATOR', 0)}**; експозицій: **{counts.get('EXPOSURE', 0)}**; налаштувань: **{counts.get('HARDENING', 0)}**",
        f"- Прогалин покриття: **{len(gaps)}**",
        f"- Детермінований digest спостережень: `{summary['analysis_digest_sha256']}`", "",
        "> Індикатор НЕ є доказом злому. Навіть повністю пройдений live-scan не виключає приховану компрометацію.", "",
        "## Покриття й обмеження", "",
        "| Перевірка | Статус | Причина / межа |", "|---|---|---|",
    ]
    for c in coverage:
        rows.append(f"| {_safe_markdown(c['check'])} | {_safe_markdown(c['status'])} | {_safe_markdown(c['details'])} |")
    rows += ["", "## Що знайдено", "", "| ID | Правило | Категорія | Важливість | Джерело |", "|---|---|---|---|---|"]
    for f in findings[:350]:
        rows.append("| " + " | ".join(_safe_markdown(f.get(k, "")) for k in ("id", "rule", "kind", "severity", "source_ref")) + " |")
    if not findings:
        rows.append("В обробленій телеметрії не виявлено налаштованих евристичних сигналів.")
    rows.extend(["", "## Наступні дії", ""])
    rows.extend(f"- {_safe_markdown(item)}" for item in advice)
    rows.extend(["", "## Чого цей аудит не доводить", ""])
    rows.extend(f"- {x}" for x in summary["cannot_exclude"])
    rows.extend(["", "**Цілісність:** `verify` перевіряє локальні хеші та перелік артефактів, а не довіреність зараженої ОС або походження від незалежного експерта.", ""])
    return "\n".join(rows)


def build_dashboard(summary: dict, findings: list[dict], coverage: list[dict], advice: list[str]) -> str:
    """Standalone offline HTML: no scripts, no remote resources, all variable fields escaped."""
    esc = lambda x: html.escape(str(x), quote=True)
    color = {"SUSPICIOUS_ACTIVITY_REQUIRES_INVESTIGATION":"#b45309",
             "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS":"#9a6700",
             "NO_COMPROMISE_INDICATORS_OBSERVED":"#166534"}[summary["outcome"]]
    rows = "".join(
        "<tr><td>" + esc(c["check"]) + "</td><td><strong>" + esc(c["status"]) + "</strong></td><td>" + esc(c["details"]) + "</td></tr>"
        for c in coverage)
    finding_rows = "".join(
        "<tr><td>" + esc(f["id"]) + "</td><td>" + esc(f["rule"]) + "</td><td>" + esc(KIND_UA.get(f["kind"], f["kind"])) + "</td><td>" + esc(f["severity"]) + "</td></tr>"
        for f in findings)
    details = "".join(
        "<details><summary>" + esc(f["rule"]) + " — " + esc(f["severity"]) + "</summary>"
        "<p>" + esc(f.get("hypothesis", "")) + "</p>"
        "<p>Джерело: " + esc(f.get("source_ref", "")) + "</p>"
        "<pre>" + esc(json.dumps(f.get("evidence", {}), ensure_ascii=False, sort_keys=True, indent=2)) + "</pre>"
        "<p>" + esc(f.get("alternative_explanation", "Requires review")) + "</p></details>"
        for f in findings)
    points = "".join("<li>" + esc(t) + "</li>" for t in advice)
    if not finding_rows:
        finding_rows = '<tr><td colspan="4">Немає евристичних знахідок у зібраних даних.</td></tr>'
    return f'''<!doctype html><html lang="uk"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>FALSICORE — Локальний звіт</title><style>
:root{{color-scheme:light dark}} body{{font:16px system-ui,-apple-system,sans-serif;line-height:1.55;max-width:1050px;margin:2rem auto;padding:0 1.3rem;color:CanvasText;background:Canvas}}
header{{border-left:5px solid {color};padding:1.4rem;background:color-mix(in srgb,CanvasText 5%,Canvas);border-radius:9px}}
h1{{margin:0}}.muted{{opacity:.73;font-size:.92rem}}.tag{{color:{color};font-weight:800;word-break:break-word}}.grid{{display:flex;gap:1rem;flex-wrap:wrap;margin:1.2rem 0}}
.metric{{min-width:150px;padding:1rem;border:1px solid #8885;border-radius:10px}}.metric strong{{display:block;font-size:1.6rem}}
table{{width:100%;border-collapse:collapse;font-size:.91rem}}th,td{{text-align:left;padding:.6rem;border-bottom:1px solid #8885;vertical-align:top;overflow-wrap:anywhere}}th{{font-weight:700}}
section{{margin:2rem 0}}.scroll{{overflow-x:auto}}li{{margin:.4rem 0}}code{{overflow-wrap:anywhere}}footer{{font-size:.85rem;opacity:.75}}
</style></head><body>
<header><h1>⊛ FALSICORE</h1><p class="tag">{esc(summary['outcome'])}</p>
<p>{esc(summary['outcome_explanation_ua'])}</p><p class="muted">Профіль: {esc(summary['profile'])} · Обсяг: {esc(summary['scope'])} · UTC: {esc(summary['created_utc'])}</p></header>
<div class="grid"><div class="metric"><strong>{sum(f['kind']=='INDICATOR' for f in findings)}</strong>Індикаторів (не доказ)</div>
<div class="metric"><strong>{sum(f['kind']=='EXPOSURE' for f in findings)}</strong>Експозицій</div>
<div class="metric"><strong>{len(summary['material_coverage_gaps'])}</strong>Прогалин</div>
<div class="metric"><strong>{esc(summary.get('stats',{}).get('runtime',{}).get('elapsed_ms','—'))}</strong>мс сканування</div></div>
<section><h2>Знахідки</h2><div class="scroll"><table><thead><tr><th>ID</th><th>Правило</th><th>Категорія</th><th>Пріоритет</th></tr></thead><tbody>{finding_rows}</tbody></table></div>{details}</section>
<section><h2>Покриття</h2><p>PARTIAL — обмеження спостереження, не знайдена загроза. FAILED — технічний збій. Цей інструмент не видає сертифіката «комп’ютер чистий».</p><div class="scroll"><table><thead><tr><th>Перевірка</th><th>Статус</th><th>Межі</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section><h2>Рекомендації</h2><ol>{points}</ol></section>
<footer>Локальний статичний HTML, без JavaScript та зовнішніх ресурсів. Дані з потенційно скомпрометованої ОС не є незалежною атестацією. Digest: {esc(summary['analysis_digest_sha256'])}</footer>
</body></html>'''


def _semantic_report_consistency(contents: dict[str, bytes]) -> bool:
    """Catch inconsistent report payloads even if someone recomputed hashes.

    This is a format/coherence check, NOT evidence authenticity or a digital
    signature. An attacker who controls the host can forge coherent records.
    """
    try:
        summary = json.loads(contents["summary.json"])
        finding_doc = json.loads(contents["findings.json"])
        coverage_doc = json.loads(contents["coverage_matrix.json"])
        command_doc = json.loads(contents["command_audit.json"])
        private_doc = json.loads(contents["private_index.json"])
        if not all(isinstance(x, dict) for x in (summary, finding_doc, coverage_doc, command_doc, private_doc)):
            return False
        findings, coverage = finding_doc["findings"], coverage_doc["checks"]
        if (summary.get("schema") != SCHEMA or finding_doc.get("schema") != "falsicore.findings.v3"
                or coverage_doc.get("schema") != "falsicore.coverage.v3"
                or command_doc.get("schema") != "falsicore.commands.v3"
                or not isinstance(findings, list) or not isinstance(coverage, list)
                or not isinstance(command_doc.get("commands"), list)
                or not isinstance(private_doc.get("source_ref_to_path"), dict)):
            return False
        if (not all(isinstance(f, dict) and isinstance(f.get("rule"), str)
                    and isinstance(f.get("kind"), str) for f in findings)
                or not all(isinstance(c, dict) and isinstance(c.get("check"), str)
                           and isinstance(c.get("status"), str) for c in coverage)):
            return False
        verdict = d.interpret_verdict(findings, coverage)
        if summary.get("findings_limited") and verdict == "NO_COMPROMISE_INDICATORS_OBSERVED":
            verdict = "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS"
        statuses = dict(sorted(Counter(c["status"] for c in coverage).items()))
        gap_rows = [{"check": c["check"], "status": c["status"], "reason": c.get("details", "")}
                    for c in coverage if c["status"] != "COMPLETED"]
        return all((
            summary.get("analysis_digest_sha256") == _analysis_digest(findings, coverage),
            summary.get("outcome") == verdict,
            summary.get("outcome_explanation_ua") == OUTCOME_UA[verdict],
            summary.get("coverage_status_counts") == statuses,
            summary.get("material_coverage_gaps") == gap_rows,
            summary.get("finding_counts_by_kind") == dict(sorted(Counter(f["kind"] for f in findings).items())),
            summary.get("finding_counts_by_rule") == d.normalized_finding_summary(findings),
            summary.get("confirmed_compromise") is False,
            summary.get("confirmed_attacker_attribution") is False,
        ))
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        return False


def verify_reports(folder: Path) -> dict:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("Report directory is invalid or symlinked")
    meta = folder.stat()
    if meta.st_uid != os.geteuid() or stat.S_IMODE(meta.st_mode) & 0o077:
        raise PermissionError("Report directory must be owned by current user and private")
    raw, status = safe_read(folder / "evidence_manifest.sha256", 100_000)
    if raw is None:
        raise ValueError(f"Manifest unavailable: {status}")
    entries: list[dict] = []
    names: set[str] = set()
    matched_contents: dict[str, bytes] = {}
    for line in raw.decode("ascii", "replace").splitlines():
        bits = line.split("  ", 1)
        if len(bits) != 2 or not re_full_sha(bits[0]):
            entries.append({"entry": "INVALID_MANIFEST_LINE", "verified": False})
            continue
        expected, name = bits
        if name not in REQUIRED | OPTIONAL or name in names:
            entries.append({"entry": "INVALID_OR_DUPLICATE_ENTRY", "verified": False})
            continue
        names.add(name)
        content, status = safe_read(folder / name, 4 * 1024 * 1024)
        matched = content is not None and hashlib.sha256(content).hexdigest() == expected
        if matched:
            matched_contents[name] = content
        entries.append({"entry": name, "verified": bool(matched), "status": status})
    actual_names = {p.name for p in folder.iterdir()}
    valid_structure = REQUIRED <= names and names == actual_names - {"evidence_manifest.sha256"}
    verified_hashes = bool(entries) and valid_structure and all(x["verified"] for x in entries)
    semantic_consistency = verified_hashes and _semantic_report_consistency(matched_contents)
    return {"verified": bool(verified_hashes and semantic_consistency),
            "entries": entries, "complete_file_set": valid_structure,
            "semantic_consistency": bool(semantic_consistency)}


def load_verified_summary(path: Path) -> dict:
    if path.name != "summary.json":
        raise ValueError("Baseline must be a summary.json from a verified FALSICORE run")
    result = verify_reports(path.parent)
    if not result["verified"]:
        raise ValueError("Baseline failed report integrity verification")
    raw, status = safe_read(path, 4 * 1024 * 1024)
    if raw is None:
        raise ValueError(f"Baseline summary unreadable: {status}")
    try:
        obj = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError("Malformed baseline summary") from exc
    if not isinstance(obj, dict) or obj.get("schema") != SCHEMA or not isinstance(obj.get("baseline"), dict):
        raise ValueError("Baseline schema mismatch")
    return obj


def comparable(old: dict, current: dict) -> bool:
    # Rule semantics and normalized baseline logic may change with the tool.
    # Never silently compare a newly revised detector set to an old-version
    # baseline: detector drift is not evidence of attacker activity.
    return all(old.get(k) == current.get(k) for k in ("schema", "tool_version", "scope", "profile", "target_uid", "host_ref"))


def find_baseline(parent: Path, current: dict) -> Path | None:
    if parent.is_symlink() or not parent.is_dir():
        return None
    candidates = []
    for p in parent.iterdir():
        if p.is_symlink() or not p.is_dir() or not p.name.startswith("run-"):
            continue
        try:
            if p.stat().st_uid == os.geteuid() and not stat.S_IMODE(p.stat().st_mode) & 0o077:
                candidates.append((p.stat().st_mtime_ns, p))
        except OSError:
            continue
    for _, p in sorted(candidates, key=lambda pair: (pair[0], pair[1].name), reverse=True)[:64]:
        try:
            old = load_verified_summary(p / "summary.json")
            if comparable(old, current):
                return p / "summary.json"
        except (ValueError, PermissionError, OSError):
            continue
    return None


def write_reports(run_dir: Path, audit, compare_report: Path | None = None,
                  auto_baseline_parent: Path | None = None) -> dict:
    summary = report_data(audit)
    source = compare_report
    if source is None and auto_baseline_parent is not None:
        source = find_baseline(auto_baseline_parent, summary)
    difference = None
    if source is not None:
        old = load_verified_summary(source)
        if not comparable(old, summary):
            raise ValueError("Baseline is from a different host/UID/scope/profile")
        difference = d.baseline_diff(old["baseline"], summary["baseline"])
        summary["baseline_comparison"] = {"status": "VERIFIED_LOCAL_COMPARISON", "prior_analysis_digest": old["analysis_digest_sha256"]}
    else:
        summary["baseline_comparison"] = {"status": "NO_COMPATIBLE_VERIFIED_BASELINE"}
    advice = recommendations(audit)
    findings = stable_findings(audit.findings)
    coverage = sorted(audit.coverage, key=lambda c: c["check"])
    write_json(run_dir / "summary.json", summary)
    write_json(run_dir / "findings.json", {"schema": "falsicore.findings.v3", "findings": findings})
    write_json(run_dir / "coverage_matrix.json", {"schema": "falsicore.coverage.v3", "checks": coverage})
    write_json(run_dir / "command_audit.json", {"schema": "falsicore.commands.v3", "commands": audit.commands})
    write_json(run_dir / "private_index.json", {
        "warning": "LOCAL PRIVATE DATA: filenames/endpoints may be untrusted. NEVER paste to any AI service.",
        "source_ref_to_path": audit.private_index,
    })
    if difference is not None:
        write_json(run_dir / "baseline_diff.json", difference)
    exclusive_write(run_dir / "report.md", build_markdown(summary, findings, coverage, advice))
    exclusive_write(run_dir / "dashboard.html", build_dashboard(summary, findings, coverage, advice))
    exclusive_write(run_dir / "next_actions.md", "# Наступні дії — не виконуються автоматично\n\n" + "\n".join(f"- {x}" for x in advice) + "\n")
    artifacts = sorted(p for p in run_dir.iterdir() if p.is_file())
    entries = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in artifacts]
    exclusive_write(run_dir / "evidence_manifest.sha256", "\n".join(entries) + "\n")
    return summary


def re_full_sha(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)
