"""Tests written to kill mutants that survived `tools/mutate.py --module report`.

Each pins a behaviour of report construction or verification that a plausible
fault would change: manifest-line validation, the semantic consistency
checks, baseline selection, host reference, Markdown/HTML content and the
finding-limit boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from falsicore import guide, report
from falsicore.report import (MARKDOWN_FINDING_LIMIT, SCHEMA, SEVERITY_ORDER, _gap_rows, _scope_limit_rows,
                              build_dashboard, build_markdown, find_baseline, host_ref, re_full_sha, report_data,
                              stable_findings, verify_reports, write_reports)

ESSENTIAL = ("processes", "network", "persistence", "browsers", "auth", "packages", "crossview")


def fake(findings=None, coverage=None, dropped=0, offline=False):
    return SimpleNamespace(
        scope="user", profile="standard", uid=1000, root=Path("/"), offline=offline,
        coverage=coverage if coverage is not None else
        [{"check": x, "status": "COMPLETED", "details": f"d {x}", "reason_codes": {}, "scope_limits": {}} for x in ESSENTIAL],
        findings=findings or [], dropped_findings=dropped, stats={"runtime": {"elapsed_ms": 12}},
        baseline={"listeners": [], "process_exe_hashes": [], "systemd_units": [], "cron_entry_hashes": [],
                  "ssh_key_fingerprints": [], "browser_extensions": [], "native_hosts": []},
        commands=[], private_index={})


def finding(rule="EXECUTABLE_IN_VOLATILE_PATH", severity="medium", kind="INDICATOR", **extra):
    base = {"id": "F0001", "rule": rule, "severity": severity, "kind": kind, "hypothesis": "h", "source_ref": "src_x",
            "evidence": {"k": 1}, "classification": "SUSPICIOUS_UNCONFIRMED", "attack_technique": None,
            "confirmation": "NOT_ESTABLISHED", "alternative_explanation": "a", "observations": []}
    base.update(extra)
    return base


def rewrite_manifest(run_dir: Path) -> None:
    """Recompute the hash manifest after editing a report file (isolates the semantic check)."""
    entries = []
    for p in sorted(run_dir.iterdir()):
        if p.name != "evidence_manifest.sha256":
            entries.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}")
    (run_dir / "evidence_manifest.sha256").write_text("\n".join(entries) + "\n")


def edit_json(run_dir: Path, name: str, mutate) -> None:
    path = run_dir / name
    doc = json.loads(path.read_text())
    doc = mutate(doc) or doc
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    rewrite_manifest(run_dir)


class ManifestLineValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.umask(0o077)
        self.run_dir = Path(self.tmp.name) / "run-a"
        self.run_dir.mkdir(mode=0o700)
        write_reports(self.run_dir, fake())

    def test_full_sha_grammar(self):                                   # report:469 and->or
        self.assertTrue(re_full_sha("a" * 64))
        self.assertFalse(re_full_sha("a" * 63))
        self.assertFalse(re_full_sha("g" * 64))
        self.assertFalse(re_full_sha("A" * 64))

    def test_invalid_hash_on_a_well_formed_line_is_invalid(self):      # report:337 or->and, 338
        manifest = self.run_dir / "evidence_manifest.sha256"
        lines = manifest.read_text().splitlines()
        lines[0] = "zz" + lines[0][2:]
        manifest.write_text("\n".join(lines) + "\n")
        result = verify_reports(self.run_dir)
        self.assertFalse(result["verified"])
        self.assertEqual(result["entries"][0], {"entry": "INVALID_MANIFEST_LINE", "verified": False})
        self.assertEqual(len(result["entries"]), len(lines), "later lines are still examined")   # report:339

    def test_duplicate_entry_is_invalid_and_later_lines_still_examined(self):   # report:343
        manifest = self.run_dir / "evidence_manifest.sha256"
        lines = manifest.read_text().splitlines()
        manifest.write_text("\n".join([lines[0], lines[0]] + lines[1:]) + "\n")
        result = verify_reports(self.run_dir)
        self.assertFalse(result["verified"])
        self.assertEqual(result["entries"][1], {"entry": "INVALID_OR_DUPLICATE_ENTRY", "verified": False})
        self.assertEqual(len(result["entries"]), len(lines) + 1)

    def test_symlinked_report_directory_is_refused(self):              # report:324 or->and
        link = Path(self.tmp.name) / "link"
        link.symlink_to(self.run_dir)
        with self.assertRaises(ValueError):
            verify_reports(link)
        with self.assertRaises(ValueError):
            verify_reports(self.run_dir / "summary.json")

    def test_oversized_report_file_is_unverified(self):                 # report:345 bound
        (self.run_dir / "report.md").write_bytes(b"#" * (4 * 1024 * 1024 + 1))
        rewrite_manifest(self.run_dir)
        result = verify_reports(self.run_dir)
        self.assertFalse(result["verified"])
        row = next(e for e in result["entries"] if e["entry"] == "report.md")
        self.assertEqual((row["verified"], row["status"]), (False, "TOO_LARGE"))


class SemanticConsistency(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.umask(0o077)
        self.run_dir = Path(self.tmp.name) / "run-a"
        self.run_dir.mkdir(mode=0o700)
        write_reports(self.run_dir, fake(findings=[finding()]))
        self.assertTrue(verify_reports(self.run_dir)["verified"])

    def test_non_object_documents_are_rejected(self):                  # report:285
        edit_json(self.run_dir, "findings.json", lambda d: ["not", "an", "object"])
        result = verify_reports(self.run_dir)
        self.assertTrue(result["hashes_verified"])
        self.assertFalse(result["semantic_consistency"])

    def test_finding_without_string_rule_is_rejected(self):            # report:294/298
        def mutate(d):
            d["findings"][0]["rule"] = 7
        edit_json(self.run_dir, "findings.json", mutate)
        self.assertFalse(verify_reports(self.run_dir)["semantic_consistency"])

    def test_coverage_row_without_status_is_rejected(self):            # report:296
        def mutate(d):
            del d["checks"][0]["status"]
        edit_json(self.run_dir, "coverage_matrix.json", mutate)
        self.assertFalse(verify_reports(self.run_dir)["semantic_consistency"])

    def test_wrong_schema_is_rejected(self):                           # report:293
        def mutate(d):
            d["schema"] = "falsicore.findings.v1"
        edit_json(self.run_dir, "findings.json", mutate)
        self.assertFalse(verify_reports(self.run_dir)["semantic_consistency"])

    def test_findings_limited_forces_inconclusive(self):               # report:300
        run_dir = Path(self.tmp.name) / "run-b"
        run_dir.mkdir(mode=0o700)
        summary = write_reports(run_dir, fake(dropped=3))
        self.assertEqual(summary["outcome"], "INCONCLUSIVE_DUE_TO_VISIBILITY_LIMITATIONS")
        self.assertTrue(verify_reports(run_dir)["verified"])
        def mutate(d):
            d["outcome"] = "NO_COMPROMISE_INDICATORS_OBSERVED"
            d["outcome_explanation_ua"] = report.OUTCOME_UA["NO_COMPROMISE_INDICATORS_OBSERVED"]
        edit_json(run_dir, "summary.json", mutate)
        self.assertFalse(verify_reports(run_dir)["semantic_consistency"])

    def test_baseline_must_be_a_dict_of_lists(self):                   # report:305/306
        def mutate(d):
            d["baseline"] = {"listeners": "tcp/22"}
        edit_json(self.run_dir, "summary.json", mutate)
        self.assertFalse(verify_reports(self.run_dir)["semantic_consistency"])


class SummaryShape(unittest.TestCase):
    def test_mode_and_lists(self):                                     # report:126, 84, 88
        coverage = [{"check": x, "status": "COMPLETED", "details": "", "reason_codes": {}, "scope_limits": {}} for x in ESSENTIAL]
        coverage[0] = {"check": "processes", "status": "PARTIAL", "details": "p", "reason_codes": {"TIMEOUT": 1},
                       "scope_limits": {"REQUIRES_SYSTEM_SCOPE": 1}}
        summary = report_data(fake(coverage=coverage))
        self.assertEqual(summary["mode"], "live")
        self.assertEqual(report_data(fake(offline=True))["mode"], "offline")
        self.assertEqual([g["check"] for g in summary["material_coverage_gaps"]], ["processes"])
        self.assertEqual(_gap_rows(coverage)[0]["reason_codes"], {"TIMEOUT": 1})
        self.assertEqual(_scope_limit_rows(coverage), [{"check": "processes", "scope_limits": {"REQUIRES_SYSTEM_SCOPE": 1}}])
        self.assertIsInstance(summary["scope_limits"], list)

    def test_severity_order_sorts_findings(self):                      # report:29
        findings = [finding(severity=s, evidence={"s": s}) for s in ("info", "low", "medium", "high", "critical")]
        ordered = [f["severity"] for f in stable_findings(findings)]
        self.assertEqual(ordered, ["critical", "high", "medium", "low", "info"])
        self.assertEqual(SEVERITY_ORDER, {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4})

    def test_host_ref_is_a_32_hex_digest_or_unavailable(self):         # report:36-39
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.assertEqual(host_ref(root), "UNAVAILABLE")
            (root / "etc").mkdir()
            (root / "etc/machine-id").write_text("\n")
            self.assertEqual(host_ref(root), "UNAVAILABLE")
            (root / "etc/machine-id").write_text("0123456789abcdef0123456789abcdef\n")
            ref = host_ref(root)
            self.assertRegex(ref, r"^[0-9a-f]{32}$")
            self.assertEqual(ref, hashlib.sha256(b"0123456789abcdef0123456789abcdef").hexdigest()[:32])


class MarkdownAndDashboardContent(unittest.TestCase):
    def render(self, findings, coverage=None):
        audit = fake(findings=findings, coverage=coverage)
        summary = report_data(audit)
        stable = stable_findings(audit.findings)
        cov = sorted(audit.coverage, key=lambda c: c["check"])
        advice = report.recommendations(audit)
        return summary, build_markdown(summary, stable, cov, advice), build_dashboard(summary, stable, cov, advice), advice

    def test_markdown_sections_and_rows(self):                         # report:191-216
        coverage = [{"check": x, "status": "COMPLETED", "details": "d \"q\"", "reason_codes": {}, "scope_limits": {}} for x in ESSENTIAL]
        _, md, html, advice = self.render([finding()], coverage)
        self.assertIn("| processes | COMPLETED |", md)
        self.assertIn("## Наступні дії", md)
        self.assertIn("## Чого цей аудит не доводить", md)
        self.assertIn("zero-day exploitation", md)
        self.assertIn("**Цілісність:**", md)
        self.assertIn(guide.rule("EXECUTABLE_IN_VOLATILE_PATH")["action"], md)
        self.assertNotIn("В обробленій телеметрії не виявлено", md)
        self.assertIn("Індикаторів: **1**", md)
        self.assertIn("&quot;q&quot;", html)                            # report:222 quote=True

    def test_markdown_without_findings_says_so_and_coverage_note_only_when_incomplete(self):   # report:152/153/200/201
        _, md, html, advice = self.render([])
        self.assertIn("В обробленій телеметрії не виявлено", md)
        self.assertFalse(any(a.startswith("COVERAGE:") for a in advice))
        self.assertIn("Немає евристичних знахідок", html)
        coverage = [{"check": x, "status": "COMPLETED", "details": "", "reason_codes": {}, "scope_limits": {}} for x in ESSENTIAL]
        coverage[1] = {"check": "network", "status": "FAILED", "details": "x", "reason_codes": {"COLLECTOR_ERROR": 1}, "scope_limits": {}}
        _, _, _, advice = self.render([], coverage)
        self.assertTrue(any(a.startswith("COVERAGE:") for a in advice))

    def test_dashboard_counts_kinds(self):                             # report:261/262
        findings = [finding(evidence={"i": 1}), finding(kind="EXPOSURE", rule="REMOTE_ACCESS_PORT_EXPOSED", evidence={"e": 1}),
                    finding(kind="EXPOSURE", rule="REMOTE_ACCESS_PORT_EXPOSED", evidence={"e": 2})]
        _, _, html, _ = self.render(findings)
        self.assertIn("<strong>1</strong>Індикаторів", html)
        self.assertIn("<strong>2</strong>Експозицій", html)
        self.assertIn("&quot;i&quot;: 1", html)                        # report:243 indent=2 (escaped quotes)
        self.assertIn("\n  &quot;evidence&quot;", html)

    def test_finding_limit_boundary(self):                             # report:198 > vs >=
        many = [finding(evidence={"n": i}) for i in range(MARKDOWN_FINDING_LIMIT)]
        _, md, _, _ = self.render(many)
        self.assertNotIn("знахідок лише у findings.json", md)
        _, md, _, _ = self.render(many + [finding(evidence={"n": "extra"})])
        self.assertIn("| … | ще 1 знахідок лише у findings.json", md)


class BaselineSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        os.umask(0o077)
        self.parent = Path(self.tmp.name)

    def make_run(self, name: str, mtime: int, findings=None) -> Path:
        run_dir = self.parent / name
        run_dir.mkdir(mode=0o700)
        write_reports(run_dir, fake(findings=findings))
        os.utime(run_dir, (mtime, mtime))
        return run_dir

    def test_most_recent_compatible_run_wins_and_filters_apply(self):  # report:405/408/412
        older = self.make_run("run-old", 1_700_000_000)
        newer = self.make_run("run-new", 1_700_000_100)
        (self.parent / "run-link").symlink_to(newer)                   # symlinks are skipped
        shared = self.make_run("run-shared", 1_700_000_200)
        shared.chmod(0o750)                                            # not private: skipped
        (self.parent / "other").mkdir(mode=0o700)                      # not a run-* dir
        current = report_data(fake())
        self.assertEqual(find_baseline(self.parent, current), newer / "summary.json")
        self.assertNotEqual(find_baseline(self.parent, current), older / "summary.json")

    def test_skipped_reasons_are_counted_exactly(self):                # report:416/422
        self.make_run("run-a", 1_700_000_000)
        bad = self.make_run("run-b", 1_700_000_050)
        (bad / "summary.json").write_text("{}")                        # breaks the hash manifest
        current = report_data(fake())
        current["profile"] = "deep"                                    # every verified candidate differs in profile
        from collections import Counter
        skipped: Counter = Counter()
        self.assertIsNone(find_baseline(self.parent, current, skipped))
        self.assertEqual(skipped, Counter({"unverified_or_old_schema": 1, "different_profile": 1}))

    def test_candidate_cap_is_64(self):                                # report:412 [:64]
        for i in range(70):
            d = self.parent / f"run-{i:03d}"
            d.mkdir(mode=0o700)
            os.utime(d, (1_700_000_000 + i, 1_700_000_000 + i))
        from collections import Counter
        skipped: Counter = Counter()
        self.assertIsNone(find_baseline(self.parent, report_data(fake()), skipped))
        self.assertEqual(skipped["unverified_or_old_schema"], 64)


if __name__ == "__main__":
    unittest.main()
