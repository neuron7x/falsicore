"""Property-based tests (Hypothesis): universally quantified claims, not examples.

Each test states a property that must hold for EVERY generated input. A
failing example is a refutation of the corresponding claim in README/AUDIT.
Hypothesis is a development dependency only; the shipped tool stays
standard-library. When `FALSICORE_REQUIRE_HYPOTHESIS=1` (CI), a missing
Hypothesis is a failure, never a silent skip.
"""
from __future__ import annotations

import json
import os
import random
import tempfile
import unittest
from pathlib import Path

from falsicore import config_commands, detectors, guide, report, safety, shell_syntax

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
    HAVE_HYPOTHESIS = True
except ImportError:  # pragma: no cover - exercised only where Hypothesis is absent
    HAVE_HYPOTHESIS = False

REQUIRED = os.environ.get("FALSICORE_REQUIRE_HYPOTHESIS") == "1"

if HAVE_HYPOTHESIS:
    settings.register_profile(
        "falsicore",
        deadline=None,                     # CI machines vary; time is not the property
        database=None,                     # never write .hypothesis/ into the source tree
        max_examples=int(os.environ.get("FALSICORE_PBT_EXAMPLES", "200")),
        suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
    )
    settings.load_profile("falsicore")

    # ---- strategies -------------------------------------------------------
    NO_NUL_NO_NL = st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00\n")
    # One physical line as the adapters see it: str.splitlines() also breaks on
    # \r \v \f \x1c \x1d \x1e \x85    , so a single-line model excludes them.
    ONE_LINE = st.characters(blacklist_categories=("Cs", "Zl", "Zp"),
                             blacklist_characters="\x00\n\r\x0b\x0c\x1c\x1d\x1e\x85")
    any_text = st.text(max_size=400)
    shell_text = st.text(st.characters(blacklist_categories=("Cs",)), max_size=600)
    identifier = st.from_regex(r"\A[A-Za-z_][A-Za-z0-9_]{0,15}\Z")
    temp_prefix = st.sampled_from(shell_syntax.TEMP_PREFIXES)
    wrapper = st.sampled_from([
        "nohup", "setsid", "exec", "command", "builtin", "time", "sudo", "sudo -u root", "doas",
        "env", "env FOO=bar", "nice -n 5", "ionice -c 3", "timeout 5", "timeout -s KILL 5",
        "stdbuf -o0", "xargs", "FOO=bar", "A=1 B=2",
    ])
    wrapper_chain = st.lists(wrapper, max_size=3).map(" ".join)
    fetcher = st.sampled_from(["curl", "curl -fsSL", "curl -s -o -", "wget", "wget -qO-"])
    url = st.from_regex(r"\Ahttps?://[a-z]{1,10}\.example/[a-z0-9]{0,8}\Z")
    code_sink = st.sampled_from([
        "sh", "bash", "bash -s", "dash", "zsh", "ksh", "sh -s --", "python3", "python3 -", "python",
        "python3.12", "perl", "node", "ruby", "php", "lua", "sudo bash", "nohup sh", "exec bash",
    ])
    base64_blob = st.from_regex(r"\A[A-Za-z0-9+/]{4,40}={0,2}\Z")

    json_values = st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=20),
        lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
        max_leaves=20,
    )
    rules = st.sampled_from(["EXECUTABLE_IN_VOLATILE_PATH", "SUSPICIOUS_SHELL_INIT", "POWERFUL_BROWSER_EXTENSION",
                             "REMOTE_ACCESS_PORT_EXPOSED", "PACKAGE_FILE_DRIFT", "UNLISTED_RULE"])
    severities = st.sampled_from(list(report.SEVERITY_ORDER) + ["unranked"])
    kinds = st.sampled_from(["INDICATOR", "EXPOSURE", "HARDENING", "CONTEXT"])
    observation = st.dictionaries(st.sampled_from(["pid", "ppid", "uid", "start_ticks", "exe_name"]),
                                  st.integers(0, 70000) | st.text(max_size=8), max_size=4)
    finding = st.fixed_dictionaries({
        "id": st.text(max_size=8),
        "rule": rules, "severity": severities, "kind": kinds,
        "hypothesis": st.text(max_size=20), "source_ref": st.text(max_size=12),
        "evidence": st.dictionaries(st.text(max_size=6), st.integers() | st.text(max_size=6) | st.booleans(), max_size=3),
        "observations": st.lists(observation, max_size=25),
    })
    coverage_row = st.fixed_dictionaries({
        "check": st.sampled_from(["processes", "network", "persistence", "browsers", "auth", "packages", "kernel", "environment"]),
        "status": st.sampled_from(["COMPLETED", "PARTIAL", "FAILED", "UNAVAILABLE", "SKIPPED"]),
        "details": st.text(max_size=20),
        "reason_codes": st.dictionaries(st.sampled_from(["TIMEOUT", "INPUT_TRUNCATED", "PERMISSION_DENIED"]), st.integers(1, 9), max_size=3),
        "scope_limits": st.dictionaries(st.sampled_from(["REQUIRES_SYSTEM_SCOPE", "NOT_IN_PROFILE"]), st.integers(1, 9), max_size=2),
    })
    baseline = st.dictionaries(st.sampled_from(["listeners", "systemd_units", "native_hosts"]),
                               st.lists(st.text(max_size=6), max_size=4), max_size=3)
    cron_field = st.sampled_from(["*", "5", "*/10", "0,30", "1-5", "00"])
    cron_dow = st.sampled_from(["*", "1", "mon", "1-5", "sun"])
    cron_mon = st.sampled_from(["*", "12", "jan", "*/2"])
    cron_command = st.text(ONE_LINE, min_size=1, max_size=60).filter(lambda s: s.strip())
else:  # pragma: no cover
    def given(*_a, **_k):  # type: ignore[misc]
        return lambda f: f


class HypothesisAvailability(unittest.TestCase):
    def test_hypothesis_present_when_required(self):
        if not REQUIRED:
            self.skipTest("FALSICORE_REQUIRE_HYPOTHESIS unset: property tests are optional here")
        self.assertTrue(HAVE_HYPOTHESIS, "FALSICORE_REQUIRE_HYPOTHESIS=1 but hypothesis is not importable")


if HAVE_HYPOTHESIS:
    # Strategy names exist only when Hypothesis imported; the classes live inside the guard
    # so the module (and the packaged self-test) imports cleanly without it.
    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class ShellAnalysisProperties(unittest.TestCase):
        """Claim C5: the shell analyser never guesses and never crashes."""

        @given(shell_text)
        def test_total_deterministic_and_closed_vocabulary(self, text):
            first = shell_syntax.analyze(text)
            second = shell_syntax.analyze(text)
            self.assertEqual(first, second)
            self.assertTrue(set(first["patterns"]) <= shell_syntax.PATTERN_CODES, first["patterns"])
            self.assertTrue(set(first["limitations"]) <= shell_syntax.LIMITATION_CODES, first["limitations"])
            self.assertEqual(first["patterns"], sorted(set(first["patterns"])))
            self.assertEqual(first["limitations"], sorted(set(first["limitations"])))
            lines = [m["line"] for m in first["matches"]]
            self.assertEqual(lines, sorted(lines))
            self.assertTrue(all(isinstance(n, int) and n >= 1 for n in lines))
            self.assertTrue(all(isinstance(s, str) for s in first["sourced"]))

        @given(st.text(NO_NUL_NO_NL, max_size=200))
        def test_comment_line_is_inert(self, body):
            result = shell_syntax.analyze("# " + body)
            self.assertEqual(result["patterns"], [])
            self.assertEqual(result["limitations"], [])
            self.assertEqual(result["sourced"], [])

        @given(st.text(st.characters(blacklist_categories=("Cs",), blacklist_characters="'\x00"), max_size=200))
        def test_single_quoted_data_is_inert(self, body):
            result = shell_syntax.analyze(f"echo '{body}'")
            self.assertEqual(result["patterns"], [])
            self.assertEqual(result["limitations"], [])

        @given(wrapper_chain, temp_prefix, identifier)
        def test_volatile_executable_is_seen_through_transparent_wrappers(self, chain, prefix, name):
            text = f"{chain} {prefix}{name} --arg".strip()
            self.assertIn("TEMP_PATH_IN_EXECUTION", shell_syntax.analyze(text)["patterns"], text)

        @given(fetcher, url, code_sink)
        def test_download_piped_into_interpreter_is_seen(self, fetch, address, sink):
            text = f"{fetch} {address} | {sink}"
            self.assertIn("REMOTE_SCRIPT_PIPELINE", shell_syntax.analyze(text)["patterns"], text)

        @given(base64_blob, code_sink)
        def test_decoded_data_piped_into_interpreter_is_seen(self, blob, sink):
            text = f"echo {blob} | base64 -d | {sink}"
            self.assertIn("BASE64_DECODE_EXECUTION_CONTEXT", shell_syntax.analyze(text)["patterns"], text)

        @given(identifier, st.text(NO_NUL_NO_NL, max_size=30))
        def test_expanded_command_head_is_a_limitation_not_a_verdict(self, name, rest):
            result = shell_syntax.analyze(f"${name} {rest}")
            self.assertIn("EXPANSION_NOT_RESOLVED", result["limitations"])

        @given(shell_text)
        def test_nul_bytes_cannot_forge_markers(self, text):
            with_nul = text + "\x00PROCSUB9\x00 \x00VAR:HOME\x00"
            result = shell_syntax.analyze(with_nul)
            self.assertIn("NUL_IN_INPUT", result["limitations"])
            stripped = shell_syntax.analyze(with_nul.replace("\x00", ""))
            self.assertEqual(result["patterns"], stripped["patterns"])


    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class DetectorTotality(unittest.TestCase):
        """Pure detectors are total functions over untrusted text with closed outputs."""

        ENDPOINT_CLASSES = {"wildcard", "loopback", "link_local", "private", "public", "other", "unknown"}
        JOURNAL_RULES = {"SSH_ACCEPTED", "SSH_FAILED", "SUDO_SESSION", "SEGFAULT", "APPARMOR_DENIED",
                         "NEW_USER", "CRON_EVENT", "OOM_EVENT"}

        @given(any_text)
        def test_endpoint_class_closed(self, text):
            self.assertIn(detectors.endpoint_class(text), self.ENDPOINT_CLASSES)

        @given(any_text)
        def test_parse_ss_total(self, text):
            rows = detectors.parse_ss(text)
            for row in rows:
                self.assertEqual(set(row), {"proto", "state", "local_class", "local_port", "remote_class",
                                            "remote_id", "has_process_info", "pids"})
                self.assertEqual(row["pids"], sorted(row["pids"]))
                self.assertIn(row["proto"], ("tcp", "udp", "tcp6", "udp6"))

        @given(any_text)
        def test_dpkg_review_counts_every_nonblank_line_exactly_once(self, text):
            review = detectors.dpkg_verify_review(text)
            nonblank = sum(1 for line in text.splitlines() if line.split())
            counted = sum(review[k] for k in ("content_changed_conffiles", "content_changed_other_files",
                                              "missing_files", "unverifiable", "unparsed_lines"))
            self.assertEqual(counted, nonblank)
            self.assertLessEqual(len(review["missing_by_prefix"]), 10)
            self.assertLessEqual(sum(review["missing_by_prefix"].values()), review["missing_files"])

        @given(any_text)
        def test_journal_rules_closed(self, text):
            self.assertTrue(set(detectors.detect_journal_message(text)) <= self.JOURNAL_RULES)

        @given(any_text, st.integers(0, 70000), st.booleans())
        def test_classify_executable_total(self, path, uid, deleted):
            for rule, severity in detectors.classify_executable(path, uid, deleted):
                self.assertIn(rule, {"EXECUTABLE_IN_VOLATILE_PATH", "DELETED_RUNNING_EXECUTABLE", "ROOT_RUNNING_USER_PATH"})
                self.assertIn(severity, {"high", "medium"})

        @given(st.dictionaries(st.text(max_size=12), json_values, max_size=8))
        def test_extension_assessment_total(self, manifest):
            result = detectors.extension_assessment(manifest)
            self.assertIsInstance(result["risk_flag"], bool)
            self.assertIsInstance(result["broad_host_access"], bool)
            self.assertEqual(result["sensitive_permissions"], sorted(result["sensitive_permissions"]))

        @given(any_text)
        def test_host_pattern_check_total(self, pattern):
            self.assertIsInstance(detectors.grants_host_access(pattern, ("instagram.com", "www.instagram.com", "i.instagram.com", "graph.instagram.com")), bool)

        @given(st.binary(max_size=300), st.integers(0, 299))
        def test_json_size_bound_is_enforced_before_parsing(self, raw, limit):
            if len(raw) > limit:
                with self.assertRaises(ValueError):
                    detectors.safe_json_parse(raw, limit)

        @given(st.lists(st.text(max_size=20)))
        def test_browser_flag_review_total(self, argv):
            review = detectors.browser_flag_review(argv)
            self.assertIn(review["debug_channel"], (None, "pipe", "port"))
            self.assertEqual(review["flags"], sorted(set(review["flags"])))


    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class ReportIdentityProperties(unittest.TestCase):
        """Claim C3: identity and digest depend on observations, not on enumeration order."""

        @given(st.lists(finding, max_size=8), st.randoms(use_true_random=False))
        def test_stable_findings_is_permutation_invariant(self, findings, rnd):
            shuffled = list(findings)
            rnd.shuffle(shuffled)
            self.assertEqual(report.stable_findings(findings), report.stable_findings(shuffled))

        @given(st.lists(finding, max_size=8))
        def test_stable_findings_is_idempotent(self, findings):
            once = report.stable_findings(findings)
            self.assertEqual(report.stable_findings(once), once)

        @given(st.lists(finding, max_size=8))
        def test_ids_unique_and_observations_bounded(self, findings):
            stable = report.stable_findings(findings)
            ids = [f["id"] for f in stable]
            self.assertEqual(len(ids), len(set(ids)))
            total_in = sum(len(f["observations"]) for f in findings)
            kept = sum(len(f["observations"]) for f in stable)
            omitted = sum(f["observations_omitted"] for f in stable)
            self.assertEqual(kept + omitted, total_in)
            for f in stable:
                self.assertLessEqual(len(f["observations"]), report.MAX_OBSERVATIONS_PER_FINDING)

        @given(st.lists(finding, max_size=6), st.lists(coverage_row, max_size=6), baseline,
               st.randoms(use_true_random=False))
        def test_analysis_digest_is_order_independent(self, findings, coverage, base, rnd):
            digest = report._analysis_digest(findings, coverage, base)
            f2, c2 = list(findings), list(coverage)
            rnd.shuffle(f2)
            rnd.shuffle(c2)
            self.assertEqual(digest, report._analysis_digest(f2, c2, base))
            self.assertEqual(len(digest), 64)

        @given(st.lists(finding, max_size=6), st.lists(coverage_row, max_size=6), baseline)
        def test_pid_attribution_never_enters_the_digest(self, findings, coverage, base):
            relabelled = [{**f, "observations": [{"pid": 1}], "id": "X"} for f in findings]
            self.assertEqual(report._analysis_digest(findings, coverage, base),
                             report._analysis_digest(relabelled, coverage, base))

        @given(any_text)
        def test_markdown_cells_cannot_break_tables_or_inject_html(self, text):
            cell = report._safe_markdown(text)
            for forbidden in ("|", "\n", "\r", "`", "<", ">"):
                self.assertNotIn(forbidden, cell)

        @given(any_text, st.integers(1, 400))
        def test_terminal_safe_strips_controls_and_bounds_length(self, text, limit):
            out = guide.terminal_safe(text, limit)
            self.assertIsNone(guide._CONTROL.search(out))
            self.assertLessEqual(len(out), 6 * limit)

        @given(st.dictionaries(st.text(max_size=8), json_values, max_size=6))
        def test_identity_line_total(self, finding_doc):
            self.assertIsInstance(guide.identity_line(finding_doc), str)

        @given(any_text)
        def test_every_rule_name_has_a_complete_guide_entry(self, name):
            entry = guide.rule(name)
            self.assertEqual(set(entry), {"priority", "observed", "benign", "uncertainty", "action"})


    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class CommandExtractionModel(unittest.TestCase):
        """Cron and .desktop adapters return exactly the command text, nothing else."""

        @given(cron_field, cron_field, cron_field, cron_mon, cron_dow, cron_command)
        def test_user_crontab_schedule_is_stripped_exactly(self, m, h, dom, mon, dow, command):
            line = f"{m} {h} {dom} {mon} {dow} {command}"
            self.assertEqual(config_commands.cron_commands(line), command.strip())

        @given(cron_field, cron_field, cron_field, cron_mon, cron_dow, identifier, cron_command)
        def test_system_crontab_user_field_is_stripped_exactly(self, m, h, dom, mon, dow, user, command):
            line = f"{m} {h} {dom} {mon} {dow} {user} {command}"
            self.assertEqual(config_commands.cron_commands(line, system=True), command.strip())

        @given(st.sampled_from(["@reboot", "@daily", "@hourly", "@weekly"]), cron_command)
        def test_special_schedule_is_stripped_exactly(self, special, command):
            self.assertEqual(config_commands.cron_commands(f"{special} {command}"), command.strip())

        @given(st.sampled_from(["Exec", "TryExec"]), st.text(ONE_LINE, max_size=60))
        def test_desktop_exec_value_is_returned_verbatim(self, key, value):
            self.assertEqual(config_commands.desktop_commands(f"[Desktop Entry]\n{key}={value}\nName=x\n"), value.strip())

        @given(st.text(ONE_LINE, max_size=60).filter(lambda s: s.strip() not in ("Exec", "TryExec")), st.text(ONE_LINE, max_size=60))
        def test_other_desktop_keys_are_data(self, key, value):
            self.assertEqual(config_commands.desktop_commands(f"{key}={value}\n"), "")


    @unittest.skipUnless(HAVE_HYPOTHESIS, "hypothesis not installed")
    class BoundedReadProperties(unittest.TestCase):
        """safe_read returns exactly the bytes within its bound, or a reason, never a prefix."""

        def setUp(self):
            self.tmp = tempfile.TemporaryDirectory()
            self.addCleanup(self.tmp.cleanup)
            self.counter = 0

        @given(st.binary(max_size=5000), st.integers(0, 10000))
        def test_safe_read_is_exact_or_refuses(self, data, limit):
            self.counter += 1
            path = Path(self.tmp.name) / f"f{self.counter}"
            path.write_bytes(data)
            result = safety.safe_read(path, limit)
            if len(data) <= limit:
                self.assertEqual(result, (data, "COMPLETED"))
            else:
                self.assertEqual(result, (None, "TOO_LARGE"))

        @given(st.text(max_size=300))
        def test_exclusive_write_roundtrip_and_no_overwrite(self, content):
            self.counter += 1
            path = Path(self.tmp.name) / f"w{self.counter}"
            safety.exclusive_write(path, content)
            self.assertEqual(path.read_bytes(), content.encode("utf-8"))
            with self.assertRaises(FileExistsError):
                safety.exclusive_write(path, "again")



if __name__ == "__main__":  # pragma: no cover
    unittest.main()
