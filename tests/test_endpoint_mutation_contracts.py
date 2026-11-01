"""FC-13/FC-11/FC-12: negative controls for listener identity and gaps.

Synthetic observations only. No claims about live hosts or malware.
"""
from __future__ import annotations

import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsicore.collectors import Audit, Gaps, _proc_listener_endpoint, _ss_listener_endpoints


class ProcEndpointParsing(unittest.TestCase):
    def test_ipv4_byte_order_address_and_port_are_part_of_identity(self):
        self.assertEqual(_proc_listener_endpoint("tcp", "0100007F:1F90"),
                         ("tcp4", "127.0.0.1", 8080))
        self.assertEqual(_proc_listener_endpoint("tcp", "0200007F:1F90"),
                         ("tcp4", "127.0.0.2", 8080))
        self.assertEqual(_proc_listener_endpoint("udp", "00000000:FFFF"),
                         ("udp4", "0.0.0.0", 65535))

    def test_ipv6_words_are_little_endian_not_flat_byte_reversed(self):
        self.assertEqual(_proc_listener_endpoint(
            "tcp6", "00000000000000000000000001000000:01BB"),
            ("tcp6", "::1", 443))
        self.assertEqual(_proc_listener_endpoint(
            "udp6", "B80D0120000000000000000001000000:01BB"),
            ("udp6", "2001:db8::1", 443))

    def test_malformed_proc_addresses_are_never_exact_observations(self):
        for value in ("0100007F", "0100007:0016", "0100007FFF:0016",
                      "0100007G:0016", "0100007F:0G16",
                      "0100007F:016", "0100007F:00016"):
            with self.subTest(value=value):
                self.assertIsNone(_proc_listener_endpoint("tcp", value))
        self.assertIsNone(_proc_listener_endpoint("tcp6", "0100007F:0016"))
        self.assertIsNone(_proc_listener_endpoint(
            "tcp", "00000000000000000000000000000000:0016"))


class SocketTableParsing(unittest.TestCase):
    def test_exact_family_port_and_address_set_with_maximum_port(self):
        data = ("tcp LISTEN 0 0 127.0.0.1:22 0.0.0.0:*\n"
                "udp UNCONN 0 0 0.0.0.0:65535 0.0.0.0:*\n"
                "tcp6 LISTEN 0 0 [2001:db8::1]:443 [::]:*\n"
                "udp6 UNCONN 0 0 [::]:53 [::]:*\n")
        self.assertEqual(_ss_listener_endpoints(data), {
            ("tcp4", "127.0.0.1", 22), ("udp4", "0.0.0.0", 65535),
            ("tcp6", "2001:db8::1", 443), ("udp6", "::", 53)})

    def test_five_fields_are_sufficient(self):
        self.assertEqual(_ss_listener_endpoints("tcp LISTEN 0 0 127.0.0.1:22"),
                         {("tcp4", "127.0.0.1", 22)})

    def test_ignored_rows_do_not_abort_subsequent_valid_rows(self):
        self.assertEqual(_ss_listener_endpoints(
            "malformed-single-token\n"
            "sctp LISTEN 0 0 0.0.0.0:1000\n"
            "tcp ESTAB 0 0 127.0.0.1:5000\n"
            "tcp LISTEN 0 0 127.0.0.2:5001\n"),
            {("tcp4", "127.0.0.2", 5001)})

    def test_incomplete_listening_row_requires_limit_not_negative_inference(self):
        for row in ("tcp LISTEN", "tcp LISTEN 0 0", "udp UNCONN 0 0"):
            with self.subTest(row=row):
                self.assertIsNone(_ss_listener_endpoints(row))

    def test_malformed_socket_endpoints_fail_closed(self):
        for row in (
            "tcp LISTEN 0 0 127.0.0.1:000001",
            "tcp LISTEN 0 0 127.0.0.1:65536",
            "tcp LISTEN 0 0 :443",
            "tcp LISTEN 0 0 *:443",
            "tcp LISTEN 0 0 [::1:443",
            "tcp LISTEN 0 0 fe80::1%eth0:443",
            "tcp6 LISTEN 0 0 127.0.0.1:443",
            "udp6 UNCONN 0 0 [::1]:65536",
        ):
            with self.subTest(row=row):
                self.assertIsNone(_ss_listener_endpoints(row))
        self.assertIsNone(_ss_listener_endpoints(
            "tcp LISTEN 0 0 127.0.0.1:000001\n"
            "tcp LISTEN 0 0 127.0.0.1:22\n"))


class ProcSocketTable(unittest.TestCase):
    def test_four_columns_accept_and_three_columns_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "proc"
            net = root / "net"
            net.mkdir(parents=True)
            for family in ("tcp", "tcp6", "udp", "udp6"):
                (net / family).write_text("sl local_address rem_address st\n")
            (net / "tcp").write_text(
                "sl local_address rem_address st\n"
                "0: 0100007F:1F90 00000000:0000 0A\n")
            audit = Audit.__new__(Audit)
            audit.proc_root = root
            audit._proc_self = lambda: root / "self"
            self.assertEqual(audit._procnet_listeners(),
                             {("tcp4", "127.0.0.1", 8080)})
            (net / "tcp").write_text(
                "sl local_address rem_address st\n"
                "0: 0100007F:1F90 0A\n")
            self.assertIsNone(audit._procnet_listeners())
            (net / "tcp").write_text("sl local_address rem_address st\n")
            (net / "udp6").unlink()
            self.assertIsNone(audit._procnet_listeners())


class PrivacyBoundIdentity(unittest.TestCase):
    def test_key_length_uniqueness_and_privacy(self):
        audit = Audit.__new__(Audit)
        secret = bytes(range(32))
        with patch("falsicore.collectors.os.urandom", return_value=secret) as rng:
            first = audit._listener_evidence(("tcp4", "127.0.0.1", 8080), "PROCFS_ONLY")
            other = audit._listener_evidence(("tcp4", "127.0.0.2", 8080), "NETLINK_ONLY")
            repeat = audit._listener_evidence(("tcp4", "127.0.0.1", 8080), "NETLINK_ONLY")
        rng.assert_called_once_with(32)
        digest = hmac.new(secret, b"tcp4\x00127.0.0.1\x008080", hashlib.sha256).hexdigest()[:24]
        self.assertEqual(first["local_endpoint_id"], digest)
        self.assertNotEqual(first["local_endpoint_id"], other["local_endpoint_id"])
        self.assertEqual(first["local_endpoint_id"], repeat["local_endpoint_id"])
        self.assertEqual((first["proto"], first["family"], first["port"]),
                         ("tcp", "ipv4", 8080))
        self.assertNotIn("127.0.0.", str((first, other, repeat)))


class RepeatedObservationGaps(unittest.TestCase):
    @staticmethod
    def _audit(probes, replies):
        audit = Audit.__new__(Audit)
        audit._procnet_listeners = lambda: probes.pop(0)
        audit.command = lambda *a, **kw: replies.pop(0)
        audit.command_gap = lambda reply, gaps: gaps.add("TOOL_FAILED")
        findings = []
        audit.finding = lambda *a, **kw: findings.append((a, kw))
        audit._listener_evidence = lambda endpoint, view: {"endpoint": endpoint, "view": view}
        return audit, findings

    @staticmethod
    def _reply(output, status="COMPLETED"):
        return {"status": status, "stdout": output, "truncated": False}

    def test_missing_first_second_or_confirming_proc_snapshot_records_gap(self):
        ss = "udp UNCONN 0 0 0.0.0.0:4444 0.0.0.0:*\n"
        for probes, replies in (
            ([None], []),
            ([set(), None], [self._reply(ss)]),
            ([set(), set(), None], [self._reply(ss), self._reply(ss)]),
        ):
            with self.subTest(count=len(probes)):
                audit, findings = self._audit(probes, replies)
                gaps, stats = Gaps(), {}
                audit._hidden_listeners(gaps, stats)
                self.assertEqual(gaps.incomplete["READ_FAILED"], 1)
                self.assertEqual(findings, [])

    def test_ambiguous_second_ss_never_confirms_a_hidden_listener(self):
        ss = "udp UNCONN 0 0 0.0.0.0:4444 0.0.0.0:*\n"
        audit, findings = self._audit(
            [set(), set()], [self._reply(ss), self._reply("udp UNCONN 0 0 *:4444")])
        gaps, stats = Gaps(), {}
        audit._hidden_listeners(gaps, stats)
        self.assertEqual(gaps.incomplete["PARSE_UNSUPPORTED"], 1)
        self.assertEqual(stats["listeners"]["netlink_only"], 0)
        self.assertEqual(findings, [])

    def test_failed_confirming_ss_records_incompleteness(self):
        ss = "udp UNCONN 0 0 0.0.0.0:4444 0.0.0.0:*\n"
        audit, findings = self._audit(
            [set(), set()], [self._reply(ss), self._reply(ss, "FAILED")])
        gaps, stats = Gaps(), {}
        audit._hidden_listeners(gaps, stats)
        self.assertEqual(gaps.incomplete["TOOL_FAILED"], 1)
        self.assertEqual(stats["listeners"]["netlink_only"], 0)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
