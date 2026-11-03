"""Socket state vocabulary: unsupported inputs must never become a supported state.

These fixtures do not read host sockets or infer actual host compromise.
"""
import unittest

from falsicore import detectors as d


class SocketStateContractTests(unittest.TestCase):
    def test_unknown_protocol_is_explicit_boolean_false(self):
        # Exact False is the API contract: neither truthy acceptance nor None
        # may masquerade as an inspected/known socket protocol.
        for protocol, state in (
            ("sctp", "LISTEN"),
            ("tcp4", "LISTEN"),
            ("UDP", "UNCONN"),
            ("", "ESTAB"),
        ):
            with self.subTest(protocol=protocol, state=state):
                self.assertIs(d.ss_state_supported(protocol, state), False)

    def test_unknown_state_of_known_protocol_is_false(self):
        for protocol, state in (
            ("tcp", "LSTEN"),
            ("tcp6", "UNCONN"),
            ("udp", "LISTEN"),
            ("udp6", "UNKNOWN"),
        ):
            with self.subTest(protocol=protocol, state=state):
                self.assertIs(d.ss_state_supported(protocol, state), False)

    def test_known_state_benign_twins_are_true(self):
        for protocol, state in (
            ("tcp", "LISTEN"),
            ("tcp6", "SYN-SENT"),
            ("udp", "UNCONN"),
            ("udp6", "ESTAB"),
        ):
            with self.subTest(protocol=protocol, state=state):
                self.assertIs(d.ss_state_supported(protocol, state), True)

    def test_parser_reports_unknown_tcp_state_and_retains_valid_listener(self):
        issues = {}
        sockets = d.parse_ss(
            "tcp LSTEN 0 128 127.0.0.1:9222 0.0.0.0:*\n"
            "tcp LISTEN 0 128 127.0.0.1:9223 0.0.0.0:*\n",
            parse_issues=issues,
        )
        self.assertEqual(issues, {"malformed_rows": 1})
        self.assertEqual([(s["state"], s["local_port"]) for s in sockets],
                         [("LSTEN", "9222"), ("LISTEN", "9223")])


if __name__ == "__main__":
    unittest.main()
