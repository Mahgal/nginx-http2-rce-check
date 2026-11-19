#!/usr/bin/env python3
"""Tests for nginx-http2-rce-check. Stdlib unittest only, no network.

Run:  python3 -m unittest discover -s tests -v
       (or: python3 tests/run_tests.py)
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nginx_http2_check as nhc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "nginx_http2_check.py")

HTTP2_ON = (
    "events { worker_connections 1024; }\n"
    "http {\n"
    "    server {\n"
    "        listen 443 ssl http2;\n"
    "        server_name example.com;\n"
    "    }\n"
    "}\n"
)
HTTP2_OFF = (
    "events { worker_connections 1024; }\n"
    "http {\n"
    "    http2 off;\n"
    "    server {\n"
    "        listen 443 ssl;\n"
    "        server_name example.com;\n"
    "    }\n"
    "}\n"
)
NO_HTTP2 = (
    "events { worker_connections 1024; }\n"
    "http {\n"
    "    server {\n"
    "        listen 80;\n"
    "        server_name example.com;\n"
    "    }\n"
    "}\n"
)


def verdict_for(version_text, config_text=HTTP2_ON):
    """Full pipeline verdict for a version string + config text."""
    parsed = nhc.parse_nginx_version(version_text)
    http2_state, findings = nhc.parse_config_text(config_text)
    verdict, _lines, code = nhc.assess(parsed, "test", http2_state, findings)
    return verdict, code


class TestVersionBoundaries(unittest.TestCase):
    # Boundary rows required by the task, HTTP/2 on throughout.
    CASES = [
        # (version string, expected verdict, expected exit)
        ("1.9.4", "NOT_AFFECTED", 0),   # predates both first-affected
        ("1.9.5", "VULNERABLE", 1),     # first affected, 123007 only
        ("1.19.6", "VULNERABLE", 1),    # 123007 only (123633 starts 1.19.7)
        ("1.19.7", "VULNERABLE", 1),    # first affected, both CVEs
        ("1.24.0", "VULNERABLE", 1),    # mid-range
        ("1.30.6", "VULNERABLE", 1),    # last affected on stable
        ("1.30.7", "PATCHED", 0),       # stable fix
        ("1.31.0", "VULNERABLE", 1),    # mainline still vulnerable
        ("1.31.8", "VULNERABLE", 1),    # last affected on mainline
        ("1.31.9", "PATCHED", 0),       # mainline fix
        ("1.32.0", "PATCHED", 0),       # newer than the mainline fix
        ("nginx version: nginx/1.31.8", "VULNERABLE", 1),  # -v format
        ("nginx version: nginx/1.30.7", "PATCHED", 0),
    ]

    def test_boundary_rows(self):
        for version, verdict, code in self.CASES:
            with self.subTest(version=version):
                got_verdict, got_code = verdict_for(version)
                self.assertEqual(got_verdict, verdict)
                self.assertEqual(got_code, code)

    def test_1_19_6_only_123007(self):
        # 1.19.6 is affected by 123007 but predates 123633 — the
        # per-CVE reasons must say exactly that.
        parsed = nhc.parse_nginx_version("1.19.6")
        status, reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "affected")
        joined = " ".join(reasons)
        self.assertIn("CVE-2026-123007: AFFECTED", joined)
        self.assertIn("CVE-2026-123633: NOT AFFECTED", joined)

    def test_branch_trap(self):
        # THE trap: 1.30.7 is fixed, but 1.31.0-1.31.8 are still
        # vulnerable. A plain "version >= 1.30.7 means safe" rule
        # would call 1.31.8 safe — this tool must not.
        self.assertEqual(verdict_for("1.30.7"), ("PATCHED", 0))
        for v in ("1.31.0", "1.31.5", "1.31.8"):
            with self.subTest(version=v):
                self.assertEqual(verdict_for(v), ("VULNERABLE", 1))

    def test_malformed_version_string(self):
        parsed = nhc.parse_nginx_version("garbage with no version\n")
        self.assertEqual(parsed["kind"], "unknown")
        verdict, _lines, code = nhc.assess(parsed, "test", True, [])
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(code, 3)

    def test_missing_nginx(self):
        parsed = nhc.parse_nginx_version("")
        verdict, _lines, code = nhc.assess(parsed, "test", True, [])
        self.assertEqual(verdict, "UNKNOWN")
        self.assertEqual(code, 3)


class TestHttp2Gate(unittest.TestCase):
    def test_http2_off_makes_affected_version_not_affected(self):
        verdict, code = verdict_for("1.31.8", HTTP2_OFF)
        self.assertEqual((verdict, code), ("NOT_AFFECTED", 0))

    def test_http2_off_with_http2_on_directive(self):
        config = HTTP2_ON.replace("listen 443 ssl http2;",
                                  "listen 443 ssl;\n        http2 on;")
        verdict, code = verdict_for("1.31.8", config)
        self.assertEqual((verdict, code), ("VULNERABLE", 1))

    def test_no_http2_directive_is_unknown(self):
        # Version affected, config silent: cannot decide the gate.
        verdict, code = verdict_for("1.31.8", NO_HTTP2)
        self.assertEqual((verdict, code), ("UNKNOWN", 3))

    def test_patched_ignores_http2_gate(self):
        # A fixed build is PATCHED even with HTTP/2 on — and even
        # when the config says nothing about HTTP/2.
        for config in (HTTP2_ON, HTTP2_OFF, NO_HTTP2):
            verdict, code = verdict_for("1.30.7", config)
            self.assertEqual((verdict, code), ("PATCHED", 0))

    def test_commented_http2_does_not_count(self):
        config = NO_HTTP2.replace("listen 80;",
                                  "# listen 443 ssl http2;\n        listen 80;")
        state, _findings = nhc.parse_config_text(config)
        self.assertIsNone(state)

    def test_conflicting_directives_are_unknown(self):
        config = HTTP2_ON + "    http2 off;\n"
        state, findings = nhc.parse_config_text(config)
        self.assertIsNone(state)
        self.assertTrue(any("both enabling and disabling" in f
                            for f in findings))

    def test_listen_http2_case_insensitive(self):
        state, _findings = nhc.parse_config_text(
            "server { LISTEN 443 SSL HTTP2; }")
        self.assertTrue(state)


class TestDistroUnknown(unittest.TestCase):
    DISTRO_VERSIONS = [
        "1.24.0-0ubuntu1",
        "1.26.2-1~deb12u1",
        "1.18.0-0ubuntu1",
        "nginx version: nginx/1.24.0 (Ubuntu)",
        "1.30.6-1",
    ]

    def test_distro_builds_are_unknown(self):
        for version in self.DISTRO_VERSIONS:
            with self.subTest(version=version):
                parsed = nhc.parse_nginx_version(version)
                self.assertTrue(parsed["distro"])
                status, reasons = nhc.classify_version(parsed)
                self.assertEqual(status, "unknown")
                self.assertTrue(any("backport" in r for r in reasons))

    def test_distro_unknown_even_with_http2_on(self):
        verdict, code = verdict_for("1.24.0-0ubuntu1", HTTP2_ON)
        self.assertEqual((verdict, code), ("UNKNOWN", 3))

    def test_plain_upstream_version_is_not_distro(self):
        parsed = nhc.parse_nginx_version("nginx version: nginx/1.31.8")
        self.assertFalse(parsed["distro"])
        self.assertEqual(parsed["kind"], "oss")


class TestPlusTable(unittest.TestCase):
    def test_r33_r36_have_no_fix(self):
        for release in (33, 34, 35, 36):
            with self.subTest(release=release):
                parsed = nhc.parse_nginx_version(
                    "nginx version: nginx/1.27.4 (nginx-plus-r%d)" % release)
                self.assertEqual(parsed["kind"], "plus")
                status, _reasons = nhc.classify_version(parsed)
                self.assertEqual(status, "affected")

    def test_r32_predates(self):
        parsed = nhc.parse_nginx_version(
            "nginx version: nginx/1.27.4 (nginx-plus-r32)")
        status, _reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "not_affected")

    def test_37_0_7_1_fixes_123633_only(self):
        # 37.0.7.1 closes 123633 but not 123007 — overall still
        # affected (the other CVE is actionable).
        parsed = nhc.parse_nginx_version("nginx-plus-r37 37.0.7.1")
        status, reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "affected")
        joined = " ".join(reasons)
        self.assertIn("CVE-2026-123633: PATCHED", joined)
        self.assertIn("CVE-2026-123007: AFFECTED", joined)

    def test_37_0_8_1_fixes_both(self):
        parsed = nhc.parse_nginx_version("nginx-plus-r37 37.0.8.1")
        status, _reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "patched")

    def test_37_2_0_1_fixes_123633_only(self):
        # 37.2 train: 123633 fixed, 123007 published as still
        # vulnerable on this build — affected, not guessed safe.
        parsed = nhc.parse_nginx_version("nginx-plus-r37 37.2.0.1")
        status, reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "affected")
        joined = " ".join(reasons)
        self.assertIn("CVE-2026-123633: PATCHED", joined)
        self.assertIn("CVE-2026-123007: AFFECTED", joined)

    def test_37_3_0_1_fixes_both(self):
        parsed = nhc.parse_nginx_version("nginx-plus-r37 37.3.0.1")
        status, _reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "patched")

    def test_37_1_train_unknown(self):
        parsed = nhc.parse_nginx_version("nginx-plus-r37 37.1.0.1")
        status, _reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "unknown")

    def test_r37_without_build_is_unknown(self):
        parsed = nhc.parse_nginx_version(
            "nginx version: nginx/1.27.4 (nginx-plus-r37)")
        status, _reasons = nhc.classify_version(parsed)
        self.assertEqual(status, "unknown")

    def test_plus_vulnerable_with_http2_on(self):
        parsed = nhc.parse_nginx_version(
            "nginx version: nginx/1.27.4 (nginx-plus-r35)")
        http2_state, findings = nhc.parse_config_text(HTTP2_ON)
        verdict, _lines, code = nhc.assess(parsed, "test", http2_state,
                                           findings)
        self.assertEqual((verdict, code), ("VULNERABLE", 1))

    def test_plus_http2_off_not_affected(self):
        parsed = nhc.parse_nginx_version(
            "nginx version: nginx/1.27.4 (nginx-plus-r35)")
        http2_state, findings = nhc.parse_config_text(HTTP2_OFF)
        verdict, _lines, code = nhc.assess(parsed, "test", http2_state,
                                           findings)
        self.assertEqual((verdict, code), ("NOT_AFFECTED", 0))


class TestDemoDeterminism(unittest.TestCase):
    def run_demo(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--demo"],
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout

    def test_demo_twice_byte_identical(self):
        code1, out1 = self.run_demo()
        code2, out2 = self.run_demo()
        self.assertEqual(out1, out2)
        self.assertEqual(code1, code2)

    def test_demo_verdicts_and_exit(self):
        code, out = self.run_demo()
        self.assertIn("Verdict: VULNERABLE", out)
        self.assertIn("Verdict: PATCHED", out)
        self.assertIn("nginx: 1.31.8", out)
        self.assertIn("nginx: 1.30.7", out)
        self.assertIn("Demo uses labelled fixtures only", out)
        # A vulnerable case is present, so exit 1 is the designed outcome.
        self.assertEqual(code, 1)

    def test_demo_json(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--demo", "--json"],
                              capture_output=True, text=True, timeout=60)
        data = json.loads(proc.stdout)
        self.assertTrue(data["demo"])
        self.assertEqual([c["verdict"] for c in data["cases"]],
                         ["VULNERABLE", "PATCHED"])
        self.assertEqual(proc.returncode, 1)


class TestCliEndToEnd(unittest.TestCase):
    def run_cli(self, *argv, env=None):
        return subprocess.run([sys.executable, SCRIPT, *argv],
                              capture_output=True, text=True, timeout=60,
                              env=env)

    def test_version_and_config_flags(self):
        proc = self.run_cli("--version", "1.31.8", "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-on.conf"))
        self.assertIn("Verdict: VULNERABLE", proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_patched_via_flags(self):
        proc = self.run_cli("--version", "1.30.7", "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-on.conf"))
        self.assertIn("Verdict: PATCHED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_http2_off_config_via_flags(self):
        proc = self.run_cli("--version", "1.31.8", "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-off.conf"))
        self.assertIn("Verdict: NOT_AFFECTED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_config_dir_scan(self):
        with tempfile.TemporaryDirectory() as root:
            confd = os.path.join(root, "conf.d")
            os.makedirs(confd)
            with open(os.path.join(confd, "site.conf"), "w") as handle:
                handle.write("server { listen 443 ssl http2; }\n")
            proc = self.run_cli("--version", "1.24.0", "--config", root)
            self.assertIn("Verdict: VULNERABLE", proc.stdout)
            self.assertEqual(proc.returncode, 1)

    def test_fake_nginx_vulnerable(self):
        fake = os.path.join(ROOT, "examples", "fake-nginx-vulnerable.sh")
        proc = self.run_cli("--nginx-path", fake, "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-on.conf"))
        self.assertIn("Verdict: VULNERABLE", proc.stdout)
        self.assertEqual(proc.returncode, 1)

    def test_fake_nginx_patched(self):
        fake = os.path.join(ROOT, "examples", "fake-nginx-patched.sh")
        proc = self.run_cli("--nginx-path", fake, "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-on.conf"))
        self.assertIn("Verdict: PATCHED", proc.stdout)
        self.assertEqual(proc.returncode, 0)

    def test_missing_config_is_usage_error(self):
        proc = self.run_cli("--version", "1.31.8", "--config",
                            "/nonexistent/nginx.conf")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr)

    def test_missing_nginx_path_is_usage_error(self):
        proc = self.run_cli("--nginx-path", "/nonexistent/nginx")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("error", proc.stderr)

    def test_no_nginx_on_path_is_unknown(self):
        env = dict(os.environ)
        env["PATH"] = tempfile.mkdtemp()  # empty dir: no nginx anywhere
        proc = self.run_cli(env=env)
        self.assertIn("Verdict: UNKNOWN", proc.stdout)
        self.assertEqual(proc.returncode, 3)

    def test_bad_flag_is_usage_error(self):
        proc = self.run_cli("--nope")
        self.assertEqual(proc.returncode, 2)

    def test_json_output(self):
        proc = self.run_cli("--version", "1.30.7", "--config",
                            os.path.join(ROOT, "examples",
                                         "nginx-http2-on.conf"),
                            "--json")
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PATCHED")
        self.assertEqual(data["cves"],
                         ["CVE-2026-123007", "CVE-2026-123633"])
        self.assertTrue(data["http2"]["enabled"])
        self.assertEqual(proc.returncode, 0)

    def test_json_distro_unknown(self):
        proc = self.run_cli("--version", "1.24.0-0ubuntu1", "--json")
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertTrue(data["version"]["distro"])
        self.assertEqual(proc.returncode, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
