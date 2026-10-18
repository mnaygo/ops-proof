from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest

from triage_nginx import analyze, markdown, redact

ROOT = Path(__file__).resolve().parent


class TriageTests(unittest.TestCase):
    def test_sample_counts_and_evidence(self):
        report = analyze((ROOT / "sample-error.log").read_text(encoding="utf-8"))
        self.assertEqual(report["line_count"], 7)
        self.assertEqual(report["matched_line_count"], 6)
        findings = {f["id"]: f for f in report["findings"]}
        self.assertEqual(len(findings), 5)
        self.assertEqual(findings["upstream-refused"]["count"], 2)
        self.assertEqual(findings["permission-denied"]["evidence"][0]["line"], 5)

    def test_unknown_is_not_healthy(self):
        report = analyze("2026/10/18 [notice] signal process started")
        self.assertEqual(report["status"], "unknown")
        self.assertIn("未知", markdown(report))

    def test_connect_and_read_timeout_are_separate(self):
        report = analyze("upstream timed out (110: Connection timed out) while connecting to upstream")
        self.assertEqual([f["id"] for f in report["findings"]], ["upstream-connect-timeout"])

    def test_does_not_classify_user_text_as_a_refused_connection(self):
        self.assertEqual(analyze('GET /?q=Connection refused')["findings"], [])

    def test_request_contents_cannot_create_a_false_diagnosis(self):
        log = '[error] open failed, request: "GET /?q=connect() failed (111: Connection refused) while connecting to upstream"'
        self.assertEqual(analyze(log)["findings"], [])

    def test_tls_error_is_not_assumed_to_be_public_certificate(self):
        report = analyze("certificate verify failed: certificate has expired while SSL handshaking to upstream")
        self.assertEqual(report["findings"][0]["id"], "upstream-tls-expired")
        self.assertIn("对外", report["findings"][0]["limit"])

    def test_redacts_common_secrets(self):
        source = ('client: 203.0.113.9, email: demo@example.com '
                  'https://alice:mypass@example.com/path?token=querysecret '
                  'password=plainsecret\nAuthorization: Bearer bearer-secret\nCookie: session=cookie-secret')
        safe = redact(source)
        for value in ["203.0.113.9", "demo@example.com", "mypass", "querysecret", "plainsecret", "bearer-secret", "cookie-secret"]:
            self.assertNotIn(value, safe)

    def test_private_key_redaction_preserves_line_count(self):
        source = 'first\n-----BEGIN RSA PRIVATE KEY-----\nprivate-data\n-----END RSA PRIVATE KEY-----\nlast'
        self.assertEqual(len(redact(source).splitlines()), len(source.splitlines()))
        self.assertNotIn("private-data", redact(source))

    def test_quoted_secrets_are_redacted(self):
        safe = redact('api_key="demo quoted key" password=\'demo quoted password\' secret=demo-secret')
        for value in ["demo quoted key", "demo quoted password", "demo-secret"]:
            self.assertNotIn(value, safe)

    def test_reports_never_include_raw_sample_token(self):
        report = analyze((ROOT / "sample-error.log").read_text(encoding="utf-8"))
        self.assertNotIn("demo-private-token", json.dumps(report))
        self.assertNotIn("demo-private-token", markdown(report))

    def test_evidence_is_bounded_but_counts_remain_complete(self):
        line = 'connect() failed (111: Connection refused) while connecting to upstream\n'
        finding = analyze(line * 100)["findings"][0]
        self.assertEqual(finding["count"], 100)
        self.assertEqual(len(finding["evidence"]), 3)

    def test_cli_keeps_source_and_existing_report_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "error.log"
            output = Path(directory) / "report.json"
            log.write_text("No space left on device\n", encoding="utf-8")
            digest = hashlib.sha256(log.read_bytes()).hexdigest()
            cmd = [sys.executable, str(ROOT / "triage_nginx.py"), str(log), "--format", "json", "--output", str(output)]
            result = subprocess.run(cmd, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["status"], "findings")
            previous = output.read_bytes()
            self.assertEqual(subprocess.run(cmd, capture_output=True).returncode, 2)
            self.assertEqual(output.read_bytes(), previous)
            overwrite_input = cmd[:-1] + [str(log)]
            self.assertEqual(subprocess.run(overwrite_input, capture_output=True).returncode, 2)
            self.assertEqual(hashlib.sha256(log.read_bytes()).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
