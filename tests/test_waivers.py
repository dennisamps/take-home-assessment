"""Tests for scripts/waivers.py. Run with: python3 -m unittest discover -s tests -v"""
import json
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import waivers  # noqa: E402

NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
TODAY = NOW.date()


def waiver(**overrides):
    w = {
        "id": "W-2026-001",
        "scanner": "trivy-vuln",
        "rule": "CVE-2020-14343",
        "path": "requirements.txt",
        "resource": "pyyaml",
        "reason": "Upgrade needs a parser change; loader is not reachable from user input.",
        "reference": "SEC-123",
        "requested_by": "@alice",
        "approved_by": "@bob",
        "created_at": date(2026, 9, 25),
        "expires_at": date(2026, 10, 20),
    }
    w.update(overrides)
    return {k: v for k, v in w.items() if v is not None}


def break_glass(**overrides):
    b = {
        "id": "BG-2026-001",
        "incident": "INC-42",
        "reason": "Production outage; rollback fix must ship before the CVE fix lands.",
        "invoked_by": "@alice",
        "approved_by": "@bob",
        "invoked_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=11),
    }
    b.update(overrides)
    return b


VULN_REPORT = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2020-14343", "PkgName": "pyyaml", "Severity": "CRITICAL"},
    {"VulnerabilityID": "CVE-2020-14343", "PkgName": "other-pkg", "Severity": "HIGH"},
    {"VulnerabilityID": "CVE-2000-0001", "PkgName": "pyyaml", "Severity": "MEDIUM"},
]}]}
SAST_REPORT = {"results": [{"check_id": "python.flask.injection", "path": "app.py", "start": {"line": 8},
                            "extra": {"severity": "ERROR", "metadata": {"confidence": "HIGH"}}}]}
IAC_REPORT = {"Results": [{"Target": "terraform/main.tf", "Misconfigurations": [
    {"ID": "AWS-0107", "Severity": "HIGH", "Status": "FAIL", "Title": "Open ingress",
     "CauseMetadata": {"Resource": "aws_security_group.open"}}]}]}
SECRET_REPORT = [{"RuleID": "aws-access-token", "File": "app/config.ini", "Commit": "a" * 40, "StartLine": 1}]


class WaiverValidation(unittest.TestCase):
    def assertRejected(self, text, **overrides):
        errors = waivers.validate_waiver(waiver(**overrides), TODAY)
        self.assertTrue(any(text in e for e in errors), errors)

    def test_valid_waiver_is_accepted(self):
        self.assertEqual(waivers.validate_waiver(waiver(), TODAY), [])

    def test_expired_waiver_is_rejected(self):
        self.assertRejected("EXPIRED", created_at=date(2026, 9, 10), expires_at=date(2026, 10, 2))

    def test_waiver_expires_at_start_of_expiry_day(self):
        w = waiver(expires_at=date(2026, 10, 3))
        self.assertEqual(waivers.validate_waiver(w, date(2026, 10, 2)), [])
        self.assertTrue(waivers.validate_waiver(w, date(2026, 10, 3)))

    def test_long_lived_waiver_is_rejected(self):
        self.assertRejected("longer than 30 days", expires_at=date(2026, 12, 31))

    def test_missing_and_unknown_fields_are_rejected(self):
        self.assertRejected("missing field 'approved_by'", approved_by=None)
        self.assertRejected("unknown field 'permanent'", permanent="true")

    def test_self_approval_is_rejected(self):
        self.assertRejected("different person", approved_by="@Alice")

    def test_broad_scope_is_rejected(self):
        self.assertRejected("too broad", rule="*")
        self.assertRejected("too broad", rule="CVE-2020-*")
        self.assertRejected("too broad", path="src/**/*.py")
        self.assertRejected("too broad", resource="*")
        self.assertRejected("not a directory", path="src/")
        self.assertRejected("not a directory", path="../other/requirements.txt")
        self.assertRejected("not a directory", path=os.path.dirname(os.path.abspath(__file__)))

    def test_resource_rules_per_scanner(self):
        self.assertRejected("package name", resource=None)
        self.assertRejected("commit SHA", scanner="gitleaks", rule="aws-access-token", resource="abc123")
        self.assertRejected("not used for semgrep", scanner="semgrep", rule="python.x.y")

    def test_quoted_dates_and_bad_reference_are_rejected(self):
        self.assertRejected("unquoted dates", expires_at="2026-10-20")
        self.assertRejected("ticket key", reference="see slack")


class BreakGlassValidation(unittest.TestCase):
    def test_valid_entry_is_accepted(self):
        self.assertEqual(waivers.validate_break_glass(break_glass(), NOW), [])

    def test_window_over_24_hours_is_rejected(self):
        errors = waivers.validate_break_glass(break_glass(expires_at=NOW + timedelta(hours=30)), NOW)
        self.assertTrue(any("longer than 24 hours" in e for e in errors), errors)

    def test_expired_entry_is_rejected(self):
        entry = break_glass(invoked_at=NOW - timedelta(hours=20), expires_at=NOW - timedelta(hours=1))
        self.assertTrue(any("EXPIRED" in e for e in waivers.validate_break_glass(entry, NOW)))

    def test_self_approval_is_rejected(self):
        errors = waivers.validate_break_glass(break_glass(approved_by="@alice"), NOW)
        self.assertTrue(any("different person" in e for e in errors), errors)


class GateCase(unittest.TestCase):
    """Helpers only: write scanner reports to a temporary directory and run the gate on them."""

    def run_gate(self, reports, waiver_list=(), bg=()):
        with tempfile.TemporaryDirectory() as d:
            for name, data in reports.items():
                with open(os.path.join(d, name), "w") as f:
                    json.dump(data, f)
            findings, problems = waivers.load_findings(d)
        return waivers.decide(list(waiver_list), list(bg), findings, problems)

    def all_reports(self, **overrides):
        reports = {"gitleaks.json": [], "semgrep.json": {"results": []},
                   "trivy-vuln.json": {"Results": []}, "trivy-config.json": {"Results": []}}
        reports.update(overrides)
        return reports


class Gate(GateCase):
    def test_clean_reports_pass(self):
        lines, blocked, _, _ = self.run_gate(self.all_reports())
        self.assertEqual((lines, blocked), ([], 0))

    def test_threshold_blocks_high_and_critical_only(self):
        _, blocked, _, _ = self.run_gate(self.all_reports(**{"trivy-vuln.json": VULN_REPORT}))
        self.assertEqual(blocked, 2)

    def test_waiver_applies_only_to_the_exact_finding(self):
        lines, blocked, _, unused = self.run_gate(
            self.all_reports(**{"trivy-vuln.json": VULN_REPORT}), [waiver()])
        self.assertEqual(blocked, 1)  # same CVE in other-pkg is still blocked
        self.assertTrue(any(l.startswith("WAIVED by W-2026-001") and "resource=pyyaml" in l for l in lines))
        self.assertTrue(any(l.startswith("BLOCK") and "resource=other-pkg" in l for l in lines))
        self.assertEqual(unused, [])

    def test_waiver_for_another_file_does_not_apply(self):
        _, blocked, _, unused = self.run_gate(
            self.all_reports(**{"trivy-vuln.json": VULN_REPORT}), [waiver(path="other/requirements.txt")])
        self.assertEqual(blocked, 2)
        self.assertEqual(len(unused), 1)

    def test_semgrep_blocks_only_high_confidence_errors(self):
        def finding(severity, confidence):
            return {"check_id": f"rule.{severity}.{confidence}", "path": "app.py", "start": {"line": 1},
                    "extra": {"severity": severity, "metadata": {"confidence": confidence}}}
        report = {"results": [finding("ERROR", "HIGH"), finding("ERROR", "MEDIUM"), finding("WARNING", "HIGH")]}
        lines, blocked, _, _ = self.run_gate(self.all_reports(**{"semgrep.json": report}))
        self.assertEqual(blocked, 1)
        self.assertIn("rule.ERROR.HIGH", lines[0])

    def test_missing_report_blocks(self):
        reports = self.all_reports()
        del reports["semgrep.json"]
        lines, blocked, _, _ = self.run_gate(reports)
        self.assertEqual(blocked, 1)
        self.assertIn("did not run", lines[0])

class BreakGlassGate(GateCase):
    """With break-glass active: findings may be bypassed, secrets and scanner failures never."""

    def run_with_break_glass(self, reports):
        return self.run_gate(reports, bg=[break_glass()])

    def statuses(self, lines, scanner):
        return [l.split(":")[0].split(" ")[0] for l in lines if f"scanner={scanner} " in l]

    def test_sast_finding_is_bypassed(self):
        lines, blocked, bypassed, _ = self.run_with_break_glass(self.all_reports(**{"semgrep.json": SAST_REPORT}))
        self.assertEqual((blocked, bypassed), (0, 1))
        self.assertEqual(self.statuses(lines, "semgrep"), ["BYPASS"])

    def test_sca_finding_is_bypassed(self):
        lines, blocked, bypassed, _ = self.run_with_break_glass(self.all_reports(**{"trivy-vuln.json": VULN_REPORT}))
        self.assertEqual((blocked, bypassed), (0, 2))
        self.assertEqual(self.statuses(lines, "trivy-vuln"), ["BYPASS", "BYPASS"])

    def test_iac_finding_is_bypassed(self):
        lines, blocked, bypassed, _ = self.run_with_break_glass(self.all_reports(**{"trivy-config.json": IAC_REPORT}))
        self.assertEqual((blocked, bypassed), (0, 1))
        self.assertEqual(self.statuses(lines, "trivy-config"), ["BYPASS"])

    def test_gitleaks_finding_still_blocks(self):
        reports = self.all_reports(**{"trivy-vuln.json": VULN_REPORT, "gitleaks.json": SECRET_REPORT})
        lines, blocked, bypassed, _ = self.run_with_break_glass(reports)
        self.assertEqual((blocked, bypassed), (1, 2))
        self.assertEqual(self.statuses(lines, "gitleaks"), ["BLOCK"])

    def test_missing_semgrep_report_still_blocks(self):
        reports = self.all_reports()
        del reports["semgrep.json"]
        lines, blocked, bypassed, _ = self.run_with_break_glass(reports)
        self.assertEqual((blocked, bypassed), (1, 0))
        self.assertEqual(self.statuses(lines, "semgrep"), ["BLOCK"])

    def test_malformed_semgrep_report_still_blocks(self):
        lines, blocked, bypassed, _ = self.run_with_break_glass(self.all_reports(**{"semgrep.json": {"oops": 1}}))
        self.assertEqual((blocked, bypassed), (1, 0))
        self.assertEqual(self.statuses(lines, "semgrep"), ["BLOCK"])

    def test_missing_trivy_reports_still_block(self):
        reports = self.all_reports()
        del reports["trivy-vuln.json"], reports["trivy-config.json"]
        lines, blocked, bypassed, _ = self.run_with_break_glass(reports)
        self.assertEqual((blocked, bypassed), (2, 0))
        self.assertEqual(self.statuses(lines, "trivy-vuln") + self.statuses(lines, "trivy-config"), ["BLOCK", "BLOCK"])

    def test_failed_trivy_image_scan_still_blocks(self):
        # The workflow writes a non-JSON marker when the image scan fails.
        lines, blocked, bypassed, _ = self.run_with_break_glass(self.all_reports(**{"trivy-image.json": "image scan failed"}))
        self.assertEqual((blocked, bypassed), (1, 0))
        self.assertEqual(self.statuses(lines, "trivy-vuln"), ["BLOCK"])

    def test_failed_scanner_blocks_while_findings_are_bypassed(self):
        reports = self.all_reports(**{"trivy-vuln.json": VULN_REPORT})
        del reports["semgrep.json"]
        _, blocked, bypassed, _ = self.run_with_break_glass(reports)
        self.assertEqual((blocked, bypassed), (1, 2))


class WaiverFile(unittest.TestCase):
    def load(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(text)
        try:
            return waivers.load(f.name, NOW)
        finally:
            os.unlink(f.name)

    def test_repository_waiver_file_is_valid(self):
        path = os.path.join(os.path.dirname(__file__), "..", "waivers", "waivers.yaml")
        self.assertEqual(waivers.load(path, datetime.now(timezone.utc))[2], [])

    def test_empty_lists_are_valid(self):
        self.assertEqual(self.load("waivers: []\nbreak_glass: []\n")[2], [])

    def test_malformed_file_is_rejected(self):
        self.assertTrue(self.load("waivers: [\n")[2])
        self.assertTrue(self.load("waivers: []\n")[2])
        self.assertTrue(self.load("waivers:\nbreak_glass: []\n")[2])
        self.assertTrue(self.load("waivers: []\nbreak_glass: []\nignore_all: true\n")[2])

    def test_duplicate_ids_and_targets_are_rejected(self):
        entry = """
  - id: {id}
    scanner: trivy-vuln
    rule: CVE-2020-14343
    path: requirements.txt
    resource: pyyaml
    reason: Upgrade needs a parser change; loader is not reachable from user input.
    reference: SEC-123
    requested_by: "@alice"
    approved_by: "@bob"
    created_at: 2026-09-25
    expires_at: 2026-10-20"""
        text = "waivers:" + entry.format(id="W-2026-001") + entry.format(id="W-2026-001") + "\nbreak_glass: []\n"
        errors = self.load(text)[2]
        self.assertTrue(any("duplicate id" in e for e in errors), errors)
        self.assertTrue(any("already covers" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
