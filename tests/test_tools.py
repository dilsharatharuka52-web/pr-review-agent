import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.schemas import DiffStats, Finding, Vulnerability, ReleaseNoteEntry, AnalysisReport, RunMetadata
from tools.risk_score import score


FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text()


# ---------------------------------------------------------------------------
# risk_score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_empty_returns_zero(self):
        assert score([], [], None) == 0.0

    def test_low_findings_low_score(self):
        findings = [Finding("f.py", 1, "low", "minor", "style")]
        assert 0.0 < score(findings, [], None) < 4.0

    def test_high_findings_high_score(self):
        findings = [Finding("f.py", 1, "critical", "bad", "bug") for _ in range(10)]
        assert score(findings, [], None) >= 5.0

    def test_vulnerabilities_increase_score(self):
        findings = [Finding("f.py", 1, "medium", "x", "rule")]
        vulns = [Vulnerability("f.py", severity="high", description="cve")]
        s_with = score(findings, vulns, None)
        s_without = score(findings, [], None)
        assert s_with > s_without

    def test_large_diff_increases_score(self):
        stats = DiffStats(files_changed=5, lines_added=600, lines_removed=200)
        s_large = score([], [], stats)
        stats_small = DiffStats(files_changed=1, lines_added=10, lines_removed=5)
        s_small = score([], [], stats_small)
        assert s_large > s_small

    def test_tests_changed_lowers_score(self):
        stats_with = DiffStats(files_changed=10, lines_added=800, lines_removed=300, tests_changed=True)
        stats_without = DiffStats(files_changed=10, lines_added=800, lines_removed=300, tests_changed=False)
        s_with = score([], [], stats_with)
        s_without = score([], [], stats_without)
        assert s_with <= s_without

    def test_score_bounds_0_to_10(self):
        findings = [Finding("f.py", 1, "critical", "x", "bug") for _ in range(100)]
        vulns = [Vulnerability("f.py", severity="critical", description="boom") for _ in range(50)]
        stats = DiffStats(files_changed=50, lines_added=5000, lines_removed=3000)
        assert 0.0 <= score(findings, vulns, stats) <= 10.0


# ---------------------------------------------------------------------------
# code_review (mocked DeepSeek API)
# ---------------------------------------------------------------------------

class TestCodeReview:
    @patch("tools.code_review.httpx.Client")
    def test_review_returns_findings(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": json.dumps([
                {"file": "src/main.py", "line": 42, "severity": "high",
                 "message": "SQL injection risk", "rule": "security-sqli"},
            ])}}],
            "usage": {"total_tokens": 50},
        }
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp

        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            from tools.code_review import review
            findings = review(load_fixture("trivial.diff"))

        assert len(findings) == 1
        assert findings[0].file == "src/main.py"
        assert findings[0].rule == "security-sqli"

    @patch("tools.code_review.httpx.Client")
    def test_review_empty_on_no_key(self, mock_client):
        from tools.code_review import review
        findings = review(load_fixture("trivial.diff"))
        assert findings == []

    @patch("tools.code_review.httpx.Client")
    def test_review_handles_bad_json(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "not json"}}],
            "usage": {"total_tokens": 10},
        }
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp

        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}):
            from tools.code_review import review
            findings = review("some diff")
        assert findings == []


# ---------------------------------------------------------------------------
# security_scan (mocked Semgrep + OSV)
# ---------------------------------------------------------------------------

class TestSecurityScan:
    @patch("tools.security_scan._semgrep_scan", return_value=[
        Vulnerability("src/auth.py", severity="high", description="XSS", source="semgrep"),
    ])
    @patch("tools.security_scan._osv_scan", return_value=[])
    def test_scan_merges_sources(self, mock_osv, mock_semgrep):
        from tools.security_scan import scan
        vulns = scan("")
        assert len(vulns) == 1
        assert vulns[0].source == "semgrep"

    @patch("tools.security_scan._semgrep_scan", return_value=[])
    @patch("tools.security_scan._osv_scan", return_value=[])
    def test_scan_empty(self, mock_osv, mock_semgrep):
        from tools.security_scan import scan
        assert scan("") == []


# ---------------------------------------------------------------------------
# release_notes
# ---------------------------------------------------------------------------

class TestReleaseNotes:
    def test_parses_diff_notes(self):
        from tools.release_notes import _parse_diff
        diff = load_fixture("trivial.diff")
        entries = _parse_diff(diff)
        assert len(entries) >= 1
        assert entries[0].category == "feat"

    def test_generate_without_commits(self):
        from tools.release_notes import generate_notes
        diff = load_fixture("trivial.diff")
        entries = generate_notes(diff)
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# github_comment body building
# ---------------------------------------------------------------------------

class TestGithubComment:
    def test_build_body_includes_risk(self):
        from outputs.github_comment import _build_body
        report = AnalysisReport(risk_score=7.5, risk_level="high")
        body = _build_body(report)
        assert "7.5" in body
        assert "high" in body


# ---------------------------------------------------------------------------
# slack_alert
# ---------------------------------------------------------------------------

class TestSlackAlert:
    def test_send_alert_no_webhook(self):
        from outputs.slack_alert import send_alert
        report = AnalysisReport(risk_score=8.0, risk_level="high")
        send_alert(report)  # should not raise

    @patch("outputs.slack_alert.httpx.Client")
    def test_send_alert_success(self, mock_client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.return_value.__enter__.return_value.post.return_value = mock_resp

        report = AnalysisReport(
            risk_score=9.0, risk_level="high",
            vulnerabilities=[Vulnerability("f.py", cve="CVE-123", severity="critical")],
        )
        with patch.dict("os.environ", {"SLACK_WEBHOOK_URL": "https://hooks.test"}):
            from outputs.slack_alert import send_alert
            send_alert(report)
            assert mock_client.return_value.__enter__.return_value.post.called


# ---------------------------------------------------------------------------
# orchestrator utilities
# ---------------------------------------------------------------------------

class TestDiffStats:
    def test_parses_added_removed(self):
        from agent.orchestrator import _diff_stats
        diff = """diff --git a/a.py b/a.py
+++ b/a.py
@@ -1 +1,3 @@
+new line
+another
 old line
"""
        stats = _diff_stats(diff)
        assert stats.lines_added == 2
        assert stats.lines_removed == 0

    def test_detects_tests_changed(self):
        from agent.orchestrator import _diff_stats
        diff = """diff --git a/tests/test_a.py b/tests/test_a.py
+++ b/tests/test_a.py
@@ -0,0 +1 @@
+test
"""
        stats = _diff_stats(diff)
        assert stats.tests_changed is True


class TestSerialization:
    def test_round_trip(self):
        from agent.orchestrator import _serialize, _deserialize
        report = AnalysisReport(
            risk_score=5.0, risk_level="medium",
            findings=[Finding("f.py", 1, "high", "msg", "rule")],
            vulnerabilities=[Vulnerability("v.py", cve="CVE-123")],
            release_notes=[ReleaseNoteEntry("feat", "new feature")],
            diff_stats=DiffStats(files_changed=2, lines_added=10, lines_removed=5),
            metadata=RunMetadata(pr_number=42, pr_title="test", base_sha="a", head_sha="b"),
        )
        data = _serialize(report)
        restored = _deserialize(data)
        assert restored.risk_score == 5.0
        assert len(restored.findings) == 1
        assert len(restored.vulnerabilities) == 1
        assert len(restored.release_notes) == 1
        assert restored.metadata.pr_number == 42
