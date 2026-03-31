"""Tests for LLM analyzer — prompt building and graceful failure."""

from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from repo_security_scanner.llm import LLMAnalyzer
from repo_security_scanner.models import (
    Dependency, Ecosystem, ScanReport, ScanResult, Severity, Vulnerability,
)


def _make_report(vulns_count=3):
    results = []
    for i in range(vulns_count):
        dep = Dependency(name=f"pkg-{i}", version=f"1.{i}.0", ecosystem=Ecosystem.NPM, source_file="package.json")
        vuln = Vulnerability(
            id=f"CVE-2026-{i:04d}", summary=f"Test vulnerability {i}",
            severity=Severity.HIGH if i == 0 else Severity.MEDIUM,
            affected_versions=f"<1.{i}.1", fixed_version=f"1.{i}.1",
        )
        results.append(ScanResult(dependency=dep, vulnerabilities=[vuln]))
    return ScanReport(directory="/tmp/test", scanned_at=datetime.now(timezone.utc), results=results)


class TestPromptBuilding:
    def test_build_prompt_includes_summary(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key="test")
        report = _make_report()
        prompt = analyzer._build_prompt(report)
        assert "Total dependencies: 3" in prompt
        assert "Critical: 0" in prompt
        assert "High: 1" in prompt

    def test_build_prompt_includes_vulns(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key="test")
        report = _make_report()
        prompt = analyzer._build_prompt(report)
        assert "pkg-0" in prompt
        assert "CVE-2026-0000" in prompt

    def test_build_prompt_empty_report(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key="test")
        report = _make_report(vulns_count=0)
        prompt = analyzer._build_prompt(report)
        assert "No critical or high severity vulnerabilities found" in prompt


class TestAnalyzeGracefulFailure:
    def test_no_api_key_returns_none(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key=None)
        report = _make_report()
        assert analyzer.analyze(report) is None

    def test_api_error_returns_none(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key="test-key")
        report = _make_report()
        with patch.object(analyzer.session, "post", side_effect=Exception("API error")):
            result = analyzer.analyze(report)
            assert result is None

    def test_anthropic_success(self):
        analyzer = LLMAnalyzer(provider="anthropic", api_key="test-key")
        report = _make_report()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"content": [{"text": "## Priority: Fix pkg-0 first"}]}
        mock_resp.raise_for_status = MagicMock()
        with patch.object(analyzer.session, "post", return_value=mock_resp):
            result = analyzer.analyze(report)
            assert result == "## Priority: Fix pkg-0 first"

    def test_openai_success(self):
        analyzer = LLMAnalyzer(provider="openai", api_key="test-key")
        report = _make_report()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"choices": [{"message": {"content": "Fix pkg-0"}}]}
        mock_resp.raise_for_status = MagicMock()
        with patch.object(analyzer.session, "post", return_value=mock_resp):
            result = analyzer.analyze(report)
            assert result == "Fix pkg-0"

    def test_detect_api_key_from_env(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test-123"}):
            analyzer = LLMAnalyzer(provider="anthropic")
            assert analyzer.api_key == "sk-test-123"
