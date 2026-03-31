"""Tests for early warning system components."""

from repo_security_scanner.models import Dependency, Ecosystem, Vulnerability, Severity, ScanResult, ScanReport
from repo_security_scanner.filters import should_search_web, matches_package, relevance_score
from repo_security_scanner.cache import FileCache
from datetime import datetime, timezone
import tempfile
import os


class TestFilters:
    def test_should_search_web_normal_package(self):
        dep = Dependency(name="requests", version="2.31.0", ecosystem=Ecosystem.PYPI, source_file="req.txt")
        assert should_search_web(dep) is True

    def test_should_search_web_generic_name(self):
        dep = Dependency(name="utils", version="1.0", ecosystem=Ecosystem.NPM, source_file="package.json")
        assert should_search_web(dep) is False

    def test_should_search_web_short_name(self):
        dep = Dependency(name="os", version="1.0", ecosystem=Ecosystem.NPM, source_file="package.json")
        assert should_search_web(dep) is False

    def test_should_search_web_scoped_npm(self):
        dep = Dependency(name="@angular/core", version="16.0", ecosystem=Ecosystem.NPM, source_file="package.json")
        # "core" is in blocklist, but the full scoped name's last part is checked
        assert should_search_web(dep) is False

    def test_should_search_web_maven(self):
        dep = Dependency(name="org.springframework:spring-core", version="5.3", ecosystem=Ecosystem.MAVEN, source_file="pom.xml")
        assert should_search_web(dep) is True  # "spring-core" is not in blocklist

    def test_matches_package_with_security_keyword(self):
        assert matches_package("axios vulnerability found in npm package", "axios") is True

    def test_matches_package_no_security_keyword(self):
        assert matches_package("axios is a great HTTP client library", "axios") is False

    def test_matches_package_substring_no_match(self):
        # "ax" should not match "axios" via word boundary
        assert matches_package("ax vulnerability found", "axios") is False

    def test_matches_package_case_insensitive(self):
        assert matches_package("AXIOS Critical CVE discovered", "axios") is True

    def test_relevance_score_high(self):
        score = relevance_score(
            "axios vulnerability CVE-2023-45857 critical exploit found",
            "axios", age_days=1, engagement=50,
        )
        assert score >= 0.5

    def test_relevance_score_low(self):
        score = relevance_score(
            "something mentioned in passing",
            "axios", age_days=13, engagement=1,
        )
        assert score < 0.5


class TestFileCache:
    def test_set_and_get(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            cache.set("test_key", {"data": "hello"})
            result = cache.get("test_key", max_age_seconds=3600)
            assert result == {"data": "hello"}

    def test_get_expired(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            cache.set("test_key", {"data": "hello"})
            result = cache.get("test_key", max_age_seconds=0)
            assert result is None

    def test_get_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            result = cache.get("nonexistent", max_age_seconds=3600)
            assert result is None

    def test_clear(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = FileCache(cache_dir=tmpdir)
            cache.set("key1", {"a": 1})
            cache.set("key2", {"b": 2})
            cache.clear()
            assert cache.get("key1", 3600) is None
            assert cache.get("key2", 3600) is None


class TestModelConfidence:
    def test_vulnerability_default_confidence(self):
        v = Vulnerability(id="CVE-123", summary="test", severity=Severity.HIGH,
                          affected_versions="1.0", fixed_version="1.1")
        assert v.confidence == "confirmed"

    def test_vulnerability_early_signal(self):
        v = Vulnerability(id="HN-123", summary="test", severity=Severity.UNKNOWN,
                          affected_versions="unknown", fixed_version=None,
                          confidence="early_signal")
        assert v.confidence == "early_signal"

    def test_scan_report_separates_confirmed_and_signals(self):
        confirmed_vuln = Vulnerability(id="CVE-1", summary="confirmed", severity=Severity.HIGH,
                                       affected_versions="1.0", fixed_version="1.1", confidence="confirmed")
        signal_vuln = Vulnerability(id="HN-1", summary="signal", severity=Severity.UNKNOWN,
                                    affected_versions="unknown", fixed_version=None, confidence="early_signal")
        dep = Dependency(name="flask", version="2.0", ecosystem=Ecosystem.PYPI, source_file="req.txt")
        result = ScanResult(dependency=dep, vulnerabilities=[confirmed_vuln, signal_vuln])
        report = ScanReport(directory="/tmp", scanned_at=datetime.now(timezone.utc), results=[result])

        assert len(report.confirmed_results) == 1
        assert len(report.confirmed_results[0].vulnerabilities) == 1
        assert report.confirmed_results[0].vulnerabilities[0].id == "CVE-1"

        assert len(report.early_signals) == 1
        assert len(report.early_signals[0].vulnerabilities) == 1
        assert report.early_signals[0].vulnerabilities[0].id == "HN-1"
        assert report.early_signal_count == 1
