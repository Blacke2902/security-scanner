"""Integration tests with real-world vulnerability fixtures.

Verifies the scanner detects known 2025/2026 vulnerabilities with correct
severity, descriptions, and fix versions using mocked API responses based
on real OSV data.
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

from repo_security_scanner.scanner import SecurityScanner
from repo_security_scanner.vulndb.osv import OSVDatabase
from repo_security_scanner.models import Severity


# --- Fixture: OSV hydration responses based on real data ---

AXIOS_VULN = {
    "id": "GHSA-8hc4-vh64-cxmj",
    "summary": "Axios Cross-Site Request Forgery Vulnerability via SSRF and credential leak",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [{
        "package": {"name": "axios", "ecosystem": "npm"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.8.2"}]}],
    }],
    "references": [{"url": "https://github.com/axios/axios/issues/10604"}],
    "database_specific": {"severity": "HIGH"},
}

LITELLM_VULN = {
    "id": "GHSA-litellm-supply-chain",
    "summary": "LiteLLM supply chain compromise - malicious code injected into published package",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "litellm", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.55.0"}, {"fixed": "1.56.0"}]}],
    }],
    "references": [{"url": "https://github.com/BerriAI/litellm/issues/24512"}],
    "database_specific": {"severity": "CRITICAL"},
}

JSONWEBTOKEN_VULN = {
    "id": "GHSA-8cf7-32gw-wr33",
    "summary": "jsonwebtoken unrestricted key type could lead to legacy keys usage",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"}],
    "affected": [{
        "package": {"name": "jsonwebtoken", "ecosystem": "npm"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.0.0"}]}],
    }],
    "references": [{"url": "https://github.com/advisories/GHSA-8cf7-32gw-wr33"}],
    "database_specific": {"severity": "HIGH"},
}

REACT_RCE_VULN = {
    "id": "GHSA-react-rce-2025",
    "summary": "React Server Components pre-authentication remote code execution via unsafe deserialization (CVE-2025-55182)",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "react-server-dom-webpack", "ecosystem": "npm"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "19.0.0"}, {"fixed": "19.2.1"}]}],
    }],
    "references": [
        {"url": "https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components"},
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-55182"},
    ],
    "database_specific": {"severity": "CRITICAL"},
}


def _make_batch_response(vuln_ids: list[str]) -> dict:
    """Create a mock OSV batch response with stub IDs."""
    return {"results": [{"vulns": [{"id": vid, "modified": "2026-01-01T00:00:00Z"} for vid in vuln_ids]}]}


def _make_hydration_side_effect(vuln_map: dict):
    """Create a side_effect function for mocked requests.get that returns full vuln data."""
    def side_effect(url, **kwargs):
        resp = MagicMock()
        vuln_id = url.rsplit("/", 1)[-1]
        if vuln_id in vuln_map:
            resp.status_code = 200
            resp.json.return_value = vuln_map[vuln_id]
            resp.raise_for_status = MagicMock()
        else:
            resp.status_code = 404
            resp.raise_for_status.side_effect = Exception("Not found")
        return resp
    return side_effect


def _run_scan_with_fixtures(tmpdir: str, vuln_ids: list[str], vuln_map: dict):
    """Run scanner with mocked batch + hydration responses."""
    batch_resp = MagicMock()
    batch_resp.status_code = 200
    batch_resp.json.return_value = _make_batch_response(vuln_ids)
    batch_resp.raise_for_status = MagicMock()

    osv = OSVDatabase()

    with patch.object(osv.session, "post", return_value=batch_resp):
        with patch("repo_security_scanner.vulndb.osv.requests.get",
                    side_effect=_make_hydration_side_effect(vuln_map)):
            scanner = SecurityScanner(vuln_sources=[osv])
            return scanner.scan(tmpdir)


class TestAxiosSSRF:
    """axios SSRF + credential leak — https://github.com/axios/axios/issues/10604"""

    def test_detects_vulnerable_axios(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {"dependencies": {"axios": "1.6.0"}}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)

            report = _run_scan_with_fixtures(
                tmpdir,
                [AXIOS_VULN["id"]],
                {AXIOS_VULN["id"]: AXIOS_VULN},
            )

            assert len(report.vulnerable_dependencies) >= 1
            vuln = report.vulnerable_dependencies[0].vulnerabilities[0]
            assert vuln.severity == Severity.HIGH
            assert vuln.fixed_version == "1.8.2"
            assert "axios" in vuln.summary.lower() or "SSRF" in vuln.summary or "credential" in vuln.summary


class TestLitellmSupplyChain:
    """litellm supply chain compromise — https://github.com/BerriAI/litellm/issues/24512"""

    def test_detects_compromised_litellm(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "requirements.txt"), "w") as f:
                f.write("litellm==1.55.0\n")

            report = _run_scan_with_fixtures(
                tmpdir,
                [LITELLM_VULN["id"]],
                {LITELLM_VULN["id"]: LITELLM_VULN},
            )

            assert len(report.vulnerable_dependencies) >= 1
            vuln = report.vulnerable_dependencies[0].vulnerabilities[0]
            assert vuln.severity == Severity.CRITICAL
            assert vuln.fixed_version == "1.56.0"
            assert "supply chain" in vuln.summary.lower() or "malicious" in vuln.summary.lower()


class TestJsonwebtokenBypass:
    """jsonwebtoken JWT bypass — GHSA-8cf7-32gw-wr33 (Juice Shop test case)"""

    def test_detects_jwt_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {"dependencies": {"jsonwebtoken": "0.4.0"}}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)

            report = _run_scan_with_fixtures(
                tmpdir,
                [JSONWEBTOKEN_VULN["id"]],
                {JSONWEBTOKEN_VULN["id"]: JSONWEBTOKEN_VULN},
            )

            assert len(report.vulnerable_dependencies) >= 1
            vuln = report.vulnerable_dependencies[0].vulnerabilities[0]
            assert vuln.severity == Severity.HIGH
            assert vuln.fixed_version == "9.0.0"
            assert "jsonwebtoken" in vuln.summary.lower()
            assert len(vuln.references) >= 1


class TestReactRCE:
    """React Server Components RCE — CVE-2025-55182 (CVSS 10.0, CISA KEV)"""

    def test_detects_react_rce(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {"dependencies": {"react-server-dom-webpack": "19.1.0"}}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)

            report = _run_scan_with_fixtures(
                tmpdir,
                [REACT_RCE_VULN["id"]],
                {REACT_RCE_VULN["id"]: REACT_RCE_VULN},
            )

            assert len(report.vulnerable_dependencies) >= 1
            vuln = report.vulnerable_dependencies[0].vulnerabilities[0]
            assert vuln.severity == Severity.CRITICAL
            assert vuln.fixed_version == "19.2.1"
            assert "CVE-2025-55182" in vuln.summary or "deserialization" in vuln.summary.lower()
            assert len(vuln.references) >= 1


class TestCleanPackage:
    """Negative test — express 4.21.0 should have no vulnerabilities."""

    def test_no_vulns_for_clean_package(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            pkg = {"dependencies": {"express": "4.21.0"}}
            with open(os.path.join(tmpdir, "package.json"), "w") as f:
                json.dump(pkg, f)

            # Batch returns empty results for this package
            batch_resp = MagicMock()
            batch_resp.status_code = 200
            batch_resp.json.return_value = {"results": [{"vulns": []}]}
            batch_resp.raise_for_status = MagicMock()

            osv = OSVDatabase()
            with patch.object(osv.session, "post", return_value=batch_resp):
                scanner = SecurityScanner(vuln_sources=[osv])
                report = scanner.scan(tmpdir)

            assert report.is_clean
            assert report.total_vulns == 0
