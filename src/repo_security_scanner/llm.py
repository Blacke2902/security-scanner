"""Optional LLM-powered security analysis for scan reports."""

from __future__ import annotations

import json
import os

import requests

from repo_security_scanner.models import ScanReport, Severity

SYSTEM_PROMPT = """You are a senior security engineer reviewing dependency scan results for a software project. Based on the findings provided, deliver:

1. **Priority Ranking**: List the top vulnerabilities to fix first, with brief reasoning for each.
2. **Mitigation Steps**: For each critical/high finding, provide specific upgrade commands or configuration changes.
3. **Security Posture**: Rate overall as Good / Fair / Poor / Critical with a one-line justification.

Be concise and actionable. Developers will read this directly."""


class LLMAnalyzer:
    def __init__(self, provider: str = "anthropic", api_key: str = None):
        self.provider = provider
        self.api_key = api_key or self._detect_api_key()
        self.session = requests.Session()

    def _detect_api_key(self) -> str | None:
        if self.provider == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY")
        elif self.provider == "openai":
            return os.environ.get("OPENAI_API_KEY")
        return None

    def analyze(self, report: ScanReport) -> str | None:
        if not self.api_key:
            return None
        prompt = self._build_prompt(report)
        try:
            if self.provider == "anthropic":
                return self._call_anthropic(prompt)
            elif self.provider == "openai":
                return self._call_openai(prompt)
        except Exception:
            return None

    def _build_prompt(self, report: ScanReport) -> str:
        lines = [
            f"## Scan Summary",
            f"- Directory: {report.directory}",
            f"- Total dependencies: {report.total_dependencies}",
            f"- Total vulnerabilities: {report.total_vulns}",
            f"- Critical: {report.critical_count}, High: {report.high_count}, "
            f"Medium: {report.medium_count}, Low: {report.low_count}",
            f"- Early warning signals: {report.early_signal_count}",
            "",
            "## Top Vulnerabilities (Critical + High)",
            "",
        ]

        count = 0
        for result in report.results:
            for v in result.vulnerabilities:
                if v.severity in (Severity.CRITICAL, Severity.HIGH) and count < 15:
                    fix = v.fixed_version or "no fix available"
                    lines.append(
                        f"- **{result.dependency.name}** ({result.dependency.version}, "
                        f"{result.dependency.ecosystem.value}): "
                        f"{v.id} — {v.severity.value} — {v.summary[:100]} — Fix: {fix}"
                    )
                    count += 1

        if count == 0:
            lines.append("No critical or high severity vulnerabilities found.")

        # Add early signals if any
        signals = report.early_signals
        if signals:
            lines.append("")
            lines.append("## Early Warning Signals")
            for result in signals[:5]:
                for v in result.vulnerabilities:
                    lines.append(
                        f"- **{result.dependency.name}**: {v.summary[:100]} (source: {v.source})"
                    )

        return "\n".join(lines)

    def _call_anthropic(self, prompt: str) -> str | None:
        resp = self.session.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 2048,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        content = data.get("content", [])
        if content and isinstance(content, list):
            return content[0].get("text", "")
        return None

    def _call_openai(self, prompt: str) -> str | None:
        resp = self.session.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 2048,
            },
            timeout=60,
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return None
