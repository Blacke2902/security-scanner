from __future__ import annotations

import json
from dataclasses import asdict

from repo_security_scanner.models import ScanReport


def generate_json_report(report: ScanReport, llm_analysis: str = None) -> str:
    data = {
        "summary": {
            "directory": report.directory,
            "scanned_at": report.scanned_at.isoformat(),
            "total_dependencies": report.total_dependencies,
            "total_vulnerabilities": report.total_vulns,
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
        },
        "early_signal_count": report.early_signal_count,
        "results": [],
        "early_signals": [],
        "llm_analysis": llm_analysis,
    }

    for result in report.confirmed_results:
        entry = _format_result(result)
        data["results"].append(entry)

    for result in report.early_signals:
        entry = _format_result(result)
        data["early_signals"].append(entry)

    return json.dumps(data, indent=2)


def _format_result(result) -> dict:
    return {
        "package": result.dependency.name,
        "version": result.dependency.version,
        "ecosystem": result.dependency.ecosystem.value,
        "source_file": result.dependency.source_file,
        "vulnerabilities": [
            {
                "id": v.id,
                "summary": v.summary,
                "severity": v.severity.value,
                "affected_versions": v.affected_versions,
                "fixed_version": v.fixed_version,
                "references": v.references,
                "source": v.source,
                "confidence": v.confidence,
            }
            for v in result.vulnerabilities
        ],
    }
