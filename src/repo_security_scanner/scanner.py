from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from repo_security_scanner.models import Dependency, ScanReport, ScanResult, Severity
from repo_security_scanner.parsers import PARSER_REGISTRY
from repo_security_scanner.vulndb.base import VulnDatabase

IGNORED_DIRS = {
    "node_modules", ".venv", "venv", "__pycache__", ".git",
    "vendor", "target", "build", "dist", ".tox", ".eggs",
    ".mypy_cache", ".pytest_cache", "env", ".env",
}


class SecurityScanner:
    def __init__(self, vuln_sources: list[VulnDatabase] | None = None):
        self.vuln_sources = vuln_sources or []

    def scan(self, directory: str) -> ScanReport:
        root = Path(directory).resolve()
        if not root.is_dir():
            raise ValueError(f"Not a directory: {root}")

        # 1. Find and parse dependency files
        dependencies = self._collect_dependencies(root)

        # 2. Deduplicate (lock file versions take priority)
        dependencies = self._deduplicate(dependencies)

        # 3. Query vulnerability databases
        vuln_map = self._query_vulns(dependencies)

        # 4. Build results
        results = []
        for dep in dependencies:
            vulns = vuln_map.get(dep.key, [])
            results.append(ScanResult(dependency=dep, vulnerabilities=vulns))

        # Sort: vulnerable first, then by severity
        results.sort(key=self._result_sort_key)

        return ScanReport(
            directory=str(root),
            scanned_at=datetime.now(timezone.utc),
            results=results,
        )

    def _collect_dependencies(self, root: Path) -> list[Dependency]:
        deps = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directories
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

            for fname in filenames:
                parser = PARSER_REGISTRY.get(fname)
                if parser:
                    filepath = Path(dirpath) / fname
                    rel_path = str(filepath.relative_to(root))
                    try:
                        content = filepath.read_text(encoding="utf-8", errors="ignore")
                        parsed = parser.parse(content, rel_path)
                        deps.extend(parsed)
                    except (OSError, UnicodeDecodeError):
                        continue
        return deps

    def _deduplicate(self, deps: list[Dependency]) -> list[Dependency]:
        """Deduplicate dependencies. Lock file versions win over manifest versions."""
        seen: dict[str, Dependency] = {}
        lock_files = {
            "Pipfile.lock", "poetry.lock", "package-lock.json",
            "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock", "Cargo.lock", "composer.lock",
        }

        # Process non-lock files first, then lock files (so lock files overwrite)
        sorted_deps = sorted(deps, key=lambda d: Path(d.source_file).name in lock_files)
        for dep in sorted_deps:
            seen[dep.key] = dep
        return list(seen.values())

    def _query_vulns(self, deps: list[Dependency]) -> dict[str, list]:
        """Query all vulnerability sources and merge results."""
        merged: dict[str, list] = {}
        seen_ids: dict[str, set] = {}  # dep_key -> set of vuln IDs

        for source in self.vuln_sources:
            try:
                results = source.query_batch(deps)
            except Exception:
                continue

            for dep_key, vulns in results.items():
                if dep_key not in merged:
                    merged[dep_key] = []
                    seen_ids[dep_key] = set()
                for v in vulns:
                    if v.id not in seen_ids[dep_key]:
                        seen_ids[dep_key].add(v.id)
                        merged[dep_key].append(v)

        return merged

    def _result_sort_key(self, result: ScanResult) -> tuple:
        if not result.vulnerabilities:
            return (1, 4, result.dependency.name)
        worst = min(
            (self._severity_order(v.severity) for v in result.vulnerabilities),
            default=4,
        )
        return (0, worst, result.dependency.name)

    def _severity_order(self, severity: Severity) -> int:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.UNKNOWN: 4,
        }
        return order.get(severity, 4)
