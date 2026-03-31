from __future__ import annotations

import os
import time

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.filters import should_search_web
from repo_security_scanner.models import Dependency, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

OPENCVE_API_URL = "https://app.opencve.io/api/cve"
CACHE_TTL = 3600  # 1 hour


class OpenCVEDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 15):
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.username = os.environ.get("OPENCVE_USER", "")
        self.password = os.environ.get("OPENCVE_PASS", "")
        self.session = requests.Session()
        if self.username and self.password:
            self.session.auth = (self.username, self.password)

    @property
    def available(self) -> bool:
        return bool(self.username and self.password)

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        if not self.available:
            return {}

        results: dict[str, list[Vulnerability]] = {}
        searchable = [d for d in dependencies if should_search_web(d)]

        for dep in searchable:
            vulns = self._search(dep)
            if vulns:
                results[dep.key] = vulns
            time.sleep(0.5)

        return results

    def _search(self, dep: Dependency) -> list[Vulnerability]:
        name = dep.name.split("/")[-1].split(":")[-1]
        cache_key = f"opencve_{name}"
        cached = self.cache.get(cache_key, CACHE_TTL)

        if cached is None:
            try:
                resp = self.session.get(
                    OPENCVE_API_URL,
                    params={"search": name},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                cached = resp.json()
                self.cache.set(cache_key, cached)
            except (requests.RequestException, ValueError):
                return []

        vulns = []
        entries = cached if isinstance(cached, list) else cached.get("results", [])
        for entry in entries[:5]:  # Limit to top 5 matches
            cve_id = entry.get("cve_id", entry.get("id", "unknown"))
            summary = entry.get("summary", entry.get("description", ""))
            cvss = entry.get("cvss3", entry.get("cvss2"))

            severity = Severity.UNKNOWN
            if cvss is not None:
                try:
                    score = float(cvss)
                    if score >= 9.0:
                        severity = Severity.CRITICAL
                    elif score >= 7.0:
                        severity = Severity.HIGH
                    elif score >= 4.0:
                        severity = Severity.MEDIUM
                    else:
                        severity = Severity.LOW
                except (ValueError, TypeError):
                    pass

            vulns.append(Vulnerability(
                id=cve_id,
                summary=summary[:200] if summary else "No description",
                severity=severity,
                affected_versions="see advisory",
                fixed_version=None,
                references=[f"https://www.opencve.io/cve/{cve_id}"],
                source="opencve",
                confidence="confirmed",
            ))

        return vulns
