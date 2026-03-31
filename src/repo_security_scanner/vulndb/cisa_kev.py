from __future__ import annotations

import re

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.models import Dependency, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL = 6 * 3600  # 6 hours


class CISAKEVDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 30):
        self.cache = cache or FileCache()
        self.timeout = timeout

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        kev_data = self._fetch_kev()
        if not kev_data:
            return {}

        results: dict[str, list[Vulnerability]] = {}
        vulns_list = kev_data.get("vulnerabilities", [])

        for dep in dependencies:
            matched = self._match(dep, vulns_list)
            if matched:
                results[dep.key] = matched

        return results

    def _fetch_kev(self) -> dict | None:
        cached = self.cache.get("cisa_kev", CACHE_TTL)
        if cached:
            return cached

        try:
            resp = requests.get(CISA_KEV_URL, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            self.cache.set("cisa_kev", data)
            return data
        except (requests.RequestException, ValueError):
            return None

    def _match(self, dep: Dependency, vulns: list[dict]) -> list[Vulnerability]:
        matched = []
        dep_name = self._normalize(dep.name)

        for v in vulns:
            product = self._normalize(v.get("product", ""))
            vendor = self._normalize(v.get("vendorProject", ""))

            if dep_name == product or dep_name == f"{vendor}:{product}":
                matched.append(Vulnerability(
                    id=v.get("cveID", "unknown"),
                    summary=v.get("shortDescription", v.get("vulnerabilityName", ""))[:200],
                    severity=Severity.CRITICAL,  # KEV = actively exploited
                    affected_versions="see advisory",
                    fixed_version=None,
                    references=[f"https://nvd.nist.gov/vuln/detail/{v.get('cveID', '')}"],
                    source="cisa_kev",
                    confidence="confirmed",
                ))
        return matched

    def _normalize(self, name: str) -> str:
        return re.sub(r'[_\-\s]+', '', name).lower()
