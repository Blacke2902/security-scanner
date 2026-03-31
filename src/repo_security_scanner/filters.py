from __future__ import annotations

import re

from repo_security_scanner.models import Dependency

GENERIC_NAME_BLOCKLIST = {
    "utils", "core", "test", "config", "is", "has", "get", "set",
    "run", "start", "init", "app", "api", "cli", "lib", "base",
    "common", "debug", "log", "http", "url", "path", "os", "io",
    "fs", "net", "crypto", "buffer", "stream", "util", "helpers",
    "types", "data", "model", "server", "client", "main", "index",
    "setup", "build", "make", "cmd", "pkg", "src", "dev", "prod",
}

MIN_NAME_LENGTH = 3

SECURITY_KEYWORDS = {
    "vulnerability", "vulnerable", "cve", "exploit", "malicious",
    "compromised", "backdoor", "security", "rce", "injection",
    "xss", "ssrf", "supply chain", "supply-chain", "trojan",
    "malware", "yanked", "deprecated", "hijack", "typosquat",
    "remote code execution", "arbitrary code", "critical",
}


def should_search_web(dep: Dependency) -> bool:
    """Whether this dependency name is specific enough for web searching."""
    name = dep.name.lower().split("/")[-1]  # handle scoped npm packages
    name = name.split(":")[-1]  # handle maven group:artifact
    if len(name) < MIN_NAME_LENGTH:
        return False
    if name in GENERIC_NAME_BLOCKLIST:
        return False
    return True


def matches_package(text: str, package_name: str) -> bool:
    """Word-boundary match of package name in text, with security keyword co-occurrence."""
    text_lower = text.lower()
    name = package_name.lower()

    # Check package name appears with word boundaries
    if not re.search(r'\b' + re.escape(name) + r'\b', text_lower):
        return False

    # Require at least one security keyword in the same text
    for kw in SECURITY_KEYWORDS:
        if kw in text_lower:
            return True

    return False


def relevance_score(
    text: str,
    package_name: str,
    age_days: float = 0,
    engagement: int = 0,
    max_age_days: float = 14,
    max_engagement: int = 100,
) -> float:
    """Score 0.0-1.0 for how relevant a text mention is. Threshold: >= 0.5."""
    score = 0.0
    text_lower = text.lower()
    name_lower = package_name.lower()

    # Name prominence (0.3): is the name in the title / first 200 chars?
    first_chunk = text_lower[:200]
    if re.search(r'\b' + re.escape(name_lower) + r'\b', first_chunk):
        score += 0.3
    elif re.search(r'\b' + re.escape(name_lower) + r'\b', text_lower):
        score += 0.15

    # Keyword density (0.2): how many security keywords appear?
    kw_count = sum(1 for kw in SECURITY_KEYWORDS if kw in text_lower)
    score += min(kw_count / 5, 1.0) * 0.2

    # Recency (0.3): newer = better
    if max_age_days > 0:
        recency = max(0, 1 - (age_days / max_age_days))
        score += recency * 0.3

    # Engagement (0.2): more upvotes/reactions = better
    if max_engagement > 0:
        eng = min(engagement / max_engagement, 1.0)
        score += eng * 0.2

    return round(score, 3)
