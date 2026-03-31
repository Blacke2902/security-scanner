from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from repo_security_scanner.cache import FileCache
from repo_security_scanner.filters import matches_package, should_search_web
from repo_security_scanner.models import Dependency, Severity, Vulnerability
from repo_security_scanner.vulndb.base import VulnDatabase

FEEDS = [
    ("https://www.bleepingcomputer.com/feed/", "bleepingcomputer"),
    ("https://security.googleblog.com/feeds/posts/default", "google_security"),
]

CACHE_TTL = 7200  # 2 hours
MAX_AGE_DAYS = 14


class RSSFeedDatabase(VulnDatabase):
    def __init__(self, cache: FileCache = None, timeout: int = 15):
        self.cache = cache or FileCache()
        self.timeout = timeout
        self.session = requests.Session()

    def query_batch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        articles = self._fetch_all_feeds()
        if not articles:
            return {}

        results: dict[str, list[Vulnerability]] = {}
        searchable = [d for d in dependencies if should_search_web(d)]

        for dep in searchable:
            name = dep.name.split("/")[-1].split(":")[-1]
            matched = self._match_articles(name, articles)
            if matched:
                results[dep.key] = matched

        return results

    def _fetch_all_feeds(self) -> list[dict]:
        all_articles = []
        for url, feed_name in FEEDS:
            articles = self._fetch_feed(url, feed_name)
            all_articles.extend(articles)
        return all_articles

    def _fetch_feed(self, url: str, feed_name: str) -> list[dict]:
        cache_key = f"rss_{feed_name}"
        cached = self.cache.get(cache_key, CACHE_TTL)
        if cached is not None:
            return cached

        try:
            resp = self.session.get(url, timeout=self.timeout)
            resp.raise_for_status()
            articles = self._parse_feed(resp.text, feed_name)
            self.cache.set(cache_key, articles)
            return articles
        except (requests.RequestException, ET.ParseError):
            return []

    def _parse_feed(self, xml_text: str, feed_name: str) -> list[dict]:
        articles = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return articles

        now = datetime.now(timezone.utc)

        # RSS 2.0 format: <channel><item>
        for item in root.iter("item"):
            title = item.findtext("title", "")
            link = item.findtext("link", "")
            desc = item.findtext("description", "")
            pub_date = item.findtext("pubDate", "")
            age_days = self._parse_age(pub_date, now)
            if age_days is not None and age_days <= MAX_AGE_DAYS:
                articles.append({
                    "title": title, "link": link, "description": desc,
                    "feed": feed_name, "age_days": age_days,
                })

        # Atom format: <entry>
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
            title = entry.findtext("{http://www.w3.org/2005/Atom}title", "")
            link_el = entry.find("{http://www.w3.org/2005/Atom}link")
            link = link_el.get("href", "") if link_el is not None else ""
            content = entry.findtext("{http://www.w3.org/2005/Atom}content", "")
            summary = entry.findtext("{http://www.w3.org/2005/Atom}summary", "")
            updated = entry.findtext("{http://www.w3.org/2005/Atom}updated", "")
            age_days = self._parse_age_iso(updated, now)
            if age_days is not None and age_days <= MAX_AGE_DAYS:
                articles.append({
                    "title": title, "link": link, "description": summary or content,
                    "feed": feed_name, "age_days": age_days,
                })

        return articles

    def _parse_age(self, date_str: str, now: datetime) -> float | None:
        if not date_str:
            return None
        try:
            dt = parsedate_to_datetime(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (now - dt).total_seconds() / 86400
        except (ValueError, TypeError):
            return None

    def _parse_age_iso(self, date_str: str, now: datetime) -> float | None:
        if not date_str:
            return None
        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            return (now - dt).total_seconds() / 86400
        except ValueError:
            return None

    def _match_articles(self, package_name: str, articles: list[dict]) -> list[Vulnerability]:
        matched = []
        for article in articles:
            text = f"{article['title']} {article.get('description', '')}"
            if matches_package(text, package_name):
                article_hash = hashlib.md5(article["link"].encode()).hexdigest()[:8]
                matched.append(Vulnerability(
                    id=f"RSS-{article['feed']}-{article_hash}",
                    summary=article["title"][:200],
                    severity=Severity.UNKNOWN,
                    affected_versions="unknown",
                    fixed_version=None,
                    references=[article["link"]],
                    source=f"rss_{article['feed']}",
                    confidence="early_signal",
                ))
        return matched
