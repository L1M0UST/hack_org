"""RSS, webpage, and simple API collectors with retry, timeout, proxy, and artifacts."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import json
import os

import feedparser
import httpx
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from .artifact_store import ArtifactStore, LocalArtifactStore, artifact_object_key
from .errors import CollectionNetworkError
from .models import Article, SourceConfig
from .utils import sha256_text, write_json, utcnow


class Collector:
    """Collect articles from configured public sources."""

    def __init__(
        self,
        raw_dir: Path,
        timeout: float = 20.0,
        proxy: str | None = None,
        user_agent: str | None = None,
        artifact_store: ArtifactStore | None = None,
        event_logger=None,
        seen_url_checker=None,
    ) -> None:
        self.raw_dir = raw_dir
        self.timeout = timeout
        self.proxy = proxy
        self.user_agent = user_agent or "hack-org-intel-collector/0.1"
        self.artifact_store = artifact_store or LocalArtifactStore()
        self.event_logger = event_logger
        self.seen_url_checker = seen_url_checker

    def collect(self, source: SourceConfig, limit: int = 50) -> list[Article]:
        """Collect articles for one source."""

        source_limit = min(limit, source.max_items) if source.max_items else limit
        if source.type == "rss":
            return self._collect_rss(source, source_limit)
        if source.type == "api_json":
            return [self._collect_api_json(source)]
        return [self._collect_webpage(source)]

    def _collect_rss(self, source: SourceConfig, limit: int) -> list[Article]:
        response = self._get(str(source.url), self._headers(source))
        feed = feedparser.parse(_response_text(response))
        articles: list[Article] = []
        for entry in feed.entries[:limit]:
            link = entry.get("link") or str(source.url)
            title = entry.get("title") or link
            if self._seen_url(link):
                self._log_event(
                    "INFO",
                    "known_url_skipped_before_fetch",
                    "已采集过的文章跳过正文抓取",
                    source_id=source.id,
                    title=title,
                    url=link,
                )
                continue
            published = _parse_date(entry.get("published") or entry.get("updated"))
            summary = html_to_text(entry.get("summary", ""))
            html = self._safe_get_text(link, self._headers(source)) if source.fetch_full_article else ""
            text = html_to_text(html) if html else summary
            metadata = {
                "collector_type": "rss",
                "feed_url": str(source.url),
                "feed_title": feed.feed.get("title"),
                "entry_id": entry.get("id"),
                "entry_link": link,
                "entry_summary": summary,
                "entry_tags": [tag.get("term") for tag in entry.get("tags", []) if tag.get("term")],
                "source_category": source.category,
                "source_tier": source.tier,
                "source_weight": source.weight,
                "source_keywords": source.keywords,
                "fetch_full_article": source.fetch_full_article,
            }
            paths = self._save_artifacts(source.id, link, html or entry.get("summary", ""), text, metadata)
            articles.append(_article(source, title, link, published, f"{title}\n{text}", paths, metadata))
        return articles

    def _collect_webpage(self, source: SourceConfig) -> Article:
        if self._seen_url(str(source.url)):
            self._log_event(
                "INFO",
                "known_url_skipped_before_fetch",
                "已采集过的网页跳过重复抓取",
                source_id=source.id,
                title=source.name,
                url=str(source.url),
            )
            raise KnownUrlSkipped(str(source.url))
        html = _response_text(self._get(str(source.url), self._headers(source)))
        text = html_to_text(html)
        metadata = {"collector_type": "webpage", "source_category": source.category, "source_tier": source.tier, "source_weight": source.weight, "source_keywords": source.keywords}
        paths = self._save_artifacts(source.id, str(source.url), html, text, metadata)
        return _article(source, source.name, str(source.url), None, text, paths, metadata)

    def _collect_api_json(self, source: SourceConfig) -> Article:
        """Collect one generic JSON API payload as an article-like raw artifact."""

        if self._seen_url(str(source.url)):
            self._log_event(
                "INFO",
                "known_url_skipped_before_fetch",
                "已采集过的 API 跳过重复抓取",
                source_id=source.id,
                title=source.name,
                url=str(source.url),
            )
            raise KnownUrlSkipped(str(source.url))
        response = self._get(str(source.url), self._headers(source))
        payload = response.json()
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        metadata = {"collector_type": "api_json", "source_category": source.category, "source_tier": source.tier, "source_weight": source.weight, "source_keywords": source.keywords}
        paths = self._save_artifacts(source.id, str(source.url), _response_text(response), text, metadata)
        return _article(source, source.name, str(source.url), None, text, paths, metadata)

    def _get(self, url: str, headers: dict[str, str]) -> httpx.Response:
        """Fetch a URL once; if proxy network fails, retry once without proxy."""

        try:
            response = httpx.get(url, headers=headers, timeout=self.timeout, follow_redirects=True, proxy=self.proxy)
            response.raise_for_status()
            return response
        except httpx.RequestError as proxy_exc:
            if not self.proxy:
                raise CollectionNetworkError(str(proxy_exc)) from proxy_exc
            self._log_event(
                "WARNING",
                "proxy_request_failed_retry_direct",
                "代理请求失败，正在直连重试一次",
                url=url,
                proxy=self.proxy,
                error=str(proxy_exc),
            )
            try:
                response = httpx.get(url, headers=headers, timeout=self.timeout, follow_redirects=True, proxy=None)
                response.raise_for_status()
                self._log_event(
                    "INFO",
                    "direct_retry_succeeded",
                    "代理失败后的直连重试成功",
                    url=url,
                    proxy=self.proxy,
                )
                return response
            except httpx.RequestError as direct_exc:
                raise CollectionNetworkError(str(direct_exc)) from direct_exc

    def _log_event(self, level: str, event: str, message: str, **fields) -> None:
        """Emit collector events into the harvest logger when available."""

        if self.event_logger:
            self.event_logger(level, event, message, **fields)

    def _safe_get_text(self, url: str, headers: dict[str, str]) -> str:
        try:
            return _response_text(self._get(url, headers))
        except Exception:
            return ""

    def _seen_url(self, url: str) -> bool:
        if not self.seen_url_checker:
            return False
        try:
            return bool(self.seen_url_checker(url))
        except Exception:
            return False

    def _headers(self, source: SourceConfig) -> dict[str, str]:
        headers = {"User-Agent": source.user_agent or self.user_agent}
        headers.update(dict(source.headers))
        if source.api_key_env and source.auth_header:
            api_key = os.environ.get(source.api_key_env)
            if api_key:
                headers[source.auth_header] = f"{source.auth_prefix}{api_key}"
        return headers

    def _save_artifacts(self, source_id: str, url: str, html: str, text: str, metadata: dict) -> dict[str, str]:
        digest = sha256_text(url)[:16]
        day = utcnow().date().isoformat()
        base = self.raw_dir / day / source_id / digest
        base.mkdir(parents=True, exist_ok=True)
        html_path = base / "raw.html"
        text_path = base / "clean.txt"
        meta_path = base / "meta.json"
        html_path.write_text(html, encoding="utf-8", errors="ignore")
        text_path.write_text(text, encoding="utf-8", errors="ignore")
        write_json(meta_path, {"url": url, **metadata})
        raw_object_key = self.artifact_store.upload_file(
            html_path, artifact_object_key(source_id, digest, "raw.html", day=day)
        )
        clean_object_key = self.artifact_store.upload_file(
            text_path, artifact_object_key(source_id, digest, "clean.txt", day=day)
        )
        meta_object_key = self.artifact_store.upload_file(
            meta_path, artifact_object_key(source_id, digest, "meta.json", day=day)
        )
        return {
            "html_path": str(html_path),
            "text_path": str(text_path),
            "meta_path": str(meta_path),
            "raw_object_key": raw_object_key,
            "clean_object_key": clean_object_key,
            "meta_object_key": meta_object_key,
        }


def html_to_text(html: str) -> str:
    """Extract readable text from HTML."""

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return "\n".join(line.strip() for line in soup.get_text("\n").splitlines() if line.strip())


def _response_text(response: httpx.Response) -> str:
    """Decode HTTP bytes without emitting third-party replacement warnings."""

    encodings = []
    if response.encoding:
        encodings.append(response.encoding)
    encodings.extend(["utf-8-sig", "utf-8", "gb18030", "big5", "cp1252", "latin1"])
    seen = set()
    for encoding in encodings:
        encoding = encoding.lower()
        if encoding in seen:
            continue
        seen.add(encoding)
        try:
            return response.content.decode(encoding)
        except UnicodeDecodeError:
            continue
        except LookupError:
            continue
    return response.content.decode("utf-8", errors="ignore")


class KnownUrlSkipped(Exception):
    """Raised internally when a one-document source URL is already collected."""


def _article(source: SourceConfig, title: str, url: str, published_at, text: str, paths: dict[str, str], metadata: dict) -> Article:
    parsed = urlparse(url)
    return Article(
        source_id=source.id,
        source_title=title,
        source_url=url,
        source_domain=parsed.netloc,
        published_at=published_at,
        collected_at=utcnow(),
        html_path=paths.get("html_path"),
        text_path=paths.get("text_path"),
        title=title,
        text=text,
        metadata={
            **metadata,
            "meta_path": paths.get("meta_path"),
            "raw_object_key": paths.get("raw_object_key"),
            "clean_object_key": paths.get("clean_object_key"),
            "meta_object_key": paths.get("meta_object_key"),
        },
    )


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return date_parser.parse(value)
    except Exception:
        return None
