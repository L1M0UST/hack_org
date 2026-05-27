"""Collection orchestration before MiMo/data-cleaning processing."""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .artifact_store import ArtifactStore, LocalArtifactStore
from .collectors import Collector, KnownUrlSkipped
from .logging_system import DailyLogger
from .llm_inputs import candidate_groups_for_article, term_matches
from .models import Article, GroupProfile, SourceConfig
from .storage import StateStore
from .utils import utcnow, write_json


class HarvestManager:
    """Run multi-source collection with logging, deduplication, and MiMo export."""

    def __init__(
        self,
        store: StateStore,
        state_dir: Path,
        timeout: float = 20.0,
        proxy: str | None = None,
        workers: int = 4,
        artifact_store: ArtifactStore | None = None,
    ) -> None:
        self.store = store
        self.state_dir = state_dir
        self.timeout = timeout
        self.proxy = proxy
        self.workers = max(1, workers)
        self.artifact_store = artifact_store or LocalArtifactStore()
        self.logger = DailyLogger(state_dir / "logs")
        self.mimo_inbox = state_dir / "mimo_inbox"
        self.raw_dir = state_dir / "raw"
        self.keyword_pack = [
            "apt",
            "threat actor",
            "ransomware",
            "espionage",
            "campaign",
            "malware",
            "backdoor",
            "cve-",
            "zero-day",
            "phishing",
            "intrusion",
            "wiper",
            "botnet",
        ]

    def collect_sources(self, sources: list[SourceConfig], limit: int = 25) -> dict[str, Any]:
        """Collect enabled sources concurrently and persist new articles."""

        enabled = [source for source in sources if source.enabled]
        self.logger.log(
            "collection",
            "INFO",
            "collection_run_started",
            "采集任务开始",
            sources_total=len(enabled),
            workers=self.workers,
            limit=limit,
            proxy=self.proxy,
        )
        self.store.add_system_log("collection", "INFO", "采集任务开始", details={"sources_total": len(enabled), "workers": self.workers, "limit": limit})
        for source in enabled:
            self.store.upsert_source(source)
        summary = {
            "sources": len(enabled),
            "collected": 0,
            "inserted": 0,
            "duplicates": 0,
            "failed": 0,
        }
        run_ids = {source.id: self.store.start_collection_run(source.id) for source in enabled}
        collected_articles: list[Article] = []
        inserted_articles: list[tuple[int, Article]] = []
        for source in enabled:
            self.logger.log(
                "collection",
                "INFO",
                "source_run_started",
                "数据源采集开始",
                source_id=source.id,
                source_name=source.name,
                source_type=source.type,
                source_tier=source.tier,
                source_category=source.category,
            )
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = {executor.submit(self._collect_one_source, source, limit): source for source in enabled}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    articles = future.result()
                    inserted = 0
                    duplicates = 0
                    for article in articles:
                        article_id, is_new = self.store.save_article(article)
                        if is_new and article_id is not None:
                            inserted += 1
                            inserted_articles.append((article_id, article))
                            self.logger.log(
                                "collection",
                                "INFO",
                                "document_inserted",
                                "文档已入库",
                                source_id=source.id,
                                article_id=article_id,
                                title=article.title,
                                url=article.source_url,
                                published_at=article.published_at.isoformat() if article.published_at else None,
                                raw_path=article.html_path,
                                clean_path=article.text_path,
                                meta_path=article.metadata.get("meta_path"),
                            )
                            self.logger.log(
                                "storage",
                                "INFO",
                                "database_inserted",
                                "文档记录已写入 SQLite",
                                source_id=source.id,
                                article_id=article_id,
                                url=article.source_url,
                            )
                            self.logger.log(
                                "storage",
                                "INFO",
                                "raw_artifacts_saved",
                                "原始文档工件已保存",
                                source_id=source.id,
                                article_id=article_id,
                                raw_path=article.html_path,
                                clean_path=article.text_path,
                                meta_path=article.metadata.get("meta_path"),
                            )
                            self.store.add_system_log(
                                "collection",
                                "INFO",
                                "文档已入库",
                                source_id=source.id,
                                article_id=article_id,
                                details={"title": article.title, "url": article.source_url},
                            )
                        else:
                            duplicates += 1
                            self.logger.log(
                                "collection",
                                "INFO",
                                "document_duplicate_skipped",
                                "重复文档已跳过",
                                source_id=source.id,
                                title=article.title,
                                url=article.source_url,
                            )
                    collected_articles.extend(articles)
                    summary["collected"] += len(articles)
                    summary["inserted"] += inserted
                    summary["duplicates"] += duplicates
                    self.store.finish_collection_run(run_ids[source.id], "success", len(articles), inserted, duplicates)
                    self.logger.log(
                        "collection",
                        "INFO",
                        "source_run_finished",
                        "数据源采集完成",
                        source_id=source.id,
                        source_name=source.name,
                        source_type=source.type,
                        source_tier=source.tier,
                        source_category=source.category,
                        collected=len(articles),
                        inserted=inserted,
                        duplicates=duplicates,
                    )
                    self.store.add_system_log(
                        "collection",
                        "INFO",
                        "数据源采集完成",
                        source_id=source.id,
                        details={"collected": len(articles), "inserted": inserted, "duplicates": duplicates},
                    )
                except Exception as exc:
                    if isinstance(exc, KnownUrlSkipped):
                        self.store.finish_collection_run(run_ids[source.id], "success", 0, 0, 1)
                        summary["duplicates"] += 1
                        self.logger.log(
                            "collection",
                            "INFO",
                            "source_known_url_skipped",
                            "数据源 URL 已采集过，本轮跳过",
                            source_id=source.id,
                            source_name=source.name,
                            source_type=source.type,
                            source_tier=source.tier,
                            source_category=source.category,
                        )
                        continue
                    from .errors import classify_error

                    error_info = classify_error(exc)
                    summary["failed"] += 1
                    self.store.finish_collection_run(run_ids[source.id], "failed", error=str(exc))
                    self.logger.log(
                        "collection",
                        "CRITICAL" if error_info["severity"] == "fatal" else "ERROR",
                        "source_run_failed",
                        "数据源采集失败",
                        source_id=source.id,
                        source_name=source.name,
                        source_type=source.type,
                        source_tier=source.tier,
                        source_category=source.category,
                        **error_info,
                        error=str(exc),
                    )
                    self.store.add_system_log(
                        "collection",
                        "ERROR",
                        "数据源采集失败",
                        source_id=source.id,
                        details={"error": str(exc), **error_info},
                    )
        write_json(self.state_dir / "articles.json", [article.model_dump(mode="json") for article in self.store.article_models()])
        if inserted_articles:
            self._write_mimo_jsonl(inserted_articles)
        for key, value in {
            "sources_total": summary["sources"],
            "documents_collected": summary["collected"],
            "documents_inserted": summary["inserted"],
            "documents_duplicate": summary["duplicates"],
            "sources_failed": summary["failed"],
        }.items():
            self.logger.count(key, value)
        self.logger.log("collection", "INFO", "collection_run_finished", "采集任务完成", **summary)
        self.store.add_system_log("collection", "INFO", "采集任务完成", details=summary)
        self.logger.write_summary()
        return summary

    def _collect_one_source(self, source: SourceConfig, limit: int) -> list[Article]:
        collector = Collector(
            raw_dir=self.raw_dir,
            timeout=self.timeout,
            proxy=self.proxy,
            artifact_store=self.artifact_store,
            seen_url_checker=self.store.has_article_url,
            event_logger=lambda level, event, message, **fields: self.logger.log(
                "collection", level, event, message, **fields
            ),
        )
        return collector.collect(source, limit=limit)

    def _write_mimo_jsonl(self, articles: list[tuple[int, Article]]) -> Path:
        """Write newly inserted articles in a stable JSONL format for MiMo cleaning."""

        self.mimo_inbox.mkdir(parents=True, exist_ok=True)
        path = self.mimo_inbox / f"articles_{utcnow().strftime('%Y%m%d_%H%M%S')}.jsonl"
        with path.open("w", encoding="utf-8") as handle:
            groups = self.store.group_profiles()
            for article_id, article in articles:
                candidate_groups = self._candidate_groups(article, groups)
                keyword_hits = self._keyword_hits(article)
                payload = {
                    "article_id": article_id,
                    "source_id": article.source_id,
                    "source_title": article.source_title,
                    "source_url": article.source_url,
                    "source_domain": article.source_domain,
                    "source_category": article.metadata.get("source_category"),
                    "source_tier": article.metadata.get("source_tier"),
                    "source_weight": article.metadata.get("source_weight"),
                    "published_at": article.published_at.isoformat() if article.published_at else None,
                    "collected_at": article.collected_at.isoformat(),
                    "title": article.title,
                    "text": article.text,
                    "author": article.author,
                    "html_path": article.html_path,
                    "text_path": article.text_path,
                    "meta_path": article.metadata.get("meta_path"),
                    "rss": {
                        "feed_url": article.metadata.get("feed_url"),
                        "feed_title": article.metadata.get("feed_title"),
                        "entry_id": article.metadata.get("entry_id"),
                        "entry_link": article.metadata.get("entry_link"),
                        "entry_summary": article.metadata.get("entry_summary"),
                        "entry_tags": article.metadata.get("entry_tags", []),
                    },
                    "candidate_groups": candidate_groups,
                    "keyword_hits": keyword_hits,
                    "collection_policy": "store_all_then_filter_locally",
                    "task": "extract_summary_entities_aliases_topics",
                }
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.logger.log(
            "processing",
            "INFO",
            "mimo_inbox_written",
            "MiMo inbox batch written",
            path=str(path),
            count=len(articles),
        )
        return path

    def _candidate_groups(self, article: Article, groups: list[GroupProfile], limit: int = 12) -> list[dict[str, Any]]:
        """Find exact canonical/alias mentions for MiMo context without filtering articles."""

        return candidate_groups_for_article(article, groups, limit=limit)

    def _term_matches(self, term: str, text: str) -> bool:
        """Match organization names conservatively for MiMo context hints."""

        return term_matches(term, text)

    def _keyword_hits(self, article: Article) -> list[str]:
        """Return broad threat-intel keyword hits for downstream local filtering."""

        haystack = f"{article.title}\n{article.text}".casefold()
        source_keywords = [str(value).casefold() for value in article.metadata.get("source_keywords", [])]
        keywords = [*self.keyword_pack, *source_keywords]
        return sorted({keyword for keyword in keywords if keyword and keyword in haystack})
