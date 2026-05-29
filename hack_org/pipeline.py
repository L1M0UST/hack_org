"""End-to-end daily processing pipeline."""

from __future__ import annotations

import hashlib
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import load_sources
from .artifact_store import load_artifact_store
from .harvesting import HarvestManager
from .logging_system import DailyLogger
from .llm_client import OpenAICompatibleClient, load_llm_config
from .llm_inputs import build_article_extract_variables
from .model_ingestor import ModelOutputIngestor
from .pg_archive import PostgresArchiveExporter
from .pg_client import connect_database
from .pg_repository import PostgresRepository
from .storage import StateStore
from .db_config import load_database_config
from .daily_report import DailyReportBuilder
from .discovery import discover_unknown_groups
from .notification import load_notifier, render_report_message
from .errors import classify_error, DatabaseConnectionFatalError


@dataclass
class PipelineSummary:
    """Counters emitted by one end-to-end pipeline run."""

    articles_seen: int = 0
    articles_processed: int = 0
    articles_skipped: int = 0
    article_failures: int = 0
    groups_refreshed: int = 0
    synthesis_failures: int = 0
    archives_exported: int = 0
    apt_table_rows_exported: int = 0
    unknown_group_candidates: int = 0
    unknown_group_evidence: int = 0
    promoted_unknown_groups: int = 0
    collection_summary: dict[str, Any] | None = None
    backlog_after: dict[str, Any] | None = None
    touched_groups: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Return JSON-serializable counters."""

        return {
            "articles_seen": self.articles_seen,
            "articles_processed": self.articles_processed,
            "articles_skipped": self.articles_skipped,
            "article_failures": self.article_failures,
            "groups_refreshed": self.groups_refreshed,
            "synthesis_failures": self.synthesis_failures,
            "archives_exported": self.archives_exported,
            "apt_table_rows_exported": self.apt_table_rows_exported,
            "unknown_group_candidates": self.unknown_group_candidates,
            "unknown_group_evidence": self.unknown_group_evidence,
            "promoted_unknown_groups": self.promoted_unknown_groups,
            "collection_summary": self.collection_summary,
            "backlog_after": self.backlog_after,
            "touched_groups": sorted(self.touched_groups),
        }


class DailyPipeline:
    """Run article extraction followed by affected-group refreshes."""

    def __init__(self, root: Path, store: StateStore) -> None:
        self.root = root
        self.store = store
        self.llm_config = load_llm_config(root / "config" / "llm.yaml")
        self.llm = OpenAICompatibleClient(self.llm_config, env_path=root / ".env")
        self.db_config = load_database_config(root / "config" / "database.yaml", env_path=root / ".env")
        self.sources = load_sources(root / "config" / "sources.yaml")
        self.artifact_store = load_artifact_store(root / "config" / "storage.yaml", env_path=root / ".env")
        self.logger = DailyLogger(root / ".state" / "logs")

    def run(
        self,
        article_limit: int | None = None,
        *,
        collect: bool = False,
        collect_limit: int = 25,
        workers: int = 4,
        timeout: float = 20.0,
        proxy: str | None = "http://127.0.0.1:7890",
        export_outputs: bool = True,
        article_order: str = "newest",
        model_workers: int = 1,
        auto_promote_discovered: bool = False,
        promote_min_evidence: int = 2,
        promote_min_confidence: float = 0.65,
        promote_limit: int = 20,
        apt_group_only: bool = False,
    ) -> PipelineSummary:
        """Process pending articles and refresh only the affected groups."""

        summary = PipelineSummary()
        self.logger.log(
            "processing",
            "INFO",
            "pipeline_started",
            "流水线启动",
            collect=collect,
            collect_limit=collect_limit,
            article_limit=article_limit,
            article_order=article_order,
            model_workers=model_workers,
            auto_promote_discovered=auto_promote_discovered,
            promote_min_evidence=promote_min_evidence,
            promote_min_confidence=promote_min_confidence,
            promote_limit=promote_limit,
            apt_group_only=apt_group_only,
        )
        self._preflight()
        if collect:
            self.logger.log(
                "collection",
                "INFO",
                "collection_phase_started",
                "开始采集阶段",
                collect_limit=collect_limit,
                workers=workers,
                timeout=timeout,
                proxy=proxy,
            )
            manager = HarvestManager(
                store=self.store,
                state_dir=self.root / ".state",
                timeout=timeout,
                proxy=proxy,
                workers=workers,
                artifact_store=self.artifact_store,
            )
            summary.collection_summary = manager.collect_sources(self.sources, limit=collect_limit)
            self.logger.log(
                "collection",
                "INFO",
                "collection_phase_finished",
                "采集阶段完成",
                **summary.collection_summary,
            )
        if auto_promote_discovered:
            discovery = discover_unknown_groups(
                self.store,
                article_limit=article_limit,
                min_confidence=promote_min_confidence,
            )
            summary.unknown_group_candidates = discovery.candidates_found
            summary.unknown_group_evidence = discovery.evidence_written
            promoted = self.store.promote_discovered_group_candidates(
                min_evidence=promote_min_evidence,
                min_confidence=promote_min_confidence,
                limit=promote_limit,
            )
            summary.promoted_unknown_groups = sum(
                1 for item in promoted if item.get("status") == "promoted"
            )
            self.logger.log(
                "processing",
                "INFO",
                "unknown_groups_auto_promoted",
                "æœªçŸ¥ç»„ç»‡è‡ªåŠ¨è½¬æ­£å®Œæˆ",
                candidates_found=summary.unknown_group_candidates,
                evidence_written=summary.unknown_group_evidence,
                promoted=summary.promoted_unknown_groups,
            )
        groups = self.store.group_profiles()
        self.logger.log("processing", "INFO", "load_groups_finished", "组织身份加载完成", groups=len(groups))
        article_rows = self.store.article_records(order=article_order)
        self.logger.log("processing", "INFO", "load_articles_finished", "待处理文章加载完成", articles=len(article_rows), order=article_order)
        article_models = {row["id"]: self.store.article_model_by_id(row["id"]) for row in article_rows}
        touched_groups: set[str] = set()

        try:
            conn_context = connect_database(self.db_config)
        except Exception as exc:
            fatal = DatabaseConnectionFatalError(str(exc))
            self.logger.log(
                "storage",
                "CRITICAL",
                "database_connection_failed",
                "数据库连接失败",
                **classify_error(fatal),
                error=str(exc),
            )
            raise fatal from exc

        with conn_context as conn:
            repository = PostgresRepository(conn)
            self.logger.log("storage", "INFO", "postgres_connected", "PostgreSQL 连接成功")
            repository.ensure_runtime_schema()
            self.logger.log("storage", "INFO", "runtime_schema_checked", "运行时表结构检查完成")
            repository.sync_sources(self.sources)
            self.logger.log("storage", "INFO", "sources_synced_to_pg", "情报源配置已同步到 PostgreSQL", sources=len(self.sources))
            pg_group_ids = repository.sync_group_profiles(groups)
            self.logger.log("storage", "INFO", "groups_synced_to_pg", "组织身份已同步到 PostgreSQL", groups=len(pg_group_ids))
            ingestor = ModelOutputIngestor(repository)

            pending_extracts: list[dict[str, Any]] = []
            for row in article_rows:
                if article_limit is not None and len(pending_extracts) >= article_limit:
                    break
                summary.articles_seen += 1
                article = article_models[row["id"]]
                if article is None:
                    continue
                pg_document_id = repository.upsert_collected_document(row)
                if repository.has_successful_model_run("article_extract", pg_document_id):
                    summary.articles_skipped += 1
                    self.logger.log(
                        "processing",
                        "INFO",
                        "article_extract_skipped",
                        "????????????",
                        article_id=row["id"],
                        document_id=pg_document_id,
                        title=article.title,
                    )
                    continue
                variables = build_article_extract_variables(
                    pg_document_id,
                    article,
                    groups,
                    pg_group_ids=pg_group_ids,
                )
                candidate_codes = [item["organization_code"] for item in variables["candidate_groups_json"]]
                variables["existing_database_context_json"] = {
                    "groups": list(repository.group_context_by_organization_codes(candidate_codes).values())
                }
                run_id = repository.start_model_run(
                    "article_extract",
                    self.llm_config.model,
                    self._prompt_version("article_extract"),
                    variables,
                    document_id=pg_document_id,
                    model_version=self.llm_config.model,
                )
                self.logger.log(
                    "processing",
                    "INFO",
                    "article_extract_started",
                    "??????????",
                    article_id=row["id"],
                    document_id=pg_document_id,
                    title=article.title,
                    candidate_groups=len(candidate_codes),
                    model_workers=model_workers,
                )
                pending_extracts.append(
                    {
                        "row": row,
                        "article": article,
                        "document_id": pg_document_id,
                        "run_id": run_id,
                        "variables": variables,
                    }
                )

            if pending_extracts:
                self.logger.log(
                    "processing",
                    "INFO",
                    "article_extract_batch_started",
                    "??????????",
                    pending=len(pending_extracts),
                    model_workers=max(1, model_workers),
                )
                with ThreadPoolExecutor(max_workers=max(1, model_workers)) as executor:
                    futures = {
                        executor.submit(self.llm.run_task, "article_extract", item["variables"], self.root): item
                        for item in pending_extracts
                    }
                    for future in as_completed(futures):
                        item = futures[future]
                        pg_document_id = item["document_id"]
                        run_id = item["run_id"]
                        try:
                            payload = future.result()
                            with conn.transaction():
                                ingestor.ingest(payload)
                                repository.finish_model_run(run_id, "success", payload)
                            touched_groups.update(
                                repository.organization_codes_for_group_ids(
                                    [matched["group_id"] for matched in payload["matched_groups"]]
                                )
                            )
                            summary.articles_processed += 1
                            self.logger.log(
                                "processing",
                                "INFO",
                                "article_extract_succeeded",
                                "??????",
                                document_id=pg_document_id,
                                matched_groups=len(payload["matched_groups"]),
                            )
                        except Exception as exc:
                            error_info = classify_error(exc)
                            repository.finish_model_run(run_id, "failed", error_message=str(exc))
                            summary.article_failures += 1
                            self.logger.log(
                                "processing",
                                "CRITICAL" if error_info["severity"] == "fatal" else "ERROR",
                                "article_extract_failed",
                                "??????",
                                document_id=pg_document_id,
                                **error_info,
                                error=str(exc),
                            )
                self.logger.log(
                    "processing",
                    "INFO",
                    "article_extract_batch_finished",
                    "??????????",
                    processed=summary.articles_processed,
                    failed=summary.article_failures,
                )

            for organization_code in sorted(touched_groups):
                try:
                    self._refresh_group(repository, ingestor, organization_code, apt_group_only=apt_group_only)
                    summary.groups_refreshed += 1
                    self.logger.log(
                        "processing",
                        "INFO",
                        "group_refresh_succeeded",
                        "组织综合刷新成功",
                        organization_code=organization_code,
                    )
                except Exception as exc:
                    error_info = classify_error(exc)
                    summary.synthesis_failures += 1
                    self.logger.log(
                        "processing",
                        "CRITICAL" if error_info["severity"] == "fatal" else "ERROR",
                        "group_refresh_failed",
                        "组织综合刷新失败",
                        organization_code=organization_code,
                        **error_info,
                        error=str(exc),
                    )
            if export_outputs:
                self.logger.log("storage", "INFO", "export_phase_started", "开始导出归档和宽表")
                summary.archives_exported = PostgresArchiveExporter(self.root / "data").export(
                    repository.group_archive_snapshots()
                )
                summary.apt_table_rows_exported = self._export_apt_table(repository)
                self.logger.log(
                    "storage",
                    "INFO",
                    "export_phase_finished",
                    "导出归档和宽表完成",
                    archives_exported=summary.archives_exported,
                    apt_table_rows_exported=summary.apt_table_rows_exported,
                )
            summary.backlog_after = repository.document_backlog_summary()
            self.logger.log("processing", "INFO", "backlog_checked", "处理积压统计完成", **summary.backlog_after)

        summary.touched_groups = sorted(touched_groups)
        self.logger.count("pipeline_articles_seen", summary.articles_seen)
        self.logger.count("pipeline_articles_processed", summary.articles_processed)
        self.logger.count("pipeline_articles_skipped", summary.articles_skipped)
        self.logger.count("pipeline_article_failures", summary.article_failures)
        self.logger.count("pipeline_groups_refreshed", summary.groups_refreshed)
        self.logger.count("pipeline_synthesis_failures", summary.synthesis_failures)
        self.logger.count("pipeline_archives_exported", summary.archives_exported)
        self.logger.count("pipeline_apt_table_rows_exported", summary.apt_table_rows_exported)
        self.logger.write_summary()
        self.logger.log("processing", "INFO", "daily_summary_written", "本日日志摘要已写入")
        with connect_database(self.db_config) as conn:
            report_path = DailyReportBuilder(self.root / ".state", self.store, PostgresRepository(conn)).write()
        self.logger.log("processing", "INFO", "daily_report_written", "日报已生成", report_path=str(report_path))
        try:
            self._send_report(report_path)
        except Exception as exc:
            error_info = classify_error(exc)
            self.logger.log(
                "notification",
                "ERROR",
                "daily_report_send_failed",
                "日报通知发送失败，流水线主体已完成",
                **error_info,
                error=str(exc),
                report_path=str(report_path),
            )
        self.logger.log("processing", "INFO", "pipeline_finished", "流水线完成", **summary.as_dict())
        return summary

    def _refresh_group(
        self,
        repository: PostgresRepository,
        ingestor: ModelOutputIngestor,
        organization_code: str,
        *,
        apt_group_only: bool = False,
    ) -> None:
        """Run profile, structure, and export synthesis for one group."""

        if apt_group_only:
            tasks = [("apt_group_export_synthesis", repository.export_synthesis_input(organization_code))]
        else:
            tasks = [
                ("group_profile_synthesis", repository.profile_synthesis_input(organization_code)),
                ("group_structure_synthesis", repository.structure_synthesis_input(organization_code)),
                ("apt_group_export_synthesis", repository.export_synthesis_input(organization_code)),
            ]
        for task_type, variables in tasks:
            self.logger.log(
                "processing",
                "INFO",
                "group_synthesis_started",
                "开始刷新组织画像",
                organization_code=organization_code,
                task_type=task_type,
            )
            run_id = repository.start_model_run(
                task_type,
                self.llm_config.model,
                self._prompt_version(task_type),
                variables,
                model_version=self.llm_config.model,
            )
            try:
                payload = self.llm.run_task(task_type, variables, self.root)
                with repository.conn.transaction():
                    ingestor.ingest(payload)
                    repository.finish_model_run(run_id, "success", payload)
                self.logger.log(
                    "processing",
                    "INFO",
                    "group_synthesis_succeeded",
                    "组织画像刷新子任务成功",
                    organization_code=organization_code,
                    task_type=task_type,
                )
            except Exception as exc:
                repository.finish_model_run(run_id, "failed", error_message=str(exc))
                self.logger.log(
                    "processing",
                    "ERROR",
                    "group_synthesis_failed",
                    "组织画像刷新子任务失败",
                    organization_code=organization_code,
                    task_type=task_type,
                    error=str(exc),
                )
                raise

    def _preflight(self) -> None:
        """Check required runtime components before collection or model token use."""

        self.logger.log("processing", "INFO", "preflight_started", "启动前组件预检开始")
        with connect_database(self.db_config) as conn:
            PostgresRepository(conn).ensure_runtime_schema()
        self.logger.log("storage", "INFO", "preflight_pg_ok", "PostgreSQL 连接和表结构预检通过")
        if not self.llm.api_key:
            raise RuntimeError("LLM API key is missing")
        self.logger.log(
            "processing",
            "INFO",
            "preflight_llm_config_ok",
            "模型配置预检通过",
            model=self.llm_config.model,
            base_url=self.llm_config.base_url,
        )

    def _prompt_version(self, task_type: str) -> str:
        """Build a stable version hash from prompt and schema content."""

        prompt = self.llm_config.prompts[task_type]
        digest = hashlib.sha256()
        for path in (prompt.system, prompt.user_template, prompt.schema):
            digest.update((self.root / path).read_bytes())
        return digest.hexdigest()[:16]

    def _export_apt_table(self, repository: PostgresRepository) -> int:
        """Write the default TSV export after each successful pipeline run."""

        rows = repository.apt_group_export_rows(chinese_headers=True)
        output_path = self.root / ".state" / "apt_group_export.tsv"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        columns = list(rows[0].keys()) if rows else []
        with output_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, delimiter="\t")
            if columns:
                writer.writeheader()
                writer.writerows(rows)
        return len(rows)

    def _send_report(self, report_path: Path) -> None:
        """Send daily report through the configured notifier."""

        import json

        report = json.loads(report_path.read_text(encoding="utf-8"))
        notifier = load_notifier(self.root / "config" / "notifications.yaml", self.root, env_path=self.root / ".env")
        title, body = render_report_message(report)
        notifier.send(title, body, report)
