"""Daily operational report generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .pg_repository import PostgresRepository
from .storage import StateStore
from .utils import write_json


@dataclass(frozen=True)
class ReportThresholds:
    """Thresholds that turn counters into actionable health statuses."""

    backlog_warning: int = 50
    backlog_critical: int = 200
    source_failure_warning: int = 1
    model_failure_warning: int = 1
    streak_days: int = 3


class DailyReportBuilder:
    """Build one cross-system operational report for a calendar day."""

    def __init__(
        self,
        state_dir: Path,
        store: StateStore,
        repository: PostgresRepository | None = None,
        thresholds: ReportThresholds | None = None,
    ) -> None:
        self.state_dir = state_dir
        self.store = store
        self.repository = repository
        self.thresholds = thresholds or ReportThresholds()

    def build(self, report_date: str | None = None) -> dict[str, Any]:
        """Return a JSON-serializable daily report."""

        day = report_date or datetime.now().astimezone().date().isoformat()
        local = self._local_metrics(day)
        logs = self._log_metrics(day)
        pg = self._postgres_metrics(day) if self.repository else self._missing_postgres_metrics()
        health = self._health(local, logs, pg)
        return {
            "date": day,
            "health": health,
            "collection": {
                "runs": local["collection_runs"],
                "documents_collected": local["documents_collected"],
                "documents_inserted": local["documents_inserted"],
                "documents_duplicate": local["documents_duplicate"],
                "failed_run_count": local["failed_run_count"],
                "failed_source_count": local["failed_source_count"],
                "failed_sources": local["failed_sources"],
                "source_failure_streaks": local["source_failure_streaks"],
            },
            "processing": {
                "model_runs": pg["model_runs"],
                "article_extract_success": pg["article_extract_success"],
                "article_extract_failed": pg["article_extract_failed"],
                "groups_updated": pg["groups_updated"],
                "touched_groups": pg["touched_groups"],
            },
            "storage": {
                "sqlite": self.store.stats(),
                "postgres": pg["table_counts"],
            },
            "backlog": pg["backlog"],
            "alerts": health["alerts"],
            "problem_summary": self._problem_summary(health["alerts"], local, pg),
            "files": logs["files"],
        }

    def write(self, report_date: str | None = None) -> Path:
        """Write report JSON under the matching daily log directory."""

        report = self.build(report_date)
        path = self.state_dir / "logs" / report["date"] / "daily_report.json"
        write_json(path, report)
        return path

    def _local_metrics(self, day: str) -> dict[str, Any]:
        """Read SQLite collection metrics for the requested local day."""

        start, end = _day_bounds(day)
        rows = self.store.conn.execute(
            """
            SELECT source_id, status, collected_count, inserted_count, duplicate_count
            FROM collection_runs
            WHERE started_at >= ? AND started_at < ?
            """,
            (start, end),
        ).fetchall()
        metrics = {
            "collection_runs": len(rows),
            "documents_collected": sum(row["collected_count"] for row in rows),
            "documents_inserted": sum(row["inserted_count"] for row in rows),
            "documents_duplicate": sum(row["duplicate_count"] for row in rows),
            "failed_run_count": sum(1 for row in rows if row["status"] == "failed"),
            "failed_sources": sorted(
                {row["source_id"] for row in rows if row["status"] == "failed" and row["source_id"]}
            ),
        }
        metrics["source_failure_streaks"] = self._source_failure_streaks(day)
        return metrics

    def _source_failure_streaks(self, day: str) -> list[dict[str, Any]]:
        """Find sources that have failed on consecutive recent days."""

        end_day = date.fromisoformat(day)
        lookback = [end_day - timedelta(days=offset) for offset in range(self.thresholds.streak_days)]
        rows = self.store.conn.execute(
            """
            SELECT source_id, substr(started_at, 1, 10) AS day
            FROM collection_runs
            WHERE status = 'failed' AND source_id IS NOT NULL
            """
        ).fetchall()
        failed_by_source: dict[str, set[str]] = {}
        for row in rows:
            failed_by_source.setdefault(row["source_id"], set()).add(row["day"])
        streaks = []
        for source_id, days in sorted(failed_by_source.items()):
            streak = 0
            for current_day in lookback:
                if current_day.isoformat() in days:
                    streak += 1
                else:
                    break
            if streak:
                streaks.append({"source_id": source_id, "consecutive_failed_days": streak})
        return streaks

    def _log_metrics(self, day: str) -> dict[str, Any]:
        """Return available report/log files for one day."""

        day_dir = self.state_dir / "logs" / day
        files = []
        if day_dir.exists():
            files = sorted(path.name for path in day_dir.iterdir() if path.is_file())
        return {"files": files}

    def _postgres_metrics(self, day: str) -> dict[str, Any]:
        """Read PostgreSQL processing and storage metrics."""

        start, end = _day_bounds(day)
        assert self.repository is not None
        with self.repository.conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_type, status, COUNT(*)
                FROM model_runs
                WHERE created_at >= %s AND created_at < %s
                GROUP BY run_type, status
                """,
                (start, end),
            )
            model_runs = [
                {"run_type": row[0], "status": row[1], "count": row[2]}
                for row in cur.fetchall()
            ]
            cur.execute(
                """
                SELECT run_type, error_message, COUNT(*)
                FROM model_runs
                WHERE status = 'failed'
                  AND created_at >= %s AND created_at < %s
                GROUP BY run_type, error_message
                ORDER BY COUNT(*) DESC
                LIMIT 10
                """,
                (start, end),
            )
            model_failures = [
                {"run_type": row[0], "error": row[1], "count": row[2]}
                for row in cur.fetchall()
            ]
            cur.execute(
                """
                SELECT DISTINCT tg.organization_code, tg.canonical_name
                FROM model_runs mr
                CROSS JOIN LATERAL jsonb_array_elements(
                  COALESCE(mr.output_payload->'matched_groups', '[]'::jsonb)
                ) AS mg
                JOIN threat_groups tg ON tg.id = (mg->>'group_id')::uuid
                WHERE mr.run_type = 'article_extract'
                  AND mr.status = 'success'
                  AND mr.created_at >= %s AND mr.created_at < %s
                ORDER BY tg.canonical_name
                """,
                (start, end),
            )
            touched_groups = [
                {"organization_code": row[0], "canonical_name": row[1]}
                for row in cur.fetchall()
            ]
            counts = {}
            for table in (
                "threat_groups",
                "group_aliases",
                "collected_documents",
                "group_fact_events",
                "group_structure_events",
                "group_activity_timeline",
                "apt_group_export",
            ):
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = cur.fetchone()[0]
        article_extract_success = _count(model_runs, "article_extract", "success")
        article_extract_failed = _count(model_runs, "article_extract", "failed")
        groups_updated = sum(
            _count(model_runs, task, "success")
            for task in ("group_profile_synthesis", "group_structure_synthesis", "apt_group_export_synthesis")
        )
        return {
            "model_runs": model_runs,
            "model_failures": model_failures,
            "article_extract_success": article_extract_success,
            "article_extract_failed": article_extract_failed,
            "groups_updated": groups_updated,
            "touched_groups": touched_groups,
            "table_counts": counts,
            "backlog": self.repository.document_backlog_summary(),
        }

    @staticmethod
    def _missing_postgres_metrics() -> dict[str, Any]:
        """Return neutral placeholders when PostgreSQL is unavailable."""

        return {
            "model_runs": [],
            "model_failures": [],
            "article_extract_success": 0,
            "article_extract_failed": 0,
            "groups_updated": 0,
            "touched_groups": [],
            "table_counts": {},
            "backlog": {"total_pending": None, "by_source": []},
        }

    def _health(self, local: dict[str, Any], logs: dict[str, Any], pg: dict[str, Any]) -> dict[str, Any]:
        """Compute one overall health status plus typed alerts."""

        alerts = []
        local["failed_source_count"] = len(local["failed_sources"])
        if local["failed_run_count"] >= self.thresholds.source_failure_warning:
            alerts.append(
                {
                    "level": "warning",
                    "code": "source_failures",
                    "message": f"{local['failed_source_count']} 个来源共失败 {local['failed_run_count']} 次",
                }
            )
        for item in local["source_failure_streaks"]:
            if item["consecutive_failed_days"] >= self.thresholds.streak_days:
                alerts.append(
                    {
                        "level": "warning",
                        "code": "source_failure_streak",
                        "message": f"{item['source_id']} 已连续失败 {item['consecutive_failed_days']} 天",
                    }
                )
        if pg["article_extract_failed"] >= self.thresholds.model_failure_warning:
            alerts.append(
                {
                    "level": "warning",
                    "code": "model_failures",
                    "message": f"文章抽取失败 {pg['article_extract_failed']} 次",
                }
            )
        fatal_model_failures = [
            failure
            for failure in pg.get("model_failures", [])
            if _looks_fatal_model_error(failure.get("error") or "")
        ]
        if fatal_model_failures:
            alerts.append(
                {
                    "level": "critical",
                    "code": "model_fatal_error",
                    "message": "模型连接或认证失败",
                }
            )
        pending = pg["backlog"]["total_pending"]
        if pending is None:
            alerts.append(
                {
                    "level": "warning",
                    "code": "postgres_unavailable",
                    "message": "PostgreSQL 指标不可用",
                }
            )
        elif pending >= self.thresholds.backlog_critical:
            alerts.append(
                {
                    "level": "critical",
                    "code": "backlog_critical",
                    "message": f"待处理文档积压 {pending} 篇，已达到严重阈值",
                }
            )
        elif pending >= self.thresholds.backlog_warning:
            alerts.append(
                {
                    "level": "warning",
                    "code": "backlog_warning",
                    "message": f"待处理文档积压 {pending} 篇",
                }
            )
        status = "critical" if any(item["level"] == "critical" for item in alerts) else "warning" if alerts else "healthy"
        return {"status": status, "alerts": alerts}

    @staticmethod
    def _problem_summary(alerts: list[dict[str, str]], local: dict[str, Any], pg: dict[str, Any]) -> list[str]:
        """Create short human-readable problem bullets for notifications."""

        if not alerts:
            return ["未发现运行问题。"]
        lines = []
        for alert in alerts:
            lines.append(f"[{_level_cn(alert['level'])}] {alert['code']}: {alert['message']}")
        if local["failed_sources"]:
            lines.append(f"失败来源：{', '.join(local['failed_sources'])}")
        for failure in pg.get("model_failures", [])[:3]:
            lines.append(f"模型失败：{failure['run_type']} x{failure['count']} - {failure['error']}")
        return lines


def _day_bounds(day: str) -> tuple[str, str]:
    """Return ISO UTC bounds for a local calendar-day string."""

    local_day = date.fromisoformat(day)
    start = datetime.combine(local_day, datetime.min.time()).astimezone()
    end = start + timedelta(days=1)
    return start.astimezone(timezone.utc).isoformat(), end.astimezone(timezone.utc).isoformat()


def _count(rows: list[dict[str, Any]], run_type: str, status: str) -> int:
    """Count one run_type/status pair from grouped rows."""

    return sum(row["count"] for row in rows if row["run_type"] == run_type and row["status"] == status)


def _looks_fatal_model_error(value: str) -> bool:
    """Detect stored model auth/connection errors from error text."""

    text = value.casefold()
    fatal_markers = (
        "401",
        "403",
        "unauthorized",
        "forbidden",
        "api key",
        "connection",
        "connecterror",
        "timeout",
        "ssl",
    )
    return any(marker in text for marker in fatal_markers)


def _level_cn(level: str) -> str:
    """Translate alert level for human-readable summaries."""

    return {"healthy": "正常", "warning": "警告", "critical": "严重"}.get(level, level)
