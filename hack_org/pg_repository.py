"""PostgreSQL write repository for validated MiMo outputs."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from psycopg import Connection

from .models import GroupProfile, SourceConfig
from .normalization import normalize_name


APT_GROUP_EXPORT_CN_COLUMNS = {
    "apt_organization": "APT组织",
    "organization_code": "组织编码",
    "team_name": "组织名称",
    "attack_type": "攻击类型",
    "technical_skills": "技术能力",
    "suspected_source": "疑似来源",
    "affected_industry": "受影响行业",
    "alias": "别名",
    "attack_pattern": "攻击模式",
    "attack_frequency": "攻击频率",
    "target_country": "目标国家或地区",
    "earliest_active_time": "最早活跃时间",
    "active_time": "活跃时间",
    "common_language": "常用语言",
    "team_description": "组织描述",
    "tactics": "战术技术",
    "associated_domain": "关联域名",
    "associative_hash": "关联哈希",
    "associative_ip": "关联IP",
    "associative_url": "关联URL",
    "related_certificates": "关联证书",
    "storage_time": "入库时间",
}


_APT_GROUP_EXPORT_CN_VIEW_SQL = """
CREATE OR REPLACE VIEW apt_group_export_cn AS
SELECT
  apt_organization AS "APT组织",
  organization_code AS "组织编码",
  team_name AS "组织名称",
  attack_type AS "攻击类型",
  technical_skills AS "技术能力",
  suspected_source AS "疑似来源",
  affected_industry AS "受影响行业",
  alias AS "别名",
  attack_pattern AS "攻击模式",
  attack_frequency AS "攻击频率",
  target_country AS "目标国家或地区",
  earliest_active_time AS "最早活跃时间",
  active_time AS "活跃时间",
  common_language AS "常用语言",
  team_description AS "组织描述",
  tactics AS "战术技术",
  associated_domain AS "关联域名",
  associative_hash AS "关联哈希",
  associative_ip AS "关联IP",
  associative_url AS "关联URL",
  related_certificates AS "关联证书",
  storage_time AS "入库时间"
FROM apt_group_export
"""


class PostgresRepository:
    """Encapsulate PostgreSQL insert/update operations for model outputs."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn

    def ensure_runtime_schema(self) -> None:
        """Apply forward-compatible runtime tables for append-only ledgers and projections."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                ALTER TABLE apt_group_export
                ADD COLUMN IF NOT EXISTS source_evidence TEXT
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS intel_sources (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    tier TEXT NOT NULL DEFAULT 'A',
                    category TEXT NOT NULL,
                    url TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT TRUE,
                    weight NUMERIC(8,4) NOT NULL DEFAULT 1.0,
                    fetch_full_article BOOLEAN NOT NULL DEFAULT TRUE,
                    keywords JSONB NOT NULL DEFAULT '[]'::jsonb,
                    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
                    api_key_env TEXT,
                    auth_header TEXT,
                    max_items INTEGER,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS model_runs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
                    run_type TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    model_version TEXT,
                    prompt_version TEXT NOT NULL,
                    input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                    output_payload JSONB,
                    status TEXT NOT NULL DEFAULT 'running',
                    error_message TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    finished_at TIMESTAMPTZ
                )
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_model_runs_document_type_status
                ON model_runs (document_id, run_type, status)
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS group_fact_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
                    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
                    fact_type TEXT NOT NULL,
                    fact_value TEXT NOT NULL,
                    normalized_value TEXT,
                    confidence NUMERIC(5,4) NOT NULL,
                    evidence_text TEXT NOT NULL,
                    source_url TEXT,
                    source_title TEXT,
                    source_published_at TIMESTAMPTZ,
                    valid_time TEXT,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (group_id, document_id, fact_type, normalized_value, evidence_text)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS group_structure_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
                    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
                    structure_type TEXT NOT NULL,
                    relation_type TEXT,
                    target_entity_type TEXT,
                    target_name TEXT,
                    member_name TEXT,
                    role TEXT,
                    confidence NUMERIC(5,4) NOT NULL,
                    evidence_text TEXT NOT NULL,
                    source_url TEXT,
                    source_title TEXT,
                    source_published_at TIMESTAMPTZ,
                    valid_time TEXT,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS ux_group_structure_events_dedupe
                ON group_structure_events (
                    group_id,
                    document_id,
                    structure_type,
                    COALESCE(target_name, ''),
                    COALESCE(member_name, ''),
                    evidence_text
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS group_activity_timeline (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    group_id UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
                    event_id UUID,
                    document_id UUID REFERENCES collected_documents(id) ON DELETE SET NULL,
                    event_date DATE,
                    date_precision TEXT NOT NULL DEFAULT 'unknown',
                    event_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    targets JSONB NOT NULL DEFAULT '{}'::jsonb,
                    techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
                    malware JSONB NOT NULL DEFAULT '[]'::jsonb,
                    vulnerabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
                    iocs JSONB NOT NULL DEFAULT '{}'::jsonb,
                    confidence NUMERIC(5,4) NOT NULL,
                    evidence_texts JSONB NOT NULL DEFAULT '[]'::jsonb,
                    source_url TEXT,
                    source_title TEXT,
                    source_published_at TIMESTAMPTZ,
                    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            cur.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS ux_group_activity_timeline_dedupe
                ON group_activity_timeline (
                    group_id,
                    document_id,
                    event_type,
                    title,
                    COALESCE(event_date, DATE '0001-01-01')
                )
                """
            )
            cur.execute(_APT_GROUP_EXPORT_CN_VIEW_SQL)

    def has_successful_model_run(self, run_type: str, document_id: str | None = None) -> bool:
        """Return whether one successful model run already exists."""

        with self.conn.cursor() as cur:
            if document_id:
                cur.execute(
                    """
                    SELECT EXISTS (
                      SELECT 1 FROM model_runs
                      WHERE run_type = %s AND document_id = %s AND status = 'success'
                    )
                    """,
                    (run_type, document_id),
                )
            else:
                raise ValueError("document_id is required for document-scoped model runs")
            return bool(cur.fetchone()[0])

    def document_backlog_summary(self) -> dict[str, Any]:
        """Return document processing backlog grouped by source."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM collected_documents d
                WHERE NOT EXISTS (
                  SELECT 1 FROM model_runs mr
                  WHERE mr.document_id = d.id
                    AND mr.run_type = 'article_extract'
                    AND mr.status = 'success'
                )
                """
            )
            total_pending = cur.fetchone()[0]
            cur.execute(
                """
                SELECT d.source_id, COUNT(*) AS pending_count,
                       MIN(d.collected_at) AS oldest_collected_at,
                       MAX(d.collected_at) AS newest_collected_at
                FROM collected_documents d
                WHERE NOT EXISTS (
                  SELECT 1 FROM model_runs mr
                  WHERE mr.document_id = d.id
                    AND mr.run_type = 'article_extract'
                    AND mr.status = 'success'
                )
                GROUP BY d.source_id
                ORDER BY pending_count DESC, d.source_id
                """
            )
            by_source = [
                {
                    "source_id": row[0],
                    "pending_count": row[1],
                    "oldest_collected_at": row[2].isoformat() if row[2] else None,
                    "newest_collected_at": row[3].isoformat() if row[3] else None,
                }
                for row in cur.fetchall()
            ]
        return {"total_pending": total_pending, "by_source": by_source}

    def start_model_run(
        self,
        run_type: str,
        model_name: str,
        prompt_version: str,
        input_payload: dict[str, Any],
        document_id: str | None = None,
        model_version: str | None = None,
    ) -> str:
        """Create a model run row and return its UUID."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO model_runs
                  (document_id, run_type, model_name, model_version, prompt_version,
                   input_payload, status)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, 'running')
                RETURNING id
                """,
                (
                    document_id,
                    run_type,
                    model_name,
                    model_version,
                    prompt_version,
                    json.dumps(input_payload, ensure_ascii=False),
                ),
            )
            return str(cur.fetchone()[0])

    def finish_model_run(
        self,
        run_id: str,
        status: str,
        output_payload: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> None:
        """Finalize one model run."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE model_runs
                SET output_payload = %s::jsonb,
                    status = %s,
                    error_message = %s,
                    finished_at = NOW()
                WHERE id = %s
                """,
                (
                    json.dumps(output_payload, ensure_ascii=False) if output_payload is not None else None,
                    status,
                    error_message,
                    run_id,
                ),
            )

    def organization_codes_for_group_ids(self, group_ids: list[str]) -> list[str]:
        """Resolve PostgreSQL group UUIDs back to local stable organization codes."""

        if not group_ids:
            return []
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT organization_code FROM threat_groups WHERE id = ANY(%s)",
                (group_ids,),
            )
            return [row[0] for row in cur.fetchall() if row[0]]

    def sync_group_profile(self, group: GroupProfile) -> str:
        """Upsert one local stable group into PostgreSQL and return its UUID."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO threat_groups
                  (organization_code, canonical_name, display_name)
                VALUES (%s, %s, %s)
                ON CONFLICT (organization_code) DO UPDATE SET
                  canonical_name = EXCLUDED.canonical_name,
                  display_name = EXCLUDED.display_name,
                  updated_at = NOW()
                RETURNING id
                """,
                (group.group_id, group.canonical_name, group.canonical_name),
            )
            group_id = str(cur.fetchone()[0])
            for alias in group.aliases:
                cur.execute(
                    """
                    INSERT INTO group_aliases
                      (group_id, alias, normalized_alias, alias_type, status, source_type, confidence)
                    VALUES (%s, %s, %s, 'same_as', 'confirmed', 'local_identity', 1.0000)
                    ON CONFLICT (group_id, normalized_alias) DO UPDATE SET
                      alias = EXCLUDED.alias,
                      status = EXCLUDED.status,
                      confidence = GREATEST(group_aliases.confidence, EXCLUDED.confidence),
                      last_seen_at = NOW(),
                      updated_at = NOW()
                    """,
                    (group_id, alias, normalize_name(alias)),
                )
        return group_id

    def sync_group_profiles(self, groups: list[GroupProfile]) -> dict[str, str]:
        """Sync many local groups and return local-id to PostgreSQL-id mapping."""

        return {str(group.group_id): self.sync_group_profile(group) for group in groups if group.group_id}

    def sync_source(self, source: SourceConfig) -> None:
        """Upsert one configured collection source."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO intel_sources
                  (id, name, source_type, tier, category, url, enabled, weight,
                   fetch_full_article, keywords, headers, api_key_env, auth_header, max_items)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                  name = EXCLUDED.name,
                  source_type = EXCLUDED.source_type,
                  tier = EXCLUDED.tier,
                  category = EXCLUDED.category,
                  url = EXCLUDED.url,
                  enabled = EXCLUDED.enabled,
                  weight = EXCLUDED.weight,
                  fetch_full_article = EXCLUDED.fetch_full_article,
                  keywords = EXCLUDED.keywords,
                  headers = EXCLUDED.headers,
                  api_key_env = EXCLUDED.api_key_env,
                  auth_header = EXCLUDED.auth_header,
                  max_items = EXCLUDED.max_items,
                  updated_at = NOW()
                """,
                (
                    source.id,
                    source.name,
                    source.type,
                    source.tier,
                    source.category,
                    str(source.url),
                    source.enabled,
                    source.weight,
                    source.fetch_full_article,
                    json.dumps(source.keywords, ensure_ascii=False),
                    json.dumps(source.headers, ensure_ascii=False),
                    source.api_key_env,
                    source.auth_header,
                    source.max_items,
                ),
            )

    def sync_sources(self, sources: list[SourceConfig]) -> int:
        """Sync configured sources and return count."""

        for source in sources:
            self.sync_source(source)
        return len(sources)

    def upsert_collected_document(self, article_row: dict[str, Any]) -> str:
        """Upsert one locally collected article and return its PostgreSQL UUID."""

        metadata = json.loads(article_row["metadata_json"] or "{}")
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO collected_documents
                  (source_id, source_title, source_url, source_domain, document_type, published_at,
                   collected_at, title, author, language, url_hash, title_hash, text_hash,
                   raw_object_key, clean_object_key, meta_object_key,
                   raw_local_path, clean_local_path, meta_local_path, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (url_hash) DO UPDATE SET
                  source_title = EXCLUDED.source_title,
                  source_url = EXCLUDED.source_url,
                  source_domain = EXCLUDED.source_domain,
                  published_at = COALESCE(EXCLUDED.published_at, collected_documents.published_at),
                  title = EXCLUDED.title,
                  author = EXCLUDED.author,
                  language = EXCLUDED.language,
                  title_hash = EXCLUDED.title_hash,
                  text_hash = EXCLUDED.text_hash,
                  raw_object_key = EXCLUDED.raw_object_key,
                  clean_object_key = EXCLUDED.clean_object_key,
                  meta_object_key = EXCLUDED.meta_object_key,
                  raw_local_path = EXCLUDED.raw_local_path,
                  clean_local_path = EXCLUDED.clean_local_path,
                  meta_local_path = EXCLUDED.meta_local_path,
                  metadata = EXCLUDED.metadata
                RETURNING id
                """,
                (
                    article_row["source_id"],
                    article_row["source_title"],
                    article_row["source_url"],
                    article_row["source_domain"],
                    metadata.get("collector_type", "article"),
                    article_row["published_at"],
                    article_row["collected_at"],
                    article_row["title"],
                    article_row["author"],
                    metadata.get("language"),
                    article_row["url_hash"],
                    article_row["title_hash"],
                    article_row["text_hash"],
                    metadata.get("raw_object_key"),
                    metadata.get("clean_object_key"),
                    metadata.get("meta_object_key"),
                    article_row["html_path"],
                    article_row["text_path"],
                    metadata.get("meta_path"),
                    json.dumps(metadata, ensure_ascii=False),
                ),
            )
            return str(cur.fetchone()[0])

    def group_context_by_organization_codes(self, organization_codes: list[str]) -> dict[str, dict[str, Any]]:
        """Load synthesis context for local stable group ids from append-only ledgers."""

        if not organization_codes:
            return {}
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, organization_code, canonical_name, latest_overview, latest_structure_overview
                FROM threat_groups
                WHERE organization_code = ANY(%s)
                """,
                (organization_codes,),
            )
            groups = {
                row[1]: {
                    "group_id": str(row[0]),
                    "organization_code": row[1],
                    "canonical_name": row[2],
                    "known_aliases": [],
                    "known_facts": [],
                    "known_relations": [],
                    "latest_overview": row[3],
                    "latest_structure_overview": row[4],
                }
                for row in cur.fetchall()
            }
            if not groups:
                return {}
            pg_ids = [group["group_id"] for group in groups.values()]
            by_pg_id = {group["group_id"]: group for group in groups.values()}
            cur.execute(
                """
                SELECT group_id, alias
                FROM group_aliases
                WHERE group_id = ANY(%s) AND status IN ('confirmed', 'manual_confirmed', 'auto_confirmed')
                ORDER BY alias
                """,
                (pg_ids,),
            )
            for group_id, alias in cur.fetchall():
                by_pg_id[str(group_id)]["known_aliases"].append(alias)
            cur.execute(
                """
                SELECT id, group_id, fact_type, fact_value, normalized_value, confidence
                FROM group_fact_events
                WHERE group_id = ANY(%s)
                ORDER BY confidence DESC, collected_at DESC
                LIMIT 500
                """,
                (pg_ids,),
            )
            for fact_id, group_id, fact_type, fact_value, normalized_value, confidence in cur.fetchall():
                by_pg_id[str(group_id)]["known_facts"].append(
                    {
                        "fact_id": str(fact_id),
                        "fact_type": fact_type,
                        "fact_value": normalized_value or fact_value,
                        "confidence": float(confidence),
                        "current_best": False,
                    }
                )
            cur.execute(
                """
                SELECT group_id, relation_type, target_name, confidence
                FROM group_structure_events
                WHERE group_id = ANY(%s) AND structure_type = 'relation'
                ORDER BY confidence DESC, collected_at DESC
                LIMIT 300
                """,
                (pg_ids,),
            )
            for group_id, relation_type, target_name, confidence in cur.fetchall():
                by_pg_id[str(group_id)]["known_relations"].append(
                    {
                        "relation_type": relation_type,
                        "target_name": target_name,
                        "confidence": float(confidence),
                    }
                )
        return groups

    def group_by_organization_code(self, organization_code: str) -> dict[str, Any]:
        """Return one PostgreSQL group row by local stable organization code."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, organization_code, canonical_name, display_name,
                       latest_overview, latest_structure_overview
                FROM threat_groups
                WHERE organization_code = %s
                """,
                (organization_code,),
            )
            row = cur.fetchone()
        if not row:
            raise KeyError(f"group not found for organization_code={organization_code}")
        return {
            "group_id": str(row[0]),
            "organization_code": row[1],
            "canonical_name": row[2],
            "display_name": row[3],
            "latest_overview": row[4],
            "latest_structure_overview": row[5],
        }

    def profile_synthesis_input(self, organization_code: str) -> dict[str, Any]:
        """Build prompt variables for basic-profile synthesis from fact ledger rows."""

        group = self.group_by_organization_code(organization_code)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, fact_type, fact_value, normalized_value, confidence,
                       evidence_text, source_url, source_title, source_published_at
                FROM group_fact_events
                WHERE group_id = %s
                ORDER BY fact_type, confidence DESC, collected_at DESC
                LIMIT 500
                """,
                (group["group_id"],),
            )
            facts = []
            evidence: dict[str, list[dict[str, Any]]] = {}
            for row in cur.fetchall():
                fact_id = str(row[0])
                facts.append(
                    {
                        "fact_id": fact_id,
                        "fact_type": row[1],
                        "fact_value": row[2],
                        "normalized_value": row[3],
                        "confidence": float(row[4]),
                        "source_count": 1,
                        "is_current": True,
                        "current_best": False,
                    }
                )
                evidence[fact_id] = [
                    {
                        "evidence_text": row[5],
                        "source_url": row[6],
                        "source_title": row[7],
                        "published_at": row[8].isoformat() if row[8] else None,
                        "confidence": float(row[4]),
                    }
                ]
        return {
            "group_json": group,
            "facts_json": facts,
            "fact_evidence_json": evidence,
            "previous_overview_json": group["latest_overview"],
        }

    def structure_synthesis_input(self, organization_code: str) -> dict[str, Any]:
        """Build prompt variables for organization-structure synthesis from structure ledger rows."""

        group = self.group_by_organization_code(organization_code)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, relation_type, target_name, confidence, evidence_text
                FROM group_structure_events
                WHERE group_id = %s AND structure_type = 'relation'
                ORDER BY confidence DESC, collected_at DESC
                LIMIT 300
                """,
                (group["group_id"],),
            )
            relations = [
                {
                    "relation_id": str(row[0]),
                    "relation_type": row[1],
                    "target_name": row[2],
                    "confidence": float(row[3]),
                    "is_current": True,
                }
                for row in cur.fetchall()
            ]
            cur.execute(
                """
                SELECT id, member_name, role, confidence, evidence_text
                FROM group_structure_events
                WHERE group_id = %s AND structure_type = 'member'
                ORDER BY confidence DESC, collected_at DESC
                LIMIT 300
                """,
                (group["group_id"],),
            )
            members = []
            evidence = []
            for row in cur.fetchall():
                member_id = str(row[0])
                members.append(
                    {
                        "member_id": member_id,
                        "member_name": row[1],
                        "role": row[2],
                        "confidence": float(row[3]),
                        "is_current": True,
                    }
                )
                evidence.append({"member_id": member_id, "relation_id": None, "evidence_text": row[4], "confidence": float(row[3])})
            cur.execute(
                """
                SELECT id, evidence_text, confidence
                FROM group_structure_events
                WHERE group_id = %s AND structure_type = 'relation'
                ORDER BY confidence DESC, collected_at DESC
                LIMIT 300
                """,
                (group["group_id"],),
            )
            for row in cur.fetchall():
                evidence.append({"relation_id": str(row[0]), "member_id": None, "evidence_text": row[1], "confidence": float(row[2])})
        return {
            "group_json": group,
            "relations_json": relations,
            "members_json": members,
            "structure_evidence_json": evidence,
            "previous_structure_overview_json": group["latest_structure_overview"],
        }

    def export_synthesis_input(self, organization_code: str) -> dict[str, Any]:
        """Build prompt variables for apt_group_export synthesis from ledgers."""

        group = self.group_by_organization_code(organization_code)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT fact_type, COALESCE(NULLIF(normalized_value, ''), fact_value) AS value, confidence
                FROM group_fact_events
                WHERE group_id = %s
                ORDER BY fact_type, confidence DESC, collected_at DESC
                LIMIT 500
                """,
                (group["group_id"],),
            )
            current_best_facts = [
                {"fact_type": row[0], "fact_value": row[1], "confidence": float(row[2]), "current_best": False}
                for row in cur.fetchall()
            ]
            cur.execute(
                """
                SELECT alias
                FROM group_aliases
                WHERE group_id = %s AND status IN ('confirmed', 'manual_confirmed', 'auto_confirmed')
                ORDER BY alias
                """,
                (group["group_id"],),
            )
            aliases = [row[0] for row in cur.fetchall()]
            cur.execute(
                """
                SELECT event_date, event_type, title, summary, confidence
                FROM group_activity_timeline
                WHERE group_id = %s
                ORDER BY event_date DESC NULLS LAST, created_at DESC
                LIMIT 20
                """,
                (group["group_id"],),
            )
            events = [
                {
                    "event_date": row[0].isoformat() if row[0] else None,
                    "event_type": row[1],
                    "title": row[2],
                    "summary": row[3],
                    "confidence": float(row[4]),
                }
                for row in cur.fetchall()
            ]
        return {
            "group_json": group,
            "current_best_facts_json": current_best_facts,
            "aliases_json": aliases,
            "events_summary_json": events,
            "approved_overviews_json": {
                "latest_overview": group["latest_overview"],
                "latest_structure_overview": group["latest_structure_overview"],
            },
        }



    def drop_legacy_projection_tables(self) -> list[str]:
        """Drop PostgreSQL tables made obsolete by append-only ledgers."""

        legacy_tables = [
            "event_evidence",
            "event_entities",
            "event_groups",
            "activity_events",
            "structure_evidence",
            "group_members",
            "group_relations",
            "fact_evidence",
            "group_facts",
        ]
        with self.conn.cursor() as cur:
            for table in legacy_tables:
                cur.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
        return legacy_tables

    def ledger_counts(self) -> dict[str, int]:
        """Return counts for the three append-only ledgers."""

        tables = ("group_fact_events", "group_structure_events", "group_activity_timeline")
        counts: dict[str, int] = {}
        with self.conn.cursor() as cur:
            for table in tables:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                counts[table] = int(cur.fetchone()[0])
        return counts

    def recent_ledger_rows(self, ledger: str, limit: int = 20) -> list[dict[str, Any]]:
        """Return recent rows from one append-only ledger for operator inspection."""

        allowed = {
            "facts": "group_fact_events",
            "structure": "group_structure_events",
            "activity": "group_activity_timeline",
        }
        table = allowed.get(ledger)
        if not table:
            raise ValueError(f"unknown ledger: {ledger}")
        with self.conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT row_to_json(t)
                FROM (
                  SELECT
                    tg.canonical_name AS apt_organization,
                    tg.organization_code,
                    tg.display_name AS team_name,
                    l.*
                  FROM {table} l
                  JOIN threat_groups tg ON tg.id = l.group_id
                  ORDER BY l.created_at DESC
                  LIMIT %s
                ) t
                """,
                (limit,),
            )
            return [row[0] for row in cur.fetchall()]

    def apt_group_export_rows(self, chinese_headers: bool = False) -> list[dict[str, Any]]:
        """Return rows in the same column order as table.txt."""

        columns = [
            "apt_organization",
            "organization_code",
            "team_name",
            "attack_type",
            "technical_skills",
            "suspected_source",
            "affected_industry",
            "alias",
            "attack_pattern",
            "attack_frequency",
            "target_country",
            "earliest_active_time",
            "active_time",
            "common_language",
            "team_description",
            "tactics",
            "associated_domain",
            "associative_hash",
            "associative_ip",
            "associative_url",
            "related_certificates",
            "source_evidence",
            "storage_time",
        ]
        with self.conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {", ".join(columns)}
                FROM apt_group_export
                ORDER BY apt_organization
                """
            )
            rows = cur.fetchall()
        result = []
        for row in rows:
            item = dict(zip(columns, row))
            if item["storage_time"] is not None:
                item["storage_time"] = item["storage_time"].isoformat()
            if chinese_headers:
                item = {APT_GROUP_EXPORT_CN_COLUMNS.get(key, key): value for key, value in item.items()}
            result.append(item)
        return result

    def group_archive_snapshots(self) -> list[dict[str, Any]]:
        """Return normalized archive-ready snapshots for every PostgreSQL group from append-only ledgers."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, organization_code, canonical_name, latest_overview, latest_structure_overview
                FROM threat_groups
                ORDER BY canonical_name
                """
            )
            groups = [
                {
                    "group_id": str(row[0]),
                    "organization_code": row[1],
                    "canonical_name": row[2],
                    "latest_overview": row[3] or "",
                    "latest_structure_overview": row[4] or "",
                    "aliases": [],
                    "facts": [],
                    "relations": [],
                    "members": [],
                    "events": [],
                }
                for row in cur.fetchall()
            ]
            by_id = {group["group_id"]: group for group in groups}
            pg_ids = list(by_id)
            if not pg_ids:
                return groups
            cur.execute(
                """
                SELECT group_id, alias
                FROM group_aliases
                WHERE group_id = ANY(%s)
                  AND status IN ('confirmed', 'manual_confirmed', 'auto_confirmed')
                ORDER BY alias
                """,
                (pg_ids,),
            )
            for group_id, alias in cur.fetchall():
                by_id[str(group_id)]["aliases"].append(alias)
            cur.execute(
                """
                SELECT group_id, fact_type, COALESCE(NULLIF(normalized_value, ''), fact_value), confidence
                FROM group_fact_events
                WHERE group_id = ANY(%s)
                ORDER BY fact_type, confidence DESC, collected_at DESC
                """,
                (pg_ids,),
            )
            for group_id, fact_type, fact_value, confidence in cur.fetchall():
                by_id[str(group_id)]["facts"].append(
                    {"fact_type": fact_type, "fact_value": fact_value, "confidence": float(confidence), "current_best": False}
                )
            cur.execute(
                """
                SELECT group_id, relation_type, target_name, confidence
                FROM group_structure_events
                WHERE group_id = ANY(%s) AND structure_type = 'relation'
                ORDER BY relation_type, confidence DESC, target_name
                """,
                (pg_ids,),
            )
            for group_id, relation_type, target_name, confidence in cur.fetchall():
                by_id[str(group_id)]["relations"].append(
                    {"relation_type": relation_type, "target_name": target_name, "confidence": float(confidence)}
                )
            cur.execute(
                """
                SELECT group_id, member_name, role, confidence
                FROM group_structure_events
                WHERE group_id = ANY(%s) AND structure_type = 'member'
                ORDER BY confidence DESC, member_name
                """,
                (pg_ids,),
            )
            for group_id, member_name, role, confidence in cur.fetchall():
                by_id[str(group_id)]["members"].append(
                    {"member_name": member_name, "role": role, "confidence": float(confidence)}
                )
            cur.execute(
                """
                SELECT group_id, event_date, date_precision, event_type, title, summary, confidence
                FROM group_activity_timeline
                WHERE group_id = ANY(%s)
                ORDER BY event_date NULLS LAST, created_at
                """,
                (pg_ids,),
            )
            for group_id, event_date, date_precision, event_type, title, summary, confidence in cur.fetchall():
                by_id[str(group_id)]["events"].append(
                    {
                        "event_date": event_date.isoformat() if event_date else None,
                        "date_precision": date_precision,
                        "event_type": event_type,
                        "title": title,
                        "summary": summary,
                        "confidence": float(confidence),
                    }
                )
        return groups

    def upsert_article_match(self, document_id: str, item: dict[str, Any]) -> None:
        """Persist one document-to-group match."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO document_group_matches
                  (document_id, group_id, match_confidence, match_reasons, matched_terms)
                VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)
                ON CONFLICT (document_id, group_id) DO UPDATE SET
                  match_confidence = EXCLUDED.match_confidence,
                  match_reasons = EXCLUDED.match_reasons,
                  matched_terms = EXCLUDED.matched_terms
                """,
                (
                    document_id,
                    item["group_id"],
                    item["match_confidence"],
                    json.dumps(item["match_reasons"], ensure_ascii=False),
                    json.dumps(item.get("matched_terms", []), ensure_ascii=False),
                ),
            )



    def _document_source_context(self, document_id: str | None) -> dict[str, Any]:
        """Return source metadata for ledger rows when model payload omits it."""

        if not document_id:
            return {"source_url": None, "source_title": None, "source_published_at": None}
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT source_url, title, source_title, published_at
                FROM collected_documents
                WHERE id = %s
                """,
                (document_id,),
            )
            row = cur.fetchone()
        if not row:
            return {"source_url": None, "source_title": None, "source_published_at": None}
        return {
            "source_url": row[0],
            "source_title": row[1] or row[2],
            "source_published_at": row[3],
        }

    def append_fact_event(self, item: dict[str, Any], document_id: str | None) -> None:
        """Append one immutable basic-profile fact event with source evidence."""

        ctx = self._document_source_context(document_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_fact_events
                  (group_id, document_id, fact_type, fact_value, normalized_value, confidence,
                   evidence_text, source_url, source_title, source_published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    item["group_id"], document_id, item["fact_type"], item["fact_value"],
                    item.get("normalized_value"), item["confidence"], item["evidence_text"],
                    item.get("source_url") or ctx["source_url"],
                    item.get("source_title") or ctx["source_title"],
                    item.get("published_at") or ctx["source_published_at"],
                ),
            )

    def append_structure_event(self, item: dict[str, Any], document_id: str | None, *, structure_type: str) -> None:
        """Append one immutable organization-structure observation."""

        ctx = self._document_source_context(document_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_structure_events
                  (group_id, document_id, structure_type, relation_type, target_entity_type,
                   target_name, member_name, role, confidence, evidence_text,
                   source_url, source_title, source_published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    item["group_id"], document_id, structure_type, item.get("relation_type"),
                    item.get("target_entity_type"), item.get("target_name"), item.get("member_name"),
                    item.get("role"), item["confidence"], item["evidence_text"],
                    ctx["source_url"], ctx["source_title"], ctx["source_published_at"],
                ),
            )

    def append_activity_timeline_event(self, item: dict[str, Any], document_id: str | None, event_id: str | None = None) -> None:
        """Append one immutable activity timeline record."""

        ctx = self._document_source_context(document_id)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_activity_timeline
                  (group_id, event_id, document_id, event_date, date_precision, event_type, title,
                   summary, targets, techniques, malware, vulnerabilities, iocs, confidence,
                   evidence_texts, source_url, source_title, source_published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s::jsonb, %s, %s::jsonb, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (
                    item["group_id"], event_id, document_id, item.get("event_date"),
                    item["date_precision"], item["event_type"], item["title"], item["summary"],
                    json.dumps(item["targets"], ensure_ascii=False),
                    json.dumps(item["techniques"], ensure_ascii=False),
                    json.dumps(item["malware"], ensure_ascii=False),
                    json.dumps(item["vulnerabilities"], ensure_ascii=False),
                    json.dumps(item["iocs"], ensure_ascii=False), item["confidence"],
                    json.dumps(item["evidence_texts"], ensure_ascii=False),
                    ctx["source_url"], ctx["source_title"], ctx["source_published_at"],
                ),
            )

    def rebuild_apt_group_projection(self) -> int:
        """Rebuild apt_group_export from append-only ledgers as the current display projection."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                WITH fact_ranked AS (
                  SELECT g.id AS group_id, g.organization_code, g.canonical_name, f.fact_type,
                         COALESCE(NULLIF(f.normalized_value, ''), f.fact_value) AS value,
                         f.confidence, f.source_url, f.source_title, f.source_published_at, f.collected_at,
                         ROW_NUMBER() OVER (
                           PARTITION BY g.id, f.fact_type, COALESCE(NULLIF(f.normalized_value, ''), f.fact_value)
                           ORDER BY f.confidence DESC, COALESCE(f.source_published_at, f.collected_at) DESC
                         ) AS rn
                  FROM threat_groups g
                  LEFT JOIN group_fact_events f ON f.group_id = g.id
                ), facts AS (
                  SELECT group_id, organization_code, canonical_name, fact_type,
                         string_agg(DISTINCT value, '?' ORDER BY value) FILTER (WHERE rn = 1) AS values
                  FROM fact_ranked
                  WHERE fact_type IS NOT NULL
                  GROUP BY group_id, organization_code, canonical_name, fact_type
                ), fact_pivot AS (
                  SELECT group_id, organization_code, canonical_name,
                    MAX(values) FILTER (WHERE fact_type = 'attack_type') AS attack_type,
                    MAX(values) FILTER (WHERE fact_type = 'technical_skill') AS technical_skills,
                    MAX(values) FILTER (WHERE fact_type = 'suspected_source') AS suspected_source,
                    MAX(values) FILTER (WHERE fact_type = 'target_sector') AS affected_industry,
                    MAX(values) FILTER (WHERE fact_type = 'attack_pattern') AS attack_pattern,
                    MAX(values) FILTER (WHERE fact_type = 'target_country') AS target_country,
                    MAX(values) FILTER (WHERE fact_type = 'common_language') AS common_language,
                    MAX(values) FILTER (WHERE fact_type = 'tactic') AS tactics,
                    MAX(values) FILTER (WHERE fact_type = 'malware') AS malware,
                    MAX(values) FILTER (WHERE fact_type = 'cve') AS cves
                  FROM facts
                  GROUP BY group_id, organization_code, canonical_name
                ), aliases AS (
                  SELECT group_id, string_agg(alias::TEXT, '?' ORDER BY alias::TEXT) AS alias
                  FROM group_aliases
                  WHERE status IN ('confirmed', 'manual_confirmed', 'auto_confirmed')
                  GROUP BY group_id
                ), timeline AS (
                  SELECT group_id,
                         MIN(event_date)::TEXT AS earliest_active_time,
                         CASE
                           WHEN COUNT(event_date) = 0 THEN NULL
                           WHEN MIN(event_date) = MAX(event_date) THEN MIN(event_date)::TEXT
                           ELSE MIN(event_date)::TEXT || ' ? ' || MAX(event_date)::TEXT
                         END AS active_time,
                         CASE
                           WHEN COUNT(*) >= 12 THEN '??'
                           WHEN COUNT(*) >= 4 THEN '??'
                           WHEN COUNT(*) >= 1 THEN '??'
                           ELSE NULL
                         END AS attack_frequency
                  FROM group_activity_timeline
                  GROUP BY group_id
                ), ioc_values AS (
                  SELECT group_id, 'domain' AS entity_type, jsonb_array_elements_text(COALESCE(iocs->'domains', '[]'::jsonb)) AS entity_value FROM group_activity_timeline
                  UNION ALL
                  SELECT group_id, 'hash', jsonb_array_elements_text(COALESCE(iocs->'hashes', '[]'::jsonb)) FROM group_activity_timeline
                  UNION ALL
                  SELECT group_id, 'ip', jsonb_array_elements_text(COALESCE(iocs->'ips', '[]'::jsonb)) FROM group_activity_timeline
                  UNION ALL
                  SELECT group_id, 'url', jsonb_array_elements_text(COALESCE(iocs->'urls', '[]'::jsonb)) FROM group_activity_timeline
                ), iocs AS (
                  SELECT group_id,
                    string_agg(DISTINCT entity_value, '?' ORDER BY entity_value) FILTER (WHERE entity_type = 'domain') AS associated_domain,
                    string_agg(DISTINCT entity_value, '?' ORDER BY entity_value) FILTER (WHERE entity_type = 'hash') AS associative_hash,
                    string_agg(DISTINCT entity_value, '?' ORDER BY entity_value) FILTER (WHERE entity_type = 'ip') AS associative_ip,
                    string_agg(DISTINCT entity_value, '?' ORDER BY entity_value) FILTER (WHERE entity_type = 'url') AS associative_url
                  FROM ioc_values
                  GROUP BY group_id
                ), evidence AS (
                  SELECT group_id, jsonb_agg(item ORDER BY evidence_time DESC) AS source_evidence
                  FROM (
                    SELECT group_id,
                           jsonb_build_object('source_url', source_url, 'source_title', source_title, 'published_at', source_published_at, 'fact_type', fact_type, 'confidence', confidence) AS item,
                           COALESCE(source_published_at, collected_at) AS evidence_time,
                           ROW_NUMBER() OVER (PARTITION BY group_id ORDER BY confidence DESC, COALESCE(source_published_at, collected_at) DESC) AS rn
                    FROM group_fact_events
                    WHERE source_url IS NOT NULL
                  ) x
                  WHERE rn <= 8
                  GROUP BY group_id
                )
                INSERT INTO apt_group_export (
                  apt_organization, organization_code, team_name, attack_type, technical_skills,
                  suspected_source, affected_industry, alias, attack_pattern, attack_frequency,
                  target_country, earliest_active_time, active_time, common_language, team_description,
                  tactics, associated_domain, associative_hash, associative_ip, associative_url,
                  related_certificates, source_evidence, storage_time
                )
                SELECT
                  g.canonical_name, g.organization_code, g.display_name,
                  fp.attack_type, fp.technical_skills, fp.suspected_source, fp.affected_industry,
                  a.alias, fp.attack_pattern, t.attack_frequency, fp.target_country,
                  t.earliest_active_time, t.active_time, fp.common_language, g.latest_overview,
                  fp.tactics, i.associated_domain, i.associative_hash, i.associative_ip,
                  i.associative_url, NULL, COALESCE(e.source_evidence::TEXT, '[]'), NOW()
                FROM threat_groups g
                LEFT JOIN fact_pivot fp ON fp.group_id = g.id
                LEFT JOIN aliases a ON a.group_id = g.id
                LEFT JOIN timeline t ON t.group_id = g.id
                LEFT JOIN iocs i ON i.group_id = g.id
                LEFT JOIN evidence e ON e.group_id = g.id
                ON CONFLICT (apt_organization) DO UPDATE SET
                  organization_code = EXCLUDED.organization_code,
                  team_name = EXCLUDED.team_name,
                  attack_type = EXCLUDED.attack_type,
                  technical_skills = EXCLUDED.technical_skills,
                  suspected_source = EXCLUDED.suspected_source,
                  affected_industry = EXCLUDED.affected_industry,
                  alias = EXCLUDED.alias,
                  attack_pattern = EXCLUDED.attack_pattern,
                  attack_frequency = EXCLUDED.attack_frequency,
                  target_country = EXCLUDED.target_country,
                  earliest_active_time = EXCLUDED.earliest_active_time,
                  active_time = EXCLUDED.active_time,
                  common_language = EXCLUDED.common_language,
                  team_description = EXCLUDED.team_description,
                  tactics = EXCLUDED.tactics,
                  associated_domain = EXCLUDED.associated_domain,
                  associative_hash = EXCLUDED.associative_hash,
                  associative_ip = EXCLUDED.associative_ip,
                  associative_url = EXCLUDED.associative_url,
                  related_certificates = EXCLUDED.related_certificates,
                  source_evidence = EXCLUDED.source_evidence,
                  storage_time = NOW()
                """
            )
            return cur.rowcount

    def upsert_fact(self, item: dict[str, Any], document_id: str | None) -> str:
        """Upsert one group fact and append evidence, returning the fact id."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_facts
                  (group_id, fact_type, fact_value, normalized_value, confidence, source_count,
                   is_current, first_seen_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, 1, TRUE, NOW(), NOW())
                ON CONFLICT (group_id, fact_type, normalized_value) DO UPDATE SET
                  fact_value = EXCLUDED.fact_value,
                  confidence = GREATEST(group_facts.confidence, EXCLUDED.confidence),
                  source_count = group_facts.source_count + 1,
                  last_seen_at = NOW(),
                  updated_at = NOW()
                RETURNING id
                """,
                (
                    item["group_id"],
                    item["fact_type"],
                    item["fact_value"],
                    item["normalized_value"],
                    item["confidence"],
                ),
            )
            fact_id = str(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO fact_evidence
                  (fact_id, document_id, evidence_text, source_url, source_title, published_at, confidence)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    fact_id,
                    document_id,
                    item["evidence_text"],
                    item["source_url"],
                    item["source_title"],
                    item["published_at"],
                    item["confidence"],
                ),
            )
        return fact_id

    def insert_relation(self, item: dict[str, Any], document_id: str | None) -> str:
        """Insert one structure relation and evidence row."""

        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_relations
                  (source_group_id, relation_type, target_name, confidence, is_current,
                   first_seen_at, last_seen_at)
                VALUES (%s, %s, %s, %s, TRUE, NOW(), NOW())
                RETURNING id
                """,
                (item["group_id"], item["relation_type"], item["target_name"], item["confidence"]),
            )
            relation_id = str(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO structure_evidence
                  (relation_id, document_id, evidence_text, confidence)
                VALUES (%s, %s, %s, %s)
                """,
                (relation_id, document_id, item["evidence_text"], item["confidence"]),
            )
        return relation_id

    def upsert_member(self, item: dict[str, Any], document_id: str | None) -> str:
        """Upsert one group member and append evidence."""

        normalized = item["member_name"].casefold()
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO group_members
                  (group_id, member_name, normalized_member_name, role, confidence, is_current,
                   first_seen_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, TRUE, NOW(), NOW())
                ON CONFLICT (group_id, normalized_member_name) DO UPDATE SET
                  role = COALESCE(EXCLUDED.role, group_members.role),
                  confidence = GREATEST(group_members.confidence, EXCLUDED.confidence),
                  last_seen_at = NOW(),
                  updated_at = NOW()
                RETURNING id
                """,
                (
                    item["group_id"],
                    item["member_name"],
                    normalized,
                    item["role"],
                    item["confidence"],
                ),
            )
            member_id = str(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO structure_evidence
                  (member_id, document_id, evidence_text, confidence)
                VALUES (%s, %s, %s, %s)
                """,
                (member_id, document_id, item["evidence_text"], item["confidence"]),
            )
        return member_id

    def insert_event(self, item: dict[str, Any], document_id: str | None) -> str:
        """Insert or reuse one activity event and attach entities/evidence."""

        fingerprint = _event_fingerprint(item)
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO activity_events
                  (event_fingerprint, event_date, date_precision, event_type, title, summary,
                   confidence, primary_document_id, published_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (event_fingerprint) DO UPDATE SET
                  confidence = GREATEST(activity_events.confidence, EXCLUDED.confidence),
                  updated_at = NOW()
                RETURNING id
                """,
                (
                    fingerprint,
                    item["event_date"],
                    item["date_precision"],
                    item["event_type"],
                    item["title"],
                    item["summary"],
                    item["confidence"],
                    document_id,
                ),
            )
            event_id = str(cur.fetchone()[0])
            cur.execute(
                """
                INSERT INTO event_groups (event_id, group_id, role, confidence)
                VALUES (%s, %s, 'actor', %s)
                ON CONFLICT (event_id, group_id) DO UPDATE SET
                  confidence = GREATEST(event_groups.confidence, EXCLUDED.confidence)
                """,
                (event_id, item["group_id"], item["confidence"]),
            )
            for entity_type, values in _event_entities(item).items():
                for value in values:
                    cur.execute(
                        """
                        INSERT INTO event_entities
                          (event_id, entity_type, entity_value, normalized_value, confidence)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (event_id, entity_type, value, value.casefold(), item["confidence"]),
                    )
            for evidence in item["evidence_texts"]:
                cur.execute(
                    """
                    INSERT INTO event_evidence
                      (event_id, document_id, evidence_text, confidence)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (event_id, document_id, evidence, item["confidence"]),
                )
        return event_id

    def apply_profile_synthesis(self, payload: dict[str, Any]) -> None:
        """Apply latest overview only; facts remain append-only ledger rows."""

        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE threat_groups SET latest_overview = %s, updated_at = NOW() WHERE id = %s",
                (payload["latest_overview"], payload["group_id"]),
            )

    def apply_structure_synthesis(self, payload: dict[str, Any]) -> None:
        """Apply latest structure overview to the group."""

        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE threat_groups SET latest_structure_overview = %s, updated_at = NOW() WHERE id = %s",
                (payload["latest_structure_overview"], payload["group_id"]),
            )

    def upsert_apt_group_export(self, payload: dict[str, Any]) -> None:
        """Upsert one apt_group_export row."""

        row = payload["apt_group_export"]
        columns = list(row.keys())
        values = [row[column] for column in columns]
        assignments = ", ".join(f"{column}=EXCLUDED.{column}" for column in columns if column != "apt_organization")
        with self.conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO apt_group_export ({", ".join(columns)})
                VALUES ({", ".join(["%s"] * len(columns))})
                ON CONFLICT (apt_organization) DO UPDATE SET
                  {assignments},
                  storage_time = NOW()
                """,
                values,
            )


def _event_fingerprint(item: dict[str, Any]) -> str:
    material = "|".join(
        [
            item["group_id"],
            item.get("event_date") or "",
            item["event_type"],
            item["title"].casefold(),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _event_entities(item: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "country": item["targets"]["countries"],
        "sector": item["targets"]["sectors"],
        "victim_org": item["targets"]["organizations"],
        "technique": item["techniques"],
        "malware": item["malware"],
        "cve": item["vulnerabilities"],
        "domain": item["iocs"]["domains"],
        "ip": item["iocs"]["ips"],
        "url": item["iocs"]["urls"],
        "hash": item["iocs"]["hashes"],
    }
