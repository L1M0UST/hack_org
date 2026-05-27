"""SQLite storage for long-lived group identity and collection state."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import Article, GroupProfile, SourceConfig
from .normalization import normalize_name, stable_group_id
from .utils import sha256_text, utcnow


CONFIRMED_ALIAS_STATUSES = ("confirmed", "auto_confirmed", "manual_confirmed")


class StateStore:
    """SQLite-backed state store for groups, aliases, observations, and evidence."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.migrate()

    def close(self) -> None:
        """Close the SQLite connection."""

        self.conn.close()

    def migrate(self) -> None:
        """Create database tables when they do not exist."""

        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS groups (
              id TEXT PRIMARY KEY,
              canonical_name TEXT NOT NULL,
              normalized_name TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              description TEXT DEFAULT '',
              status TEXT NOT NULL DEFAULT 'active',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_aliases (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
              alias TEXT NOT NULL,
              normalized_alias TEXT NOT NULL,
              status TEXT NOT NULL,
              source TEXT NOT NULL,
              source_url TEXT,
              confidence REAL NOT NULL DEFAULT 1.0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(group_id, normalized_alias)
            );

            CREATE INDEX IF NOT EXISTS idx_group_aliases_lookup
              ON group_aliases(normalized_alias, status);

            CREATE TABLE IF NOT EXISTS group_observations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
              raw_name TEXT NOT NULL,
              raw_description TEXT DEFAULT '',
              input_file TEXT NOT NULL,
              row_hash TEXT NOT NULL UNIQUE,
              imported_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS group_relations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
              target_group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
              relation_type TEXT NOT NULL,
              source TEXT NOT NULL,
              confidence REAL NOT NULL DEFAULT 1.0,
              created_at TEXT NOT NULL,
              UNIQUE(source_group_id, target_group_id, relation_type, source)
            );

            CREATE TABLE IF NOT EXISTS sources (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              type TEXT NOT NULL,
              url TEXT NOT NULL,
              enabled INTEGER NOT NULL,
              weight REAL NOT NULL,
              category TEXT NOT NULL,
              tier TEXT NOT NULL DEFAULT 'A',
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS collection_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_id TEXT,
              status TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              collected_count INTEGER NOT NULL DEFAULT 0,
              inserted_count INTEGER NOT NULL DEFAULT 0,
              duplicate_count INTEGER NOT NULL DEFAULT 0,
              error TEXT
            );

            CREATE TABLE IF NOT EXISTS articles (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              source_id TEXT NOT NULL,
              source_title TEXT NOT NULL,
              source_url TEXT NOT NULL,
              source_domain TEXT NOT NULL,
              published_at TEXT,
              collected_at TEXT NOT NULL,
              title TEXT NOT NULL,
              author TEXT,
              html_path TEXT,
              text_path TEXT,
              url_hash TEXT NOT NULL UNIQUE,
              title_hash TEXT NOT NULL,
              text_hash TEXT NOT NULL,
              metadata_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_id);
            CREATE INDEX IF NOT EXISTS idx_articles_text_hash ON articles(text_hash);

            CREATE TABLE IF NOT EXISTS system_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              log_type TEXT NOT NULL,
              level TEXT NOT NULL,
              source_id TEXT,
              article_id INTEGER,
              group_id TEXT,
              message TEXT NOT NULL,
              details_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );



            CREATE TABLE IF NOT EXISTS discovered_group_candidates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              normalized_name TEXT NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'candidate',
              promoted_group_id TEXT,
              confidence REAL NOT NULL DEFAULT 0.0,
              evidence_count INTEGER NOT NULL DEFAULT 0,
              first_seen_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovered_group_evidence (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              candidate_id INTEGER NOT NULL REFERENCES discovered_group_candidates(id) ON DELETE CASCADE,
              article_id INTEGER REFERENCES articles(id) ON DELETE SET NULL,
              source_id TEXT,
              source_url TEXT,
              source_title TEXT,
              evidence_text TEXT NOT NULL,
              confidence REAL NOT NULL DEFAULT 0.0,
              discovered_at TEXT NOT NULL,
              UNIQUE(candidate_id, article_id, evidence_text)
            );
            
            CREATE TABLE IF NOT EXISTS group_facts (
              id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
              fact_type TEXT NOT NULL,
              fact_value TEXT NOT NULL,
              normalized_value TEXT NOT NULL,
              confidence REAL NOT NULL,
              source_count INTEGER NOT NULL DEFAULT 1,
              is_current INTEGER NOT NULL DEFAULT 1,
              current_best INTEGER NOT NULL DEFAULT 0,
              first_seen_at TEXT NOT NULL,
              last_seen_at TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(group_id, fact_type, normalized_value)
            );
            """
        )
        self._ensure_column("sources", "tier", "TEXT NOT NULL DEFAULT 'A'")
        self._ensure_column("group_facts", "current_best", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column("discovered_group_candidates", "promoted_group_id", "TEXT")
        self.conn.commit()

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        """Add a column to an existing SQLite table when migrations evolve."""

        columns = {row["name"] for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def upsert_source(self, source: SourceConfig) -> None:
        """Insert or update one configured source in SQLite."""

        self.conn.execute(
            """
            INSERT INTO sources (id, name, type, url, enabled, weight, category, tier, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              type = excluded.type,
              url = excluded.url,
              enabled = excluded.enabled,
              weight = excluded.weight,
              category = excluded.category,
              tier = excluded.tier,
              updated_at = excluded.updated_at
            """,
            (
                source.id,
                source.name,
                source.type,
                str(source.url),
                1 if source.enabled else 0,
                source.weight,
                source.category,
                source.tier,
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()

    def start_collection_run(self, source_id: str | None) -> int:
        """Create a collection run log entry and return its id."""

        cur = self.conn.execute(
            "INSERT INTO collection_runs (source_id, status, started_at) VALUES (?, 'running', ?)",
            (source_id, utcnow().isoformat()),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def finish_collection_run(
        self,
        run_id: int,
        status: str,
        collected_count: int = 0,
        inserted_count: int = 0,
        duplicate_count: int = 0,
        error: str | None = None,
    ) -> None:
        """Mark a collection run as finished with counts and optional error."""

        self.conn.execute(
            """
            UPDATE collection_runs
            SET status = ?, finished_at = ?, collected_count = ?, inserted_count = ?,
                duplicate_count = ?, error = ?
            WHERE id = ?
            """,
            (status, utcnow().isoformat(), collected_count, inserted_count, duplicate_count, error, run_id),
        )
        self.conn.commit()

    def save_article(self, article: Article) -> tuple[int | None, bool]:
        """Persist an article; return (article_id, inserted)."""

        url_hash = sha256_text(article.source_url)
        title_hash = sha256_text(article.title.casefold())
        text_hash = sha256_text((article.text or "")[:10000].casefold())
        existing = self.conn.execute("SELECT id FROM articles WHERE url_hash = ?", (url_hash,)).fetchone()
        if existing:
            return int(existing["id"]), False
        cur = self.conn.execute(
            """
            INSERT INTO articles
              (source_id, source_title, source_url, source_domain, published_at, collected_at,
               title, author, html_path, text_path, url_hash, title_hash, text_hash, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                article.source_id,
                article.source_title,
                article.source_url,
                article.source_domain,
                article.published_at.isoformat() if article.published_at else None,
                article.collected_at.isoformat(),
                article.title,
                article.author,
                article.html_path,
                article.text_path,
                url_hash,
                title_hash,
                text_hash,
                json.dumps(article.metadata, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid), True

    def has_article_url(self, url: str) -> bool:
        """Return whether a URL has already been collected locally."""

        url_hash = sha256_text(url)
        row = self.conn.execute("SELECT 1 FROM articles WHERE url_hash = ? LIMIT 1", (url_hash,)).fetchone()
        return row is not None

    def article_records(self, limit: int | None = None, order: str = "newest") -> list[dict[str, Any]]:
        """Return article records as JSON-serializable dictionaries."""

        direction = "ASC" if order == "oldest" else "DESC"
        query = f"SELECT * FROM articles ORDER BY collected_at {direction}"
        params: tuple[Any, ...] = ()
        if limit:
            query += " LIMIT ?"
            params = (limit,)
        rows = self.conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def article_record_by_id(self, article_id: int) -> dict[str, Any] | None:
        """Return one raw article row by local SQLite id."""

        row = self.conn.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        return dict(row) if row else None

    def article_models(self, limit: int | None = None) -> list[Article]:
        """Return persisted articles as Article models."""

        articles: list[Article] = []
        for row in self.article_records(limit):
            from datetime import datetime

            articles.append(
                Article(
                    source_id=row["source_id"],
                    source_title=row["source_title"],
                    source_url=row["source_url"],
                    source_domain=row["source_domain"],
                    published_at=datetime.fromisoformat(row["published_at"]) if row["published_at"] else None,
                    collected_at=datetime.fromisoformat(row["collected_at"]),
                    author=row["author"],
                    html_path=row["html_path"],
                    text_path=row["text_path"],
                    title=row["title"],
                    text=Path(row["text_path"]).read_text(encoding="utf-8", errors="ignore") if row["text_path"] and Path(row["text_path"]).exists() else "",
                    metadata=json.loads(row["metadata_json"] or "{}"),
                )
            )
        return articles

    def article_model_by_id(self, article_id: int) -> Article | None:
        """Return one persisted article by local SQLite id."""

        row = self.conn.execute("SELECT * FROM articles WHERE id = ?", (article_id,)).fetchone()
        if not row:
            return None
        from datetime import datetime

        return Article(
            source_id=row["source_id"],
            source_title=row["source_title"],
            source_url=row["source_url"],
            source_domain=row["source_domain"],
            published_at=datetime.fromisoformat(row["published_at"]) if row["published_at"] else None,
            collected_at=datetime.fromisoformat(row["collected_at"]),
            author=row["author"],
            html_path=row["html_path"],
            text_path=row["text_path"],
            title=row["title"],
            text=Path(row["text_path"]).read_text(encoding="utf-8", errors="ignore") if row["text_path"] and Path(row["text_path"]).exists() else "",
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def upsert_group(self, canonical_name: str, description: str = "") -> str:
        """Create or update a group and return its stable id."""

        normalized = normalize_name(canonical_name)
        existing = self.find_group_by_name_or_alias(canonical_name)
        now = utcnow().isoformat()
        if existing:
            group_id = existing["id"]
            if description and not existing["description"]:
                self.conn.execute(
                    "UPDATE groups SET description = ?, updated_at = ? WHERE id = ?",
                    (description, now, group_id),
                )
                self.conn.commit()
            return group_id
        group_id = stable_group_id(canonical_name)
        self.conn.execute(
            """
            INSERT OR IGNORE INTO groups
              (id, canonical_name, normalized_name, display_name, description, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (group_id, canonical_name, normalized, canonical_name, description, now, now),
        )
        self.conn.commit()
        return group_id

    def find_group_by_name_or_alias(self, name: str) -> sqlite3.Row | None:
        """Find a group by canonical name or confirmed alias."""

        normalized = normalize_name(name)
        row = self.conn.execute("SELECT * FROM groups WHERE normalized_name = ?", (normalized,)).fetchone()
        if row:
            return row
        placeholders = ",".join("?" for _ in CONFIRMED_ALIAS_STATUSES)
        return self.conn.execute(
            f"""
            SELECT g.* FROM group_aliases a
            JOIN groups g ON g.id = a.group_id
            WHERE a.normalized_alias = ? AND a.status IN ({placeholders})
            ORDER BY a.confidence DESC
            LIMIT 1
            """,
            (normalized, *CONFIRMED_ALIAS_STATUSES),
        ).fetchone()

    def add_alias(
        self,
        group_id: str,
        alias: str,
        status: str,
        source: str,
        confidence: float = 1.0,
        source_url: str | None = None,
    ) -> None:
        """Add or update an alias for a group."""

        normalized = normalize_name(alias)
        now = utcnow().isoformat()
        self.conn.execute(
            """
            INSERT INTO group_aliases
              (group_id, alias, normalized_alias, status, source, source_url, confidence, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(group_id, normalized_alias) DO UPDATE SET
              status = excluded.status,
              source = excluded.source,
              source_url = excluded.source_url,
              confidence = MAX(group_aliases.confidence, excluded.confidence),
              updated_at = excluded.updated_at
            """,
            (group_id, alias, normalized, status, source, source_url, confidence, now, now),
        )
        self.conn.commit()

    def add_observation(self, group_id: str, raw_name: str, raw_description: str, input_file: str) -> bool:
        """Record a CSV row observation; return False when it was already imported."""

        row_hash = sha256_text(f"{input_file}\0{raw_name}\0{raw_description}")
        now = utcnow().isoformat()
        cur = self.conn.execute(
            """
            INSERT OR IGNORE INTO group_observations
              (group_id, raw_name, raw_description, input_file, row_hash, imported_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (group_id, raw_name, raw_description, input_file, row_hash, now),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def group_profiles(self) -> list[GroupProfile]:
        """Return group profiles with confirmed aliases for matching and archiving."""

        groups = self.conn.execute("SELECT * FROM groups ORDER BY canonical_name").fetchall()
        profiles: list[GroupProfile] = []
        for group in groups:
            aliases = [
                row["alias"]
                for row in self.conn.execute(
                    """
                    SELECT alias FROM group_aliases
                    WHERE group_id = ? AND status IN ('confirmed', 'auto_confirmed', 'manual_confirmed')
                    ORDER BY alias
                    """,
                    (group["id"],),
                ).fetchall()
            ]
            terms = sorted({group["canonical_name"], *aliases})
            profiles.append(
                GroupProfile(
                    group_id=group["id"],
                    canonical_name=group["canonical_name"],
                    description=group["description"] or "",
                    aliases=aliases,
                    search_terms=terms,
                )
            )
        return profiles

    def stats(self) -> dict[str, int]:
        """Return simple database counts for CLI output."""

        names = ("groups", "group_aliases", "group_observations", "sources", "articles", "collection_runs", "system_logs", "group_facts", "discovered_group_candidates", "discovered_group_evidence")
        return {name: self.conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in names}


    def upsert_discovered_group_candidate(
        self,
        display_name: str,
        evidence_text: str,
        *,
        article_id: int | None,
        source_id: str | None,
        source_url: str | None,
        source_title: str | None,
        confidence: float,
    ) -> int:
        """Create or update a candidate for an organization not yet in the catalog."""

        normalized = normalize_name(display_name)
        now = utcnow().isoformat()
        row = self.conn.execute(
            "SELECT id, evidence_count, confidence FROM discovered_group_candidates WHERE normalized_name = ?",
            (normalized,),
        ).fetchone()
        if row:
            candidate_id = int(row["id"])
            self.conn.execute(
                """
                UPDATE discovered_group_candidates
                SET display_name = CASE WHEN LENGTH(display_name) >= LENGTH(?) THEN display_name ELSE ? END,
                    confidence = MAX(confidence, ?),
                    last_seen_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (display_name, display_name, confidence, now, now, candidate_id),
            )
        else:
            cur = self.conn.execute(
                """
                INSERT INTO discovered_group_candidates
                  (normalized_name, display_name, confidence, evidence_count, first_seen_at, last_seen_at, created_at, updated_at)
                VALUES (?, ?, ?, 0, ?, ?, ?, ?)
                """,
                (normalized, display_name, confidence, now, now, now, now),
            )
            candidate_id = int(cur.lastrowid)
        self.conn.execute(
            """
            INSERT OR IGNORE INTO discovered_group_evidence
              (candidate_id, article_id, source_id, source_url, source_title, evidence_text, confidence, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (candidate_id, article_id, source_id, source_url, source_title, evidence_text, confidence, now),
        )
        self.conn.execute(
            """
            UPDATE discovered_group_candidates
            SET evidence_count = (SELECT COUNT(*) FROM discovered_group_evidence WHERE candidate_id = ?),
                confidence = MAX(confidence, ?),
                updated_at = ?
            WHERE id = ?
            """,
            (candidate_id, confidence, now, candidate_id),
        )
        self.conn.commit()
        return candidate_id

    def discovered_group_candidates(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        """Return unknown organization candidates with compact evidence samples."""

        where = "WHERE status = ?" if status else ""
        params: tuple[Any, ...] = (status,) if status else ()
        rows = self.conn.execute(
            f"""
            SELECT * FROM discovered_group_candidates
            {where}
            ORDER BY evidence_count DESC, confidence DESC, last_seen_at DESC
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()
        result = []
        for row in rows:
            evidence = self.conn.execute(
                """
                SELECT article_id, source_id, source_url, source_title, evidence_text, confidence, discovered_at
                FROM discovered_group_evidence
                WHERE candidate_id = ?
                ORDER BY confidence DESC, discovered_at DESC
                LIMIT 3
                """,
                (row["id"],),
            ).fetchall()
            item = dict(row)
            item["evidence"] = [dict(ev) for ev in evidence]
            result.append(item)
        return result


    def discovered_group_candidate_by_id(self, candidate_id: int) -> dict[str, Any] | None:
        """Return one discovered candidate with all evidence rows."""

        row = self.conn.execute(
            "SELECT * FROM discovered_group_candidates WHERE id = ?",
            (candidate_id,),
        ).fetchone()
        if not row:
            return None
        evidence = self.conn.execute(
            """
            SELECT article_id, source_id, source_url, source_title, evidence_text, confidence, discovered_at
            FROM discovered_group_evidence
            WHERE candidate_id = ?
            ORDER BY confidence DESC, discovered_at DESC
            """,
            (candidate_id,),
        ).fetchall()
        item = dict(row)
        item["evidence"] = [dict(ev) for ev in evidence]
        return item

    def promote_discovered_group_candidate(
        self,
        candidate_id: int,
        *,
        canonical_name: str | None = None,
        min_evidence: int = 2,
        min_confidence: float = 0.65,
        force: bool = False,
    ) -> dict[str, Any]:
        """Promote a discovered candidate into the official group catalog."""

        candidate = self.discovered_group_candidate_by_id(candidate_id)
        if not candidate:
            raise ValueError(f"candidate not found: {candidate_id}")
        if candidate["status"] == "promoted":
            return {"candidate_id": candidate_id, "status": "already_promoted", "group_id": candidate.get("promoted_group_id")}
        if not force:
            if int(candidate["evidence_count"]) < min_evidence:
                raise ValueError(f"candidate {candidate_id} has insufficient evidence_count: {candidate['evidence_count']} < {min_evidence}")
            if float(candidate["confidence"]) < min_confidence:
                raise ValueError(f"candidate {candidate_id} has insufficient confidence: {candidate['confidence']} < {min_confidence}")
        name = canonical_name or candidate["display_name"]
        existing = self.find_group_by_name_or_alias(name)
        group_id = existing["id"] if existing else self.upsert_group(name, description="auto-promoted from discovery candidate")
        self.add_alias(group_id, candidate["display_name"], "auto_confirmed", "discovery_candidate", float(candidate["confidence"]), candidate["evidence"][0]["source_url"] if candidate["evidence"] else None)
        self.conn.execute(
            """
            UPDATE discovered_group_candidates
            SET status = 'promoted', promoted_group_id = ?, updated_at = ?, display_name = ?
            WHERE id = ?
            """,
            (group_id, utcnow().isoformat(), name, candidate_id),
        )
        self.add_system_log(
            "discovery",
            "INFO",
            "discovered candidate promoted to group",
            group_id=group_id,
            details={"candidate_id": candidate_id, "canonical_name": name, "evidence_count": candidate["evidence_count"], "confidence": candidate["confidence"]},
        )
        return {"candidate_id": candidate_id, "status": "promoted", "group_id": group_id, "canonical_name": name}

    def promote_discovered_group_candidates(
        self,
        *,
        min_evidence: int = 2,
        min_confidence: float = 0.65,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Promote candidate groups that pass evidence and confidence thresholds."""

        rows = self.conn.execute(
            """
            SELECT id FROM discovered_group_candidates
            WHERE status = 'candidate'
              AND evidence_count >= ?
              AND confidence >= ?
            ORDER BY evidence_count DESC, confidence DESC, last_seen_at DESC
            LIMIT ?
            """,
            (min_evidence, min_confidence, limit),
        ).fetchall()
        results = []
        for row in rows:
            try:
                results.append(
                    self.promote_discovered_group_candidate(
                        int(row["id"]),
                        min_evidence=min_evidence,
                        min_confidence=min_confidence,
                    )
                )
            except Exception as exc:
                results.append({"candidate_id": int(row["id"]), "status": "failed", "error": str(exc)})
        return results

    def add_system_log(
        self,
        log_type: str,
        level: str,
        message: str,
        source_id: str | None = None,
        article_id: int | None = None,
        group_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Persist an operational log entry for queryable system history."""

        self.conn.execute(
            """
            INSERT INTO system_logs
              (log_type, level, source_id, article_id, group_id, message, details_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log_type,
                level,
                source_id,
                article_id,
                group_id,
                message,
                json.dumps(details or {}, ensure_ascii=False),
                utcnow().isoformat(),
            ),
        )
        self.conn.commit()
