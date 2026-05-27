"""Initialize manually maintained aliases from conservative public seeds."""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from hack_org.db_config import load_database_config
from hack_org.normalization import normalize_name
from hack_org.pg_client import connect_database
from hack_org.storage import StateStore


MITRE_STIX_PATH = Path(".state/raw/mitre_attack_enterprise_stix/968bfd7403ab9f1c/clean.txt")
MISP_GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
SOURCE_TYPE = "manual_initial_seed"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--mitre-stix", default=str(MITRE_STIX_PATH))
    parser.add_argument("--misp-galaxy", default=".state/seed_sources/misp-threat-actor.json")
    args = parser.parse_args()

    store = StateStore(Path(".state/hack_org.sqlite"))
    groups = load_local_groups(store.conn)
    mitre_sets = load_mitre_intrusion_sets(Path(args.mitre_stix))
    misp_sets = load_misp_threat_actors(Path(args.misp_galaxy))

    planned: dict[str, set[str]] = defaultdict(set)
    reasons: dict[tuple[str, str], str] = {}
    for group in groups:
        for alias in explicit_aliases(group["canonical_name"], group["description"]):
            planned[group["id"]].add(alias)
            reasons[(group["id"], alias)] = "csv_explicit_alias"

    group_terms = {group["id"]: comparable_terms(group) for group in groups}
    for item in mitre_sets:
        mitre_terms = {term for term in [item["name"], *item["aliases"]] if term}
        normalized_mitre_terms = {compact_norm(term) for term in mitre_terms}
        for group in groups:
            if group_terms[group["id"]] & normalized_mitre_terms:
                for alias in mitre_terms:
                    planned[group["id"]].add(alias)
                    reasons[(group["id"], alias)] = f"mitre_attack:{item['name']}"
    for item in misp_sets:
        misp_terms = {term for term in [item["name"], *item["aliases"]] if term}
        normalized_misp_terms = {compact_norm(term) for term in misp_terms}
        for group in groups:
            if group_terms[group["id"]] & normalized_misp_terms:
                for alias in misp_terms:
                    planned[group["id"]].add(alias)
                    reasons[(group["id"], alias)] = f"misp_galaxy:{item['name']}"

    rows = []
    alias_to_groups: dict[str, set[str]] = defaultdict(set)
    for group_id, aliases in planned.items():
        for alias in aliases:
            alias_to_groups[compact_norm(alias)].add(group_id)
    for group in groups:
        existing = set(group["aliases"])
        for alias in sorted(planned[group["id"]], key=str.casefold):
            if len(alias_to_groups[compact_norm(alias)]) > 1:
                continue
            if not should_keep_alias(group["canonical_name"], alias, existing):
                continue
            rows.append(
                {
                    "group_id": group["id"],
                    "organization_code": group["id"],
                    "canonical_name": group["canonical_name"],
                    "alias": alias,
                    "reason": reasons.get((group["id"], alias), SOURCE_TYPE),
                }
            )

    if not args.dry_run:
        write_sqlite_aliases(store.conn, rows)
        write_pg_aliases(rows)
    print(json.dumps({"dry_run": args.dry_run, "planned_aliases": len(rows), "groups_touched": len({r["group_id"] for r in rows}), "sample": rows[:30]}, ensure_ascii=False, indent=2))
    store.close()


def load_local_groups(conn: sqlite3.Connection) -> list[dict[str, object]]:
    rows = conn.execute(
        """
        SELECT g.id, g.canonical_name,
               COALESCE(group_concat(DISTINCT a.alias), '') AS aliases,
               COALESCE(group_concat(DISTINCT o.raw_description), '') AS descriptions
        FROM groups g
        LEFT JOIN group_aliases a ON a.group_id = g.id
        LEFT JOIN group_observations o ON o.group_id = g.id
        GROUP BY g.id, g.canonical_name
        ORDER BY g.canonical_name
        """
    ).fetchall()
    groups = []
    for row in rows:
        groups.append(
            {
                "id": row["id"],
                "canonical_name": row["canonical_name"],
                "aliases": [value for value in str(row["aliases"]).split(",") if value],
                "description": str(row["descriptions"] or ""),
            }
        )
    return groups


def load_mitre_intrusion_sets(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = []
    for obj in data.get("objects", []):
        if obj.get("type") != "intrusion-set" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        aliases = [str(alias).strip() for alias in obj.get("aliases", []) if str(alias).strip()]
        name = str(obj.get("name", "")).strip()
        if name:
            items.append({"name": name, "aliases": aliases})
    return items


def load_misp_threat_actors(path: Path) -> list[dict[str, object]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with urllib.request.urlopen(MISP_GALAXY_URL, timeout=60) as response:
            path.write_bytes(response.read())
    data = json.loads(path.read_text(encoding="utf-8"))
    items = []
    for value in data.get("values", []):
        meta = value.get("meta") or {}
        aliases = [str(alias).strip() for alias in meta.get("synonyms", []) if str(alias).strip()]
        name = str(value.get("value", "")).strip()
        if name:
            items.append({"name": name, "aliases": aliases})
    return items


def explicit_aliases(name: str, description: str) -> set[str]:
    aliases: set[str] = set()
    for text in (name, description):
        text = text.replace("（", "(").replace("）", ")")
        for match in re.findall(r"\(([^)]+)\)", text):
            for part in re.split(r"[/,;，；、]", match):
                part = part.strip()
                if part:
                    aliases.add(part)
        for match in re.findall(r"\b(?:APT|UNC|TA|FIN|DEV|G|UAC|TEMP|Storm|Volt|Sandworm|Lazarus)[-\s]?\d{1,5}\b", text, flags=re.I):
            aliases.add(match.strip())
    return aliases


def comparable_terms(group: dict[str, object]) -> set[str]:
    terms = {str(group["canonical_name"]), *[str(alias) for alias in group["aliases"]]}
    terms.update(explicit_aliases(str(group["canonical_name"]), str(group["description"])))
    return {compact_norm(term) for term in terms if term}


def should_keep_alias(canonical_name: str, alias: str, existing: set[str]) -> bool:
    alias = alias.strip()
    if not alias or alias in existing:
        return False
    if compact_norm(alias) == compact_norm(canonical_name):
        return False
    if len(compact_norm(alias)) < 3:
        return False
    return True


def compact_norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def write_sqlite_aliases(conn: sqlite3.Connection, rows: list[dict[str, str]]) -> None:
    now_expr = "datetime('now')"
    for row in rows:
        conn.execute(
            f"""
            INSERT INTO group_aliases
              (group_id, alias, normalized_alias, status, source, confidence, created_at, updated_at)
            VALUES (?, ?, ?, 'manual_confirmed', ?, 1.0, {now_expr}, {now_expr})
            ON CONFLICT(group_id, normalized_alias) DO UPDATE SET
              alias = excluded.alias,
              status = 'manual_confirmed',
              source = excluded.source,
              confidence = 1.0,
              updated_at = {now_expr}
            """,
            (row["group_id"], row["alias"], normalize_name(row["alias"]), SOURCE_TYPE),
        )
    conn.commit()


def write_pg_aliases(rows: list[dict[str, str]]) -> None:
    config = load_database_config(Path("config/database.yaml"), Path(".env"))
    conn = connect_database(config)
    with conn.cursor() as cur:
        for row in rows:
            cur.execute(
                """
                INSERT INTO group_aliases
                  (group_id, alias, normalized_alias, alias_type, status, source_type, source_ref, confidence)
                SELECT id, %s, %s, 'same_as', 'manual_confirmed', %s, %s, 1.0
                FROM threat_groups
                WHERE organization_code = %s
                ON CONFLICT (group_id, normalized_alias) DO UPDATE SET
                  alias = EXCLUDED.alias,
                  status = 'manual_confirmed',
                  source_type = EXCLUDED.source_type,
                  source_ref = EXCLUDED.source_ref,
                  confidence = 1.0,
                  last_seen_at = NOW(),
                  updated_at = NOW()
                """,
                (row["alias"], normalize_name(row["alias"]), SOURCE_TYPE, row["reason"], row["organization_code"]),
            )
    conn.close()


if __name__ == "__main__":
    main()
