"""Manual alias seed import utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .storage import StateStore
from .utils import read_text_guess, repair_mojibake


def import_alias_seed(path: Path, store: StateStore) -> dict[str, int]:
    """Import human-maintained confirmed aliases from config/alias_seed.yaml."""

    data = _parse_alias_seed(path)
    stats = {"groups": 0, "aliases": 0, "relations": 0}
    for item in data.get("groups", []):
        canonical = item.get("canonical_name")
        if not canonical:
            continue
        group_id = store.upsert_group(str(canonical))
        stats["groups"] += 1
        for alias in item.get("aliases", []):
            alias = str(alias).strip()
            if not alias:
                continue
            store.add_alias(group_id, alias, "manual_confirmed", "alias_seed", 1.0)
            stats["aliases"] += 1
    for relation in data.get("relations", []):
        source = relation.get("source")
        target = relation.get("target")
        relation_type = relation.get("relation_type", "related_to")
        if source and target:
            source_id = store.upsert_group(str(source))
            target_id = store.upsert_group(str(target))
            store.conn.execute(
                """
                INSERT OR IGNORE INTO group_relations
                  (source_group_id, target_group_id, relation_type, source, confidence, created_at)
                VALUES (?, ?, ?, 'alias_seed', 1.0, datetime('now'))
                """,
                (source_id, target_id, relation_type),
            )
            store.conn.commit()
            stats["relations"] += 1
    return stats


def _parse_alias_seed(path: Path) -> dict[str, Any]:
    """Parse the small YAML subset used by config/alias_seed.yaml."""

    text = repair_mojibake(read_text_guess(path))
    result: dict[str, Any] = {"groups": [], "relations": []}
    section: str | None = None
    current: dict[str, Any] | None = None
    list_key: str | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in {"groups:", "relations:"}:
            if current and section:
                result[section].append(current)
            section = stripped[:-1]
            current = None
            list_key = None
            continue
        if stripped.startswith("- "):
            value = stripped[2:].strip()
            if ":" in value:
                if current and section:
                    result[section].append(current)
                key, val = value.split(":", 1)
                current = {key.strip(): _scalar(val)}
                list_key = None
            elif current is not None and list_key:
                current.setdefault(list_key, []).append(value)
            continue
        if ":" in stripped and current is not None:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip()
            if val:
                current[key] = _scalar(val)
                list_key = None
            else:
                current[key] = []
                list_key = key
    if current and section:
        result[section].append(current)
    return result


def _scalar(value: str) -> str:
    return value.strip().strip('"').strip("'")
