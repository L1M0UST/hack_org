"""CSV import and group normalization."""

from __future__ import annotations

import re
from io import StringIO
from pathlib import Path

import pandas as pd

from .models import GroupProfile
from .normalization import split_name_parts
from .storage import StateStore
from .utils import read_text_guess, repair_mojibake


NAME_COLUMNS = ("hacker_group_name", "组织名称", "apt_organization", "group_name")
DESC_COLUMNS = ("description", "简介", "team_description", "desc")


def import_groups(csv_path: Path) -> list[GroupProfile]:
    """Import group names and descriptions from a CSV with flexible headers."""

    frame = _read_csv(csv_path)
    name_col = _first_existing(frame.columns, NAME_COLUMNS)
    desc_col = _first_existing(frame.columns, DESC_COLUMNS)
    if not name_col:
        raise ValueError(f"CSV must contain one of these name columns: {', '.join(NAME_COLUMNS)}")
    groups: list[GroupProfile] = []
    for _, row in frame.iterrows():
        name = repair_mojibake(str(row.get(name_col, "")).strip())
        if not name or name.lower() == "nan":
            continue
        description = "" if not desc_col or pd.isna(row.get(desc_col)) else repair_mojibake(str(row.get(desc_col)).strip())
        terms = sorted({name, *split_name_parts(name)})
        groups.append(GroupProfile(canonical_name=name, description=description, aliases=[], search_terms=terms))
    return groups


def import_groups_to_store(csv_path: Path, store: StateStore) -> dict[str, int]:
    """Import CSV rows into SQLite, merging only exact canonical or confirmed alias hits."""

    groups = import_groups(csv_path)
    stats = {"rows": 0, "new_observations": 0, "groups": 0}
    for group in groups:
        stats["rows"] += 1
        existing = _find_existing_group(store, group)
        group_id = existing["id"] if existing else store.upsert_group(group.canonical_name, group.description)
        if not existing:
            stats["groups"] += 1
        if store.add_observation(group_id, group.canonical_name, group.description, str(csv_path)):
            stats["new_observations"] += 1
    return stats


def extract_aliases(name: str, description: str = "") -> list[str]:
    """Extract aliases from parenthetical names and APT-style tokens."""

    aliases: set[str] = set()
    for text in (name, description):
        text = text.replace("（", "(").replace("）", ")")
        for match in re.findall(r"\(([^)]+)\)", text):
            aliases.add(match.strip())
        for match in re.findall(r"\b(?:APT|UNC|TA|FIN|DEV|G)[-\s]?\d{1,5}\b", text, flags=re.I):
            aliases.add(match.strip())
    aliases.discard(name)
    return sorted(aliases)


def _read_csv(csv_path: Path) -> pd.DataFrame:
    """Read CSV content after repairing common double-decoding mojibake."""

    text = read_text_guess(csv_path)
    return pd.read_csv(StringIO(repair_mojibake(text)))


def _find_existing_group(store: StateStore, group: GroupProfile):
    """Find an existing group using only exact canonical names or confirmed aliases."""

    candidates = [group.canonical_name, *split_name_parts(group.canonical_name)]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        found = store.find_group_by_name_or_alias(candidate)
        if found:
            return found
    return None


def _first_existing(columns: list[str] | pd.Index, candidates: tuple[str, ...]) -> str | None:
    normalized = {str(col).strip(): str(col).strip() for col in columns}
    for candidate in candidates:
        if candidate in normalized:
            return normalized[candidate]
    return None
