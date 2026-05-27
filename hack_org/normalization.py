"""Normalization helpers for names, aliases, and stable identifiers."""

from __future__ import annotations

import re
import uuid


def normalize_name(value: str) -> str:
    """Normalize an actor name for exact matching without fuzzy merging."""

    value = value.strip()
    value = value.replace("（", "(").replace("）", ")")
    value = re.sub(r"\s+", " ", value)
    return value.casefold()


def split_name_parts(value: str) -> list[str]:
    """Split a display name into useful exact-match parts."""

    normalized = value.replace("（", "(").replace("）", ")")
    parts = [normalized]
    for match in re.findall(r"\(([^)]+)\)", normalized):
        parts.append(match.strip())
    parts.extend(part.strip() for part in re.split(r"[/,，;；]", normalized) if part.strip())
    return sorted({part for part in parts if part})


def stable_group_id(canonical_name: str) -> str:
    """Create a stable deterministic group id from a canonical name."""

    namespace = uuid.UUID("94f2b6dd-9079-4a30-b041-c2c1400d6d69")
    digest = uuid.uuid5(namespace, normalize_name(canonical_name))
    return f"grp_{digest.hex[:12]}"
