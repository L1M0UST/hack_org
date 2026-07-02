"""Small reusable helpers for paths, text, hashing, and JSON files."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOPIC_DIRS = {
    "basic": "基本情况",
    "org": "组织架构",
    "timeline": "活动时间",
}


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def read_text_guess(path: Path) -> str:
    """Read text with common encodings used by Chinese CSV exports."""

    for encoding in ("utf-8-sig", "utf-8", "gb18030"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(errors="replace")


def repair_mojibake(value: str) -> str:
    """Repair common UTF-8 text that was previously decoded as Latin-1."""

    markers = ("Ãƒ", "Ã‚", "Ã¦", "Ã§", "Ã¨", "Ã©", "Ã¯Â¼", "ä", "å", "æ", "ç", "è", "é", "ï¼")
    if sum(value.count(marker) for marker in markers) < 2:
        return value
    for encoding in ("latin1", "cp1252"):
        try:
            repaired = value.encode(encoding).decode("utf-8")
        except UnicodeError:
            continue
        if repaired.count("\ufffd") <= value.count("\ufffd"):
            return repaired
    return value


def slugify(value: str, fallback: str = "item") -> str:
    """Create a filesystem-safe slug while preserving readable CJK text."""

    value = re.sub(r"[\\/:*?\"<>|]+", "_", value.strip())
    value = re.sub(r"\s+", "_", value)
    value = value.strip("._ ")
    return value[:90] or fallback


def sha256_text(value: str) -> str:
    """Return a stable SHA-256 hash for text."""

    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def write_json(path: Path, data: Any) -> None:
    """Write pretty UTF-8 JSON, creating parent directories as needed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    """Append one JSON object to a JSONL log file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, ensure_ascii=False) + "\n")
