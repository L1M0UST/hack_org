"""Environment-file loading helpers."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


def load_env_file(path: Path | None) -> None:
    """Load .env files with a UTF-8 first pass and GB18030 fallback for migrated Windows files."""

    if not path:
        return
    try:
        load_dotenv(path, encoding="utf-8")
    except UnicodeDecodeError:
        load_dotenv(path, encoding="gb18030")
