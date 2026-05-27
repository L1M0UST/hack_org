"""Configuration loading for source registry files."""

from __future__ import annotations

import re
from pathlib import Path

from .models import SourceConfig
from .utils import read_text_guess, repair_mojibake


def load_sources(path: Path) -> list[SourceConfig]:
    """Load source registry from a small YAML subset used by config/sources.yaml."""

    text = repair_mojibake(read_text_guess(path))
    items: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#") or line.strip() == "sources:":
            continue
        if re.match(r"\s*-\s+", line):
            if current:
                items.append(current)
            current = {}
            line = re.sub(r"^\s*-\s+", "", line)
        if ":" in line and current is not None:
            key, value = line.strip().split(":", 1)
            value = value.strip().strip('"').strip("'")
            if value.startswith("[") and value.endswith("]"):
                current[key] = [part.strip().strip('"').strip("'") for part in value[1:-1].split(",") if part.strip()]
            elif value.lower() in {"true", "false"}:
                current[key] = value.lower() == "true"
            else:
                try:
                    current[key] = float(value) if "." in value else int(value)
                except ValueError:
                    current[key] = value
    if current:
        items.append(current)
    return [SourceConfig.model_validate(item) for item in items]
